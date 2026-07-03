"""L1: Vulnrichment SSVC git-history miner — parser + frame contract tests."""
import pandas as pd

from temporal_exploit.fetch.vulnrichment import (
    COMMIT_SENTINEL,
    parse_ssvc_transitions,
    transitions_to_frame,
)


def _log(*chunks):
    return "\n".join(chunks).splitlines()


def test_parser_records_earliest_transition_per_value():
    lines = _log(
        f"{COMMIT_SENTINEL}2024-07-01T10:00:00+00:00",
        "+++ b/2024/24xxx/CVE-2024-1111.json",
        '+          {"Exploitation": "poc"},',
        f"{COMMIT_SENTINEL}2024-08-02T10:00:00+00:00",
        "+++ b/2024/24xxx/CVE-2024-1111.json",
        '+          {"Exploitation": "active"},',
        f"{COMMIT_SENTINEL}2024-09-03T10:00:00+00:00",  # later re-add must NOT win
        "+++ b/2024/24xxx/CVE-2024-1111.json",
        '+          {"Exploitation": "active"},',
    )
    got = parse_ssvc_transitions(lines)
    assert got["CVE-2024-1111"]["poc"] == "2024-07-01T10:00:00+00:00"
    assert got["CVE-2024-1111"]["active"] == "2024-08-02T10:00:00+00:00"


def test_parser_handles_split_lines_deletes_and_noise():
    lines = _log(
        f"{COMMIT_SENTINEL}2024-05-05T00:00:00+00:00",
        "+++ b/2024/2xxx/CVE-2024-2222.json",
        '+          "Exploitation":',
        '+              "active",',            # value on the next added line
        "+++ /dev/null",                        # delete: clears current file
        '+          {"Exploitation": "poc"},',  # must NOT attach to anything
        "+++ b/README.md",                      # non-CVE file
        '+  "Exploitation": "active"',          # must NOT be recorded
        f"{COMMIT_SENTINEL}2024-06-06T00:00:00+00:00",
        "+++ b/2024/2xxx/CVE-2024-3333.json",
        '-          {"Exploitation": "active"},',  # removal, not addition
    )
    got = parse_ssvc_transitions(lines)
    assert got == {"CVE-2024-2222": {"active": "2024-05-05T00:00:00+00:00"}}


def test_parser_normalizes_capitalized_values():
    # The real cisagov/vulnrichment history carries a handful of capitalized
    # typos ("Active"/"PoC"/"None") alongside the lowercase norm; they must be
    # matched and normalized to lowercase, not silently dropped. An earlier
    # lowercase "poc" must still win over a later capitalized "PoC" re-add.
    lines = _log(
        f"{COMMIT_SENTINEL}2024-05-08T10:04:10-04:00",
        "+++ b/2015/2xxx/CVE-2015-2051.json",
        '+                    "Exploitation": "Active"',   # capitalized in-wild label
        f"{COMMIT_SENTINEL}2024-06-01T00:00:00+00:00",
        "+++ b/2015/2xxx/CVE-2015-2051.json",
        '+                    "Exploitation": "PoC"',       # later, must NOT overwrite active
        f"{COMMIT_SENTINEL}2024-04-01T00:00:00+00:00",     # earlier commit (order preserved by miner)
        "+++ b/2015/9xxx/CVE-2015-9999.json",
        '+                    "Exploitation": "None"',      # capitalized none -> normalized, then dropped by frame
    )
    got = parse_ssvc_transitions(lines)
    assert got["CVE-2015-2051"]["active"] == "2024-05-08T10:04:10-04:00"
    assert got["CVE-2015-2051"]["poc"] == "2024-06-01T00:00:00+00:00"
    assert got["CVE-2015-9999"] == {"none": "2024-04-01T00:00:00+00:00"}


def test_transitions_to_frame_contract():
    frame = transitions_to_frame({
        "CVE-2024-1111": {"poc": "2024-07-01T10:00:00+00:00",
                          "active": "2024-08-02T10:00:00+00:00"},
        "CVE-2024-2222": {"active": "2024-05-05T00:00:00+00:00"},
        "CVE-2024-4444": {"none": "2024-01-01T00:00:00+00:00"},  # no poc/active
    })
    assert list(frame.columns) == ["cve_id", "ssvc_active_date", "ssvc_poc_date"]
    assert str(frame["ssvc_active_date"].dtype) == "datetime64[ns, UTC]"
    row = frame.set_index("cve_id").loc["CVE-2024-1111"]
    assert row["ssvc_active_date"] == pd.Timestamp("2024-08-02T10:00:00Z")
    # CVE with only "none" is excluded — it carries no exploitation label
    assert "CVE-2024-4444" not in set(frame["cve_id"])
