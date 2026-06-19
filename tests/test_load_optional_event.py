import pandas as pd

from temporal_exploit.cli import (
    EVENT_SOURCES,
    load_optional_event,
    sources_for_label_set,
)
from temporal_exploit.labels import IN_WILD_SOURCES


def test_sources_for_in_wild_excludes_tooling_only_sources():
    # in-wild labels use only the catalog sources; loading the 188k-row poc
    # source (and metasploit/nuclei/exploitdb) for an in-wild backtest is wasted.
    s = sources_for_label_set("in_wild")
    assert set(s) == set(IN_WILD_SOURCES)
    assert "poc" not in s and "metasploit" not in s and "exploitdb" not in s


def test_sources_for_first_weaponization_uses_all():
    s = sources_for_label_set("first_weaponization")
    assert set(s) == set(EVENT_SOURCES)
    assert "poc" in s


def test_projects_to_only_needed_columns(tmp_path):
    # event parquet with extra columns the pipeline never uses
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "kev_date_added": pd.to_datetime(["2024-01-05"], utc=True),
            "notes": ["unused blob"],
            "vendor_project": ["acme"],
        }
    ).to_parquet(tmp_path / "kev_events.parquet")

    frame = load_optional_event(tmp_path, "kev_events", "kev_date_added")
    # only cve_id + the date column are read off disk; extras never enter memory
    assert set(frame.columns) == {"cve_id", "kev_date_added"}


def test_keeps_requested_extra_columns(tmp_path):
    # poc feeds build_poc_features, which needs poc_source + poc_path
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": pd.to_datetime(["2024-01-05"], utc=True),
            "poc_source": ["trickest"],
            "poc_path": ["2024/CVE-2024-0001.md"],
        }
    ).to_parquet(tmp_path / "poc_dates.parquet")
    frame = load_optional_event(
        tmp_path, "poc_dates", "poc_first_seen", ("poc_source", "poc_path")
    )
    assert set(frame.columns) == {"cve_id", "poc_first_seen", "poc_source", "poc_path"}


def test_missing_file_returns_none(tmp_path):
    assert load_optional_event(tmp_path, "does_not_exist", "x_date") is None


def test_missing_date_column_still_raises(tmp_path):
    # projection must not mask a genuinely malformed source (no date col -> raise)
    pd.DataFrame({"cve_id": ["CVE-2024-0001"]}).to_parquet(tmp_path / "kev_events.parquet")
    try:
        load_optional_event(tmp_path, "kev_events", "kev_date_added")
    except Exception as exc:  # validate_columns should fail loud
        assert "kev_date_added" in str(exc)
    else:
        raise AssertionError("expected a missing-column error")
