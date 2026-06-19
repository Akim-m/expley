import pandas as pd
import pytest

from temporal_exploit.fetch import vulncheck
from temporal_exploit.fetch.vulncheck import VulncheckKevConnector

PAGE1 = {
    "data": [
        {"cve": ["CVE-2024-0001", "CVE-2024-0002"], "date_added": "2024-01-10"},
        {"cve": ["CVE-2024-0003"], "date_added": "2024-02-01"},
    ],
    "_meta": {"next_cursor": "abc"},
}
PAGE2 = {
    "data": [
        {"cve": ["CVE-2024-0001"], "date_added": "2024-01-05"},
    ],
    "_meta": {},
}


def _mock_pages(calls):
    def fake(url, token):
        calls.append((url, token))
        return PAGE2 if "cursor=abc" in url else PAGE1

    return fake


def test_fetch_paginates_explodes_and_dedupes_earliest(monkeypatch):
    calls = []
    monkeypatch.setattr(vulncheck, "_fetch_page", _mock_pages(calls))
    frame = VulncheckKevConnector().fetch(token="tok")

    assert len(calls) == 2
    assert all(token == "tok" for _, token in calls)
    assert "cursor=abc" in calls[1][0]

    assert list(frame.columns) == ["cve_id", "vulncheck_kev_date_added"]
    assert str(frame["vulncheck_kev_date_added"].dt.tz) == "UTC"
    assert len(frame) == 3
    # CVE-2024-0001 appears on both pages; earliest date wins
    row = frame[frame["cve_id"] == "CVE-2024-0001"].iloc[0]
    assert row["vulncheck_kev_date_added"] == pd.Timestamp("2024-01-05", tz="UTC")


def test_fetch_requires_token():
    with pytest.raises(ValueError):
        VulncheckKevConnector().fetch(token="")


def test_fetch_url_encodes_cursor(monkeypatch):
    # v3 cursors are base64-ish (+ / =) — a raw f-string interpolation produces a
    # malformed query and breaks pagination on page 2 (the first real token use).
    seen = []

    def fake(url, token):
        seen.append(url)
        if "cursor" in url:
            return {"data": [{"cve": ["CVE-2024-9"], "date_added": "2024-03-01"}], "_meta": {}}
        return {"data": [{"cve": ["CVE-2024-1"], "date_added": "2024-01-01"}],
                "_meta": {"next_cursor": "a+b/c=="}}

    monkeypatch.setattr(vulncheck, "_fetch_page", fake)
    frame = VulncheckKevConnector().fetch(token="tok")
    assert any("cursor=a%2Bb%2Fc%3D%3D" in u for u in seen)  # percent-encoded, not raw
    assert set(frame["cve_id"]) == {"CVE-2024-1", "CVE-2024-9"}


def test_fetch_skips_entry_without_date(monkeypatch):
    monkeypatch.setattr(
        vulncheck, "_fetch_page",
        lambda url, token: {"data": [{"cve": ["CVE-2024-1"]}], "_meta": {}},  # no date_added
    )
    frame = VulncheckKevConnector().fetch(token="tok")  # must not KeyError
    assert frame.empty


def test_fetch_breaks_on_repeating_cursor(monkeypatch):
    # a server that returns the same cursor forever must not hang the fetch.
    monkeypatch.setattr(
        vulncheck, "_fetch_page",
        lambda url, token: {"data": [{"cve": ["CVE-2024-1"], "date_added": "2024-01-01"}],
                            "_meta": {"next_cursor": "stuck"}},
    )
    frame = VulncheckKevConnector().fetch(token="tok")  # terminates, doesn't loop
    assert len(frame) == 1


def test_save_writes_named_parquet(monkeypatch, tmp_path):
    monkeypatch.setattr(vulncheck, "_fetch_page", _mock_pages([]))
    connector = VulncheckKevConnector()
    path = connector.save(connector.fetch(token="tok"), tmp_path)

    assert path == tmp_path / "vulncheck_kev.parquet"
    assert len(pd.read_parquet(path)) == 3
