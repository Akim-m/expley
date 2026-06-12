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


def test_save_writes_named_parquet(monkeypatch, tmp_path):
    monkeypatch.setattr(vulncheck, "_fetch_page", _mock_pages([]))
    connector = VulncheckKevConnector()
    path = connector.save(connector.fetch(token="tok"), tmp_path)

    assert path == tmp_path / "vulncheck_kev.parquet"
    assert len(pd.read_parquet(path)) == 3
