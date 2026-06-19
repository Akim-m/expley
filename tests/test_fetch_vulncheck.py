import io
import json
import zipfile

import pandas as pd
import pytest

from temporal_exploit.fetch.vulncheck import VulncheckKevConnector, _best_date


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("vulncheck_known_exploited_vulnerabilities.json", json.dumps(entries))
    return buf.getvalue()


def test_best_date_prefers_earliest_evidence_and_drops_sentinel():
    entry = {
        "cve": ["CVE-1"],
        "date_added": "2024-05-01T00:00:00Z",
        "vulncheck_reported_exploitation": [
            {"date_added": "1970-01-01T00:00:00Z"},  # epoch sentinel -> dropped
            {"date_added": "2024-02-01T00:00:00Z"},  # earliest valid evidence -> wins
        ],
    }
    assert _best_date(entry) == pd.Timestamp("2024-02-01", tz="UTC")


def test_best_date_falls_back_to_date_added():
    entry = {"cve": ["CVE-1"], "date_added": "2024-05-01T00:00:00Z",
             "vulncheck_reported_exploitation": []}
    assert _best_date(entry) == pd.Timestamp("2024-05-01", tz="UTC")


def test_best_date_none_when_all_sentinel():
    entry = {"cve": ["CVE-1"], "date_added": "1970-01-01T00:00:00Z",
             "vulncheck_reported_exploitation": [{"date_added": "1970-01-01T00:00:00Z"}]}
    assert _best_date(entry) is None


def test_parse_explodes_cve_and_dedupes_earliest():
    entries = [
        {"cve": ["CVE-1", "CVE-2"], "date_added": "2024-03-01T00:00:00Z"},
        {"cve": ["CVE-1"], "vulncheck_reported_exploitation": [{"date_added": "2024-01-05T00:00:00Z"}]},
    ]
    frame = VulncheckKevConnector._parse(_zip(entries))
    assert list(frame.columns) == ["cve_id", "vulncheck_kev_date_added"]
    by = dict(zip(frame["cve_id"], frame["vulncheck_kev_date_added"]))
    assert set(by) == {"CVE-1", "CVE-2"}
    assert by["CVE-1"] == pd.Timestamp("2024-01-05", tz="UTC")  # earliest across entries wins


def test_fetch_downloads_and_parses_backup(monkeypatch):
    entries = [{"cve": ["CVE-9"], "date_added": "2024-06-01T00:00:00Z"}]
    monkeypatch.setattr(VulncheckKevConnector, "_backup_url", lambda self, t: "https://x/backup.zip")
    monkeypatch.setattr(VulncheckKevConnector, "_download", lambda self, u: _zip(entries))
    frame = VulncheckKevConnector().fetch("tok")
    assert list(frame["cve_id"]) == ["CVE-9"]
    assert str(frame["vulncheck_kev_date_added"].dt.tz) == "UTC"


def test_fetch_requires_token():
    with pytest.raises(ValueError):
        VulncheckKevConnector().fetch("")


def test_save_writes_named_parquet(monkeypatch, tmp_path):
    entries = [{"cve": ["CVE-9"], "date_added": "2024-06-01T00:00:00Z"}]
    monkeypatch.setattr(VulncheckKevConnector, "_backup_url", lambda self, t: "u")
    monkeypatch.setattr(VulncheckKevConnector, "_download", lambda self, u: _zip(entries))
    connector = VulncheckKevConnector()
    path = connector.save(connector.fetch("tok"), tmp_path)
    assert path == tmp_path / "vulncheck_kev.parquet"
    assert len(pd.read_parquet(path)) == 1
