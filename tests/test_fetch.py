import json

import pandas as pd

from temporal_exploit.fetch import kev
from temporal_exploit.fetch.base import write_fetch_manifest
from temporal_exploit.fetch.kev import KevConnector
from temporal_exploit.schema import REQUIRED_COLUMNS, validate_columns


def test_fetch_returns_normalized_frame(monkeypatch):
    monkeypatch.setattr(
        kev,
        "_fetch_json",
        lambda url: {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-20"},
                {"cveID": "CVE-2024-0002", "dateAdded": "2024-02-01"},
            ]
        },
    )
    frame = KevConnector().fetch()

    assert list(frame.columns) == ["cve_id", "kev_date_added"]
    assert len(frame) == 2
    assert str(frame["kev_date_added"].dt.tz) == "UTC"
    assert list(frame["cve_id"]) == ["CVE-2024-0001", "CVE-2024-0002"]


def test_fetch_dedupes_to_earliest(monkeypatch):
    monkeypatch.setattr(
        kev,
        "_fetch_json",
        lambda url: {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "dateAdded": "2024-03-01"},
                {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-20"},
            ]
        },
    )
    frame = KevConnector().fetch()

    assert len(frame) == 1
    assert frame["kev_date_added"].iloc[0] == pd.Timestamp("2024-01-20", tz="UTC")


def test_save_round_trips_and_validates(monkeypatch, tmp_path):
    monkeypatch.setattr(
        kev,
        "_fetch_json",
        lambda url: {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-20"},
            ]
        },
    )
    connector = KevConnector()
    path = connector.save(connector.fetch(), tmp_path)

    assert path == tmp_path / "kev_events.parquet"
    frame = pd.read_parquet(path)
    validate_columns(frame, "kev_events", REQUIRED_COLUMNS["kev_events"])


def test_write_fetch_manifest(tmp_path):
    write_fetch_manifest(tmp_path, [{"name": "kev_events", "row_count": 2}])

    payload = json.loads((tmp_path / "fetch_manifest.json").read_text(encoding="utf-8"))
    assert "fetched_utc" in payload
    assert payload["entries"][0]["row_count"] == 2
