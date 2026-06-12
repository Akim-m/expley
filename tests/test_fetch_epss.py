import gzip

import pandas as pd

from temporal_exploit.fetch import epss
from temporal_exploit.fetch.epss import EpssConnector

CSV_TEXT = (
    "#model_version:v2025.03.14,score_date:2026-03-14T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.42,0.95\n"
    "CVE-2024-0002,0.01,0.30\n"
)


def _patch(monkeypatch):
    blob = gzip.compress(CSV_TEXT.encode())
    monkeypatch.setattr(epss, "_fetch_csv_gz", lambda url: blob)


def test_fetch_normalizes_snapshot(monkeypatch):
    _patch(monkeypatch)
    frame = EpssConnector().fetch("2026-03-14")

    assert list(frame.columns) == ["cve_id", "date", "epss", "percentile"]
    assert len(frame) == 2
    assert str(frame["date"].dt.tz) == "UTC"
    assert (frame["date"] == pd.Timestamp("2026-03-14", tz="UTC")).all()
    assert list(frame["cve_id"]) == ["CVE-2024-0001", "CVE-2024-0002"]
    assert frame["epss"].tolist() == [0.42, 0.01]
    assert frame["percentile"].tolist() == [0.95, 0.30]
    assert frame["epss"].dtype == float
    assert frame["percentile"].dtype == float


def test_save_round_trips(monkeypatch, tmp_path):
    _patch(monkeypatch)
    connector = EpssConnector()
    path = connector.save(connector.fetch("2026-03-14"), tmp_path)

    assert path == tmp_path / "epss_history.parquet"
    reloaded = pd.read_parquet(path)
    assert list(reloaded.columns) == ["cve_id", "date", "epss", "percentile"]
