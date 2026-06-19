import pandas as pd

from temporal_exploit.cli import refresh_command
from temporal_exploit.fetch import epss, exploitdb, kev, zeroday


def test_refresh_runs_all_http_sources_and_isolates_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(
        kev.KevConnector, "fetch",
        lambda self, cache_dir=None: pd.DataFrame(
            {"cve_id": ["A"], "kev_date_added": pd.to_datetime(["2024-01-01"], utc=True)}
        ),
    )
    monkeypatch.setattr(
        zeroday.ZerodayConnector, "fetch",
        lambda self, url=None, cache_dir=None: pd.DataFrame({"cve_id": ["B"]}),
    )

    def _boom(self, url=None, cache_dir=None):
        raise RuntimeError("source down")

    monkeypatch.setattr(exploitdb.ExploitDbConnector, "fetch", _boom)
    monkeypatch.setattr(
        epss.EpssConnector, "fetch",
        lambda self, date, cache_dir=None: pd.DataFrame(
            {"cve_id": ["C"], "date": pd.to_datetime(["2024-01-01"], utc=True),
             "epss": [0.1], "percentile": [0.5]}
        ),
    )

    entries = refresh_command(
        str(tmp_path / "live"), cache_dir=str(tmp_path / "cache"), repo_dir=None
    )
    by = {e["source"]: e for e in entries}
    assert by["kev_events"]["rows"] == 1 and by["epss_history"]["rows"] == 1
    assert "error" in by["exploitdb"]  # one source failing doesn't abort the others
    assert (tmp_path / "live" / "kev_events.parquet").exists()
    assert (tmp_path / "live" / "fetch_manifest.json").exists()
