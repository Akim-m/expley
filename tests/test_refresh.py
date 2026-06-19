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


def _stub_keyless(monkeypatch):
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
    monkeypatch.setattr(
        exploitdb.ExploitDbConnector, "fetch",
        lambda self, url=None, cache_dir=None: pd.DataFrame({"cve_id": ["E"]}),
    )
    monkeypatch.setattr(
        epss.EpssConnector, "fetch",
        lambda self, date, cache_dir=None: pd.DataFrame(
            {"cve_id": ["C"], "date": pd.to_datetime(["2024-01-01"], utc=True),
             "epss": [0.1], "percentile": [0.5]}
        ),
    )


def test_refresh_vulncheck_skips_without_token(monkeypatch, tmp_path):
    _stub_keyless(monkeypatch)
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    entries = refresh_command(
        str(tmp_path / "live"), cache_dir=str(tmp_path / "cache"), repo_dir=None
    )
    by = {e["source"]: e for e in entries}
    assert by["vulncheck_kev"]["status"] == "skipped"  # graceful, not an error
    assert not (tmp_path / "live" / "vulncheck_kev.parquet").exists()


def test_refresh_vulncheck_fetches_with_token(monkeypatch, tmp_path):
    from temporal_exploit.fetch import vulncheck

    _stub_keyless(monkeypatch)
    monkeypatch.setattr(
        vulncheck.VulncheckKevConnector, "fetch",
        lambda self, token: pd.DataFrame(
            {"cve_id": ["V"], "vulncheck_kev_date_added": pd.to_datetime(["2024-02-01"], utc=True)}
        ),
    )
    entries = refresh_command(
        str(tmp_path / "live"), cache_dir=str(tmp_path / "cache"), repo_dir=None,
        vulncheck_token="tok",
    )
    by = {e["source"]: e for e in entries}
    assert by["vulncheck_kev"]["rows"] == 1 and by["vulncheck_kev"]["status"] == "ok"
    assert (tmp_path / "live" / "vulncheck_kev.parquet").exists()
