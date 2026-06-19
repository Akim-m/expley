import hashlib
import hmac
from pathlib import Path

import pandas as pd
import pytest

from temporal_exploit.fetch.shadowserver import ShadowserverConnector, _load_credentials


def test_normalize_earliest_per_cve_and_list_values():
    rows = [
        {"timestamp": "2024-03-01T00:00:00", "cve": "CVE-2024-1"},
        {"timestamp": "2024-01-15T00:00:00", "cve": "CVE-2024-1"},  # earlier -> wins
        {"timestamp": "2024-02-01T00:00:00", "cve": ["CVE-2024-2", "CVE-2024-3"]},
        {"timestamp": None, "cve": "CVE-2024-4"},  # dropped (no ts)
        {"timestamp": "2024-02-01T00:00:00", "cve": None},  # dropped (no cve)
    ]
    frame = ShadowserverConnector._normalize(rows)
    by = dict(zip(frame["cve_id"], frame["shadowserver_first_seen"]))
    assert set(by) == {"CVE-2024-1", "CVE-2024-2", "CVE-2024-3"}
    assert by["CVE-2024-1"] == pd.Timestamp("2024-01-15", tz="UTC")  # earliest kept


def test_load_credentials_from_env(monkeypatch):
    monkeypatch.setenv("SHADOWSERVER_API_KEY", "k")
    monkeypatch.setenv("SHADOWSERVER_API_SECRET", "s")
    assert _load_credentials(None, None) == ("k", "s")


def test_fetch_requires_credentials(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSERVER_API_KEY", raising=False)
    monkeypatch.delenv("SHADOWSERVER_API_SECRET", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)  # no ~/.shadowserver.api
    with pytest.raises(ValueError, match="Shadowserver"):
        ShadowserverConnector().fetch()


def test_call_signs_body_with_hmac_sha256(monkeypatch):
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"[]"

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = request.data
        captured["hmac"] = request.get_header("Hmac2")
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    ShadowserverConnector()._call("reports/query", {"report": "r"}, "mykey", "mysecret", 60)
    expected = hmac.new(b"mysecret", captured["body"], hashlib.sha256).hexdigest()
    assert captured["hmac"] == expected  # body signed, hex digest in HMAC2 header
    assert b'"apikey": "mykey"' in captured["body"]  # apikey travels in the body
    assert captured["url"].endswith("/reports/query")


def test_fetch_normalizes_via_call(monkeypatch):
    monkeypatch.setenv("SHADOWSERVER_API_KEY", "k")
    monkeypatch.setenv("SHADOWSERVER_API_SECRET", "s")
    monkeypatch.setattr(
        ShadowserverConnector, "_call",
        lambda self, m, p, k, s, t: [{"timestamp": "2024-05-01T00:00:00", "cve": "CVE-2024-9"}],
    )
    frame = ShadowserverConnector().fetch()
    assert list(frame["cve_id"]) == ["CVE-2024-9"]
    assert frame["shadowserver_first_seen"].iloc[0] == pd.Timestamp("2024-05-01", tz="UTC")
