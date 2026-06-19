import io
import urllib.error

import pytest

from temporal_exploit.fetch import cache


class _Resp:
    def __init__(self, body, headers):
        self._buf = io.BytesIO(body)
        self.headers = headers

    def read(self):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_first_fetch_updates_then_304_serves_cache(monkeypatch, tmp_path):
    url = "https://example.com/data.csv"
    calls = {"n": 0, "sent_headers": []}

    def fake_urlopen(request, timeout=None):
        calls["n"] += 1
        calls["sent_headers"].append(dict(request.headers))
        if calls["n"] == 1:
            return _Resp(b"v1", {"ETag": '"abc"', "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"})
        raise urllib.error.HTTPError(url, 304, "Not Modified", {}, None)

    monkeypatch.setattr(cache.urllib.request, "urlopen", fake_urlopen)

    body, status = cache.conditional_get(url, tmp_path)
    assert body == b"v1" and status == "updated"

    body, status = cache.conditional_get(url, tmp_path)
    assert body == b"v1" and status == "cached"          # 304 -> served from disk
    # the second request carried the validators
    assert calls["sent_headers"][1].get("If-none-match") == '"abc"'


def test_offline_serves_stale_cache(monkeypatch, tmp_path):
    url = "https://example.com/data.csv"
    monkeypatch.setattr(
        cache.urllib.request, "urlopen",
        lambda *a, **k: _Resp(b"cached-body", {"ETag": '"e"'}),
    )
    cache.conditional_get(url, tmp_path)  # populate

    def boom(*a, **k):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(cache.urllib.request, "urlopen", boom)
    body, status = cache.conditional_get(url, tmp_path)
    assert body == b"cached-body" and status == "offline"


def test_no_cache_and_network_down_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cache.urllib.request, "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("down")),
    )
    with pytest.raises(urllib.error.URLError):
        cache.conditional_get("https://example.com/never-cached", tmp_path)
