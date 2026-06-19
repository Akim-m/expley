import gzip
import io
import json
import zipfile

import pytest

from temporal_exploit.fetch.nvdplus import NvdPlusConnector

# a minimal NVD 2.0 cve object (bare, as NVD++ index returns it)
ENTRY = {
    "id": "CVE-2026-1",
    "published": "2026-01-01T00:00:00Z",
    "lastModified": "2026-02-01T00:00:00Z",
    "descriptions": [{"lang": "en", "value": "test"}],
    "references": [{"url": "https://a"}, {"url": "https://b"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH",
                                                "vectorString": "CVSS:3.1/AV:N"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
    "configurations": [],
}


def _zip(obj):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nvd.json", json.dumps(obj))
    return buf.getvalue()


def test_parse_handles_bare_and_wrapped_entries():
    # NVD++ gives bare cve objects; a standard NVD feed wraps them as {"cve": ...}
    raw = _zip({"data": [ENTRY, {"cve": {**ENTRY, "id": "CVE-2026-2"}}]})
    df = NvdPlusConnector._parse(raw)
    assert list(df["cve_id"]) == ["CVE-2026-1", "CVE-2026-2"]
    row = df.iloc[0]
    assert row["cvss_v3_base"] == 8.8 and row["cvss_v3_severity"] == "HIGH"
    assert list(row["cwe_ids"]) == ["CWE-79"]
    assert row["reference_count"] == 2


def test_fetch_downloads_backup(monkeypatch, tmp_path):
    # _download now streams to a temp file and returns its PATH; fetch unlinks it
    zpath = tmp_path / "nvd.zip"
    zpath.write_bytes(_zip({"data": [ENTRY]}))
    monkeypatch.setattr(NvdPlusConnector, "_backup_url", lambda self, t: "https://x/nvd.zip")
    monkeypatch.setattr(NvdPlusConnector, "_download", lambda self, u: str(zpath))
    df = NvdPlusConnector().fetch("tok")
    assert list(df["cve_id"]) == ["CVE-2026-1"]
    assert str(df["published"].dt.tz) == "UTC"
    assert not zpath.exists()  # fetch cleaned up the temp file


def test_parse_handles_gzipped_members():
    # the real NVD++ backup zip stores gzip-compressed JSON members
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nvd.json.gz", gzip.compress(json.dumps({"data": [ENTRY]}).encode()))
    df = NvdPlusConnector._parse(buf.getvalue())
    assert list(df["cve_id"]) == ["CVE-2026-1"]


def test_parse_streams_ndjson_member():
    # some dumps are NDJSON (one JSON object per line) rather than a JSON array
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        nd = "\n".join(json.dumps({**ENTRY, "id": f"CVE-2026-{i}"}) for i in range(3))
        zf.writestr("nvd.ndjson", nd)
    df = NvdPlusConnector._parse(buf.getvalue())
    assert list(df["cve_id"]) == ["CVE-2026-0", "CVE-2026-1", "CVE-2026-2"]


def test_parse_chunks_across_boundary(monkeypatch):
    # force several chunks so the concat path (not a single batch) is exercised
    monkeypatch.setattr("temporal_exploit.fetch.nvdplus._CHUNK", 4)
    entries = [{**ENTRY, "id": f"CVE-2026-{i}"} for i in range(11)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nvd.json", json.dumps({"data": entries}))
    df = NvdPlusConnector._parse(buf.getvalue())
    assert len(df) == 11 and df["cve_id"].is_unique


def test_fetch_requires_token():
    with pytest.raises(ValueError):
        NvdPlusConnector().fetch("")
