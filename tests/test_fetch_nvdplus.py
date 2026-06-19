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


def test_fetch_downloads_backup(monkeypatch):
    monkeypatch.setattr(NvdPlusConnector, "_backup_url", lambda self, t: "https://x/nvd.zip")
    monkeypatch.setattr(NvdPlusConnector, "_download", lambda self, u: _zip({"data": [ENTRY]}))
    df = NvdPlusConnector().fetch("tok")
    assert list(df["cve_id"]) == ["CVE-2026-1"]
    assert str(df["published"].dt.tz) == "UTC"


def test_fetch_requires_token():
    with pytest.raises(ValueError):
        NvdPlusConnector().fetch("")
