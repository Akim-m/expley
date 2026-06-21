"""MSRC connector parse logic — no network (CVRF doc fixtures)."""
import pandas as pd

from temporal_exploit.fetch.msrc import MsrcConnector, _exploited_cves


def _doc(release, vulns):
    return {"DocumentTracking": {"InitialReleaseDate": release}, "Vulnerability": vulns}


def _vuln(cve, exploited):
    status = f"Publicly Disclosed:No;Exploited:{'Yes' if exploited else 'No'}"
    return {"CVE": cve, "Threats": [{"Description": {"Value": status}}]}


def test_extracts_only_exploited_yes_with_date():
    doc = _doc("2024-08-13T00:00:00", [_vuln("CVE-2024-1", True), _vuln("CVE-2024-2", False)])
    rows = _exploited_cves(doc)
    assert rows == [{"cve_id": "CVE-2024-1", "msrc_exploited_date": "2024-08-13T00:00:00"}]


def test_handles_missing_threats_and_no_cve():
    doc = _doc("2024-08-13", [{"CVE": "CVE-2024-3"}, {"Threats": [{"Description": {"Value": "Exploited:Yes"}}]}])
    assert _exploited_cves(doc) == []  # no threats / no cve -> nothing


def test_connector_dedups_to_earliest_date(monkeypatch):
    # same CVE flagged exploited in two months -> keep the earliest date
    docs = {
        "2024-Jul": _doc("2024-07-09", [_vuln("CVE-2024-9", True)]),
        "2024-Aug": _doc("2024-08-13", [_vuln("CVE-2024-9", True), _vuln("CVE-2024-8", True)]),
    }
    conn = MsrcConnector()
    monkeypatch.setattr(conn, "_fetch_month", lambda m: docs.get(m))
    conn.start_year = 2024
    frame = conn.fetch(end_year=2024, end_month=8)
    assert set(frame["cve_id"]) == {"CVE-2024-8", "CVE-2024-9"}
    row = frame[frame["cve_id"] == "CVE-2024-9"].iloc[0]
    assert row["msrc_exploited_date"] == pd.Timestamp("2024-07-09", tz="UTC")  # earliest
    assert str(frame["msrc_exploited_date"].dtype) == "datetime64[ns, UTC]"
