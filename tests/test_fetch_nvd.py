import pandas as pd

from temporal_exploit.fetch import nvd
from temporal_exploit.fetch.nvd import (
    CVE_CORPUS_COLUMNS,
    NvdConnector,
    parse_nvd_vulnerabilities,
)


def _cve(**overrides):
    cve = {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2023-04-03T20:15:08.700",
        "descriptions": [
            {"lang": "es", "value": "ignored"},
            {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP."},
        ],
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-502"}]},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://a"}, {"url": "https://b"}],
    }
    cve.update(overrides)
    return {"cve": cve}


def test_parse_maps_full_entry():
    frame = parse_nvd_vulnerabilities([_cve()])

    assert list(frame.columns) == list(CVE_CORPUS_COLUMNS)
    row = frame.iloc[0]
    assert row["cve_id"] == "CVE-2021-44228"
    assert str(frame["published"].dt.tz) == "UTC"
    assert str(frame["last_modified"].dt.tz) == "UTC"
    assert "Apache Log4j2" in row["description"]
    assert row["cwe_ids"] == ["CWE-502"]
    assert row["cvss_v3_base"] == 9.8
    assert row["cvss_v3_severity"] == "CRITICAL"
    assert row["cvss_v3_vector"].startswith("CVSS:3.1")
    assert row["vendors"] == ["apache"]
    assert row["products"] == ["log4j"]
    assert row["reference_count"] == 2


def test_parse_missing_fields_no_crash():
    entry = {
        "cve": {
            "id": "CVE-2024-0001",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "descriptions": [],
        }
    }
    frame = parse_nvd_vulnerabilities([entry])

    row = frame.iloc[0]
    assert row["description"] == ""
    assert row["cwe_ids"] == []
    assert row["vendors"] == []
    assert row["products"] == []
    assert pd.isna(row["cvss_v3_base"])
    assert pd.isna(row["cvss_v2_base"])
    assert row["reference_count"] == 0


def test_fetch_pages_until_total_results(monkeypatch):
    pages = [
        {
            "totalResults": 3,
            "resultsPerPage": 2,
            "vulnerabilities": [_cve(id="CVE-A"), _cve(id="CVE-B")],
        },
        {
            "totalResults": 3,
            "resultsPerPage": 1,
            "vulnerabilities": [_cve(id="CVE-C")],
        },
    ]
    calls = []

    def fake_fetch_json(url, api_key=None):
        calls.append((url, api_key))
        return pages[len(calls) - 1]

    monkeypatch.setattr(nvd, "_fetch_json", fake_fetch_json)

    frame = NvdConnector().fetch(
        "2024-01-01T00:00:00", "2024-02-01T00:00:00", api_key="secret"
    )

    assert len(frame) == 3
    assert len(calls) == 2
    assert list(frame["cve_id"]) == ["CVE-A", "CVE-B", "CVE-C"]
    assert all(api_key == "secret" for _, api_key in calls)


def test_fetch_stops_on_short_page(monkeypatch):
    # totalResults overstates what the API returns; an empty page must end the loop
    pages = [
        {"totalResults": 100, "resultsPerPage": 1, "vulnerabilities": [_cve(id="CVE-A")]},
        {"totalResults": 100, "resultsPerPage": 0, "vulnerabilities": []},
    ]
    calls = []

    def fake_fetch_json(url, api_key=None):
        calls.append(url)
        return pages[min(len(calls) - 1, 1)]

    monkeypatch.setattr(nvd, "_fetch_json", fake_fetch_json)
    frame = NvdConnector().fetch("2024-01-01T00:00:00", "2024-02-01T00:00:00")
    assert len(frame) == 1
    assert len(calls) == 2
