from pathlib import Path

import pandas as pd


def write_tiny_handover(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
            "last_modified": pd.to_datetime(["2024-01-03", "2024-02-02"], utc=True),
            "description": [
                "Remote attacker triggers a buffer overflow.",
                "SQL injection allows authentication bypass.",
            ],
            "cvss_v3_base": [9.8, 5.3],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM"],
            "cwe_ids": [["CWE-79"], ["CWE-89"]],
            "vendors": [["apache"], ["example"]],
            "products": [["httpd"], ["widget"]],
        }
    ).to_parquet(out_dir / "cve_corpus.parquet")
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_source": ["trickest"],
            "poc_first_seen": pd.to_datetime(["2024-01-10"], utc=True),
            "poc_path": ["2024/CVE-2024-0001.md"],
        }
    ).to_parquet(out_dir / "poc_dates.parquet")
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "kev_date_added": pd.to_datetime(["2024-01-20"], utc=True),
        }
    ).to_parquet(out_dir / "kev_events.parquet")
