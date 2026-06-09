from pathlib import Path

import pandas as pd


def write_tiny_handover(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": ["2024-01-01", "2024-02-01"],
            "cvss_v3_base_score": [9.8, 5.3],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM"],
            "weaknesses": [["CWE-79"], ["CWE-89"]],
            "vendors": [["apache"], ["example"]],
            "products": [["httpd"], ["widget"]],
        }
    ).to_parquet(out_dir / "cve_corpus.parquet")
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "poc_first_seen": ["2024-01-10"],
        }
    ).to_parquet(out_dir / "poc_dates.parquet")
    pd.DataFrame({"cve_id": ["CVE-2024-0001"], "dateAdded": ["2024-01-20"]}).to_parquet(
        out_dir / "kev_events.parquet"
    )
