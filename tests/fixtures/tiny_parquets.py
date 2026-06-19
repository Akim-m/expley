from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


def write_epss_row_groups(path: Path, by_date: dict) -> str:
    """Write an EPSS-history parquet with ONE row group per date.

    Mirrors the real epss_history file (1787 row groups, one daily snapshot
    each) so tests can exercise date-based row-group skipping. ``by_date`` maps
    an ISO date string to a list of ``(cve_id, epss, percentile)`` records;
    each date becomes its own row group.
    """
    epss_path = str(path / "epss_row_groups.parquet")
    schema = pa.schema(
        [
            ("cve_id", pa.string()),
            ("date", pa.timestamp("us", tz="UTC")),
            ("epss", pa.float64()),
            ("percentile", pa.float64()),
        ]
    )
    with pq.ParquetWriter(epss_path, schema) as writer:
        for date in sorted(by_date):
            records = by_date[date]
            ts = pd.Timestamp(date, tz="UTC")
            writer.write_table(
                pa.table(
                    {
                        "cve_id": [r[0] for r in records],
                        "date": pa.array([ts] * len(records), type=pa.timestamp("us", tz="UTC")),
                        "epss": [float(r[1]) for r in records],
                        "percentile": [float(r[2]) for r in records],
                    },
                    schema=schema,
                )
            )
    return epss_path


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
