"""Fetch the full VulnCheck KEV catalog and store it to data/live/.

Token from VULNCHECK_API_TOKEN (never hard-coded). All fetch/parse logic lives in
the connector (backup zip + earliest-evidence date + sentinel filter); this just
runs it and reports.
"""
import os
from pathlib import Path

from temporal_exploit.fetch.vulncheck import VulncheckKevConnector

OUT = Path("data/live/vulncheck_kev.parquet")

frame = VulncheckKevConnector().fetch(os.environ["VULNCHECK_API_TOKEN"])
print(f"unique CVEs: {len(frame):,}")
print(f"date range: {frame['vulncheck_kev_date_added'].min().date()} -> {frame['vulncheck_kev_date_added'].max().date()}")
OUT.parent.mkdir(parents=True, exist_ok=True)
frame.to_parquet(OUT, index=False)
print(f"stored {OUT}")
