"""Fetch the full VulnCheck NVD++ corpus and store it to data/live/cve_corpus.parquet.

Token from VULNCHECK_API_TOKEN (never hard-coded). ~150 MB download / 359k CVEs;
check `free -g` first. Merge keeps the latest last_modified per cve_id.
"""
import os
from pathlib import Path

from temporal_exploit.fetch.nvdplus import NvdPlusConnector

OUT = Path("data/live/cve_corpus.parquet")

frame = NvdPlusConnector().fetch(os.environ["VULNCHECK_API_TOKEN"])
print(f"CVEs: {len(frame):,}")
print(f"published range: {frame['published'].min().date()} -> {frame['published'].max().date()}")
print(f"with CVSS v3: {int(frame['cvss_v3_base'].notna().sum()):,}  with CWE: {int(frame['cwe_ids'].str.len().gt(0).sum()):,}")
OUT.parent.mkdir(parents=True, exist_ok=True)
frame.to_parquet(OUT, index=False)
print(f"stored {OUT}")
