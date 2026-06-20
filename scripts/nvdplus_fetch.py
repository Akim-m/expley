"""Fetch the full VulnCheck NVD++ corpus and STREAM it to data/live/cve_corpus.parquet.

Token from VULNCHECK_API_TOKEN (never hard-coded). ~350 MB download (batched to
disk) + a chunked parquet writer, so peak RAM is ~one chunk, not the whole 359k-
CVE corpus. Merge keeps the latest last_modified per cve_id.
"""
import logging
import os
from pathlib import Path

import pandas as pd

from temporal_exploit.fetch.nvdplus import NvdPlusConnector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")  # download/parse progress
OUT = Path("data/live/cve_corpus.parquet")
OUT.parent.mkdir(parents=True, exist_ok=True)

n = NvdPlusConnector().fetch_to_parquet(os.environ["VULNCHECK_API_TOKEN"], OUT)
print(f"\nCVEs written: {n:,}")

# light read-back (projected columns only) for coverage vs the handover's 72%/83%
df = pd.read_parquet(OUT, columns=["cvss_v3_base", "cwe_ids", "published"])
print(f"published range: {df['published'].min().date()} -> {df['published'].max().date()}")
print(f"with CVSS v3: {int(df['cvss_v3_base'].notna().sum()):,} ({100 * df['cvss_v3_base'].notna().mean():.0f}%)")
print(f"with CWE:     {int(df['cwe_ids'].str.len().gt(0).sum()):,} ({100 * df['cwe_ids'].str.len().gt(0).mean():.0f}%)")
print(f"stored {OUT}")
