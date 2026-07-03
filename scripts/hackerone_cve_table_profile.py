"""Convert the scraped HackerOne CVE table (JSONL) to a compact parquet and profile it.

Memory-light: reads the JSONL once into a DataFrame (~363k small rows), downcasts, writes
parquet, and prints a profile — coverage vs the corpus, reports-volume distribution, and
in-wild (KEV) overlap — to confirm what the table is good/not-good for. No network, no EPSS
history. Run after scripts/hackerone_cve_table_scrape.py completes.

Run: .venv/bin/python scripts/hackerone_cve_table_profile.py
"""
from __future__ import annotations
import json
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out"
ART = REPO / "artifacts"
JSONL = ART / "hackerone_cve_table.jsonl"
PARQUET = ART / "hackerone_cve_table.parquet"

rows = [json.loads(l) for l in JSONL.open() if l.strip()]
df = pd.DataFrame(rows)
df["cve_id"] = df["cve_id"].astype(str).str.upper()
df = df.drop_duplicates("cve_id")
# downcast numeric columns to shrink footprint
for c in df.select_dtypes("float").columns:
    df[c] = pd.to_numeric(df[c], downcast="float")
for c in df.select_dtypes("integer").columns:
    df[c] = pd.to_numeric(df[c], downcast="integer")
df.to_parquet(PARQUET, index=False)

# --- profile ---
corpus = pq.read_table(OUT / "cve_corpus.parquet", columns=["cve_id"]).to_pandas()
corpus_cves = set(corpus["cve_id"].astype(str).str.upper())
kev = pq.read_table(OUT / "kev_events.parquet").to_pandas()
kcid = next(c for c in kev.columns if "cve" in c.lower())
kev_cves = set(kev[kcid].astype(str).str.upper()) & corpus_cves

h = set(df["cve_id"])
rc = df["reports_submitted_count"].fillna(0)
prof = {
    "rows": len(df),
    "unique_cves": len(h),
    "in_corpus": len(h & corpus_cves),
    "in_corpus_pct": round(100 * len(h & corpus_cves) / len(h), 1),
    "reports_eq_0": int((rc == 0).sum()),
    "reports_le_1": int((rc <= 1).sum()),
    "reports_ge_10": int((rc >= 10).sum()),
    "reports_max": int(rc.max()),
    "kev_overlap": len(h & kev_cves),
    "kev_total": len(kev_cves),
    "parquet_mb": round(PARQUET.stat().st_size / 1e6, 1),
}
(ART / "hackerone_cve_table_profile.json").write_text(json.dumps(prof, indent=2))
print(json.dumps(prof, indent=2))
print("\nInterpretation: reports_submitted_count is a snapshot-cumulative, leaky, undated volume "
      "(scanner-noise dominated); kev_overlap CVEs are already labelled. Reference/EDA only — "
      "not an in-wild label source, consistent with the disclosed-report finding.")
