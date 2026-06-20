"""RQ2 — does the weaponization pipeline cascade (PoC->MSF->Nuclei->KEV) or are
the transitions independent? Runs the existing cascade-order + competing-risks
machinery on the merged build and emits a single JSON for the thesis spine."""
import json
from pathlib import Path

import pandas as pd

from temporal_exploit.competing import (
    cif_table,
    cif_vs_independent,
    fit_aalen_johansen,
    prepare_competing_frame,
)
from temporal_exploit.evaluate import cascade_order_stats

ART = Path("artifacts/merged")
HZ = [7, 30, 90, 180]
per_signal = pd.read_parquet(ART / "per_signal_labels.parquet")
cr = pd.read_parquet(ART / "competing_risks_labels.parquet")
feats = pd.read_parquet(ART / "publication_features.parquet")

cascade = cascade_order_stats(per_signal, stages=("poc", "metasploit", "nuclei", "kev"))

# DATA-VALIDITY CHECK: the git-mined PoC date conflates true PoC publication with
# aggregator BULK-INDEXING dates for older CVEs (nomi-sec/Trickest back-filled with
# their indexing date). This right-biases time-to-PoC and inverts the apparent
# PoC->MSF ordering for old CVEs. Quantify the bulk-index spikes + show the cascade
# recovering once restricted to recent (post-aggregator) CVEs.
poc_dates = pd.to_datetime(per_signal.loc[per_signal["poc_observed"].astype(bool), "poc_event_date"], utc=True)
bulk_spikes = {str(d): int(n) for d, n in poc_dates.dt.date.value_counts().head(5).items()}
pub = pd.to_datetime(per_signal["published"], utc=True)
cascade_by_year = []
for yr in (2018, 2020, 2021, 2022):
    m = (per_signal["poc_observed"].astype(bool) & per_signal["metasploit_observed"].astype(bool)
         & (pub >= pd.Timestamp(f"{yr}-01-01", tz="UTC")))
    sub = per_signal[m]
    if len(sub) == 0:
        continue
    pb = (pd.to_datetime(sub["poc_event_date"], utc=True) <= pd.to_datetime(sub["metasploit_event_date"], utc=True))
    cascade_by_year.append({"published_from": yr, "n_both": int(len(sub)), "pct_poc_before_msf": round(100 * pb.mean(), 1)})

frame = prepare_competing_frame(cr, feats)
fitters = fit_aalen_johansen(frame)
cif = cif_table(fitters, HZ)
indep = cif_vs_independent(frame, HZ)

out = {
    "cascade_order": cascade.to_dict(orient="records"),
    "poc_date_bulk_index_spikes": bulk_spikes,
    "cascade_poc_before_msf_by_publication_year": cascade_by_year,
    "aalen_johansen_cif": cif.to_dict(orient="records"),
    "cif_vs_independent": indep.to_dict(orient="records"),
}
ART.mkdir(parents=True, exist_ok=True)
(ART / "pipeline_cascade.json").write_text(json.dumps(out, indent=2, default=str))
print("cascade-order (PoC->MSF->Nuclei->KEV, % a-precedes-b among co-observed):\n",
      cascade.to_string(index=False), flush=True)
print("\nPoC-date bulk-index spikes (date: count) — aggregator back-fill artifact:\n", bulk_spikes, flush=True)
print("\nPoC-before-MSF by CVE publication year (cascade recovers on clean recent cohort):\n",
      pd.DataFrame(cascade_by_year).to_string(index=False), flush=True)
print("\nCIF vs independent (deviation = competing-risks dependence):\n",
      indep.to_string(index=False), flush=True)
print("\nwrote artifacts/merged/pipeline_cascade.json", flush=True)
