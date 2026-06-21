"""Direction 3 (RQ3) — do CVEs mapped to particular ATT&CK tactics weaponize
faster/slower? The technique chain has technique_id (not tactic), so map each
parent technique (prefix before the dot) to its PRIMARY ATT&CK enterprise tactic
(curated; a technique can span tactics — primary is the dominant one). Stratify
time-to-first-PoC (clean cohort, published>=2021) by tactic: KM + median + n.
A CVE with techniques across tactics contributes to each tactic's stratum
(overlapping strata — the standard per-tactic KM). ~24% ATT&CK coverage (the
rest is a 'no_attack_mapping' stratum, NOT implied absence).
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter
from lifelines.statistics import multivariate_logrank_test

from temporal_exploit.attack_tactics import tactic_of  # single source of truth (RQ3 map)
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.loaders import load_parquet

OUT = Path("data/merged")
SNAP, MIN_PUB = "2026-03-14", "2021-01-01"
CHAIN = "dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/technique_cwe_chain.parquet"


# clean time-to-PoC labels (clock origin = published, event = earliest PoC per CVE)
corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
name, col = EVENT_SOURCES["poc"]
poc = load_optional_event(OUT, name, col).sort_values(col).drop_duplicates("cve_id", keep="first")[["cve_id", col]]
m = corpus.merge(poc, on="cve_id", how="left")
pub = pd.to_datetime(m["published"], utc=True)
poc_d = pd.to_datetime(m[col], utc=True)
snap = pd.Timestamp(SNAP, tz="UTC")
m["event_observed"] = (poc_d.notna() & (poc_d <= snap)).to_numpy()
m["duration_days"] = np.where(m["event_observed"], (poc_d - pub).dt.days, (snap - pub).dt.days)
m = m[(pub >= pd.Timestamp(MIN_PUB, tz="UTC")) & (m["duration_days"] > 0)].copy()
labels = m[["cve_id", "duration_days", "event_observed"]]

chain = pd.read_parquet(CHAIN, columns=["cve_id", "technique_id"])
chain["tactic"] = chain["technique_id"].map(tactic_of)
cve_tactic = chain[["cve_id", "tactic"]].drop_duplicates()  # one row per (cve, tactic)

mapped = labels.merge(cve_tactic, on="cve_id", how="left")
mapped["tactic"] = mapped["tactic"].fillna("no_attack_mapping")

rows, dropped = [], []
for tac, g in mapped.groupby("tactic"):
    if int(g["event_observed"].sum()) < 50:
        dropped.append((tac, int(g["event_observed"].sum())))
        continue
    km = KaplanMeierFitter().fit(g["duration_days"], g["event_observed"])
    med = g.loc[g["event_observed"].astype(bool), "duration_days"].median()
    rows.append({"tactic": tac, "n": int(len(g)), "n_events": int(g["event_observed"].sum()),
                 "median_days": float(med), "surv_7": float(km.predict(7)),
                 "surv_30": float(km.predict(30)), "surv_90": float(km.predict(90))})

# log-rank across mapped tactics (excluding the no-mapping + Other buckets)
core = mapped[~mapped["tactic"].isin(["no_attack_mapping", "Other"])]
lr = multivariate_logrank_test(core["duration_days"], core["tactic"], core["event_observed"])

out = {"by_tactic": sorted(rows, key=lambda r: r["median_days"]),
       "logrank_p": float(lr.p_value), "logrank_stat": float(lr.test_statistic),
       "dropped_small_tactics": dropped, "n_total_mapped": int(len(core))}
Path("artifacts/merged/tactic_conditioning.json").write_text(json.dumps(out, indent=2, default=str))
print("=== time-to-PoC by ATT&CK tactic (clean cohort, sorted fastest->slowest median) ===")
for r in out["by_tactic"]:
    print(f"  {r['tactic']:22s} n={r['n']:7d} ev={r['n_events']:6d} median={r['median_days']:6.0f}d  S(30)={r['surv_30']:.3f}")
print(f"\nlog-rank across tactics: stat={out['logrank_stat']:.1f} p={out['logrank_p']:.2e} (differences real if p<<0.05)")
print("dropped small tactics (<50 events):", dropped)
print("wrote artifacts/merged/tactic_conditioning.json")
