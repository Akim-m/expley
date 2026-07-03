"""Figure: HackerOne coordinated-disclosure as an EPSS blind-spot lens (dissertation Ch.7).

Two panels, grounded in artifacts (no network, memory-light — column-pushed reads):
  A) in-wild (KEV) rate by publication-time EPSS-percentile bin, HackerOne-disclosed
     CVEs vs the rest — H1 membership is enriched for in-wild exactly where EPSS is low.
  B) CWE mix of the in-wild CVEs that sit in EPSS's bottom decile and are H1-flagged.

Style matches scripts/build_report_figures.py (same palette / rcParams family).
Run: .venv/bin/python scripts/build_hackerone_figure.py
"""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out"
ART = REPO / "artifacts"
FIG = REPO / "docs/figures"; FIG.mkdir(parents=True, exist_ok=True)

NAVY, BLUE, AMBER, GREY = "#0b3d91", "#1f6feb", "#bf8700", "#6e7781"
plt.rcParams.update({"font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold",
                     "axes.labelsize": 10, "axes.edgecolor": "#888888", "axes.grid": True,
                     "grid.color": "#e3e6ea", "grid.linewidth": 0.7, "savefig.dpi": 300,
                     "savefig.bbox": "tight"})

# --- light loads (only needed columns) ---
rows = json.loads((ART / "hackerone_cve_reports.json").read_text())
h1 = {c.strip().upper() for r in rows for c in (r.get("cve_ids") or [])}
corpus = pq.read_table(OUT / "cve_corpus.parquet", columns=["cve_id", "cwe_ids"]).to_pandas()
corpus["cve_id"] = corpus["cve_id"].astype(str).str.upper()
corpus_cves = set(corpus["cve_id"])
cwe_map = corpus.set_index("cve_id")["cwe_ids"]
kev = pq.read_table(OUT / "kev_events.parquet").to_pandas()
kcid = next(c for c in kev.columns if "cve" in c.lower())
kev = (set(kev[kcid].astype(str).str.upper()) & corpus_cves)
ep = pq.read_table(ART / "epss_at_publication.parquet",
                   columns=["cve_id", "epss_percentile_at_publication"]).to_pandas()
ep["cve_id"] = ep["cve_id"].astype(str).str.upper()
pct = ep.set_index("cve_id")["epss_percentile_at_publication"].dropna()
h1 = h1 & corpus_cves

# --- Panel A data: KEV rate by EPSS-percentile bin, H1 vs rest ---
bins = [0, 0.1, 0.25, 0.5, 0.75, 1.0001]
labels = ["0–10", "10–25", "25–50", "50–75", "75–100"]
binned = pd.cut(pct, bins=bins, right=False, labels=labels)
df = pd.DataFrame({"cve": pct.index, "bin": binned.values})
df["h1"] = df["cve"].isin(h1)
df["kev"] = df["cve"].isin(kev)
rate = df.groupby(["bin", "h1"], observed=True)["kev"].mean().mul(100).unstack()

# --- Panel B data: CWE mix of blind-spot in-wild CVEs (H1 ∩ KEV ∩ EPSS bottom-decile) ---
def cwes(c):
    v = cwe_map.get(c)
    return [str(x) for x in v] if isinstance(v, (list, np.ndarray)) else ([str(v)] if v is not None else [])
blind = [c for c in h1 if c in kev and c in pct.index and pct[c] < 0.1]
cwe_cnt = Counter(w for c in blind for w in cwes(c)).most_common(7)

fig, (axA, axB) = plt.subplots(1, 2, figsize=(11, 4.2), gridspec_kw={"width_ratios": [1.35, 1]})
x = np.arange(len(labels)); w = 0.38
axA.bar(x - w/2, rate[False].reindex(labels).values, w, label="Other CVEs", color=GREY)
axA.bar(x + w/2, rate[True].reindex(labels).values, w, label="HackerOne-disclosed", color=AMBER)
axA.set_xticks(x); axA.set_xticklabels(labels)
axA.set_xlabel("Publication-time EPSS percentile"); axA.set_ylabel("In-the-wild (KEV) rate  (%)")
axA.set_title("A · HackerOne marks in-wild CVEs where EPSS is low")
axA.legend(frameon=False, fontsize=9)
lo = rate.reindex(labels)
axA.annotate(f"{lo[True].iloc[0]:.1f}% vs {lo[False].iloc[0]:.2f}%\n(~9× in EPSS's bottom decile)",
             xy=(0 + w/2, lo[True].iloc[0]), xytext=(0.5, max(lo[True].max(), 4)*0.72),
             fontsize=8.5, color=NAVY, arrowprops=dict(arrowstyle="->", color=NAVY, lw=1))

cw_labels = [c for c, _ in cwe_cnt][::-1]; cw_vals = [n for _, n in cwe_cnt][::-1]
axB.barh(np.arange(len(cw_labels)), cw_vals, color=BLUE)
axB.set_yticks(np.arange(len(cw_labels))); axB.set_yticklabels(cw_labels)
axB.set_xlabel("in-wild blind-spot CVEs"); axB.set_title(f"B · CWE mix of the {len(blind)} blind-spot CVEs")
axB.grid(axis="y", visible=False)
axB.annotate("incl. CVE-2017-5638\n(Apache Struts / Equifax)", xy=(cw_vals[-1], len(cw_labels)-1),
             xytext=(max(cw_vals)*0.35, len(cw_labels)-2.4), fontsize=8, color=NAVY,
             arrowprops=dict(arrowstyle="->", color=NAVY, lw=1))

fig.suptitle("HackerOne coordinated-disclosure: an EPSS blind-spot lens, not a new label source",
             fontsize=12.5, fontweight="bold", y=1.02)
out = FIG / "fig_hackerone_epss_blindspot.png"
fig.savefig(out)
print(f"wrote {out}  (blind-spot n={len(blind)}, bottom-decile H1 KEV {lo[True].iloc[0]:.2f}% "
      f"vs {lo[False].iloc[0]:.3f}%)")
