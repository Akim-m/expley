"""Direction-C scoping probe: is per-vendor/product/CWE *exploited-count* forecasting
viable, or do counts just measure the reporting apparatus?

Three gates (research-flagged before any forecaster is built):
  1. SOURCE DISAGREEMENT  — do CISA KEV / VulnCheck / 0-day / MSRC agree on which
     CVEs are exploited and when? Large disagreement => counts are feed-driven.
  2. ENRICHMENT COVERAGE  — are vendor/product/CWE/CVSS populated for in-wild CVEs?
     Missing attribution undermines per-segment aggregation.
  3. FORECASTABILITY MAP  — per-segment quarterly exploited-count density: how many
     vendor/CWE segments have enough mass (mean quarterly count) to forecast at all,
     and how concentrated is the signal (top-10 share)?

Reads data/merged only, column-pushdown, tz-aware. Writes artifacts/merged/scope_probe_direction_c.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

MERGED = Path("data/merged")
OUT = Path("artifacts/merged/scope_probe_direction_c.json")

# in-wild sources: (file, cve_col, date_col)
INWILD = {
    "cisa_kev": ("kev_events.parquet", "cve_id", "kev_date_added"),
    "vulncheck_kev": ("vulncheck_kev.parquet", "cve_id", "vulncheck_kev_date_added"),
    "google_0day": ("google_0day.parquet", "cve_id", "zeroday_date_discovered"),
    "msrc": ("msrc.parquet", "cve_id", "msrc_exploited_date"),
}


def _load(file, cve_col, date_col):
    df = pq.read_table(MERGED / file, columns=[cve_col, date_col]).to_pandas()
    df = df.rename(columns={cve_col: "cve_id", date_col: "date"})
    df["date"] = pd.to_datetime(df["date"], utc=True)
    df = df.dropna(subset=["cve_id", "date"]).drop_duplicates("cve_id", keep="first")
    return df.set_index("cve_id")["date"]


def main():
    report = {}

    # ---- load per-source first in-wild date ----
    series = {name: _load(*spec) for name, spec in INWILD.items()}
    counts = {name: int(s.shape[0]) for name, s in series.items()}
    report["source_event_counts"] = counts

    # union earliest in-wild date per CVE
    allcve = sorted(set().union(*[set(s.index) for s in series.values()]))
    inwild = pd.DataFrame(index=allcve)
    for name, s in series.items():
        inwild[name] = s.reindex(allcve)
    inwild["earliest"] = inwild[list(series)].min(axis=1)
    report["unique_inwild_cves"] = int(inwild.shape[0])

    # ---- GATE 1: source disagreement ----
    k, v = series["cisa_kev"], series["vulncheck_kev"]
    both = sorted(set(k.index) & set(v.index))
    only_k = sorted(set(k.index) - set(v.index))
    only_v = sorted(set(v.index) - set(k.index))
    diff_days = (k.reindex(both) - v.reindex(both)).dt.total_seconds() / 86400.0
    report["gate1_source_disagreement"] = {
        "cisa_only": len(only_k),
        "vulncheck_only": len(only_v),
        "in_both": len(both),
        "jaccard_cisa_vulncheck": round(len(both) / len(set(k.index) | set(v.index)), 3),
        "vulncheck_coverage_ratio_vs_cisa": round(len(v) / len(k), 2),
        "date_diff_cisa_minus_vulncheck_days": {
            "median": round(float(diff_days.median()), 1),
            "mean": round(float(diff_days.mean()), 1),
            "frac_vulncheck_earlier": round(float((diff_days > 0).mean()), 3),
            "frac_same_day": round(float((diff_days.abs() < 1).mean()), 3),
        },
    }

    # feed onboarding level-shift: per-source events per year
    per_year = {}
    for name, s in series.items():
        per_year[name] = s.dt.year.value_counts().sort_index().to_dict()
        per_year[name] = {int(y): int(c) for y, c in per_year[name].items()}
    report["per_source_events_by_year"] = per_year

    # ---- corpus: enrichment + attribution ----
    corpus = pq.read_table(
        MERGED / "cve_corpus.parquet",
        columns=["cve_id", "published", "cwe_ids", "cvss_v3_base", "vendors", "products"],
    ).to_pandas()
    corpus["published"] = pd.to_datetime(corpus["published"], utc=True)
    corpus = corpus.set_index("cve_id")

    def _has_list(x):
        return isinstance(x, (list, np.ndarray)) and len(x) > 0

    iw_idx = [c for c in inwild.index if c in corpus.index]
    iw = corpus.loc[iw_idx]
    n = len(iw)
    report["gate2_enrichment_coverage"] = {
        "inwild_cves_in_corpus": n,
        "inwild_cves_missing_from_corpus": int(inwild.shape[0] - n),
        "frac_has_cvss_v3": round(float(iw["cvss_v3_base"].notna().mean()), 3),
        "frac_has_cwe": round(float(iw["cwe_ids"].apply(_has_list).mean()), 3),
        "frac_has_vendor": round(float(iw["vendors"].apply(_has_list).mean()), 3),
        "frac_has_product": round(float(iw["products"].apply(_has_list).mean()), 3),
        # backlog proxy on full corpus (published >= 2023)
        "fullcorpus_frac_has_cvss_pub_ge_2023": round(
            float(corpus.loc[corpus["published"] >= "2023-01-01", "cvss_v3_base"].notna().mean()), 3
        ),
    }

    # ---- GATE 3: forecastability map (per-vendor & per-CWE quarterly counts) ----
    iw2 = iw.copy()
    iw2["earliest"] = inwild["earliest"].reindex(iw2.index)
    iw2 = iw2.dropna(subset=["earliest"])
    iw2["quarter"] = iw2["earliest"].dt.to_period("Q").astype(str)
    quarters = sorted(iw2["quarter"].unique())
    nq = len(quarters)

    def segment_map(col):
        # explode list column -> (segment, cve) rows
        rows = []
        for cve, val in iw2[col].items():
            if _has_list(val):
                q = iw2.at[cve, "quarter"]
                for seg in set(val):
                    rows.append((str(seg).lower(), q))
        if not rows:
            return {}
        d = pd.DataFrame(rows, columns=["seg", "quarter"])
        # total events per segment
        tot = d.groupby("seg").size().sort_values(ascending=False)
        # quarterly mean count per segment (over observed span of quarters)
        qcount = d.groupby(["seg", "quarter"]).size()
        mean_q = qcount.groupby("seg").sum() / nq
        forecastable_1 = int((mean_q >= 1.0).sum())   # >=1 event/quarter on average
        forecastable_3 = int((mean_q >= 3.0).sum())   # denser threshold
        top10_share = round(float(tot.head(10).sum() / tot.sum()), 3)
        return {
            "n_segments": int(tot.shape[0]),
            "segments_mean_q_ge_1": forecastable_1,
            "segments_mean_q_ge_3": forecastable_3,
            "top10_share_of_events": top10_share,
            "top10": {s: int(c) for s, c in tot.head(10).items()},
        }

    report["gate3_forecastability"] = {
        "n_quarters": nq,
        "quarter_span": [quarters[0], quarters[-1]] if quarters else [],
        "total_inwild_events_per_quarter_mean": round(len(iw2) / nq, 1) if nq else 0,
        "by_vendor": segment_map("vendors"),
        "by_cwe": segment_map("cwe_ids"),
    }

    OUT.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
