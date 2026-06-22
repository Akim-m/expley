"""Phase 2 — the patch-vs-exploit race, on the dated OSS commit subset.

Two deliverables:
  A. DESCRIPTIVE RACE — among weaponized CVEs with a fix-commit date, what
     fraction were weaponized BEFORE the fix existed (patch lost the race), and
     the patch->weaponization lead-time distribution. Stratified by the causal
     treatments; robustness arm restricted to NVD `Patch`-tagged CVEs.
  B. TIME-VARYING COX — the immortal-time-bias-free causal effect of patch
     AVAILABILITY on the weaponization hazard (tests the "patches enable n-day
     exploits" hypothesis: HR>1 = patch availability RAISES the hazard).

Patch-available proxy = earliest fix-commit committedDate. Reads merged data,
writes artifacts/merged/patch_race.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from lifelines import CoxTimeVaryingFitter

MERGED = Path("data/merged")
ART = Path("artifacts/merged")
OUT = ART / "patch_race.json"


def load():
    cd = pd.read_parquet(MERGED / "commit_dates.parquet")
    cd["commit_date"] = pd.to_datetime(cd["commit_date"], utc=True, errors="coerce")
    cd = cd.dropna(subset=["commit_date"]).sort_values("commit_date")
    cd = cd.groupby("cve_id", as_index=False).first()  # earliest fix commit per CVE
    lab = pd.read_parquet(ART / "modeling_labels.parquet",
                          columns=["cve_id", "published", "event_date", "event_observed",
                                   "duration_days", "negative_duration_flag"])
    lab["published"] = pd.to_datetime(lab["published"], utc=True)
    lab["event_date"] = pd.to_datetime(lab["event_date"], utc=True, errors="coerce")
    refs = pd.read_parquet(MERGED / "nvd_references.parquet", columns=["cve_id", "has_patch_ref"])
    feat = pd.read_parquet(ART / "publication_features.parquet",
                           columns=["cve_id", "published_year", "cvss_v3_base", "vendor_count",
                                    "incentive_wormable", "incentive_unauth_network_high_impact"])
    df = cd.merge(lab, on="cve_id").merge(refs, on="cve_id", how="left").merge(feat, on="cve_id", how="left")
    df = df[~df["negative_duration_flag"].astype(bool)]
    df["patch_rel"] = (df["commit_date"] - df["published"]).dt.total_seconds() / 86400.0
    return df


def descriptive(df) -> dict:
    out = {}
    for arm, sub in {"all_commit": df, "patch_tagged": df[df["has_patch_ref"] == True]}.items():  # noqa: E712
        wp = sub[sub["event_observed"] == 1].copy()
        wp = wp.dropna(subset=["event_date"])
        lead = (wp["event_date"] - wp["commit_date"]).dt.total_seconds() / 86400.0  # +ve = patch first
        patch_first = lead >= 0
        out[arm] = {
            "n_weaponized_dated": int(wp.shape[0]),
            "patch_before_weaponization_rate": round(float(patch_first.mean()), 3),
            "weaponized_before_patch_rate": round(float((~patch_first).mean()), 3),
            "lead_days_patch_to_weapon_median": round(float(lead.median()), 1),
            "lead_days_p25_p75": [round(float(lead.quantile(.25)), 1), round(float(lead.quantile(.75)), 1)],
            "wormable_weaponized_before_patch_rate": round(
                float((~patch_first[wp["incentive_wormable"] == 1]).mean()), 3)
            if (wp["incentive_wormable"] == 1).any() else None,
            "nonwormable_weaponized_before_patch_rate": round(
                float((~patch_first[wp["incentive_wormable"] == 0]).mean()), 3)
            if (wp["incentive_wormable"] == 0).any() else None,
        }
    return out


def build_long(df, confs):
    """Start/stop intervals: patch availability as a time-varying exposure on the
    weaponization clock (origin = published)."""
    rows = []
    for r in df.itertuples():
        end = float(r.duration_days)
        if end <= 0:
            continue
        evt = int(r.event_observed)
        pr = float(r.patch_rel)
        base = {c: getattr(r, c) for c in confs}
        if pr <= 0 or pr >= end:                       # always / never patched in window
            rows.append({"id": r.cve_id, "start": 0.0, "stop": end,
                         "patch_available": int(pr <= 0), "event": evt, **base})
        else:                                          # transition at pr
            rows.append({"id": r.cve_id, "start": 0.0, "stop": pr,
                         "patch_available": 0, "event": 0, **base})
            rows.append({"id": r.cve_id, "start": pr, "stop": end,
                         "patch_available": 1, "event": evt, **base})
    return pd.DataFrame(rows)


def timevarying(df, confs) -> dict:
    sub = df.dropna(subset=confs).copy()
    long = build_long(sub, confs)
    long = long[long["stop"] > long["start"]]
    ctv = CoxTimeVaryingFitter(penalizer=0.01)
    ctv.fit(long, id_col="id", event_col="event", start_col="start", stop_col="stop")
    s = ctv.summary.loc["patch_available"]
    return {
        "n_cves": int(sub.shape[0]),
        "n_intervals": int(long.shape[0]),
        "n_events": int(long["event"].sum()),
        "patch_available_hr": round(float(np.exp(s["coef"])), 3),
        "ci": [round(float(np.exp(s["coef lower 95%"])), 3),
               round(float(np.exp(s["coef upper 95%"])), 3)],
        "p": float(s["p"]),
        "interpretation": "HR>1 => patch availability RAISES weaponization hazard (n-day effect)",
        "adjusted_for": confs,
    }


def main():
    df = load()
    confs = ["published_year", "cvss_v3_base", "vendor_count"]
    report = {
        "cohort_n": int(df.shape[0]),
        "patch_rel_days_median": round(float(df["patch_rel"].median()), 1),
        "frac_patch_before_publication": round(float((df["patch_rel"] <= 0).mean()), 3),
        "descriptive_race": descriptive(df),
        "timevarying_cox": timevarying(df, confs),
    }
    OUT.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
