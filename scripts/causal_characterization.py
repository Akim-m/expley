"""Phase 1 — Causal characterization of what *accelerates* weaponization.

Upgrades the project's associational tactic study (docs/defender_interpretation,
tactic_conditioning.py) to a causal estimate of the effect of publication-time
attributes on time-to-first-weaponization (~97% public PoC/tooling — read effects
as "accelerates public weaponization tooling", per the framing caveat).

For each binary TREATMENT we report three escalating-rigor estimates plus a
sensitivity bound:
  1. crude  — unadjusted Cox HR (the associational number)
  2. adj    — Cox HR adjusting for a pre-treatment COMMON-CAUSE confounder set
              (deliberately excludes mediators/definitional covariates)
  3. ipw    — stabilized inverse-propensity-weighted marginal Cox HR (+ overlap
              diagnostics, weight trimming)
  4. evalue — VanderWeele-Ding E-value: how strong an unmeasured confounder
              (on both treatment and outcome) would have to be to nullify the HR.

HR > 1  => treatment raises the weaponization hazard => FASTER weaponization.

Reads artifacts/merged only. Writes artifacts/merged/causal_characterization.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from lifelines import CoxPHFitter
from sklearn.linear_model import LogisticRegression

MERGED = Path("artifacts/merged")
OUT = MERGED / "causal_characterization.json"

# CWE one-hots present in publication_features (vuln-type confounders)
CWE_COLS = [
    "cwe_CWE-79", "cwe_CWE-89", "cwe_CWE-787", "cwe_CWE-119", "cwe_CWE-20",
    "cwe_CWE-200", "cwe_CWE-22", "cwe_CWE-352", "cwe_CWE-125", "cwe_CWE-862",
    "cwe_CWE-94", "cwe_CWE-416", "cwe_CWE-78", "cwe_CWE-476",
]
# pre-treatment common causes that are NOT part of any CVSS-vector treatment
BASE_CONFOUNDERS = ["published_year", "vendor_count", "product_count", "weakness_count"]

# treatment -> (column, confounder set). Confounders deliberately exclude
# covariates that DEFINE or MEDIATE the treatment.
TREATMENTS = {
    # wormable = AV:N & PR:N & UI:N & AC:L. Do NOT adjust for cvss base/severity
    # (collider/definitional). Adjust for surface (vendor/product), type (CWE), era.
    "wormable": ("incentive_wormable", BASE_CONFOUNDERS + CWE_COLS + ["has_attack_chain_mapping"]),
    "unauth_network_high_impact": (
        "incentive_unauth_network_high_impact",
        BASE_CONFOUNDERS + CWE_COLS + ["has_attack_chain_mapping"],
    ),
    # ATT&CK-mapped: here CVSS base IS a legitimate confounder (not definitional).
    "attack_chain_mapped": (
        "has_attack_chain_mapping",
        BASE_CONFOUNDERS + CWE_COLS + ["cvss_v3_base", "cvss_v3_missing"],
    ),
}


def _hr_to_rr(hr: float) -> float:
    """VanderWeele HR->approx risk ratio for a (possibly) common outcome."""
    return (1 - 0.5 ** np.sqrt(hr)) / (1 - 0.5 ** np.sqrt(1.0 / hr))


def evalue(hr: float, lo: float, hi: float) -> dict:
    """E-value for a hazard ratio and its CI (point + bound nearest the null)."""
    def _e(rr):
        rr = rr if rr >= 1 else 1.0 / rr
        return rr + np.sqrt(rr * (rr - 1))
    point = _e(_hr_to_rr(hr))
    # CI bound closest to 1 (the one that matters for "could it be nullified")
    if lo > 1:
        ci = _e(_hr_to_rr(lo))
    elif hi < 1:
        ci = _e(_hr_to_rr(hi))
    else:
        ci = 1.0  # CI crosses null
    return {"point": round(float(point), 2), "ci_bound": round(float(ci), 2)}


def cox_hr(df, cols, treat):
    # model-based SE (standard for an adjusted Cox); robust sandwich on 338k x k
    # rows is prohibitively slow and only needed for the weighted IPW fit.
    cph = CoxPHFitter(penalizer=0.01)
    cph.fit(df[cols + ["duration_days", "event_observed"]],
            duration_col="duration_days", event_col="event_observed")
    s = cph.summary.loc[treat]
    return {
        "hr": round(float(np.exp(s["coef"])), 3),
        "ci": [round(float(np.exp(s["coef lower 95%"])), 3),
               round(float(np.exp(s["coef upper 95%"])), 3)],
        "p": float(s["p"]),
    }


def ipw_hr(df, treat, confs):
    X = df[confs].to_numpy(dtype=float)
    X = (X - X.mean(0)) / (X.std(0) + 1e-9)
    t = df[treat].to_numpy(dtype=int)
    ps = LogisticRegression(max_iter=1000, C=1.0).fit(X, t).predict_proba(X)[:, 1]
    ps = np.clip(ps, 1e-3, 1 - 1e-3)
    pt = t.mean()
    w = np.where(t == 1, pt / ps, (1 - pt) / (1 - ps))   # stabilized
    # trim extreme weights at 1/99th pct
    lo, hi = np.percentile(w, [1, 99])
    w = np.clip(w, lo, hi)
    # overlap: propensity percentiles by group
    overlap = {
        "ps_treated_p05_p50_p95": [round(float(x), 3) for x in np.percentile(ps[t == 1], [5, 50, 95])],
        "ps_control_p05_p50_p95": [round(float(x), 3) for x in np.percentile(ps[t == 0], [5, 50, 95])],
        "weight_max": round(float(w.max()), 2),
    }
    wdf = df[[treat, "duration_days", "event_observed"]].copy()
    wdf["_w"] = w
    cph = CoxPHFitter(penalizer=0.01)
    cph.fit(wdf, duration_col="duration_days", event_col="event_observed",
            weights_col="_w", robust=True)
    s = cph.summary.loc[treat]
    return {
        "hr": round(float(np.exp(s["coef"])), 3),
        "ci": [round(float(np.exp(s["coef lower 95%"])), 3),
               round(float(np.exp(s["coef upper 95%"])), 3)],
        "p": float(s["p"]),
        "overlap": overlap,
    }


def main():
    feat = pq.read_table(MERGED / "publication_features.parquet").to_pandas()
    lab = pq.read_table(
        MERGED / "modeling_labels.parquet",
        columns=["cve_id", "duration_days", "event_observed", "negative_duration_flag"],
    ).to_pandas()
    df = feat.merge(lab, on="cve_id", how="inner")
    # survival hygiene: drop negative/zero durations (Cox rejects), require finite
    df = df[~df["negative_duration_flag"].astype(bool)]
    df = df[df["duration_days"] > 0]
    df = df.dropna(subset=["duration_days", "event_observed"])

    report = {
        "n_total": int(df.shape[0]),
        "n_events": int(df["event_observed"].sum()),
        "event_rate": round(float(df["event_observed"].mean()), 4),
        "outcome": "time_to_first_weaponization (~97% public PoC/tooling)",
        "treatments": {},
    }

    for name, (col, confs) in TREATMENTS.items():
        confs = [c for c in confs if c in df.columns and c != col]
        sub = df.dropna(subset=[col] + confs).copy()
        sub[col] = sub[col].astype(int)
        prev = float(sub[col].mean())
        crude = cox_hr(sub, [col], col)
        adj = cox_hr(sub, [col] + confs, col)
        ipw = ipw_hr(sub, col, confs)
        ev = evalue(adj["hr"], adj["ci"][0], adj["ci"][1])
        report["treatments"][name] = {
            "treatment_col": col,
            "prevalence": round(prev, 3),
            "n": int(sub.shape[0]),
            "crude_hr": crude,
            "adjusted_hr": adj,
            "ipw_hr": ipw,
            "evalue_adjusted": ev,
            "n_confounders": len(confs),
        }

    OUT.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
