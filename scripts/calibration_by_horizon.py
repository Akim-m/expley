"""D2 — calibration assessed at concrete horizons (7/30/90/180 days).

The professor's §"what success could look like" asks for "calibration assessed at
concrete horizons". The repo already had the primitives but never wired them into
a deliverable:
  - reliability per horizon (KM-within-bin, censoring-aware) -> modeling.calibration_table
  - Brier per horizon + integrated Brier -> modeling.evaluate_survival
  - NEW: calibration slope + intercept -> calibration.calibration_slope_intercept
This script runs all three on Cox + XGBoost-AFT on the clean recent cohort
(published >= 2021) with a 70/30 time split, and writes a JSON artifact + a
markdown reliability table. No new estimator beyond the slope/intercept; the rest
is reuse.

Run: .venv/bin/python scripts/calibration_by_horizon.py
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.backtest import _fit
from temporal_exploit.calibration import calibration_slope_intercept
from temporal_exploit.modeling import (
    calibration_table,
    evaluate_survival,
    prepare_modeling_frame,
    survival_at,
    time_split_frame,
)

ART = Path("artifacts/merged")
MIN_PUB = "2021-01-01"
HORIZONS = (7, 30, 90, 180)
MODELS = ("cox", "xgb")


def main() -> None:
    labels = pd.read_parquet(ART / "modeling_labels.parquet")
    feats = pd.read_parquet(ART / "publication_features.parquet")
    frame = prepare_modeling_frame(labels, feats)
    frame = frame[pd.to_datetime(frame["published"], utc=True) >= pd.Timestamp(MIN_PUB, tz="UTC")]
    frame = frame.reset_index(drop=True)
    cut = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
    train, test = time_split_frame(frame, str(cut.date()))
    print(f"cohort published>={MIN_PUB}: train={len(train)} ({int(train.event_observed.sum())} ev) "
          f"test={len(test)} ({int(test.event_observed.sum())} ev) cut={cut.date()}")

    out = {"cohort": f"published>={MIN_PUB}", "cutoff": str(cut.date()),
           "n_train": len(train), "n_test": len(test), "horizons": list(HORIZONS), "models": {}}

    for kind in MODELS:
        model = _fit(kind, train)
        X_test = test[list(model.feature_cols_)].astype(float)
        surv = survival_at(model, X_test, list(HORIZONS), kind)  # (n_test, n_horizons)
        metrics = evaluate_survival(model, train, test, horizons=HORIZONS, kind=kind,
                                    surv_at_horizons=surv)
        rec = {"c_index_ipcw": metrics.get("c_index_ipcw"),
               "integrated_brier": metrics.get("integrated_brier"),
               "brier": metrics.get("brier", {}), "by_horizon": {}}
        for j, h in enumerate(HORIZONS):
            pred_event = 1.0 - surv[:, j]
            tbl = calibration_table(pred_event, test, h)
            si = calibration_slope_intercept(pred_event, test, h, n_boot=1000, seed=0)
            rec["by_horizon"][h] = {
                "brier": metrics.get("brier", {}).get(h),
                "slope": si["slope"], "slope_ci95": si["slope_ci95"],
                "intercept": si["intercept"], "intercept_ci95": si["intercept_ci95"],
                "n_events": si["n_events"], "n_bins": int(len(tbl)),
                "reliability": tbl.to_dict("records"),
            }
        out["models"][kind] = rec
        print(f"  {kind}: c-index={rec['c_index_ipcw']:.3f} IBS={rec['integrated_brier']}")
        for h in HORIZONS:
            b = rec["by_horizon"][h]
            s, ci = b["slope"], b["slope_ci95"]
            print(f"    h={h:3d}d brier={b['brier']} slope={s if s is None else round(s,3)} "
                  f"CI={[None if c is None else round(c,2) for c in ci]} "
                  f"intercept={b['intercept'] if b['intercept'] is None else round(b['intercept'],3)}")

    (ART / "calibration_by_horizon.json").write_text(json.dumps(out, indent=2, default=str))
    _write_doc(out)
    print(f"\nwrote {ART/'calibration_by_horizon.json'} + docs/calibration_by_horizon_2026-06.md")


def _write_doc(out: dict) -> None:
    lines = ["# Calibration at Concrete Horizons (7/30/90/180 days)", "",
             f"**Date:** 2026-06-21. Cohort `{out['cohort']}`, 70/30 time split at "
             f"`{out['cutoff']}` (train n={out['n_train']}, test n={out['n_test']}). "
             "Reproduce: `scripts/calibration_by_horizon.py` → `artifacts/merged/calibration_by_horizon.json`.",
             "",
             "Reliability is censoring-aware (KM-within-bin); Brier is IPCW (sksurv). "
             "Slope ~1 + intercept ~0 = well-calibrated; slope <1 = over-confident. "
             "CIs are 1000-resample subject bootstraps.", ""]
    for kind, rec in out["models"].items():
        lines.append(f"## {kind.upper()} — c-index(IPCW) {rec['c_index_ipcw']:.3f}, "
                     f"integrated Brier {rec['integrated_brier']}")
        lines.append("")
        lines.append("| horizon | Brier | slope [95% CI] | intercept [95% CI] | events |")
        lines.append("|---|---|---|---|---|")
        for h in out["horizons"]:
            b = rec["by_horizon"][str(h)] if str(h) in rec["by_horizon"] else rec["by_horizon"][h]
            def f(x, n=3):
                return "—" if x is None else round(x, n)
            sci = b["slope_ci95"]; ici = b["intercept_ci95"]
            sci_s = "—" if sci[0] is None else f"[{f(sci[0],2)}, {f(sci[1],2)}]"
            ici_s = "—" if ici[0] is None else f"[{f(ici[0],3)}, {f(ici[1],3)}]"
            lines.append(f"| {h}d | {f(b['brier'])} | {f(b['slope'])} {sci_s} | "
                         f"{f(b['intercept'])} {ici_s} | {b['n_events']} |")
        lines.append("")
    Path("docs/calibration_by_horizon_2026-06.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
