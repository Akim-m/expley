"""D3b — diagnose + fix the DeepHit collapse (CIF ~3e-6 vs AJ truth ~0.19).

Hypothesis (loss weighting): pycox DeepHit loss = alpha*NLL + (1-alpha)*rank.
The default alpha=0.2 underweights the likelihood (the term that calibrates CIF
MAGNITUDE) on this 52%-censored, one-cause-dominant data, so the net satisfies
the ranking term while collapsing magnitudes. Fix lever = raise alpha (and,
secondarily, quantile discretization so the grid matches event-time density).

We isolate the loss cause from data scarcity by judging on the DOMINANT poc cause
(142k events): if even that collapses, it is not scarcity. Truth = Aalen-Johansen
CIF@90 (~0.19). Run in the GPU sidecar: .venv-deep/bin/python scripts/deephit_imbalance_fix.py
"""
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.competing import cif_table, fit_aalen_johansen, prepare_competing_frame
from temporal_exploit.deephit import evaluate_deephit, fit_deephit
from temporal_exploit.modeling import time_split_frame

ART = Path("artifacts/merged")
CUTOFF = "2024-01-01"
H = 90


def main() -> None:
    labels = pd.read_parquet(ART / "competing_risks_labels.parquet")
    feats = pd.read_parquet(ART / "publication_features.parquet")
    frame = prepare_competing_frame(labels, feats)
    train, test = time_split_frame(frame, CUTOFF)

    cause_names = (labels.loc[labels["cause_code"] > 0, ["cause_code", "event_cause"]]
                   .drop_duplicates().set_index("cause_code")["event_cause"].to_dict())
    poc_code = next(k for k, v in cause_names.items() if v == "poc")
    print(f"train={len(train)} test={len(test)} poc=cause_code {poc_code} "
          f"({int((train['cause_code']==poc_code).sum())} train events)")

    # --- ground truth: Aalen-Johansen CIF@90 for the poc cause ---
    aj = fit_aalen_johansen(train)
    aj_cif = cif_table(aj, [H])
    truth = float(aj_cif[(aj_cif["cause_code"] == poc_code) & (aj_cif["horizon"] == H)]["cif"].iloc[0])
    print(f"Aalen-Johansen truth: poc CIF@{H} = {truth:.4f}\n")

    def poc_metrics(model):
        ev = evaluate_deephit(model, test, horizons=(30, H, 180))
        pc = ev["per_cause"][str(poc_code)]
        return pc["cif_at_horizons"][str(H)], pc["concordance_td"]

    # The alpha sweep (0.2->1.0) was FALSIFIED in the first run: raising alpha made
    # the collapse WORSE (CIF 3e-6 -> 3e-13), because under 52% censoring pure NLL
    # piles mass on "never-event". So alpha stays at 0.2 (best concordance) and we
    # attack the real suspect: TIME DISCRETIZATION. Equidistant bins over a [0,~1500d]
    # long tail put horizon-90 in bin 1, so CIF@90 reads ~0 by construction. Quantile
    # (event-density) cuts should place many bins early and recover CIF@90.
    configs = [
        {"label": "baseline (equidistant 20)", "scheme": "equidistant", "num_durations": 20},
        {"label": "equidistant 100 (more bins, same placement)", "scheme": "equidistant", "num_durations": 100},
        {"label": "quantile 20", "scheme": "quantiles", "num_durations": 20},
        {"label": "quantile 50", "scheme": "quantiles", "num_durations": 50},
        {"label": "quantile 100", "scheme": "quantiles", "num_durations": 100},
    ]
    results = []
    for cfg in configs:
        t0 = time.time()
        kw = {k: v for k, v in cfg.items() if k != "label"}
        # batch_size=4096 (not the 256 default): GPU was only ~25% utilized at 256
        # (212k rows -> ~830 tiny batches/epoch, CPU->GPU overhead dominates a tiny
        # MLP). 4096 -> ~52 batches/epoch, GPU-bound, ~5x faster wall time; epochs
        # bumped to keep enough gradient steps for a fair convergence verdict.
        model = fit_deephit(train, alpha=0.2, epochs=50, batch_size=4096, seed=0, **kw)
        cif90, c_td = poc_metrics(model)
        dt = time.time() - t0
        ratio = cif90 / truth if truth else float("nan")
        results.append({**cfg, "poc_cif90": cif90, "truth": truth, "ratio": ratio,
                        "poc_concordance": c_td, "fit_s": round(dt, 1)})
        print(f"  {cfg['label']:38s} CIF@90={cif90:.4g} (truth {truth:.3f}, ratio {ratio:.3g}) "
              f"c_td={c_td if c_td is None else round(c_td,3)}  [{dt:.0f}s]", flush=True)

    out = {"cutoff": CUTOFF, "poc_code": poc_code, "truth_cif90": truth, "configs": results}
    (ART / "deephit_imbalance_fix.json").write_text(json.dumps(out, indent=2, default=str))
    best = max((r for r in results if r["poc_concordance"]), key=lambda r: r["poc_concordance"], default=None)
    print(f"\nbest by concordance: {best['label'] if best else 'none'}")
    print(f"wrote {ART/'deephit_imbalance_fix.json'}")


if __name__ == "__main__":
    main()
