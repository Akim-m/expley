"""Fit the interval-censored (discrete-time) time-to-PoC model on real labels,
write metrics + the naive-KM-vs-life-table bias figure. CPU-only, memory-light."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from lifelines.utils import concordance_index

from temporal_exploit import interval_censored as ic

HORIZONS = (7.0, 30.0, 90.0, 180.0)


def run_interval_censored(artifact_dir: Path, cutoff: str = "2024-01-01") -> dict:
    artifact_dir = Path(artifact_dir)
    labels = pd.read_parquet(artifact_dir / "per_signal_labels.parquet")
    feats = pd.read_parquet(artifact_dir / "publication_features.parquet")
    feats = feats.drop(columns=["published"], errors="ignore")  # 'published' lives on labels; dropping it avoids merge suffixes and keeps it out of feature_cols (it is a tz-aware datetime, not a model feature)
    df = labels.merge(feats, on="cve_id", how="inner")
    df["published"] = pd.to_datetime(df["published"], utc=True)

    n_neg = int(df["poc_negative_duration_flag"].sum())
    df = df[~df["poc_negative_duration_flag"] & (df["poc_duration_days"] > 0)].reset_index(drop=True)

    feature_cols = [c for c in feats.columns if c != "cve_id"]
    cut = pd.Timestamp(cutoff, tz="UTC")
    train, test = df[df["published"] < cut], df[df["published"] >= cut]

    model = ic.fit_discrete_time(
        train["poc_duration_days"].to_numpy(float),
        train["poc_observed"].to_numpy(int),
        train[feature_cols],
    )
    surv = model.survival_at(test[feature_cols], HORIZONS)
    horizon_probs = {int(h): float(np.mean(1.0 - surv[:, j])) for j, h in enumerate(HORIZONS)}
    risk = model.risk_scores(test[feature_cols])
    c_index = float(concordance_index(test["poc_duration_days"], -risk, test["poc_observed"]))

    bias = ic.bias_divergence(df["poc_duration_days"].to_numpy(float), df["poc_observed"].to_numpy(int))

    finite = [e for e in ic.HORIZON_BINS[1:] if np.isfinite(e)]
    naive = ic.naive_km_survival(df["poc_duration_days"], df["poc_observed"], finite)
    lifetable = ic.grouped_life_table(df["poc_duration_days"], df["poc_observed"])
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.step(finite, naive, where="post", label="naive exact-date KM")
    ax.step(finite, lifetable, where="post", label="grouped interval NPMLE (life-table)")
    ax.set_xlabel("days since publication"); ax.set_ylabel("S(t) — no PoC yet"); ax.legend()
    ax.set_title("PoC survival: exact-date bias vs interval-censored")
    (artifact_dir / "merged").mkdir(parents=True, exist_ok=True)
    fig.tight_layout(); fig.savefig(artifact_dir / "merged" / "interval_censored_bias.png", dpi=110)
    plt.close(fig)

    out = {"n": int(len(df)), "n_negative_excluded": n_neg,
           "horizon_probs": horizon_probs, "c_index": c_index, "bias": bias}
    (artifact_dir / "merged" / "interval_censored.json").write_text(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    print(json.dumps(run_interval_censored(Path("artifacts")), indent=2))
