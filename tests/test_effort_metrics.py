"""A1 re-metric, Task 2: pooled bootstrap PR-AUC CIs + recall-by-frac paired deltas."""
import numpy as np

from temporal_exploit.effort_metrics import pooled_bootstrap_pr_auc, recall_by_frac_deltas


def test_pooled_bootstrap_pr_auc_perfect_ranker():
    y = np.array([0] * 90 + [1] * 10)
    score = y.astype(float)  # perfect separation
    out = pooled_bootstrap_pr_auc(y, score, n_boot=200, seed=0)
    assert out["pr_auc"] == 1.0
    assert out["ci95"][0] > 0.99 and out["ci95"][1] == 1.0
    assert out["n_pos"] == 10


def test_pooled_bootstrap_pr_auc_stratified_keeps_prevalence():
    rng = np.random.default_rng(1)
    y = np.array([0] * 990 + [1] * 10)
    score = rng.random(1000)  # random ranking -> PR-AUC near prevalence 0.01
    out = pooled_bootstrap_pr_auc(y, score, n_boot=300, seed=1)
    assert 0.001 < out["pr_auc"] < 0.1
    assert out["ci95"][0] <= out["pr_auc"] <= out["ci95"][1]
    # stratified resampling: every bootstrap keeps >=1 positive, so the CI is finite
    assert np.isfinite(out["ci95"]).all()


def test_pooled_bootstrap_pr_auc_degenerate_returns_none():
    assert pooled_bootstrap_pr_auc(np.zeros(50), np.random.default_rng(0).random(50)) is None


def test_recall_by_frac_deltas_hand_computed():
    def _res(vals):  # per-origin recall_at_top_by_frac[frac][h]
        return {"per_origin": [
            {"origin": o, "recall_at_top_by_frac": {"0.05": {"30": v}}}
            for o, v in vals
        ]}
    chal = _res([("2022", 0.30), ("2023", 0.50), ("2024", 0.40)])
    base = _res([("2022", 0.20), ("2023", 0.45), ("2024", 0.40)])
    d = recall_by_frac_deltas(chal, base, frac="0.05", horizon=30)
    assert d["n_paired"] == 3
    assert abs(d["mean_delta"] - (0.10 + 0.05 + 0.0) / 3) < 1e-12
    assert d["win_frac"] == 2 / 3
    assert d["ci95"] is not None


def test_recall_by_frac_deltas_skips_missing_origins():
    chal = {"per_origin": [{"origin": "a", "recall_at_top_by_frac": {"0.05": {"30": 0.5}}},
                           {"origin": "b", "recall_at_top_by_frac": {}}]}
    base = {"per_origin": [{"origin": "a", "recall_at_top_by_frac": {"0.05": {"30": 0.4}}}]}
    d = recall_by_frac_deltas(chal, base, frac="0.05", horizon=30)
    assert d["n_paired"] == 1 and d["ci95"] is None
