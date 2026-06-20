import pandas as pd
import pytest

from temporal_exploit.backtest import (
    make_origins,
    paired_origin_deltas,
    rolling_origin_backtest,
)
from temporal_exploit.features import build_publication_features
from temporal_exploit.simulate import synth_weaponization


def _bt(per_origin):
    return {"per_origin": per_origin}


def _o(origin, auc90):
    return {"origin": origin, "horizon_auc": {"90": auc90}, "ipa": {"90": 0.0}}


def test_paired_origin_deltas_pairs_shared_origins():
    challenger = _bt([_o("2022-01-01", 0.80), _o("2022-04-01", 0.70), _o("2022-07-01", 0.90)])
    baseline = _bt([_o("2022-01-01", 0.75), _o("2022-04-01", 0.72), _o("2022-07-01", 0.85)])
    out = paired_origin_deltas(challenger, baseline, metric="horizon_auc", horizon=90)
    assert out["n_paired"] == 3
    assert out["mean_delta"] == pytest.approx((0.05 - 0.02 + 0.05) / 3)
    assert out["win_frac"] == pytest.approx(2 / 3)
    assert out["ci95"][0] < out["mean_delta"] < out["ci95"][1]


def test_paired_origin_deltas_uses_only_shared_origins():
    challenger = _bt([_o("2022-01-01", 0.80), _o("2022-04-01", 0.70)])
    baseline = _bt([_o("2022-01-01", 0.75), _o("2022-07-01", 0.85)])
    out = paired_origin_deltas(challenger, baseline, metric="horizon_auc", horizon=90)
    assert out["n_paired"] == 1
    assert out["origins"] == ["2022-01-01"]


def test_paired_origin_deltas_skips_none_metric():
    challenger = _bt([_o("a", 0.80), _o("b", None)])
    baseline = _bt([_o("a", 0.75), _o("b", 0.60)])
    out = paired_origin_deltas(challenger, baseline, metric="horizon_auc", horizon=90)
    assert out["n_paired"] == 1


def test_paired_origin_deltas_one_pair_has_no_se():
    out = paired_origin_deltas(_bt([_o("a", 0.8)]), _bt([_o("a", 0.7)]), metric="horizon_auc", horizon=90)
    assert out["n_paired"] == 1
    assert out["se"] is None
    assert out["ci95"] is None
    assert out["mean_delta"] == pytest.approx(0.1)


def test_make_origins_quarterly_leaves_followup():
    origins = make_origins("2024-07-01", start="2023-01-01", min_followup_days=180)
    assert origins[0] == "2023-01-01"
    assert "2023-04-01" in origins and "2023-07-01" in origins
    assert all(o <= "2024-01-03" for o in origins)  # last origin keeps >=180d follow-up


def _setup(signal=1.5, seed=2):
    corpus, ev, _ = synth_weaponization(
        n=7000, signal=signal, seed=seed, start="2020-01-01", span_days=1400
    )
    return corpus, ev, build_publication_features(corpus)


def test_backtest_recovers_signal_across_origins():
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    res = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(30, 90, 180)
    )
    agg = res["aggregate"]
    assert agg["n_origins"] >= 3
    # a real feature signal -> mean per-horizon AUC well above chance, with a
    # spread the single split couldn't report
    assert agg["horizon_auc"]["90"]["mean"] > 0.6
    assert agg["horizon_auc"]["90"]["sd"] >= 0.0
    # PR-AUC (average precision) flows into the same aggregate at the same horizons
    assert "90" in agg["horizon_pr_auc"]
    assert 0.0 <= agg["horizon_pr_auc"]["90"]["mean"] <= 1.0
    # operational: flagging the top decile catches more than its share of weaponizers
    assert agg["recall_at_top"]["90"]["mean"] > 0.10
    # honesty companion: the subcohort-drop fraction is reported per horizon and
    # is a valid proportion (so a high-drop long horizon carries its own caveat)
    assert 0.0 <= agg["horizon_auc_dropped_frac"]["90"] <= 1.0


def test_backtest_landmark_days_restarts_clock():
    # landmark_days shifts the prediction clock to published+L and drops events at/
    # before the landmark (restart_clock), enabling landmark-regime backtests where
    # the landmark trajectory features are leakage-safe.
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    base = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(30, 90, 180)
    )
    lm = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(30, 90, 180),
        landmark_days=30,
    )
    assert lm["aggregate"]["n_origins"] >= 1
    # events at/before the landmark are dropped -> no more test events than baseline
    assert lm["aggregate"]["test_events_total"] <= base["aggregate"]["test_events_total"]


def _ntrain_by_origin(res):
    return {o["origin"]: o["n_train"] for o in res["per_origin"]}


def test_backtest_embargo_shrinks_training_set():
    # embargo_days excludes CVEs published within embargo_days of each origin, so a
    # landmark window [pub, pub+L] is closed before the origin (no as-of-T leak).
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    base = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,), embargo_days=0
    )
    emb = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,), embargo_days=120
    )
    base_nt, emb_nt = _ntrain_by_origin(base), _ntrain_by_origin(emb)
    shared = set(base_nt) & set(emb_nt)
    assert shared
    assert all(emb_nt[o] <= base_nt[o] for o in shared)  # embargo never adds rows
    assert any(emb_nt[o] < base_nt[o] for o in shared)  # and removes some


def test_landmark_restart_clock_already_prevents_window_leak():
    # The landmark "leak" (a train window [pub,pub+L] extending past the origin) is
    # prevented by restart_clock dropping as-of-origin duration <= L (so every train CVE
    # has pub < t-L), NOT by an embargo. Proof: adding embargo=L on top of landmark_days=L
    # changes NOTHING -- those rows are already gone. (F6 is sound, not leaked.)
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    no_embargo = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,), landmark_days=60
    )
    with_embargo = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,),
        landmark_days=60, embargo_days=60,
    )
    assert _ntrain_by_origin(no_embargo) == _ntrain_by_origin(with_embargo)


def test_publication_only_view_drops_landmark_features():
    from temporal_exploit.backtest import _publication_only_features

    df = pd.DataFrame(
        {
            "cve_id": [1], "cvss_v3_base": [7.5], "incentive_wormable": [1],
            "epss_at_publication": [0.1], "epss_velocity_to_landmark": [0.5],
            "poc_by_landmark": [1], "days_to_epss_01": [3], "poc_lag_days": [2.0],
        }
    )
    out = _publication_only_features(df)
    assert {"cve_id", "cvss_v3_base", "incentive_wormable", "epss_at_publication"} <= set(out.columns)
    for c in ("epss_velocity_to_landmark", "poc_by_landmark", "days_to_epss_01", "poc_lag_days"):
        assert c not in out.columns  # post-publication / landmark cols stripped


def test_instant_head_is_registered():
    from temporal_exploit.backtest import LABEL_BUILDERS
    from temporal_exploit.labels import build_in_wild_labels

    # the t=0 operating point is a first-class head (in-wild labels, publication-only view)
    assert LABEL_BUILDERS.get("instant") is build_in_wild_labels


def test_publication_only_view_runs_in_backtest():
    # the publication-only view runs end-to-end and strips an injected landmark col
    # without breaking the backtest (fixture is poc-based -> first_weaponization).
    corpus, ev, features = _setup()
    features = features.copy()
    features["epss_velocity_to_landmark"] = 0.5  # landmark col the view must strip
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    res = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,),
        feature_view="publication_only",
    )
    assert res["aggregate"]["n_origins"] >= 1


@pytest.mark.parametrize("model", ["rsf", "gbm"])
def test_backtest_runs_nonlinear_models(model):
    # the non-linear ensemble methods (RSF, gradient-boosted survival) must ride
    # the same harness as cox and recover the planted signal across origins —
    # they exist so the verdict isn't fixated on one model class. Small corpus +
    # few origins keep these ensemble fits fast (the real comparison is the
    # offline head-to-head script, not the unit test).
    corpus, ev, _ = synth_weaponization(
        n=2500, signal=1.8, seed=3, start="2020-01-01", span_days=1100
    )
    features = build_publication_features(corpus)
    origins = make_origins("2023-09-01", start="2022-01-01", min_followup_days=120)
    res = rolling_origin_backtest(
        corpus, ev, features, "2023-09-01", origins, model=model,
        horizons=(30, 90, 180),
    )
    agg = res["aggregate"]
    assert agg["n_origins"] >= 3
    assert agg["horizon_auc"]["90"]["mean"] > 0.6
    assert agg["test_events_total"] > 0


def test_backtest_augment_fn_is_called_and_consumed():
    # the augment hook must run per origin, merge a point-in-time extra column
    # onto train+test, fill unscored ids, and the fit must consume it (the
    # mechanism behind stacked transfer). A constant-per-origin call counter +
    # a stable continuous injected feature exercise the whole path.
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    calls = []

    def augment(t):
        calls.append(t)
        vals = (corpus["cve_id"].str.len() % 7).astype(float)  # stable continuous
        return pd.DataFrame({"cve_id": corpus["cve_id"], "xfer": vals})

    res = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox",
        horizons=(90,), augment_fn=augment,
    )
    assert len(calls) >= 3  # invoked once per scored origin
    assert res["aggregate"]["n_origins"] >= 3
    assert res["aggregate"]["horizon_auc"]["90"]["mean"] > 0.5


def test_backtest_augment_fn_rejects_non_numeric():
    # a non-numeric augment column would be silently dropped by the numeric-only
    # feature selection; the hook must fail loud instead of doing nothing.
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)

    def bad_augment(t):
        return pd.DataFrame({"cve_id": corpus["cve_id"], "label": "x"})

    with pytest.raises(ValueError, match="numeric"):
        rolling_origin_backtest(
            corpus, ev, features, "2024-06-01", origins, model="cox",
            horizons=(90,), augment_fn=bad_augment,
        )


def test_backtest_temperature_preserves_ranking():
    # temperature recalibration rescales absolute probabilities only — it is
    # monotone in S, so per-origin horizon-AUC (a ranking metric) must be
    # bit-identical to the uncalibrated run; only IPA/calibration can move.
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    base = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,)
    )
    temp = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,),
        temperature=True,
    )
    b = {o["origin"]: o["horizon_auc"].get("90") for o in base["per_origin"]}
    t = {o["origin"]: o["horizon_auc"].get("90") for o in temp["per_origin"]}
    common = {o for o in (set(b) & set(t)) if b[o] is not None and t[o] is not None}
    assert common
    for o in common:
        assert abs(b[o] - t[o]) < 1e-9  # ranking untouched


def test_backtest_permutation_is_chance_level():
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    perm = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox",
        horizons=(30, 90, 180), permute=True,
    )
    # shuffled durations -> no learnable signal -> AUC ~ 0.5 (harness has no leak)
    assert abs(perm["aggregate"]["horizon_auc"]["90"]["mean"] - 0.5) < 0.08


def test_backtest_clock_start_shrinks_training_set():
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2023-01-01", min_followup_days=180)
    base = rolling_origin_backtest(corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,))
    filt = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox", horizons=(90,),
        clock_start="2022-06-01",
    )
    n_base = {o["origin"]: o["n_train"] for o in base["per_origin"]}
    n_filt = {o["origin"]: o["n_train"] for o in filt["per_origin"]}
    common = set(n_base) & set(n_filt)
    assert common
    assert all(n_filt[o] <= n_base[o] for o in common)
    assert any(n_filt[o] < n_base[o] for o in common)  # pre-clock CVEs were dropped
