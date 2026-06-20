import numpy as np
import pandas as pd
import pytest

from temporal_exploit.modeling import (
    calibration_table,
    cox_ph_assumptions,
    evaluate_survival,
    feature_matrix,
    fit_cox,
    fit_rsf,
    plot_calibration,
    prepare_modeling_frame,
    survival_at,
    time_split_frame,
)


def _synthetic(n=120, seed=0):
    rng = np.random.default_rng(seed)
    cvss = rng.uniform(2.0, 10.0, n)
    # higher cvss -> shorter duration (real signal)
    base = 200.0 - 15.0 * cvss
    noise = rng.normal(0.0, 20.0, n)
    true_time = np.clip(base + noise, 1.0, None)
    censor_time = rng.uniform(30.0, 250.0, n)
    duration = np.minimum(true_time, censor_time)
    observed = true_time <= censor_time

    published = pd.to_datetime("2023-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 700, n), unit="D"
    )
    labels = pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{i:05d}" for i in range(n)],
            "published": published,
            "duration_days": duration,
            "event_observed": observed,
            "negative_duration_flag": False,
        }
    )
    features = pd.DataFrame(
        {
            "cve_id": labels["cve_id"],
            "published": published,
            "cvss_v3_base": cvss,
            "weakness_count": rng.integers(0, 4, n),
            "vendor_count": rng.integers(1, 6, n),
        }
    )
    return labels, features


def test_prepare_drops_negative_and_nonpositive_and_inner_merges():
    labels, features = _synthetic(n=20)
    labels.loc[0, "negative_duration_flag"] = True
    labels.loc[1, "duration_days"] = 0.0
    labels.loc[2, "duration_days"] = -3.0
    # row dropped by inner merge
    features = features.iloc[:-1]

    frame = prepare_modeling_frame(labels, features)

    assert labels.loc[0, "cve_id"] not in frame["cve_id"].values
    assert labels.loc[1, "cve_id"] not in frame["cve_id"].values
    assert labels.loc[2, "cve_id"] not in frame["cve_id"].values
    assert labels.loc[19, "cve_id"] not in frame["cve_id"].values  # inner merge dropped
    assert "cvss_v3_base" in frame.columns
    assert "published" in frame.columns
    assert (frame["duration_days"] > 0).all()


def _pred_event(model, frame, horizon, kind):
    X = frame[list(model.feature_cols_)].astype(float)
    return 1.0 - survival_at(model, X, [horizon], kind)[:, 0]


def test_calibration_table_shape_and_bounds():
    labels, features = _synthetic(n=200)
    frame = prepare_modeling_frame(labels, features)
    cox = fit_cox(frame)
    table = calibration_table(_pred_event(cox, frame, 90, "cox"), frame, horizon=90, n_bins=5)

    assert list(table.columns) == ["horizon", "bin_mid", "mean_pred", "observed", "count"]
    assert len(table) <= 5
    assert ((table["observed"] >= 0) & (table["observed"] <= 1)).all()
    assert ((table["mean_pred"] >= 0) & (table["mean_pred"] <= 1)).all()
    assert table["count"].sum() == len(frame)


def test_plot_calibration_writes_png(tmp_path):
    labels, features = _synthetic(n=200)
    frame = prepare_modeling_frame(labels, features)
    cox = fit_cox(frame)
    tables = {
        h: calibration_table(_pred_event(cox, frame, h, "cox"), frame, horizon=h, n_bins=5)
        for h in (30, 90)
    }
    out = tmp_path / "calibration.png"
    plot_calibration(tables, out, title="cox")
    assert out.exists() and out.stat().st_size > 0


def test_survival_at_rsf_batching_matches_single_pass():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_rsf(train, n_estimators=10, max_samples=10000)
    X = test[model.feature_cols_].astype(float)

    full = survival_at(model, X, [7, 30, 90], "rsf", batch_size=10_000)
    batched = survival_at(model, X, [7, 30, 90], "rsf", batch_size=7)
    assert np.allclose(full, batched)


def test_survival_at_rsf_step_semantics():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, _ = time_split_frame(frame, "2023-09-01")
    model = fit_rsf(train, n_estimators=10, max_samples=10000)
    X = train[model.feature_cols_].astype(float).iloc[:5]

    times = model.unique_times_
    before_first = float(times[0]) / 2.0
    surv = survival_at(model, X, [before_first, float(times[-1]) + 1000.0], "rsf")
    full = model.predict_survival_function(X, return_array=True)

    assert np.allclose(surv[:, 0], 1.0)  # before first event time S(t) == 1
    assert np.allclose(surv[:, 1], full[:, -1])  # beyond support: last value


def test_time_split_frame_partitions_on_cutoff():
    labels, features = _synthetic(n=60)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    cutoff = pd.Timestamp("2023-09-01", tz="UTC")
    assert (train["published"] < cutoff).all()
    assert (test["published"] >= cutoff).all()
    assert len(train) + len(test) == len(frame)


def test_feature_matrix_excludes_meta_columns():
    labels, features = _synthetic(n=30)
    frame = prepare_modeling_frame(labels, features)
    X, y = feature_matrix(frame)
    for col in ("cve_id", "published", "duration_days", "event_observed", "negative_duration_flag"):
        assert col not in X.columns
    assert "cvss_v3_base" in X.columns
    assert len(X) == len(frame)
    assert y.dtype.names == ("event", "time")


def test_fit_cox_drops_rare_one_hots():
    labels, features = _synthetic(n=120)
    features["rare_flag"] = 0
    features.loc[0, "rare_flag"] = 1  # 1 positive in 120 -> unstable covariate
    frame = prepare_modeling_frame(labels, features)
    model = fit_cox(frame)
    assert "rare_flag" not in model.feature_cols_
    assert "cvss_v3_base" in model.feature_cols_


def test_fit_cox_includes_feature():
    labels, features = _synthetic(n=120)
    frame = prepare_modeling_frame(labels, features)
    train, _ = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    assert "cvss_v3_base" in model.params_.index


def test_fit_rsf_no_subsample():
    labels, features = _synthetic(n=120)
    frame = prepare_modeling_frame(labels, features)
    train, _ = time_split_frame(frame, "2023-09-01")
    model = fit_rsf(train, n_estimators=10, max_samples=10000)
    assert hasattr(model, "unique_times_")
    assert len(model.feature_cols_) >= 1


def test_fit_rsf_subsample_path_deterministic():
    labels, features = _synthetic(n=120)
    frame = prepare_modeling_frame(labels, features)
    train, _ = time_split_frame(frame, "2023-09-01")
    m1 = fit_rsf(train, n_estimators=10, max_samples=30, random_state=0)
    m2 = fit_rsf(train, n_estimators=10, max_samples=30, random_state=0)
    X = feature_matrix(train)[0]
    assert np.allclose(m1.predict(X), m2.predict(X))


def test_evaluate_survival_cox():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(7, 30, 90), kind="cox")
    assert res["kind"] == "cox"
    assert 0.0 <= res["c_index_ipcw"] <= 1.0
    assert isinstance(res["brier"], dict)
    for h, v in res["brier"].items():
        assert 0.0 <= v <= 1.0
    assert res["n_train"] == len(train)
    assert res["n_test"] == len(test)


def test_evaluate_survival_reports_horizon_pr_auc():
    # PR-AUC / average precision is the informative metric for rare positives;
    # reported on the same fully-observed subcohort as horizon_auc, same horizons.
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(30, 90))
    assert "horizon_pr_auc" in res
    assert set(res["horizon_pr_auc"]) == set(res["horizon_auc"])
    for v in res["horizon_pr_auc"].values():
        assert 0.0 <= v <= 1.0


def test_evaluate_survival_reports_ipcw_auc_t():
    # IPCW time-dependent AUC(t) cross-check: the key is always present (possibly
    # empty if sksurv can't compute it on the support); any value is a valid AUC.
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(30, 90))
    assert "auc_t_ipcw" in res
    for v in res["auc_t_ipcw"].values():
        assert 0.0 <= v <= 1.0


def test_evaluate_survival_supports_short_horizons():
    # the instant / short-horizon head uses 1/3/7d; evaluate_survival must handle them,
    # and the subcohort drop-fraction is non-decreasing in horizon (longer h censors more).
    labels, features = _synthetic(n=200)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(1, 7, 30, 90))
    supp = res["horizon_auc_support"]
    assert supp  # at least one horizon within the test follow-up support
    fracs = [supp[str(h)]["dropped_frac"] for h in sorted(int(h) for h in supp)]
    assert fracs == sorted(fracs)  # monotone non-decreasing in horizon


def test_cause_specific_cindex_ranks_risk():
    from temporal_exploit.modeling import cause_specific_cindex

    durations = [10.0, 20.0, 30.0, 40.0]
    events = [True, True, True, False]  # last is a competing event / censored
    risk = [4.0, 3.0, 2.0, 1.0]  # higher risk -> earlier transition (perfect concordance)
    assert cause_specific_cindex(durations, risk, events) > 0.9


def test_evaluate_survival_rsf():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_rsf(train, n_estimators=10, max_samples=10000)
    res = evaluate_survival(model, train, test, horizons=(7, 30, 90), kind="rsf")
    assert res["kind"] == "rsf"
    assert 0.0 <= res["c_index_ipcw"] <= 1.0
    assert isinstance(res["brier"], dict)


def test_evaluate_survival_accepts_precomputed_survival():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_rsf(train, n_estimators=10, max_samples=10000)
    X = test[model.feature_cols_].astype(float)
    horizons = (7, 30, 90)
    surv = survival_at(model, X, list(horizons), "rsf")

    fresh = evaluate_survival(model, train, test, horizons=horizons, kind="rsf")
    reused = evaluate_survival(
        model, train, test, horizons=horizons, kind="rsf", surv_at_horizons=surv
    )
    # parallel tree accumulation is non-associative -> compare with tolerance
    for h in fresh["brier"]:
        assert np.isclose(fresh["brier"][h], reused["brier"][h])
    assert np.isclose(fresh["c_index_ipcw"], reused["c_index_ipcw"])


def test_evaluate_survival_skips_out_of_support_horizon():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(7, 30, 100000), kind="cox")
    assert 100000 in res["skipped_horizons"]
    assert 100000 not in res["brier"]


def test_cox_ph_assumptions_sampling_caps_rows():
    labels, features = _synthetic(n=120)
    frame = prepare_modeling_frame(labels, features)
    train, _ = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)

    diag = cox_ph_assumptions(model, train, max_rows=30)
    assert list(diag.columns) == ["covariate", "test_statistic", "p", "violates"]
    assert len(diag) == len(model.feature_cols_)


def test_cox_ph_assumptions_shape_and_sorting():
    labels, features = _synthetic(n=120)
    frame = prepare_modeling_frame(labels, features)
    train, _ = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)

    diag = cox_ph_assumptions(model, train)

    assert list(diag.columns) == ["covariate", "test_statistic", "p", "violates"]
    assert len(diag) == len(model.feature_cols_)
    assert set(diag["covariate"]) == set(model.feature_cols_)
    assert ((diag["p"] >= 0.0) & (diag["p"] <= 1.0)).all()
    assert diag["violates"].dtype == bool
    assert diag["p"].is_monotonic_increasing


def test_evaluate_survival_reports_uncertainty_and_horizon_auc():
    labels, features = _synthetic(n=300)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(30, 90))

    # Noether-approximate CI on the c-index: present, ordered, brackets the point
    lo, hi = res["c_index_ci95"]
    assert lo < res["c_index_ipcw"] < hi
    assert res["c_index_se"] > 0
    assert res["c_index_n_events"] > 0

    # censoring-free per-horizon AUC on the fully-observed subcohort
    for h in (30, 90):
        if str(h) in res["horizon_auc"]:
            assert 0.0 <= res["horizon_auc"][str(h)] <= 1.0

    # IPA (scaled Brier vs the train-KM null model); 1 is perfect, <=0 is no
    # better than the null
    for h, ipa in res["ipa"].items():
        assert ipa <= 1.0


def test_horizon_auc_skipped_when_subcohort_has_one_class():
    labels, features = _synthetic(n=300)
    # every observed event happens at day 100 — at horizon 30 the fully
    # observed subcohort has a single class (no event by 30), so no AUC
    labels["duration_days"] = np.where(labels["event_observed"], 100.0, 500.0)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(30, 120))
    assert "30" not in res["horizon_auc"]


def test_fit_cox_scales_penalizer_by_event_rate_and_filters_eventless_indicators():
    labels, features = _synthetic(n=400)
    # rare events: 5% observed
    rng = np.random.default_rng(1)
    labels["event_observed"] = rng.random(400) < 0.05
    frame = prepare_modeling_frame(labels, features)
    # indicator with plenty of positives overall but none among events
    frame["dead_indicator"] = (~frame["event_observed"]).astype(int) * (
        np.arange(len(frame)) % 2
    )
    model = fit_cox(frame, penalizer=0.1)
    event_rate = frame["event_observed"].mean()
    assert model.penalizer == pytest.approx(0.1 * event_rate)
    assert "dead_indicator" not in model.feature_cols_


def test_calibration_table_caps_bins_by_event_count():
    labels, features = _synthetic(n=300)
    frame = prepare_modeling_frame(labels, features)
    # only ~25 events -> at most 25//20 = 1 -> floor of 2 bins
    rng = np.random.default_rng(2)
    frame["event_observed"] = rng.random(len(frame)) < 0.1
    pred = rng.random(len(frame))
    table = calibration_table(pred, frame, horizon=30, n_bins=10)
    assert len(table) <= 2


def test_cox_ph_assumptions_keeps_all_events_when_sampling():
    labels, features = _synthetic(n=300)
    frame = prepare_modeling_frame(labels, features)
    model = fit_cox(frame)
    # max_rows below n forces sampling; the sample must keep every event row
    diag = cox_ph_assumptions(model, frame, max_rows=100)
    assert not diag.empty


def test_fit_cox_escalates_penalizer_until_convergence(monkeypatch):
    import warnings as _w

    import lifelines
    from lifelines.exceptions import ConvergenceWarning

    labels, features = _synthetic(n=200)
    frame = prepare_modeling_frame(labels, features)

    seen = []
    orig_fit = lifelines.CoxPHFitter.fit

    def flaky_fit(self, *args, **kwargs):
        seen.append(self.penalizer)
        if len(seen) == 1:  # first attempt "fails"
            _w.warn("Newton-Raphson failed to converge", ConvergenceWarning)
        return orig_fit(self, *args, **kwargs)

    monkeypatch.setattr(lifelines.CoxPHFitter, "fit", flaky_fit)
    model = fit_cox(frame, penalizer=0.1)
    assert len(seen) == 2
    assert seen[1] == pytest.approx(seen[0] * 10)
    assert model.penalizer == pytest.approx(seen[1])


def test_survival_at_and_risk_dispatch_cure():
    from temporal_exploit.cure import fit_cure
    from temporal_exploit.modeling import _risk_scores, survival_at
    from tests.test_cure import _synth_cure

    frame = _synth_cure()
    model = fit_cure(frame)
    X = frame[model.feature_cols_].astype(float).head(5)
    surv = survival_at(model, X, [30, 90], "cure")
    assert surv.shape == (5, 2)
    assert np.all((surv > 0) & (surv <= 1))
    risk = _risk_scores(model, X, "cure")
    assert risk.shape == (5,)


def test_bootstrap_report_brackets_point_and_self_delta_zero():
    from temporal_exploit.modeling import bootstrap_cindex_report, truncated_cindex

    rng = np.random.default_rng(0)
    n = 400
    risk = rng.normal(size=n)
    dur = np.clip(100 - 20 * risk + rng.normal(0, 10, n), 1, None)
    ev = rng.random(n) < 0.5
    tau = float(np.quantile(dur, 0.9))
    point = truncated_cindex(dur, ev, risk, tau)

    # two models, the second identical to the baseline -> paired delta ~ 0
    report = bootstrap_cindex_report(
        dur, ev, {"cox": risk, "a": risk}, tau, baseline="cox", n_boot=200, seed=0
    )
    lo, hi = report["per_model"]["a"]["ci95"]
    assert lo < point < hi and report["per_model"]["a"]["se"] > 0 and report["n_boot"] == 200
    delta = report["vs_baseline"]["a"]
    assert abs(delta["delta"]) < 1e-9
    assert delta["ci95"][0] <= 0 <= delta["ci95"][1]


def test_truncated_cindex_matches_harrell_on_uncensored():
    from lifelines.utils import concordance_index
    from temporal_exploit.modeling import truncated_cindex

    rng = np.random.default_rng(1)
    n = 300
    risk = rng.normal(size=n)
    dur = np.clip(100 - 20 * risk + rng.normal(0, 5, n), 1, None)
    ev = np.ones(n, dtype=bool)  # fully observed
    tau = float(dur.max()) + 1.0  # tau above everything -> no truncation
    tc = truncated_cindex(dur, ev, risk, tau)
    harrell = concordance_index(dur, -risk, ev)
    assert abs(tc - harrell) < 1e-9
    assert 0.0 <= truncated_cindex(dur, ev, risk, float(np.median(dur))) <= 1.0


def test_prepare_modeling_frame_rejects_nan_features():
    labels = pd.DataFrame({
        "cve_id": ["A"], "published": pd.to_datetime(["2024-01-01"], utc=True),
        "duration_days": [10.0], "event_observed": [True], "negative_duration_flag": [False],
    })
    features = pd.DataFrame({"cve_id": ["A"], "feat": [float("nan")]})
    with pytest.raises(ValueError, match="NaN in feature"):
        prepare_modeling_frame(labels, features)
