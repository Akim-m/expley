import numpy as np
import pandas as pd
import pytest

from temporal_exploit.modeling import (
    evaluate_survival,
    feature_matrix,
    fit_cox,
    fit_rsf,
    prepare_modeling_frame,
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


def test_evaluate_survival_rsf():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_rsf(train, n_estimators=10, max_samples=10000)
    res = evaluate_survival(model, train, test, horizons=(7, 30, 90), kind="rsf")
    assert res["kind"] == "rsf"
    assert 0.0 <= res["c_index_ipcw"] <= 1.0
    assert isinstance(res["brier"], dict)


def test_evaluate_survival_skips_out_of_support_horizon():
    labels, features = _synthetic(n=140)
    frame = prepare_modeling_frame(labels, features)
    train, test = time_split_frame(frame, "2023-09-01")
    model = fit_cox(train)
    res = evaluate_survival(model, train, test, horizons=(7, 30, 100000), kind="cox")
    assert 100000 in res["skipped_horizons"]
    assert 100000 not in res["brier"]
