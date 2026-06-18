import numpy as np
import pandas as pd

from temporal_exploit.competing import (
    cif_calibration_table,
    cif_table,
    fit_aalen_johansen,
    fit_cause_specific_cox,
    prepare_competing_frame,
    transition_frame,
)

CAL_COLS = ["cause_code", "horizon", "bin_mid", "mean_pred", "observed", "count"]


def _synthetic(n=200, seed=0):
    rng = np.random.default_rng(seed)
    cvss = rng.uniform(2.0, 10.0, n)
    # cause 1 accelerates with cvss; cause 2 and censoring are independent
    t1 = rng.exponential(np.exp(6.0 - 0.4 * cvss))
    t2 = rng.exponential(150.0, n)
    censor = rng.uniform(30.0, 400.0, n)
    duration = np.minimum.reduce([t1, t2, censor]) + 1.0
    cause = np.select([t1 <= np.minimum(t2, censor), t2 <= censor], [1, 2], default=0)

    published = pd.to_datetime("2023-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 700, n), unit="D"
    )
    cause_names = {0: "censored", 1: "poc", 2: "kev"}
    labels = pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{i:05d}" for i in range(n)],
            "published": published,
            "duration_days": duration,
            "event_cause": [cause_names[c] for c in cause],
            "cause_code": cause,
            "event_observed": cause != 0,
        }
    )
    features = pd.DataFrame(
        {
            "cve_id": labels["cve_id"],
            "published": published,
            "cvss_v3_base": cvss,
            "vendor_count": rng.integers(1, 6, n),
        }
    )
    return labels, features


def test_prepare_competing_frame_merges_and_drops():
    labels, features = _synthetic(n=20)
    labels.loc[0, "duration_days"] = 0.0
    labels.loc[1, "duration_days"] = -5.0
    features = features.iloc[:-1]  # last CVE dropped by inner merge

    frame = prepare_competing_frame(labels, features)

    assert labels.loc[0, "cve_id"] not in frame["cve_id"].values
    assert labels.loc[1, "cve_id"] not in frame["cve_id"].values
    assert labels.loc[19, "cve_id"] not in frame["cve_id"].values
    assert (frame["duration_days"] > 0).all()
    assert "cause_code" in frame.columns
    assert "cvss_v3_base" in frame.columns


def test_fit_aalen_johansen_one_fitter_per_nonzero_cause():
    labels, features = _synthetic()
    frame = prepare_competing_frame(labels, features)
    fitters = fit_aalen_johansen(frame)
    assert set(fitters) == {1, 2}


def test_fit_aalen_johansen_handles_tied_integer_durations():
    labels, features = _synthetic()
    labels["duration_days"] = np.ceil(labels["duration_days"])  # force ties
    frame = prepare_competing_frame(labels, features)
    fitters = fit_aalen_johansen(frame)
    assert set(fitters) == {1, 2}


def test_cif_table_bounds_monotonic_and_joint_sum():
    labels, features = _synthetic()
    frame = prepare_competing_frame(labels, features)
    fitters = fit_aalen_johansen(frame)
    horizons = [7, 30, 90, 180]
    table = cif_table(fitters, horizons)

    assert list(table.columns) == ["cause_code", "horizon", "cif"]
    assert len(table) == len(fitters) * len(horizons)
    assert ((table["cif"] >= 0.0) & (table["cif"] <= 1.0)).all()
    for _, g in table.groupby("cause_code"):
        assert g.sort_values("horizon")["cif"].is_monotonic_increasing
    for _, g in table.groupby("horizon"):
        assert g["cif"].sum() <= 1.0 + 1e-9


def test_cif_table_zero_before_first_event():
    labels, features = _synthetic()
    frame = prepare_competing_frame(labels, features)
    frame = frame[frame["duration_days"] > 5].reset_index(drop=True)
    fitters = fit_aalen_johansen(frame)
    table = cif_table(fitters, [0])
    assert (table["cif"] == 0.0).all()


def test_fit_cause_specific_cox_includes_feature():
    labels, features = _synthetic()
    frame = prepare_competing_frame(labels, features)
    model = fit_cause_specific_cox(frame, cause_code=1)
    assert "cvss_v3_base" in model.params_.index
    assert "cvss_v3_base" in model.feature_cols_
    for meta in ("cve_id", "published", "duration_days", "cause_code", "event_observed"):
        assert meta not in model.feature_cols_


def _per_signal():
    snapshot = "2023-02-01"
    nat = pd.Series([pd.NaT], dtype="datetime64[ns, UTC]")[0]
    frame = pd.DataFrame(
        {
            "cve_id": ["A", "B", "C", "D"],
            "published": pd.to_datetime(["2022-12-01"] * 4, utc=True),
            "poc_event_date": pd.to_datetime(
                ["2023-01-01", "2023-01-01", None, "2023-01-20"], utc=True
            ),
            "poc_observed": [True, True, False, True],
            "metasploit_event_date": pd.to_datetime(
                ["2023-01-11", None, "2023-01-05", "2023-01-10"], utc=True
            ),
            "metasploit_observed": [True, False, True, True],
            "_": nat,  # keep tz dtype import honest
        }
    )
    return frame.drop(columns=["_"]), snapshot


def test_transition_frame_event_and_censoring_math():
    per_signal, snapshot = _per_signal()
    out = transition_frame(per_signal, "poc", "metasploit", snapshot)

    assert list(out.columns) == ["cve_id", "duration_days", "event_observed"]
    assert set(out["cve_id"]) == {"A", "B"}  # C: no poc; D: negative dropped
    a = out.set_index("cve_id")
    assert a.loc["A", "duration_days"] == 10 and bool(a.loc["A", "event_observed"])
    assert a.loc["B", "duration_days"] == 31 and not bool(a.loc["B", "event_observed"])


def test_cif_calibration_table_columns_bounds_counts():
    labels, features = _synthetic(n=300)
    frame = prepare_competing_frame(labels, features)
    pred = frame["cvss_v3_base"].to_numpy(float) / 10.0

    table = cif_calibration_table(pred, frame, cause_code=1, horizon=90, n_bins=5)

    assert list(table.columns) == CAL_COLS
    assert (table["cause_code"] == 1).all()
    assert (table["horizon"] == 90).all()
    assert ((table["observed"] >= 0.0) & (table["observed"] <= 1.0)).all()
    assert table["count"].sum() == len(frame)


def test_cif_calibration_table_bin_without_cause_is_zero():
    # low-pred half has only cause-2/censored rows, so its observed CIF must be 0
    frame = pd.DataFrame(
        {
            "duration_days": np.arange(1.0, 21.0),
            "cause_code": [2, 0] * 5 + [1] * 10,
        }
    )
    pred = np.r_[np.linspace(0.1, 0.2, 10), np.linspace(0.8, 0.9, 10)]

    table = cif_calibration_table(pred, frame, cause_code=1, horizon=10_000, n_bins=2)

    low = table.sort_values("bin_mid").iloc[0]
    assert low["observed"] == 0.0


def test_cif_calibration_table_constant_pred_returns_empty():
    labels, features = _synthetic(n=50)
    frame = prepare_competing_frame(labels, features)
    table = cif_calibration_table(np.full(len(frame), 0.5), frame, cause_code=1, horizon=90)
    assert list(table.columns) == CAL_COLS
    assert table.empty


def _competing_split(n=800, seed=1):
    from temporal_exploit.competing import prepare_competing_frame

    labels, features = _synthetic(n=n, seed=seed)
    frame = prepare_competing_frame(labels, features)
    cutoff = pd.Timestamp("2023-12-01", tz="UTC")
    train = frame[frame["published"] < cutoff].reset_index(drop=True)
    test = frame[frame["published"] >= cutoff].reset_index(drop=True)
    return frame, train, test


def test_cause_specific_cindex_on_test_and_none_when_absent():
    from temporal_exploit.competing import cause_specific_cindex

    _, train, test = _competing_split()
    c = cause_specific_cindex(train, test, 1)  # cause 1 driven by cvss -> rankable
    assert c is not None and 0.0 <= c <= 1.0
    # a cause with no events anywhere -> undefined -> None (no crash)
    assert cause_specific_cindex(train, test, 99) is None


def test_cif_vs_independent_inflation_nonnegative():
    from temporal_exploit.competing import cif_vs_independent

    frame, _, _ = _competing_split()
    tbl = cif_vs_independent(frame, [30, 90, 180])
    assert set(tbl.columns) >= {"cause_code", "horizon", "aj_cif", "independent_km", "inflation"}
    # naive 1-KM (competing events censored) overestimates the AJ CIF
    assert (tbl["inflation"] >= -1e-9).all()
    assert (tbl["independent_km"] >= tbl["aj_cif"] - 1e-9).all()
    assert (tbl["aj_cif"] >= 0).all() and (tbl["aj_cif"] <= 1).all()
