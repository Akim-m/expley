import numpy as np
import pandas as pd
import pytest

pytest.importorskip("hazardous")

from temporal_exploit.survboost import fit_survival_boost  # noqa: E402

META = ["cve_id", "published", "duration_days", "event_cause", "cause_code", "event_observed"]


def _synthetic(n=300, seed=0):
    rng = np.random.default_rng(seed)
    cvss = rng.uniform(2.0, 10.0, n)
    t1 = np.clip(200.0 - 18.0 * cvss + rng.normal(0, 15, n), 1.0, None)  # cause 1: cvss-driven
    t2 = rng.uniform(20.0, 400.0, n)  # cause 2: random
    censor = rng.uniform(60.0, 500.0, n)
    duration = np.minimum.reduce([t1, t2, censor])
    cause = np.select([t1 == duration, t2 == duration], [1, 2], default=0)
    published = pd.to_datetime("2023-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 700, n), unit="D"
    )
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{i:05d}" for i in range(n)],
            "published": published,
            "duration_days": duration,
            "event_cause": np.where(cause == 0, "censored", "cause"),
            "cause_code": cause,
            "event_observed": cause > 0,
            "cvss_v3_base": cvss,
            "noise": rng.normal(0, 1, n),
            "constant": 1.0,
        }
    )


def test_fit_and_cif_properties():
    frame = _synthetic()
    model = fit_survival_boost(frame, n_iter=30, seed=0)

    assert model.feature_cols_ == ["cvss_v3_base", "noise"]  # meta + constant excluded
    assert model.causes_ == [1, 2]

    X = frame[model.feature_cols_]
    horizons = [30, 90, 180]
    cif = model.cif_at(X, horizons)

    assert cif.shape == (len(frame), 2, 3)
    assert ((cif >= 0.0) & (cif <= 1.0)).all()
    assert (np.diff(cif, axis=2) >= -1e-12).all()  # CIF non-decreasing in horizon


def test_cvss_drives_cause1_discrimination():
    frame = _synthetic()
    model = fit_survival_boost(frame, n_iter=30, seed=0)

    X = frame[model.feature_cols_]
    cif = model.cif_at(X, [90])
    high = frame["cvss_v3_base"] >= 8.0
    low = frame["cvss_v3_base"] <= 4.0
    assert cif[high.to_numpy(), 0, 0].mean() > cif[low.to_numpy(), 0, 0].mean()
