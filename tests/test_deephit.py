import numpy as np
import pandas as pd
import pytest

from temporal_exploit.deephit import evaluate_deephit, fit_deephit


def _competing(n=400, seed=0):
    rng = np.random.default_rng(seed)
    cvss = rng.uniform(2.0, 10.0, n)
    t1 = rng.exponential(np.exp(6.0 - 0.4 * cvss))   # cause 1 accelerates with cvss
    t2 = rng.exponential(150.0, n)
    censor = rng.uniform(30.0, 400.0, n)
    duration = np.minimum.reduce([t1, t2, censor]) + 1.0
    cause = np.select([t1 <= np.minimum(t2, censor), t2 <= censor], [1, 2], default=0)
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{i:05d}" for i in range(n)],
            "published": pd.Timestamp("2023-01-01", tz="UTC"),
            "duration_days": duration.astype(float),
            "event_cause": ["x"] * n,
            "cause_code": cause,
            "event_observed": cause != 0,
            "cvss_v3_base": cvss,
            "vendor_count": rng.integers(1, 6, n),
        }
    )


def test_deephit_rejects_noncontiguous_cause_codes():
    # the guard runs before the lazy torch import, so this is testable torch-free
    frame = pd.DataFrame(
        {
            "cve_id": ["A", "B", "C"],
            "published": pd.Timestamp("2023-01-01", tz="UTC"),
            "duration_days": [10.0, 20.0, 30.0],
            "event_cause": ["x", "y", "z"],
            "cause_code": [1, 3, 0],   # gap: no cause 2
            "event_observed": [True, True, False],
            "feat": [1.0, 2.0, 3.0],
        }
    )
    with pytest.raises(ValueError, match="contiguous"):
        fit_deephit(frame)


def test_fit_and_evaluate_deephit():
    pytest.importorskip("torch")
    pytest.importorskip("pycox")
    train, test = _competing(seed=0), _competing(seed=1)
    model = fit_deephit(train, epochs=4, num_durations=8, batch_size=128)
    assert model.causes_ == [1, 2]

    cif = model.cif_at(test.head(5), [30, 90])
    assert cif.shape == (5, 2, 2)               # samples x causes x horizons
    assert np.all((cif >= 0.0) & (cif <= 1.0))

    res = evaluate_deephit(model, test, horizons=(30, 90))
    assert res["kind"] == "deephit"
    assert set(res["per_cause"]) == {"1", "2"}
    for stats in res["per_cause"].values():
        assert stats["concordance_td"] is None or 0.0 <= stats["concordance_td"] <= 1.0


def test_evaluate_deephit_caps_eval_rows():
    pytest.importorskip("torch")
    pytest.importorskip("pycox")
    train, test = _competing(seed=0), _competing(seed=1)
    model = fit_deephit(train, epochs=4, num_durations=8, batch_size=128)
    res = evaluate_deephit(model, test, max_eval=60)
    assert res["n_test"] == 60


def _tie_heavy(n=2000, seed=0):
    """Tie-heavy durations force quantile cuts to be non-unique -> deduped."""
    rng = np.random.default_rng(seed)
    dur = rng.choice([0, 1, 1, 1, 2, 2, 5, 10, 30, 90, 200, 500.0], n).astype(float)
    cause = rng.choice([0, 0, 1, 1, 2], n)
    return pd.DataFrame({
        "cve_id": [f"C{i}" for i in range(n)],
        "published": pd.Timestamp("2022-01-01", tz="UTC"),
        "duration_days": np.maximum(dur, 0.1),
        "event_cause": np.where(cause == 0, "censored", cause.astype(str)),
        "cause_code": cause, "event_observed": cause > 0,
        "f1": rng.normal(0, 1, n), "f2": rng.integers(0, 2, n).astype(float),
    })


def test_quantile_cuts_dedupe_does_not_crash_predict():
    """Regression: quantile discretization on tie-heavy durations deduped the cut
    grid (e.g. 20 -> fewer), but the net was hardwired to the requested count, so
    predict_cif raised a shape mismatch. The net must size to len(labtrans.cuts)."""
    pytest.importorskip("torch")
    pytest.importorskip("pycox")
    fr = _tie_heavy()
    model = fit_deephit(fr, alpha=0.2, scheme="quantiles", num_durations=20, epochs=2, seed=0)
    assert len(model.duration_index_) < 20            # cuts were actually deduped
    ev = evaluate_deephit(model, fr, horizons=(30, 90))  # previously crashed here
    assert ev["kind"] == "deephit"
    cif = model.cif_at(fr.head(10), [30, 90])
    assert cif.shape == (10, len(model.causes_), 2)
    assert np.isfinite(cif).all()
