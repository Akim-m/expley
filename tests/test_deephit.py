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
