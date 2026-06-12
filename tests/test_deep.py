import numpy as np
import pandas as pd
import pytest

pytest.importorskip("torch")
pytest.importorskip("pycox")

from temporal_exploit.deep import evaluate_deepsurv, fit_deepsurv  # noqa: E402


def _frame(n=300, seed=0):
    rng = np.random.default_rng(seed)
    cvss = rng.uniform(2.0, 10.0, n)
    true_time = np.clip(200.0 - 15.0 * cvss + rng.normal(0, 20, n), 1.0, None)
    censor = rng.uniform(30.0, 250.0, n)
    duration = np.minimum(true_time, censor)
    observed = true_time <= censor
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{i:05d}" for i in range(n)],
            "published": pd.to_datetime("2023-01-01", utc=True),
            "duration_days": duration.astype(float),
            "event_observed": observed,
            "negative_duration_flag": False,
            "cvss_v3_base": cvss,
            "vendor_count": rng.integers(1, 6, n),
        }
    )


def test_fit_and_evaluate_deepsurv():
    train, test = _frame(seed=0), _frame(seed=1)
    model = fit_deepsurv(train, epochs=8, batch_size=128)

    import torch

    if torch.cuda.is_available():  # use the GPU when present
        assert next(model.model.net.parameters()).is_cuda

    assert model.feature_cols_ == ["cvss_v3_base", "vendor_count"]
    surv = model.predict_surv_df(test)
    assert surv.shape[1] == len(test)  # one survival curve per test row

    res = evaluate_deepsurv(model, test)
    assert res["kind"] == "deepsurv"
    assert 0.0 <= res["concordance_td"] <= 1.0
    assert res["integrated_brier"] >= 0.0


def test_evaluate_deepsurv_caps_eval_rows():
    train, test = _frame(seed=0), _frame(seed=1)
    model = fit_deepsurv(train, epochs=8, batch_size=128)
    res = evaluate_deepsurv(model, test, max_eval=50)
    assert res["n_test"] == 50
