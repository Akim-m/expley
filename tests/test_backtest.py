from temporal_exploit.backtest import make_origins, rolling_origin_backtest
from temporal_exploit.features import build_publication_features
from temporal_exploit.simulate import synth_weaponization


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
    # operational: flagging the top decile catches more than its share of weaponizers
    assert agg["recall_at_top"]["90"]["mean"] > 0.10


def test_backtest_permutation_is_chance_level():
    corpus, ev, features = _setup()
    origins = make_origins("2024-06-01", start="2021-01-01", min_followup_days=180)
    perm = rolling_origin_backtest(
        corpus, ev, features, "2024-06-01", origins, model="cox",
        horizons=(30, 90, 180), permute=True,
    )
    # shuffled durations -> no learnable signal -> AUC ~ 0.5 (harness has no leak)
    assert abs(perm["aggregate"]["horizon_auc"]["90"]["mean"] - 0.5) < 0.08
