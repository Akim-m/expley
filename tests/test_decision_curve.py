"""Decision-curve / net-benefit analysis (Vickers), censoring-aware.

Answers the honest operational question a bare AUC can't: at the threshold
probability a defender would actually act on, does ranking by the model beat the
trivial "treat all" / "treat none" policies? At a <1% base rate a 0.82-AUC ranker
can have ~zero net benefit; this surfaces that.
"""
import numpy as np

from temporal_exploit.decision_curve import net_benefit_table


def test_net_benefit_perfect_separation_beats_treat_all():
    # 5 high-risk CVEs all weaponize by day 10; 5 low-risk stay event-free
    # (observed out to day 100). At threshold p_t=0.5 the flagged set is exactly
    # the 5 true weaponizers, so the model has only true positives.
    risk = np.array([0.9] * 5 + [0.1] * 5)
    durations = np.array([10.0] * 5 + [100.0] * 5)
    events = np.array([True] * 10)

    tbl = net_benefit_table(risk, durations, events, horizon=30, thresholds=[0.5])
    row = tbl[tbl["threshold"] == 0.5].iloc[0]

    # w = p_t/(1-p_t) = 1. Flagged frac 0.5, all flagged have the event -> S_flag=0.
    # NB_model = 0.5*[(1-0) - 0*1] = 0.5
    assert abs(row["net_benefit_model"] - 0.5) < 1e-9
    # Treat-all: KM S(30) over everyone = 0.5 -> NB = (1-0.5) - 0.5*1 = 0.0
    assert abs(row["net_benefit_all"] - 0.0) < 1e-9
    assert row["net_benefit_none"] == 0.0


def test_net_benefit_is_censoring_aware_via_km():
    # Two CVEs censored at day 15 (before the 30d horizon: outcome unknown), one
    # event at 10, one event-free out to 50. A naive "drop censored-before-h"
    # event rate = 1/2 = 0.5; the censoring-aware KM rate is 1 - S(30) = 0.25.
    # That difference is the whole point of using KM, so the net benefit must
    # reflect 0.25, not 0.5.
    risk = np.array([0.9, 0.9, 0.9, 0.9])
    durations = np.array([10.0, 15.0, 15.0, 50.0])
    events = np.array([True, False, False, False])

    tbl = net_benefit_table(risk, durations, events, horizon=30, thresholds=[0.5])
    row = tbl[tbl["threshold"] == 0.5].iloc[0]

    # all flagged (risk 0.9 >= 0.5). KM P(event by 30) = 0.25, w = 1.
    # NB = 1.0 * [0.25 - (1-0.25)*1] = -0.5  (NOT the naive -0.0)
    assert abs(row["net_benefit_all"] - (-0.5)) < 1e-9
    assert abs(row["net_benefit_model"] - (-0.5)) < 1e-9
    assert row["flagged_frac"] == 1.0
