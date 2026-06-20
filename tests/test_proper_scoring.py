"""Tests for the right-censored log-likelihood (RCLL) proper scoring rule.

TDD: each test was written to fail against an empty module first, then the
minimal implementation in ``proper_scoring.py`` was added to make it pass.
"""
import math

import numpy as np
import pytest

from temporal_exploit.proper_scoring import rcll, rcll_skill


def test_correct_bin_beats_flat_model():
    """A model that puts ALL mass in the correct bin scores strictly lower
    (better) RCLL than a flat / uninformative model.

    Two events, two-bin grid times = [1, 2]:
      - subject 0 has its event in bin (0, 1]  -> correct model S = [0, 0]
        (mass in bin 1 = S(0)-S(1) = 1-0 = 1)
      - subject 1 has its event in bin (1, 2]  -> correct model S = [1, 0]
        (mass in bin 2 = S(1)-S(2) = 1-0 = 1)
    The "perfect" model assigns mass 1.0 to each true bin -> -log(1)=0 each,
    so rcll == 0.  A flat model that spreads mass evenly has positive rcll.
    """
    times = np.array([1.0, 2.0])
    durations = np.array([1.0, 2.0])
    events = np.array([True, True])

    surv_perfect = np.array([[0.0, 0.0],   # subj 0: event in bin 1
                             [1.0, 0.0]])   # subj 1: event in bin 2
    # flat: each subject keeps 1/2 mass in each of the two bins
    surv_flat = np.array([[0.5, 0.0],
                          [0.5, 0.0]])

    score_perfect = rcll(surv_perfect, times, durations, events)
    score_flat = rcll(surv_flat, times, durations, events)

    assert score_perfect == pytest.approx(0.0, abs=1e-9)
    assert score_perfect < score_flat


def test_hand_computed_event_plus_censored():
    """2 subjects, 2 time bins, one event + one censored; rcll computed by hand.

    times = [1, 2].
      subject 0: EVENT at d=1.5 -> falls in bin (1, 2]; mass = S(1)-S(2).
                 surv row [0.8, 0.3] -> mass = 0.8 - 0.3 = 0.5 -> -log(0.5)
      subject 1: CENSORED at d=1.0 -> largest grid time <= 1.0 is t=1;
                 contribution = -log(S(1)) = -log(0.6).
                 surv row [0.6, 0.2].
    expected mean = (-log(0.5) + -log(0.6)) / 2
    """
    times = np.array([1.0, 2.0])
    durations = np.array([1.5, 1.0])
    events = np.array([True, False])
    surv = np.array([[0.8, 0.3],
                     [0.6, 0.2]])

    expected = (-math.log(0.5) + -math.log(0.6)) / 2.0
    assert rcll(surv, times, durations, events) == pytest.approx(expected, rel=1e-12)


def test_event_before_first_grid_point_uses_implied_s0():
    """An event at d < times[0] falls in the first bin (0, times[0]];
    mass = S(0) - S(times[0]) = 1 - surv[:, 0]."""
    times = np.array([5.0, 10.0])
    durations = np.array([2.0])
    events = np.array([True])
    surv = np.array([[0.7, 0.4]])  # mass in bin 1 = 1 - 0.7 = 0.3
    expected = -math.log(0.3)
    assert rcll(surv, times, durations, events) == pytest.approx(expected, rel=1e-12)


def test_censored_before_first_grid_point_is_zero():
    """Censored at d < times[0]: survived past nothing on the grid -> S=1 ->
    contribution 0."""
    times = np.array([5.0, 10.0])
    durations = np.array([3.0])
    events = np.array([False])
    surv = np.array([[0.2, 0.1]])
    assert rcll(surv, times, durations, events) == pytest.approx(0.0, abs=1e-12)


def test_clamp_prevents_inf():
    """Zero predicted mass in the true bin is clamped to 1e-12, giving a large
    but finite penalty (-log(1e-12)), not inf."""
    times = np.array([1.0, 2.0])
    durations = np.array([0.5])
    events = np.array([True])
    surv = np.array([[1.0, 1.0]])  # mass in bin 1 = 1 - 1 = 0 -> clamp
    score = rcll(surv, times, durations, events)
    assert math.isfinite(score)
    assert score == pytest.approx(-math.log(1e-12), rel=1e-9)


def test_skill_positive_when_model_beats_km():
    """rcll_skill > 0 on an easy separable case: a sharp model that nails each
    event's bin beats the marginal-KM null (which only knows the base rate)."""
    rng = np.random.default_rng(0)
    n = 200
    times = np.array([1.0, 2.0, 3.0, 4.0])
    # half the subjects event in bin 1, half in bin 4 -- cleanly separable
    early = rng.random(n) < 0.5
    durations = np.where(early, 1.0, 4.0)
    events = np.ones(n, dtype=bool)

    # sharp model: step down at the subject's true bin
    surv_model = np.empty((n, len(times)))
    surv_model[early] = np.array([0.0, 0.0, 0.0, 0.0])     # event in bin 1
    surv_model[~early] = np.array([1.0, 1.0, 1.0, 0.0])    # event in bin 4

    # marginal KM at the grid (50% event in bin1, 50% in bin4):
    # S(1)=0.5, S(2)=0.5, S(3)=0.5, S(4)=0.0
    km_surv = np.array([0.5, 0.5, 0.5, 0.0])

    skill = rcll_skill(surv_model, times, durations, events, km_surv)
    assert skill > 0.0


def test_skill_zero_for_km_itself():
    """Scoring the KM null against itself gives skill == 0 (rcll_model == rcll_km)."""
    times = np.array([1.0, 2.0, 3.0])
    durations = np.array([1.0, 2.0, 3.0])
    events = np.array([True, True, False])
    km_surv = np.array([0.7, 0.4, 0.2])
    surv_model = np.tile(km_surv, (len(durations), 1))
    skill = rcll_skill(surv_model, times, durations, events, km_surv)
    assert skill == pytest.approx(0.0, abs=1e-12)


def test_input_validation():
    """Mismatched shapes raise rather than silently broadcasting."""
    times = np.array([1.0, 2.0])
    durations = np.array([1.0, 2.0])
    events = np.array([True, True])
    bad_surv = np.zeros((2, 3))  # 3 cols vs 2 times
    with pytest.raises(ValueError):
        rcll(bad_surv, times, durations, events)
