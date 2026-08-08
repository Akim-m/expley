import numpy as np
import pandas as pd
import pytest

from temporal_exploit import interval_censored as ic


def test_bin_index_places_duration_in_half_open_bin():
    edges = (0.0, 7.0, 30.0, 90.0, float("inf"))
    assert ic.bin_index(45.0, edges) == 2      # 30 < 45 <= 90 -> bin 2
    assert ic.bin_index(7.0, edges) == 0       # 0 < 7 <= 7   -> bin 0 (right-closed)
    assert ic.bin_index(7.5, edges) == 1       # 7 < 7.5 <= 30 -> bin 1
    assert ic.bin_index(200.0, edges) == 3     # 90 < 200      -> bin 3 (inf)


def test_expand_person_period_event_and_censored():
    edges = (0.0, 7.0, 30.0, 90.0, float("inf"))
    durations = np.array([45.0, 200.0])       # subject 0 event in bin 2, subject 1 censored bin 3
    events = np.array([1, 0])
    features = pd.DataFrame({"cvss": [9.8, 5.0]})
    long = ic.expand_person_period(durations, events, features, edges)
    s0 = long[long["cvss"] == 9.8].sort_values("bin_idx")
    assert list(s0["bin_idx"]) == [0, 1, 2]
    assert list(s0["y"]) == [0, 0, 1]         # event only in its containing bin
    s1 = long[long["cvss"] == 5.0].sort_values("bin_idx")
    assert list(s1["bin_idx"]) == [0, 1, 2, 3]
    assert list(s1["y"]) == [0, 0, 0, 0]      # censored -> never fires


def test_expand_person_period_rejects_nonpositive_duration():
    edges = (0.0, 7.0, 30.0, float("inf"))
    features = pd.DataFrame({"cvss": [9.8]})
    with pytest.raises(ValueError):
        ic.expand_person_period(np.array([0.0]), np.array([1]), features, edges)
    with pytest.raises(ValueError):
        ic.expand_person_period(np.array([-5.0]), np.array([1]), features, edges)


def test_horizon_bins_pinned():
    assert ic.HORIZON_BINS == (0.0, 7.0, 30.0, 90.0, 180.0, 365.0, 730.0, float("inf"))


def test_discrete_time_recovers_hazard_and_is_monotone():
    # Two bins, feature-free: bin 0 hazard ~0.1, bin 1 hazard ~0.5 by construction.
    edges = (0.0, 10.0, 20.0, float("inf"))
    rng = np.random.default_rng(0)
    n = 4000
    # everyone at risk through bin 0; 10% event in bin0, of survivors 50% in bin1
    dur, ev = [], []
    for _ in range(n):
        if rng.random() < 0.1:
            dur.append(5.0); ev.append(1)                 # event bin 0
        elif rng.random() < 0.5:
            dur.append(15.0); ev.append(1)                # event bin 1
        else:
            dur.append(25.0); ev.append(0)                # censored bin 2
    features = pd.DataFrame({"x": np.zeros(n)})
    m = ic.fit_discrete_time(np.array(dur), np.array(ev), features, edges)
    S = m.survival_at(pd.DataFrame({"x": [0.0]}), horizons=(10.0, 20.0))[0]
    assert 0.0 <= S[1] <= S[0] <= 1.0                     # monotone non-increasing
    assert abs(S[0] - 0.9) < 0.05                          # S(10) ~ 1-0.1
    r = m.risk_scores(pd.DataFrame({"x": [0.0]}))
    assert 0.0 <= r[0] <= 1.0
