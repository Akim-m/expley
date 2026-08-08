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
