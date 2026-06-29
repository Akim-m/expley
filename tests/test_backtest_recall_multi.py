import numpy as np
import pandas as pd

from temporal_exploit.backtest import operational_metrics


def test_recall_at_top_by_frac_matches_known_ranking():
    # 10 CVEs ranked by risk = index (9 = highest). The 3 true events sit at the
    # very top of the ranking (indices 7,8,9), each weaponizing within 30 days.
    risk = np.arange(10, dtype=float)
    dur = np.array([100, 100, 100, 100, 100, 100, 100, 5, 5, 5], dtype=float)
    obs = np.array([0, 0, 0, 0, 0, 0, 0, 1, 1, 1], dtype=bool)
    frame = pd.DataFrame({"duration_days": dur, "event_observed": obs})

    out = operational_metrics(risk, frame, horizons=[30], top_fracs=(0.1, 0.3))

    # top-10% = 1 flagged CVE (index 9, an event) -> caught 1 of 3 events
    assert out["recall_at_top_by_frac"]["0.1"]["30"] == 1 / 3
    # top-30% = 3 flagged CVEs (indices 7,8,9 = all 3 events) -> caught 3 of 3
    assert out["recall_at_top_by_frac"]["0.3"]["30"] == 1.0
    # back-compat: the single-frac recall_at_top (default 0.1) is unchanged
    assert out["recall_at_top"]["30"] == 1 / 3
