"""D1 downstream-tool tests — the PURE triage decision logic (no I/O, no models).

The heavy model-fitting/loading lives in the CLI command; everything here is a
pure function of arrays so it runs in milliseconds on constructed frames.
"""
import numpy as np
import pandas as pd
import pytest

from temporal_exploit.triage import (
    POC_PRESENT,
    PUBLISHED,
    assign_state,
    build_triage_table,
    operating_points,
    recommended_action,
    tiers,
)


def test_assign_state_truth_table():
    assert assign_state(True) == POC_PRESENT
    assert assign_state(False) == PUBLISHED


def test_tiers_are_monotone_nondecreasing_in_risk():
    risk = np.linspace(0.0, 1.0, 100)
    t = tiers(risk)  # default q=(0.5, 0.9)
    order = {"Low": 0, "Med": 1, "High": 2}
    codes = np.array([order[x] for x in t])
    # higher risk must never map to a lower tier
    assert np.all(np.diff(codes) >= 0)
    # the three tiers must all appear with a spread input
    assert set(t) == {"Low", "Med", "High"}


def test_tiers_quantile_edges():
    # bottom 50% Low, next 40% Med, top 10% High
    risk = np.arange(10, dtype=float)  # quantiles: q50=4.5, q90=8.1
    t = tiers(risk)
    assert t[0] == "Low" and t[4] == "Low"
    assert t[5] == "Med" and t[8] == "Med"
    assert t[9] == "High"


def test_recommended_action_covers_each_branch():
    # POC-present + escalation = the headline action
    a = recommended_action(POC_PRESENT, "High", epss_high=True, fast_tactic=True, escalation_flag=True)
    assert "escalate" in a.lower()
    # POC-present without escalation
    b = recommended_action(POC_PRESENT, "Low", epss_high=False, fast_tactic=False, escalation_flag=False)
    assert "poc" in b.lower() and "escalate" not in b.lower()
    # PUBLISHED high EPSS = first-wave
    c = recommended_action(PUBLISHED, "Low", epss_high=True, fast_tactic=False, escalation_flag=False)
    assert "first wave" in c.lower()
    # PUBLISHED fast tactic (RQ3)
    d = recommended_action(PUBLISHED, "Low", epss_high=False, fast_tactic=True, escalation_flag=False)
    assert "fast" in d.lower() or "prioritize" in d.lower()
    # PUBLISHED high structural tier
    e = recommended_action(PUBLISHED, "High", epss_high=False, fast_tactic=False, escalation_flag=False)
    assert "structural" in e.lower() or "schedule" in e.lower()
    # routine fallback
    f = recommended_action(PUBLISHED, "Low", epss_high=False, fast_tactic=False, escalation_flag=False)
    assert "routine" in f.lower()


def test_build_triage_table_schema_and_no_leaky_columns():
    n = 50
    rng = np.random.default_rng(0)
    meta = pd.DataFrame({
        "cve_id": [f"CVE-2024-{i:04d}" for i in range(n)],
        "published": pd.to_datetime(["2024-01-01"] * n, utc=True),
    })
    structural_risk = rng.uniform(0, 1, n)
    epss = rng.uniform(0, 1, n)
    fast_tactic = rng.integers(0, 2, n).astype(bool)
    has_poc = rng.integers(0, 2, n).astype(bool)
    poc_to_kev = np.where(has_poc, rng.uniform(0, 1, n), np.nan)

    out = build_triage_table(meta, structural_risk, epss, fast_tactic, has_poc, poc_to_kev)

    expected = {
        "cve_id", "published", "state", "epss_at_pub", "structural_risk",
        "structural_tier", "poc_to_kev_risk", "escalation_flag",
        "recommended_action",
    }
    assert expected.issubset(set(out.columns))
    # no leaky snapshot columns leaked into the deliverable
    leaky = {"description", "vrs_presence", "kev_date_added", "epss_at_snapshot"}
    assert not (leaky & set(out.columns))
    # state is consistent with has_poc
    assert (out["state"] == np.where(has_poc, POC_PRESENT, PUBLISHED)).all()
    # escalation only ever fires on POC-present rows
    assert not out.loc[out["state"] == PUBLISHED, "escalation_flag"].any()


def test_fast_tactic_cves_flags_defense_evasion_and_persistence():
    from temporal_exploit.attack_tactics import fast_tactic_cves, tactic_of

    # T1562 = Defense Evasion (fast), T1574 = Persistence (fast), T1083 = Discovery (not)
    assert tactic_of("T1562.001") == "Defense Evasion"
    chain = pd.DataFrame({
        "cve_id": ["CVE-A", "CVE-A", "CVE-B", "CVE-C"],
        "technique_id": ["T1562", "T1083", "T1574.002", "T1083"],
    })
    fast = fast_tactic_cves(chain)
    assert fast == {"CVE-A", "CVE-B"}  # CVE-C is Discovery-only -> not flagged


def test_operating_points_matches_known_ranking():
    # 100 items, the top-10 by risk contain exactly 5 of the 10 positives
    n = 100
    risk = np.arange(n, dtype=float)[::-1]  # index 0 = highest risk
    ev = np.zeros(n, bool)
    dur = np.full(n, 10.0)
    # positives at ranks 0..4 (caught by top-10%) and 50..54 (missed)
    pos = list(range(5)) + list(range(50, 55))
    ev[pos] = True
    res = operating_points(risk, dur, ev, horizon=30, ks=(0.10,))
    assert res["n_pos_within_h"] == 10
    assert res["top_10pct"]["recall"] == pytest.approx(0.5)
    assert res["top_10pct"]["precision"] == pytest.approx(0.5)
