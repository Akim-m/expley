"""D3 gated hill-climb — pure search logic (no backtests, no models).

The loop is separated from the evaluator (autoresearch's structure): the greedy
forward-selection + significance accept-gate are pure functions driven by
injected `evaluate`/`paired_delta` callbacks, so they test in milliseconds.
"""
from temporal_exploit.hillclimb import (
    feature_groups,
    greedy_forward_select,
    is_significant_gain,
    select_columns,
)


def test_feature_groups_partitions_publication_columns():
    cols = ["cve_id", "published", "epss_at_publication", "epss_at_publication_missing",
            "cvss_v3_base", "cvss_av_N", "severity_HIGH", "cwe_79", "attack_T1190",
            "incentive_ransomware", "vendor_apache", "product_httpd", "has_cpe", "weakness_count"]
    g = feature_groups(cols)
    assert set(g["epss"]) == {"epss_at_publication", "epss_at_publication_missing"}
    assert "cvss_v3_base" in g["cvss"] and "cvss_av_N" in g["cvss"]
    assert g["severity"] == ["severity_HIGH"]
    assert "vendor_apache" in g["cpe"] and "product_httpd" in g["cpe"]
    # meta columns are never a feature group
    assert "cve_id" not in sum(g.values(), [])
    assert "published" not in sum(g.values(), [])


def test_select_columns_unions_groups_and_keeps_cve_id():
    groups = {"epss": ["epss_at_publication"], "cvss": ["cvss_v3_base", "cvss_av_N"]}
    cols = select_columns(["epss", "cvss"], groups)
    assert cols[0] == "cve_id"  # always carries the merge key
    assert set(cols) == {"cve_id", "epss_at_publication", "cvss_v3_base", "cvss_av_N"}


def test_is_significant_gain_requires_ci_above_zero():
    assert is_significant_gain({"mean_delta": 0.03, "ci95": [0.01, 0.05]})
    assert not is_significant_gain({"mean_delta": 0.03, "ci95": [-0.01, 0.07]})  # CI straddles 0
    assert not is_significant_gain({"mean_delta": -0.02, "ci95": [-0.05, -0.01]})  # significant but negative
    assert not is_significant_gain({"mean_delta": 0.03, "ci95": None})  # too few origins


def test_greedy_forward_select_accepts_good_group_then_plateaus():
    # synthetic world: only adding "good" yields a significant positive delta;
    # every other group is noise (CI straddles 0). Hill-climb must accept "good"
    # once and then hard-stop (plateau).
    def evaluate(groups):
        return {"groups": tuple(sorted(groups))}

    def paired_delta(challenger, incumbent):
        added = set(challenger["groups"]) - set(incumbent["groups"])
        if added == {"good"}:
            return {"mean_delta": 0.05, "ci95": [0.02, 0.08], "win_frac": 0.9}
        return {"mean_delta": 0.001, "ci95": [-0.02, 0.02], "win_frac": 0.5}  # noise

    res = greedy_forward_select(
        candidate_groups=["good", "noise1", "noise2"],
        incumbent_groups=["epss"],
        evaluate=evaluate,
        paired_delta=paired_delta,
    )
    assert res["accepted"] == ["good"]
    assert res["plateau"] is True
    # every candidate tried in round 1 is logged
    assert any(t["added"] == "good" and t["accepted"] for t in res["trials"])
    assert any(t["added"] in {"noise1", "noise2"} and not t["accepted"] for t in res["trials"])
