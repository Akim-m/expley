import pandas as pd

from temporal_exploit.incentive_features import (
    build_incentive_features,
    incentive_feature_provenance,
)


def test_build_incentive_features():
    corpus = pd.DataFrame(
        {
            "cve_id": ["A", "B", "C"],
            "cvss_v3_vector": [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # wormable + high impact
                "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:L",  # local, scope-changed, low impact
                None,  # missing vector
            ],
        }
    )
    f = build_incentive_features(corpus).set_index("cve_id")

    # A: network + unauth + no-UI + low-complexity + high-impact -> wormable
    assert f.loc["A", "incentive_network"] == 1
    assert f.loc["A", "incentive_unauth"] == 1
    assert f.loc["A", "incentive_high_impact"] == 1
    assert f.loc["A", "incentive_wormable"] == 1
    assert f.loc["A", "incentive_unauth_network_high_impact"] == 1
    assert f.loc["A", "incentive_scope_changed"] == 0

    # B: local + needs privs + UI + low impact -> not wormable; scope changed
    assert f.loc["B", "incentive_network"] == 0
    assert f.loc["B", "incentive_wormable"] == 0
    assert f.loc["B", "incentive_high_impact"] == 0
    assert f.loc["B", "incentive_scope_changed"] == 1

    # C: missing vector -> all flags 0, missing indicator 1
    assert f.loc["C", "incentive_cvss_vector_missing"] == 1
    assert f.loc["C", "incentive_wormable"] == 0
    assert f.loc["C", "incentive_high_impact"] == 0


def test_handles_missing_cvss_vector_column():
    # some corpora (tiny fixtures) have no cvss_v3_vector -> flags 0, missing=1
    f = build_incentive_features(pd.DataFrame({"cve_id": ["A"]})).set_index("cve_id")
    assert f.loc["A", "incentive_wormable"] == 0
    assert f.loc["A", "incentive_high_impact"] == 0
    assert f.loc["A", "incentive_cvss_vector_missing"] == 1


def test_provenance_covers_every_emitted_column():
    corpus = pd.DataFrame({"cve_id": ["A"], "cvss_v3_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]})
    feats = build_incentive_features(corpus)
    prov = incentive_feature_provenance()
    assert set(prov["leakage_status"]) == {"publication_time_safe"}
    families = set(prov["feature_family"])
    for col in feats.columns:
        if col != "cve_id":
            assert col in families
