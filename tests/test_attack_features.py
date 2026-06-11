import pandas as pd

from temporal_exploit.attack_features import (
    attack_feature_provenance,
    build_attack_features,
)


def _tiny_chain() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0001"],
            "technique_id": ["T1574.006", "T1574.007", "T1562.003"],
            "technique_name": ["Dylib Hijacking", "Path Interception", "Impair Defenses"],
            "capec_via": ["CAPEC-1", "CAPEC-1", "CAPEC-2"],
            "source": ["chain", "chain", "chain"],
        }
    )


def _corpus() -> pd.DataFrame:
    return pd.DataFrame({"cve_id": ["CVE-2024-0001", "CVE-2024-0002"]})


def test_has_attack_chain_mapping_flags_presence() -> None:
    features = build_attack_features(_corpus(), _tiny_chain())
    assert features["has_attack_chain_mapping"].tolist() == [1, 0]


def test_attack_technique_count_counts_distinct_techniques() -> None:
    features = build_attack_features(_corpus(), _tiny_chain())
    assert features["attack_technique_count"].tolist() == [3, 0]


def test_parent_one_hot_collapses_sub_techniques() -> None:
    features = build_attack_features(_corpus(), _tiny_chain())
    assert features.loc[0, "attack_parent_T1574"] == 1
    assert features.loc[0, "attack_parent_T1562"] == 1
    assert features.loc[1, "attack_parent_T1574"] == 0
    assert features.loc[1, "attack_parent_T1562"] == 0


def test_top_k_parents_limits_and_ranks_deterministically() -> None:
    chain = pd.DataFrame(
        {
            "cve_id": ["A", "A", "B", "C"],
            "technique_id": ["T1001.001", "T1002.001", "T1002.002", "T1003"],
        }
    )
    corpus = pd.DataFrame({"cve_id": ["A", "B", "C"]})
    features = build_attack_features(corpus, chain, top_k_parents=1)
    # T1002 is most frequent (2), kept; T1001 and T1003 dropped.
    assert "attack_parent_T1002" in features.columns
    assert "attack_parent_T1001" not in features.columns
    assert "attack_parent_T1003" not in features.columns


def test_one_row_per_corpus_cve() -> None:
    features = build_attack_features(_corpus(), _tiny_chain())
    assert features["cve_id"].tolist() == ["CVE-2024-0001", "CVE-2024-0002"]


def test_provenance_covers_every_emitted_feature_family() -> None:
    features = build_attack_features(_corpus(), _tiny_chain())
    provenance = attack_feature_provenance()

    assert set(provenance.columns) == {"feature_family", "source", "leakage_status", "notes"}
    assert set(provenance["leakage_status"]) == {"publication_time_safe"}

    families = set(provenance["feature_family"])
    for column in features.columns:
        if column == "cve_id":
            continue
        family = "attack_parent_*" if column.startswith("attack_parent_") else column
        assert family in families
