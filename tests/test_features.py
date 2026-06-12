import numpy as np
import pandas as pd
import pytest

from temporal_exploit.features import (
    build_publication_features,
    feature_provenance,
    has_list_value,
    list_len,
)


def test_list_len_handles_lists_tuples_and_missing_values() -> None:
    assert list_len(["CWE-79"]) == 1
    assert list_len(("apache", "httpd")) == 2
    assert list_len(None) == 0
    assert list_len("not-a-list") == 0


def test_has_list_value_flags_only_non_empty_lists_and_tuples() -> None:
    assert has_list_value(["CWE-79"]) == 1
    assert has_list_value(("apache",)) == 1
    assert has_list_value([]) == 0
    assert has_list_value(None) == 0


def test_list_len_handles_numpy_arrays():
    assert list_len(np.array(["CWE-79", "CWE-89"])) == 2
    assert has_list_value(np.array(["CWE-79"])) == 1
    assert list_len(np.array([])) == 0


def test_top_k_cwe_one_hot():
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "published": ["2024-01-01", "2024-02-01", "2024-03-01"],
            "cvss_v3_base": [9.8, 5.0, 7.5],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM", "HIGH"],
            "cwe_ids": [
                np.array(["CWE-79", "CWE-89"]),
                np.array(["CWE-79"]),
                np.array([]),
            ],
            "vendors": [["apache"], [], []],
            "products": [["httpd"], [], []],
        }
    )
    features = build_publication_features(corpus, top_k_cwes=1)
    assert features["cwe_CWE-79"].tolist() == [1, 1, 0]
    assert "cwe_CWE-89" not in features.columns  # below top-k


def test_cvss_vector_component_one_hots():
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "published": ["2024-01-01", "2024-02-01", "2024-03-01"],
            "cvss_v3_base": [9.8, 5.0, None],
            "cvss_v3_severity": ["CRITICAL", "MEDIUM", None],
            "cvss_v3_vector": [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N",
                None,
            ],
            "cwe_ids": [[], [], []],
            "vendors": [[], [], []],
            "products": [[], [], []],
        }
    )
    features = build_publication_features(corpus)
    assert features["cvss_av_N"].tolist() == [1, 0, 0]
    assert features["cvss_av_L"].tolist() == [0, 1, 0]
    assert features["cvss_ac_L"].tolist() == [1, 0, 0]
    assert features["cvss_pr_N"].tolist() == [1, 0, 0]
    assert features["cvss_ui_N"].tolist() == [1, 0, 0]
    assert features["cvss_s_C"].tolist() == [0, 1, 0]
    # no-vector row contributes zeros everywhere (cvss_v3_missing already flags it)


def test_features_require_real_corpus_columns():
    corpus = pd.DataFrame({"cve_id": ["CVE-2024-0001"], "published": ["2024-01-01"]})
    with pytest.raises(ValueError, match="cvss_v3_base"):
        build_publication_features(corpus)


def test_features_flag_missing_cvss():
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "published": ["2024-01-01", "2024-02-01"],
            "cvss_v3_base": [9.8, None],
            "cvss_v3_severity": ["CRITICAL", None],
            "cwe_ids": [["CWE-79"], []],
            "vendors": [["apache"], []],
            "products": [["httpd"], []],
        }
    )
    features = build_publication_features(corpus)
    assert features["cvss_v3_missing"].tolist() == [0, 1]
    assert features["cvss_v3_base"].tolist() == [9.8, 0.0]


def test_build_publication_features_excludes_known_leaky_columns() -> None:
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published": ["2024-01-01"],
            "description": ["CISA added this actively exploited issue to KEV"],
            "cvss_v3_base": [9.8],
            "cvss_v3_severity": ["CRITICAL"],
            "cwe_ids": [["CWE-79"]],
            "vendors": [["apache"]],
            "products": [["httpd"]],
        }
    )

    features = build_publication_features(corpus)

    assert "description" not in features.columns
    assert "cvss_v3_base" in features.columns
    assert "severity_CRITICAL" in features.columns
    assert "has_weakness" in features.columns
    assert features.loc[0, "weakness_count"] == 1
    assert features.loc[0, "vendor_count"] == 1
    assert features.loc[0, "product_count"] == 1


def test_build_publication_features_handles_missing_lists() -> None:
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0002"],
            "published": ["2024-02-01"],
            "cvss_v3_base": [None],
            "cvss_v3_severity": [None],
            "cwe_ids": [None],
            "vendors": [None],
            "products": [None],
        }
    )

    features = build_publication_features(corpus)

    assert features.loc[0, "has_weakness"] == 0
    assert features.loc[0, "vendor_count"] == 0
    assert features.loc[0, "product_count"] == 0


def test_feature_provenance_documents_safe_feature_families() -> None:
    provenance = feature_provenance()

    assert set(provenance.columns) == {"feature_family", "source", "leakage_status", "notes"}
    assert "cvss_v3_base" in provenance["feature_family"].tolist()
    assert "cvss_v3_missing" in provenance["feature_family"].tolist()
    assert set(provenance["leakage_status"]) == {"publication_time_safe"}
