import pandas as pd

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


def test_build_publication_features_excludes_known_leaky_columns() -> None:
    corpus = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published": ["2024-01-01"],
            "description": ["CISA added this actively exploited issue to KEV"],
            "cvss_v3_base_score": [9.8],
            "cvss_v3_severity": ["CRITICAL"],
            "weaknesses": [["CWE-79"]],
            "vendors": [["apache"]],
            "products": [["httpd"]],
        }
    )

    features = build_publication_features(corpus)

    assert "description" not in features.columns
    assert "cvss_v3_base_score" in features.columns
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
            "cvss_v3_base_score": [None],
            "cvss_v3_severity": [None],
            "weaknesses": [None],
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
    assert "cvss_v3_base_score" in provenance["feature_family"].tolist()
    assert set(provenance["leakage_status"]) == {"publication_time_safe"}
