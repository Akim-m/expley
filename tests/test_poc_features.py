import pandas as pd

from temporal_exploit.poc_features import build_poc_features, poc_feature_provenance


def _corpus() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
            "published": pd.to_datetime(
                ["2024-01-01", "2024-02-01", "2024-03-01"], utc=True
            ),
        }
    )


def _poc_dates() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002"],
            "poc_source": ["github", "exploitdb", "github"],
            "poc_first_seen": pd.to_datetime(
                ["2024-01-11", "2024-01-06", "2024-02-03"], utc=True
            ),
            "poc_path": ["poc/exploit.py", "docs/README.MD", "tools/scan"],
        }
    )


def test_counts_and_lag_for_cve_with_multiple_pocs() -> None:
    features = build_poc_features(_corpus(), _poc_dates())
    row = features.set_index("cve_id").loc["CVE-2024-0001"]
    assert row["poc_count"] == 2
    assert row["poc_source_count"] == 2
    assert row["poc_first_lag_days"] == 5.0
    assert row["poc_missing"] == 0


def test_single_poc_cve() -> None:
    features = build_poc_features(_corpus(), _poc_dates())
    row = features.set_index("cve_id").loc["CVE-2024-0002"]
    assert row["poc_count"] == 1
    assert row["poc_source_count"] == 1
    assert row["poc_first_lag_days"] == 2.0
    assert row["poc_missing"] == 0


def test_cve_without_poc_is_flagged_missing() -> None:
    features = build_poc_features(_corpus(), _poc_dates())
    row = features.set_index("cve_id").loc["CVE-2024-0003"]
    assert row["poc_count"] == 0
    assert row["poc_source_count"] == 0
    assert row["poc_first_lag_days"] == -1.0
    assert row["poc_missing"] == 1


def test_one_row_per_corpus_cve_in_corpus_order() -> None:
    features = build_poc_features(_corpus(), _poc_dates())
    assert features["cve_id"].tolist() == [
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2024-0003",
    ]


def test_extension_one_hot_lowercased_with_none_for_missing_suffix() -> None:
    features = build_poc_features(_corpus(), _poc_dates())
    indexed = features.set_index("cve_id")
    assert indexed.loc["CVE-2024-0001", "poc_ext_py"] == 1
    assert indexed.loc["CVE-2024-0001", "poc_ext_md"] == 1
    assert indexed.loc["CVE-2024-0001", "poc_ext_none"] == 0
    assert indexed.loc["CVE-2024-0002", "poc_ext_none"] == 1
    assert indexed.loc["CVE-2024-0002", "poc_ext_py"] == 0
    assert indexed.loc["CVE-2024-0003", "poc_ext_py"] == 0


def test_top_k_extension_ranking_is_deterministic() -> None:
    # all three extensions appear once; ties break by name ascending.
    features = build_poc_features(_corpus(), _poc_dates(), top_k_exts=2)
    ext_columns = [c for c in features.columns if c.startswith("poc_ext_")]
    assert ext_columns == ["poc_ext_md", "poc_ext_none"]


def test_provenance_covers_every_emitted_feature_family() -> None:
    features = build_poc_features(_corpus(), _poc_dates())
    provenance = poc_feature_provenance()

    assert set(provenance.columns) == {"feature_family", "source", "leakage_status", "notes"}
    assert set(provenance["leakage_status"]) == {"transition_safe_post_poc"}
    assert provenance["notes"].str.contains("label leakage").all()

    families = set(provenance["feature_family"])
    for column in features.columns:
        if column == "cve_id":
            continue
        family = "poc_ext_*" if column.startswith("poc_ext_") else column
        assert family in families
