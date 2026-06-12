import pandas as pd
from pandas.api.types import is_integer_dtype

from temporal_exploit.presence_features import (
    build_presence_features,
    presence_feature_provenance,
)

FLAGS = ["in_metasploit", "in_nuclei", "in_vulncheck_kev", "in_google_zeroday"]


def _presence() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "in_metasploit": [True],
            "in_nuclei": [False],
            "in_vulncheck_kev": [True],
            "in_google_zeroday": [False],
        }
    )


def _corpus() -> pd.DataFrame:
    return pd.DataFrame({"cve_id": ["CVE-2024-0001", "CVE-2024-0002"]})


def test_one_row_per_corpus_cve() -> None:
    features = build_presence_features(_corpus(), _presence())
    assert features["cve_id"].tolist() == ["CVE-2024-0001", "CVE-2024-0002"]


def test_flags_mapped_for_present_cve() -> None:
    features = build_presence_features(_corpus(), _presence()).set_index("cve_id")
    assert features.loc["CVE-2024-0001", FLAGS].tolist() == [1, 0, 1, 0]


def test_absent_cve_all_zero() -> None:
    features = build_presence_features(_corpus(), _presence()).set_index("cve_id")
    assert features.loc["CVE-2024-0002", FLAGS].tolist() == [0, 0, 0, 0]


def test_flag_columns_are_int() -> None:
    features = build_presence_features(_corpus(), _presence())
    for flag in FLAGS:
        assert is_integer_dtype(features[flag])


def test_provenance_marks_every_flag_as_snapshot_leakage() -> None:
    provenance = presence_feature_provenance()
    assert set(provenance.columns) == {"feature_family", "source", "leakage_status", "notes"}
    assert set(provenance["feature_family"]) == set(FLAGS)
    assert set(provenance["leakage_status"]) == {"snapshot_leakage"}
