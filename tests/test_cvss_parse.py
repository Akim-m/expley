"""Task 1-2 of the speed bundle: vectorized CVSS parse + CWE membership.

The vectorized paths must reproduce the old per-row dict/set semantics exactly
(bit-identical publication_features) — pinned here on the tricky cases:
missing vector, malformed vector, duplicate keys, 'S' vs the 'CVSS:' prefix,
and per-CVE duplicate CWEs.
"""
import numpy as np
import pandas as pd

from temporal_exploit.features import build_publication_features, parse_cvss_vectors
from temporal_exploit.incentive_features import build_incentive_features


def _corpus():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
        "published": pd.to_datetime(["2024-01-01"] * 4, utc=True),
        "cvss_v3_base": [9.8, 5.0, None, 7.5],
        "cvss_v3_severity": ["CRITICAL", "MEDIUM", None, "HIGH"],
        "cvss_v3_vector": [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N",
            None,                                   # missing vector
            "AV:P/AV:N/AC:L",                       # malformed + duplicate key
        ],
        "cwe_ids": [np.array(["CWE-79"]), np.array([]), None, np.array(["CWE-89", "CWE-79"])],
        "vendors": [np.array(["a"]), np.array([]), None, np.array(["b", "c"])],
        "products": [np.array(["p"]), np.array([]), None, np.array(["q"])],
    })


def test_parse_cvss_vectors_matches_dict_semantics():
    parsed = parse_cvss_vectors(_corpus()["cvss_v3_vector"])
    assert list(parsed.columns) == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert parsed.loc[0, "AV"] == "N" and parsed.loc[0, "S"] == "U"
    assert parsed.loc[1, "UI"] == "R"
    assert all(v is None for v in parsed.loc[2])
    assert parsed.loc[3, "AV"] == "N"          # duplicate key: LAST wins
    assert parsed.loc[3, "PR"] is None          # absent key -> None
    # 'S' must not match the 'SS' inside the 'CVSS:3.1' prefix
    assert parsed.loc[0, "S"] == "U" and parsed.loc[1, "S"] == "C"


def test_builders_identical_with_and_without_preparse():
    corpus = _corpus()
    parsed = parse_cvss_vectors(corpus["cvss_v3_vector"])
    pd.testing.assert_frame_equal(
        build_publication_features(corpus),
        build_publication_features(corpus, parsed_vectors=parsed),
    )
    pd.testing.assert_frame_equal(
        build_incentive_features(corpus),
        build_incentive_features(corpus, parsed_vectors=parsed),
    )


def test_incentive_values_unchanged():
    feats = build_incentive_features(_corpus())
    assert feats.loc[0, "incentive_wormable"] == 1
    assert feats.loc[1, "incentive_wormable"] == 0
    assert feats.loc[2, "incentive_cvss_vector_missing"] == 1
    assert feats.loc[3, "incentive_network"] == 1   # AV last-occurrence = N


def test_cwe_topk_columns_and_values():
    corpus = _corpus()
    feats = build_publication_features(corpus, top_k_cwes=2)
    # frequency ranking with (-count, name) tie-break: CWE-79 (2) then CWE-89 (1)
    cwe_cols = [c for c in feats.columns if c.startswith("cwe_")]
    assert cwe_cols == ["cwe_CWE-79", "cwe_CWE-89"]
    assert feats["cwe_CWE-79"].tolist() == [1, 0, 0, 1]
    assert feats["cwe_CWE-89"].tolist() == [0, 0, 0, 1]
    # duplicate CWE within one CVE counts once (set semantics)
    dup = corpus.copy()
    dup.at[0, "cwe_ids"] = np.array(["CWE-79", "CWE-79"])
    feats_dup = build_publication_features(dup, top_k_cwes=2)
    assert feats_dup["cwe_CWE-79"].tolist() == [1, 0, 0, 1]
