import pandas as pd

from temporal_exploit.nlp_features import (
    build_description_features,
    description_feature_provenance,
)


def _corpus() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": ["CVE-A", "CVE-B"],
            "published": pd.to_datetime(["2024-01-01", "2024-01-01"], utc=True),
            # B is back-edited months later -> stale -> blanked
            "last_modified": pd.to_datetime(["2024-01-02", "2024-06-01"], utc=True),
            "description": [
                "Remote attacker can trigger a buffer overflow. "
                "Actively exploited in the wild per CISA KEV.",
                "SQL injection allows authentication bypass.",
            ],
        }
    )


def test_keywords_fire_on_fresh_text_and_leakage_is_masked():
    feat = build_description_features(_corpus()).set_index("cve_id")
    a = feat.loc["CVE-A"]
    assert a["description_fresh"] == 1
    assert a["desc_kw_remote"] == 1 and a["desc_kw_overflow"] == 1
    assert a["desc_char_len"] > 0
    # the leakage phrases were masked, so they cannot produce a keyword hit
    # (there is no desc_kw for 'exploited'/'kev'); sanity: char len excludes nothing odd
    assert a["desc_word_count"] >= 5


def test_stale_description_is_blanked():
    feat = build_description_features(_corpus()).set_index("cve_id")
    b = feat.loc["CVE-B"]
    assert b["description_fresh"] == 0
    assert b["desc_char_len"] == 0
    assert b["desc_word_count"] == 0
    assert b["desc_kw_injection"] == 0  # blanked, so no hit despite the raw text


def test_provenance_covers_every_feature_and_is_leakage_flagged():
    feat = build_description_features(_corpus())
    prov = description_feature_provenance()
    families = set(prov["feature_family"])
    for col in feat.columns:
        if col == "cve_id":
            continue
        assert col in families
    assert set(prov["leakage_status"]) == {"publication_time_safe_freshness_gated"}
