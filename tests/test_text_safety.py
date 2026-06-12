import pandas as pd

from temporal_exploit.text_safety import (
    build_safe_descriptions,
    description_is_fresh,
    mask_leakage_terms,
)


def test_mask_leakage_terms():
    text = "Buffer overflow; this CVE is being actively exploited and was added to the CISA KEV catalog."
    masked = mask_leakage_terms(text)
    assert "actively exploited" not in masked.lower()
    assert "cisa" not in masked.lower()
    assert "kev" not in masked.lower()
    assert "Buffer overflow" in masked  # benign text preserved


def test_mask_leakage_terms_non_string_passthrough():
    assert mask_leakage_terms(None) is None


def _corpus():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-2"],
            "published": pd.to_datetime(["2024-01-01", "2024-01-01"], utc=True),
            "last_modified": pd.to_datetime(["2024-01-03", "2024-09-01"], utc=True),
            "description": [
                "SQL injection in the login form.",
                "RCE now actively exploited per CISA.",
            ],
        }
    )


def test_description_is_fresh_window():
    fresh = description_is_fresh(_corpus(), epsilon_days=7)
    assert fresh.tolist() == [True, False]  # CVE-2 edited 8 months later


def test_build_safe_descriptions_masks_and_blanks():
    safe = build_safe_descriptions(_corpus(), epsilon_days=7)
    by_id = safe.set_index("cve_id")
    assert by_id.loc["CVE-1", "safe_description"] == "SQL injection in the login form."
    assert by_id.loc["CVE-1", "description_fresh"]
    # back-edited row is blanked entirely (its text post-dates the event)
    assert by_id.loc["CVE-2", "safe_description"] == ""
    assert not by_id.loc["CVE-2", "description_fresh"]
