import pandas as pd
import pytest

from temporal_exploit.schema import REQUIRED_COLUMNS, validate_columns


def test_validate_columns_accepts_valid_minimal_corpus() -> None:
    frame = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published": ["2024-01-01"],
        }
    )

    validate_columns(frame, "cve_corpus", REQUIRED_COLUMNS["cve_corpus"])


def test_validate_columns_raises_clear_error_for_missing_columns() -> None:
    frame = pd.DataFrame({"cve_id": ["CVE-2024-0001"]})

    with pytest.raises(ValueError, match="cve_corpus missing required columns: published"):
        validate_columns(frame, "cve_corpus", REQUIRED_COLUMNS["cve_corpus"])


def test_required_columns_match_real_handover_names():
    assert REQUIRED_COLUMNS["kev_events"] == ("cve_id", "kev_date_added")
    assert REQUIRED_COLUMNS["google_0day"] == ("cve_id", "zeroday_date_discovered")
