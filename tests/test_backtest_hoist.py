"""Task 4 of the speed bundle: hoisted feature validation + prepared-frame parity.

validate_feature_matrix is the one-shot NaN guard hoisted out of the per-origin
backtest loop; the features_validated flag must not change prepare_modeling_frame
output in any way (only skip the redundant scan).
"""
import numpy as np
import pandas as pd
import pytest

from temporal_exploit.modeling import prepare_modeling_frame, validate_feature_matrix


def _labels():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
        "published": pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01"], utc=True),
        "duration_days": [10.0, 20.0, 30.0],
        "event_observed": [1, 0, 1],
        "negative_duration_flag": [False, False, False],
    })


def _features(nan=False):
    f = pd.DataFrame({"cve_id": ["CVE-1", "CVE-2", "CVE-3"], "x": [1.0, 2.0, 3.0]})
    if nan:
        f.loc[1, "x"] = np.nan
    return f


def test_validate_feature_matrix_names_culprit():
    validate_feature_matrix(_features())          # clean -> no raise
    with pytest.raises(ValueError, match="x"):
        validate_feature_matrix(_features(nan=True))


def test_prepared_frame_identical_with_skip_flag():
    pd.testing.assert_frame_equal(
        prepare_modeling_frame(_labels(), _features()),
        prepare_modeling_frame(_labels(), _features(), features_validated=True),
    )


def test_skip_flag_does_not_mask_label_side_guarantees():
    # the flag only skips the FEATURE NaN scan; merge/filter/downcast unchanged
    out = prepare_modeling_frame(_labels(), _features(), features_validated=True)
    assert list(out["cve_id"]) == ["CVE-1", "CVE-2", "CVE-3"]
    assert out["duration_days"].tolist() == [10.0, 20.0, 30.0]
