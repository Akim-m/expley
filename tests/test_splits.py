import pandas as pd

from temporal_exploit.splits import make_time_split


def _labels():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0003"],
            "published": pd.to_datetime(["2024-02-01", "2024-01-01", "2024-06-01"], utc=True),
            "event_observed": [True, False, False],
            "duration_days": [10, 60, 30],
        }
    )


def test_time_split_partitions_on_cutoff():
    split = make_time_split(_labels(), cutoff_date="2024-06-01")
    assert split.train["cve_id"].tolist() == ["CVE-2024-0001", "CVE-2024-0002"]
    assert split.test["cve_id"].tolist() == ["CVE-2024-0003"]
