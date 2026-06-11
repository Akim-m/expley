import json

import pandas as pd

from temporal_exploit.splits import make_time_split, write_time_split


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


def test_write_time_split_persists_ids_and_metadata(tmp_path):
    split = make_time_split(_labels(), cutoff_date="2024-06-01")
    write_time_split(split, tmp_path)
    train_ids = (tmp_path / "train_cve_ids.txt").read_text().splitlines()
    test_ids = (tmp_path / "test_cve_ids.txt").read_text().splitlines()
    metadata = json.loads((tmp_path / "split_metadata.json").read_text())
    assert train_ids == ["CVE-2024-0001", "CVE-2024-0002"]
    assert test_ids == ["CVE-2024-0003"]
    assert metadata == {"cutoff_date": "2024-06-01", "test_count": 1, "train_count": 2}
