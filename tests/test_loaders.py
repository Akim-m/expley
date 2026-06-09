from pathlib import Path

import pytest

from temporal_exploit.loaders import load_parquet, load_required_parquets
from tests.fixtures.tiny_parquets import write_tiny_handover


def test_load_parquet_reads_named_file(tmp_path: Path) -> None:
    write_tiny_handover(tmp_path)

    df = load_parquet(tmp_path, "cve_corpus")

    assert df["cve_id"].tolist() == ["CVE-2024-0001", "CVE-2024-0002"]


def test_load_parquet_raises_clear_error_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Missing parquet"):
        load_parquet(tmp_path, "cve_corpus")


def test_load_required_parquets_returns_mapping(tmp_path: Path) -> None:
    write_tiny_handover(tmp_path)

    frames = load_required_parquets(tmp_path, ["cve_corpus", "kev_events"])

    assert list(frames) == ["cve_corpus", "kev_events"]
