import json

import pandas as pd

from temporal_exploit.cli import build_dataset_command, main
from tests.fixtures.tiny_parquets import write_tiny_handover


def test_build_dataset_writes_artifacts(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)

    build_dataset_command(out_dir, artifact_dir, snapshot_date="2024-03-01")

    labels = pd.read_parquet(artifact_dir / "modeling_labels.parquet")
    features = pd.read_parquet(artifact_dir / "publication_features.parquet")
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert set(labels["cve_id"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert "cvss_v3_base" in features.columns
    assert manifest["snapshot_date"] == "2024-03-01"
    assert manifest["event_source_rows"]["poc"] == 1
    assert manifest["event_source_rows"]["kev"] == 1
    assert (artifact_dir / "feature_provenance.csv").exists()


def test_build_dataset_writes_splits_when_cutoff_given(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)

    build_dataset_command(
        out_dir, artifact_dir, snapshot_date="2024-03-01", cutoff_date="2024-01-15"
    )

    assert (artifact_dir / "train_cve_ids.txt").exists()
    assert (artifact_dir / "test_cve_ids.txt").exists()
    assert (artifact_dir / "split_metadata.json").exists()


def test_main_build_dataset_smoke(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)
    main(
        [
            "build-dataset",
            "--out-dir", str(out_dir),
            "--artifact-dir", str(artifact_dir),
            "--snapshot-date", "2024-03-01",
        ]
    )
    assert (artifact_dir / "manifest.json").exists()
