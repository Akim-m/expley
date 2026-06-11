import json

import pandas as pd

from temporal_exploit.cli import build_dataset_command
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
