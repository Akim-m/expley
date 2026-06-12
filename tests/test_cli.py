import json

import pandas as pd
import pytest

from temporal_exploit.cli import build_dataset_command, main
from temporal_exploit.fetch import kev
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

    per_signal = pd.read_parquet(artifact_dir / "per_signal_labels.parquet")
    competing = pd.read_parquet(artifact_dir / "competing_risks_labels.parquet")
    assert set(per_signal["cve_id"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert "cause_code" in competing.columns
    assert manifest["per_signal_rows"] == 2
    assert manifest["competing_risks_rows"] == 2
    assert manifest["attack_features_enabled"] is False
    assert manifest["epss_features_enabled"] is False


def test_build_dataset_enriches_with_attack(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)
    chain_path = tmp_path / "technique_cwe_chain.parquet"
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0001"],
            "technique_id": ["T1059", "T1059.001"],
        }
    ).to_parquet(chain_path)

    build_dataset_command(
        out_dir, artifact_dir, snapshot_date="2024-03-01", technique_chain=chain_path
    )

    features = pd.read_parquet(artifact_dir / "publication_features.parquet")
    provenance = pd.read_csv(artifact_dir / "feature_provenance.csv")
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert "has_attack_chain_mapping" in features.columns
    assert (provenance["source"].str.startswith("technique_cwe_chain")).any()
    assert manifest["attack_features_enabled"] is True


def test_build_dataset_enriches_with_epss(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)
    epss_path = tmp_path / "epss_history.parquet"
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "date": pd.to_datetime(["2024-01-05"], utc=True),
            "epss": [0.42],
            "percentile": [0.9],
        }
    ).to_parquet(epss_path)

    build_dataset_command(
        out_dir, artifact_dir, snapshot_date="2024-03-01", epss_path=epss_path
    )

    features = pd.read_parquet(artifact_dir / "publication_features.parquet")
    provenance = pd.read_csv(artifact_dir / "feature_provenance.csv")
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert "epss_at_publication" in features.columns
    assert (provenance["source"].str.startswith("epss_history")).any()
    assert manifest["epss_features_enabled"] is True


def test_build_dataset_writes_presence_snapshot(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "in_metasploit": [True],
            "in_nuclei": [False],
            "in_vulncheck_kev": [True],
            "in_google_zeroday": [False],
        }
    ).to_parquet(out_dir / "vrs_presence.parquet")

    build_dataset_command(out_dir, artifact_dir, snapshot_date="2024-03-01")

    presence = pd.read_parquet(artifact_dir / "presence_snapshot.parquet")
    for flag in ["in_metasploit", "in_nuclei", "in_vulncheck_kev", "in_google_zeroday"]:
        assert flag in presence.columns
    provenance = pd.read_csv(artifact_dir / "feature_provenance.csv")
    assert (provenance["leakage_status"] == "snapshot_leakage").any()

    features = pd.read_parquet(artifact_dir / "publication_features.parquet")
    assert "in_metasploit" not in features.columns

    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert manifest["presence_available"] is True
    assert manifest["presence_rows"] == 1


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
    chain_path = tmp_path / "technique_cwe_chain.parquet"
    pd.DataFrame(
        {"cve_id": ["CVE-2024-0001"], "technique_id": ["T1059"]}
    ).to_parquet(chain_path)
    epss_path = tmp_path / "epss_history.parquet"
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "date": pd.to_datetime(["2024-01-05"], utc=True),
            "epss": [0.42],
            "percentile": [0.9],
        }
    ).to_parquet(epss_path)
    main(
        [
            "build-dataset",
            "--out-dir", str(out_dir),
            "--artifact-dir", str(artifact_dir),
            "--snapshot-date", "2024-03-01",
            "--technique-chain", str(chain_path),
            "--epss-path", str(epss_path),
        ]
    )
    assert (artifact_dir / "manifest.json").exists()


def test_main_fetch_kev(tmp_path, monkeypatch):
    monkeypatch.setattr(
        kev,
        "_fetch_json",
        lambda url: {
            "vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-20"}]
        },
    )
    main(["fetch", "--source", "kev", "--live-dir", str(tmp_path)])

    assert (tmp_path / "kev_events.parquet").exists()
    manifest = json.loads((tmp_path / "fetch_manifest.json").read_text())
    assert manifest["entries"][0]["source"] == "kev_events"
    assert manifest["entries"][0]["row_count"] == 1


def test_main_fetch_epss_requires_date(tmp_path):
    with pytest.raises(ValueError, match="--date"):
        main(["fetch", "--source", "epss", "--live-dir", str(tmp_path)])
