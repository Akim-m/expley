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
    in_wild = pd.read_parquet(artifact_dir / "in_wild_labels.parquet")
    assert set(per_signal["cve_id"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert "cause_code" in competing.columns
    assert set(in_wild["event_source"]) <= {"kev", "google_0day", "censored"}
    assert manifest["per_signal_rows"] == 2
    assert manifest["competing_risks_rows"] == 2
    assert manifest["in_wild_observed"] == 1
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


def test_main_merge_smoke(tmp_path):
    handover = tmp_path / "handover"
    live = tmp_path / "live"
    out = tmp_path / "unified"
    handover.mkdir()
    live.mkdir()
    pd.DataFrame(
        {"cve_id": ["CVE-1"], "kev_date_added": pd.to_datetime(["2024-02-01"], utc=True)}
    ).to_parquet(handover / "kev_events.parquet", index=False)
    pd.DataFrame(
        {"cve_id": ["CVE-2"], "kev_date_added": pd.to_datetime(["2024-03-01"], utc=True)}
    ).to_parquet(live / "kev_events.parquet", index=False)

    main(
        [
            "merge",
            "--handover-dir", str(handover),
            "--live-dir", str(live),
            "--out-dir", str(out),
        ]
    )

    merged = pd.read_parquet(out / "kev_events.parquet")
    assert set(merged["cve_id"]) == {"CVE-1", "CVE-2"}
    assert (out / "merge_manifest.json").exists()


def _synthetic_artifacts(artifact_dir):
    import numpy as np

    rng = np.random.default_rng(0)
    n = 160
    cvss = rng.uniform(2.0, 10.0, n)
    true_time = np.clip(200.0 - 15.0 * cvss + rng.normal(0, 20, n), 1.0, None)
    censor = rng.uniform(30.0, 250.0, n)
    duration = np.minimum(true_time, censor)
    observed = true_time <= censor
    published = pd.to_datetime("2023-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 700, n), unit="D"
    )
    cve_id = [f"CVE-2023-{i:05d}" for i in range(n)]
    artifact_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        {
            "cve_id": cve_id,
            "published": published,
            "duration_days": duration,
            "event_observed": observed,
            "negative_duration_flag": False,
        }
    ).to_parquet(artifact_dir / "modeling_labels.parquet", index=False)
    pd.DataFrame(
        {
            "cve_id": cve_id,
            "published": published,
            "cvss_v3_base": cvss,
            "weakness_count": rng.integers(0, 4, n),
        }
    ).to_parquet(artifact_dir / "publication_features.parquet", index=False)
    # in-wild target: same schema, sparser events (only the fastest-weaponized observed)
    in_wild_observed = observed & (duration < 60)
    pd.DataFrame(
        {
            "cve_id": cve_id,
            "published": published,
            "duration_days": duration,
            "event_observed": in_wild_observed,
            "negative_duration_flag": False,
        }
    ).to_parquet(artifact_dir / "in_wild_labels.parquet", index=False)


def test_train_command_writes_metrics(tmp_path):
    from temporal_exploit.cli import train_command

    artifact_dir = tmp_path / "artifacts"
    report_dir = tmp_path / "report"
    _synthetic_artifacts(artifact_dir)

    metrics = train_command(
        artifact_dir, "2023-09-01", report_dir, horizons=(7, 30, 90), rsf_sample=10000
    )

    written = json.loads((report_dir / "metrics.json").read_text())
    assert written == metrics
    assert metrics["cox"]["kind"] == "cox"
    assert metrics["rsf"]["kind"] == "rsf"
    assert 0.0 <= metrics["cox"]["c_index_ipcw"] <= 1.0
    assert metrics["naive_event_rate_by_horizon"][0]["horizon_days"] == 7
    assert metrics["n_train"] + metrics["n_test"] <= 160
    assert metrics["label_set"] == "first_weaponization"


def test_train_command_in_wild_label_set(tmp_path):
    from temporal_exploit.cli import train_command

    artifact_dir = tmp_path / "artifacts"
    report_dir = tmp_path / "report"
    _synthetic_artifacts(artifact_dir)

    metrics = train_command(
        artifact_dir,
        "2023-09-01",
        report_dir,
        horizons=(7, 30, 90),
        rsf_sample=10000,
        label_set="in_wild",
    )

    assert metrics["label_set"] == "in_wild"
    assert 0.0 <= metrics["cox"]["c_index_ipcw"] <= 1.0


def test_train_command_rejects_unknown_label_set(tmp_path):
    from temporal_exploit.cli import train_command

    artifact_dir = tmp_path / "artifacts"
    _synthetic_artifacts(artifact_dir)
    with pytest.raises(ValueError, match="label_set"):
        train_command(artifact_dir, "2023-09-01", tmp_path / "r", label_set="bogus")
