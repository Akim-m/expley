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
    assert "modeling_labels.parquet" in manifest["artifact_sha256"]
    assert "feature_provenance.csv" in manifest["artifact_sha256"]
    assert manifest["event_source_dominance"]["dominant_source"] == "poc"  # only observed event

    # transition-safe PoC features written separately (never merged into the
    # publication-time-safe feature set)
    poc_feats = pd.read_parquet(artifact_dir / "poc_transition_features.parquet")
    assert "poc_count" in poc_feats.columns
    assert len(poc_feats) == 2
    assert "poc_count" not in features.columns


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


def test_build_dataset_writes_landmark_features(tmp_path):
    out_dir = tmp_path / "out"
    artifact_dir = tmp_path / "artifacts"
    write_tiny_handover(out_dir)

    build_dataset_command(
        out_dir, artifact_dir, snapshot_date="2024-03-01", landmarks=(30,)
    )

    lm = pd.read_parquet(artifact_dir / "landmark_features_30d.parquet")
    lm = lm.set_index("cve_id")
    # tiny fixture: PoC for CVE-2024-0001 lands 9 days after publication
    assert lm.loc["CVE-2024-0001", "poc_by_landmark"] == 1
    assert lm.loc["CVE-2024-0001", "poc_lag_days"] == 9.0
    assert lm.loc["CVE-2024-0002", "poc_by_landmark"] == 0
    # kev/google_0day are the in-wild label sources, never landmark covariates
    assert not any(c.startswith(("kev_", "google_0day_")) for c in lm.columns)

    provenance = pd.read_csv(artifact_dir / "feature_provenance.csv")
    assert (provenance["leakage_status"] == "landmark_safe").any()
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert manifest["landmarks"] == [30]


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


def test_main_fetch_nuclei(tmp_path, monkeypatch):
    from temporal_exploit.fetch import gitmine

    monkeypatch.setattr(gitmine, "shallow_clone", lambda url, dest: None)
    monkeypatch.setattr(
        gitmine, "first_add_dates", lambda repo, paths=None: {"http/cves/2021/cve-2021-44228.yaml": 1_600_000_000}
    )
    main(
        [
            "fetch", "--source", "nuclei",
            "--live-dir", str(tmp_path / "live"),
            "--repo", str(tmp_path / "cache"),
        ]
    )
    saved = pd.read_parquet(tmp_path / "live" / "nuclei_dates.parquet")
    assert set(saved["cve_id"]) == {"CVE-2021-44228"}


def test_main_fetch_poc_requires_repo(tmp_path):
    with pytest.raises(ValueError, match="--repo"):
        main(["fetch", "--source", "poc", "--live-dir", str(tmp_path)])


def test_main_fetch_metasploit(tmp_path, monkeypatch):
    import json as _json

    from temporal_exploit.fetch import gitmine

    monkeypatch.setattr(gitmine, "shallow_clone", lambda url, dest, with_blobs=False: None)
    monkeypatch.setattr(
        gitmine,
        "file_at_head",
        lambda repo, path: _json.dumps(
            {"m": {"path": "modules/exploits/x.rb", "references": ["CVE-2021-44228"]}}
        ),
    )
    monkeypatch.setattr(gitmine, "earliest_introduction", lambda repo, cve, path: (1_600_000_000, "abc123"))
    main(
        [
            "fetch", "--source", "metasploit",
            "--live-dir", str(tmp_path / "live"),
            "--repo", str(tmp_path / "cache"),
        ]
    )
    saved = pd.read_parquet(tmp_path / "live" / "metasploit_dates.parquet")
    assert set(saved["cve_id"]) == {"CVE-2021-44228"}


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


def test_main_fetch_zeroday(tmp_path, monkeypatch):
    from temporal_exploit.fetch import zeroday

    csv = "CVE,Vendor,Product,Type,Date Discovered,Date Patched\nCVE-2021-0001,V,P,RCE,2021-01-05,2021-02-01\n"
    monkeypatch.setattr(zeroday, "_fetch_csv", lambda url: csv)
    main(["fetch", "--source", "zeroday", "--live-dir", str(tmp_path / "live")])
    saved = pd.read_parquet(tmp_path / "live" / "google_0day.parquet")
    assert set(saved["cve_id"]) == {"CVE-2021-0001"}


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
            "event_source": np.where(in_wild_observed, "kev", "censored"),
            "negative_duration_flag": False,
        }
    ).to_parquet(artifact_dir / "in_wild_labels.parquet", index=False)


def _competing_artifacts(artifact_dir):
    import numpy as np

    rng = np.random.default_rng(1)
    n = 200
    cvss = rng.uniform(2.0, 10.0, n)
    poc_time = np.clip(150.0 - 12.0 * cvss + rng.normal(0, 15, n), 1.0, None)
    kev_time = rng.uniform(20.0, 400.0, n)
    censor = rng.uniform(50.0, 300.0, n)
    published = pd.to_datetime("2023-01-01", utc=True) + pd.to_timedelta(
        rng.integers(0, 700, n), unit="D"
    )
    cve_id = [f"CVE-2023-{i:05d}" for i in range(n)]

    first = np.minimum.reduce([poc_time, kev_time, censor])
    cause = np.select(
        [first == poc_time, first == kev_time], [1, 2], default=0
    )
    cause[first == censor] = 0
    pd.DataFrame(
        {
            "cve_id": cve_id,
            "published": published,
            "duration_days": first,
            "event_cause": np.select([cause == 1, cause == 2], ["poc", "kev"], "censored"),
            "cause_code": cause,
            "event_observed": cause > 0,
        }
    ).to_parquet(artifact_dir / "competing_risks_labels.parquet", index=False)

    poc_obs = cause == 1
    msf_obs = poc_obs & (rng.random(n) < 0.4)
    poc_date = published + pd.to_timedelta(poc_time, unit="D")
    msf_date = poc_date + pd.to_timedelta(rng.uniform(5.0, 60.0, n), unit="D")
    pd.DataFrame(
        {
            "cve_id": cve_id,
            "published": published,
            "poc_event_date": poc_date.where(pd.Series(poc_obs)),
            "poc_observed": poc_obs,
            "metasploit_event_date": msf_date.where(pd.Series(msf_obs)),
            "metasploit_observed": msf_obs,
        }
    ).to_parquet(artifact_dir / "per_signal_labels.parquet", index=False)

    pd.DataFrame(
        {
            "cve_id": cve_id,
            "poc_count": rng.integers(0, 5, n),
            "poc_source_count": rng.integers(0, 3, n),
            "poc_missing": (~poc_obs).astype(int),
            "poc_first_lag_days": np.where(poc_obs, poc_time, -1.0),
        }
    ).to_parquet(artifact_dir / "poc_transition_features.parquet", index=False)


def test_train_competing_command_writes_metrics(tmp_path):
    from temporal_exploit.cli import train_competing_command

    artifact_dir = tmp_path / "artifacts"
    report_dir = tmp_path / "report"
    _synthetic_artifacts(artifact_dir)
    _competing_artifacts(artifact_dir)

    metrics = train_competing_command(
        artifact_dir,
        "2023-09-01",
        report_dir,
        horizons=(30, 90),
        transitions=(("poc", "metasploit"),),
        snapshot_date="2025-01-01",
    )

    written = json.loads((report_dir / "competing_metrics.json").read_text())
    assert written == metrics
    aj = metrics["aj_cif_train"]
    assert all(0.0 <= row["cif"] <= 1.0 for row in aj)
    assert {row["cause_code"] for row in aj} == {1, 2}
    assert "1" in metrics["cause_specific_cox"]
    assert metrics["cause_specific_cox"]["1"]["n_events"] > 0
    trans = metrics["transitions"]["poc->metasploit"]
    assert trans["n"] > 0
    assert 0.0 <= trans["c_index"] <= 1.0


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


def test_train_command_model_selection(tmp_path):
    import pytest

    pytest.importorskip("xgboost")
    from temporal_exploit.cli import train_command

    artifact_dir = tmp_path / "artifacts"
    report_dir = tmp_path / "report"
    _synthetic_artifacts(artifact_dir)

    metrics = train_command(
        artifact_dir, "2023-09-01", report_dir, horizons=(7, 30, 90),
        models=("cox", "xgb"),
    )

    assert metrics["xgb"]["kind"] == "xgb"
    assert "rsf" not in metrics
    assert (report_dir / "calibration_xgb.png").exists()
    assert not (report_dir / "calibration_rsf.png").exists()


def test_train_command_rejects_unknown_model(tmp_path):
    import pytest

    from temporal_exploit.cli import train_command

    artifact_dir = tmp_path / "artifacts"
    _synthetic_artifacts(artifact_dir)
    with pytest.raises(ValueError, match="unknown models"):
        train_command(
            artifact_dir, "2023-09-01", tmp_path / "report", models=("cox", "bogus")
        )


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


def test_in_wild_clock_start_picks_latest_active_catalog(monkeypatch):
    import temporal_exploit.cli as cli

    # only sources with a known catalog-launch artifact constrain the clock
    assert cli.in_wild_clock_start(("kev", "google_0day", "censored")) == cli.CATALOG_START["kev"]
    # no catalog source active (google_0day has genuine dates) -> no filter
    assert cli.in_wild_clock_start(("google_0day", "censored")) is None
    assert cli.in_wild_clock_start(()) is None
    # with multiple catalog sources, take the latest (most conservative) start
    monkeypatch.setitem(cli.CATALOG_START, "vulncheck_kev", "2024-02-01")
    assert cli.in_wild_clock_start(("kev", "vulncheck_kev", "google_0day")) == "2024-02-01"


def test_train_command_rejects_unknown_label_set(tmp_path):
    from temporal_exploit.cli import train_command

    artifact_dir = tmp_path / "artifacts"
    _synthetic_artifacts(artifact_dir)
    with pytest.raises(ValueError, match="label_set"):
        train_command(artifact_dir, "2023-09-01", tmp_path / "r", label_set="bogus")
