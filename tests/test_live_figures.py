"""Live figure metrics must drive figures — no silent hardcoded fallback."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import build_live_figure_metrics as blfm
from scripts import build_report_figures as brf


def test_build_live_figure_metrics_from_verify_reports(tmp_path, monkeypatch):
    art = tmp_path / "artifacts"
    (art / "reports" / "verify_inwild").mkdir(parents=True)
    (art / "reports" / "verify_firstweap").mkdir(parents=True)

    iw = {
        "label_set": "in_wild",
        "cox": {
            "c_index_ipcw": 0.849,
            "c_index_n_events": 251,
            "c_index_ci95": [0.8, 0.9],
            "ipa": {"180": -0.001},
        },
    }
    fw = {
        "label_set": "first_weaponization",
        "cox": {
            "c_index_ipcw": 0.566,
            "c_index_n_events": 100,
            "ipa": {"180": 0.3},
        },
        "xgb": {
            "c_index_ipcw": 0.594,
            "c_index_n_events": 100,
            "ipa": {"180": 0.28},
        },
    }
    (art / "reports" / "verify_inwild" / "metrics.json").write_text(json.dumps(iw))
    (art / "reports" / "verify_firstweap" / "metrics.json").write_text(json.dumps(fw))

    # minimal labels for funnel + patch race
    import pandas as pd

    lab = pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
            "event_observed": [1, 1, 0],
            "event_source": ["poc", "google_0day", "censored"],
            "negative_duration_flag": [False, True, False],
            "duration_days": [10.0, -5.0, 100.0],
        }
    )
    iwlab = pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
            "event_observed": [0, 1, 0],
            "negative_duration_flag": [False, True, False],
            "duration_days": [10.0, -5.0, 100.0],
        }
    )
    lab.to_parquet(art / "modeling_labels.parquet")
    iwlab.to_parquet(art / "in_wild_labels.parquet")
    (art / "manifest.json").write_text(json.dumps({"snapshot_date": "2026-03-14", "in_wild_observed": 1}))

    monkeypatch.setattr(blfm, "ART", art)
    monkeypatch.setattr(blfm, "OUT", art / "live_figure_metrics.json")
    monkeypatch.setattr(blfm, "REPO", tmp_path)

    out = blfm.main(run_causal=False)
    bundle = json.loads(out.read_text())
    assert bundle["two_heads"]["in_wild"]["c_index_ipcw"] == pytest.approx(0.849)
    assert bundle["two_heads"]["first_weap"]["model"] == "xgb"
    assert bundle["two_heads"]["first_weap"]["c_index_ipcw"] == pytest.approx(0.594)
    assert bundle["label_funnel"]["corpus_rows"] == 3
    assert bundle["patch_race"]["in_wild_predisclosure_pct"] == pytest.approx(100.0)


def test_build_report_figures_requires_live_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(brf, "METRICS_PATH", tmp_path / "missing.json")
    monkeypatch.setattr(brf, "FIGDIR", tmp_path / "figures")
    with pytest.raises(SystemExit):
        brf.load_metrics()
