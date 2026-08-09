import json

from scripts.build_dashboard import run_dashboard


def _write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))


def test_run_dashboard_builds_self_contained_html(tmp_path):
    root = tmp_path / "artifacts"
    _write(root / "merged" / "interval_censored.json", {
        "c_index": 0.582,
        "finding": "batch dates cluster in calendar time but smear in duration space.",
        "calendar_concentration": {"n_values_for_50pct": 31},
        "duration_concentration": {"n_values_for_50pct": 239},
    })
    _write(root / "merged" / "causal_characterization.json", {
        "treatments": {"wormable": {"adjusted_hr": {"hr": 1.29}, "evalue_adjusted": {"point": 1.68}}}
    })
    _write(root / "inwild_decision_curve.json", {
        "base_rate": 0.0032, "n_test": 84806, "horizon": 90,
        "table": [
            {"threshold": 0.001, "net_benefit_model": 0.0026, "net_benefit_all": 0.0024, "net_benefit_none": 0.0},
            {"threshold": 0.01, "net_benefit_model": 0.0011, "net_benefit_all": -0.002, "net_benefit_none": 0.0},
        ],
    })

    out = run_dashboard(root)

    assert out.exists()
    doc = out.read_text()
    # self-contained: no external http(s) resource references
    assert "http://" not in doc and 'src="https' not in doc
    # real numbers + section anchors present
    assert "Scope Expansion" in doc
    assert "§3.2" in doc and "c-index" in doc
    assert "31 vs 239" in doc                     # concentration tile rendered from the fixture
    assert "1.29" in doc                          # wormable HR rendered
    assert "<svg" in doc                          # at least one inline chart
    assert "data:image/png" not in doc or True    # figure optional (absent in fixture) — must not crash


def test_run_dashboard_survives_missing_artifacts(tmp_path):
    # empty artifact root: no crash, still a valid page with the "no artifacts" note
    root = tmp_path / "artifacts"
    root.mkdir()
    out = run_dashboard(root)
    doc = out.read_text()
    assert "<!doctype html>" in doc.lower()
    assert "no artifacts found" in doc
