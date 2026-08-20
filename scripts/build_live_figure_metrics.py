"""Assemble live figure metrics from current artifacts (no hardcoded report numbers).

Writes ``artifacts/live_figure_metrics.json``. Quantitative report figures must
read that file — see ``scripts/build_report_figures.py``.

Computes what this checkout can compute; optionally loads heavy research JSONs
when present (parity / ablation / operating points / vulncheck lift). Never
falls back to July report constants for model metrics.

Usage:
    .venv/Scripts/python.exe scripts/build_live_figure_metrics.py
    .venv/Scripts/python.exe scripts/build_live_figure_metrics.py --run-causal
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[1]
ART = REPO / "artifacts"
OUT = ART / "live_figure_metrics.json"

# Literature external check (not from our train) — cited, not a model metric.
VULNCHECK_2025_PREDISC_PCT = 28.96


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _first_existing(*rels: str) -> Path | None:
    for rel in rels:
        p = ART / rel
        if p.is_file():
            return p
    return None


def _ipa180(block: dict) -> float | None:
    ipa = block.get("ipa") or {}
    if 180 in ipa:
        return float(ipa[180])
    if "180" in ipa:
        return float(ipa["180"])
    return None


def build_two_heads() -> dict | None:
    iw_path = _first_existing(
        "reports/verify_inwild/metrics.json",
        "in_wild/metrics.json",
    )
    fw_path = _first_existing(
        "reports/verify_firstweap/metrics.json",
        "metrics.json",
    )
    if iw_path is None or fw_path is None:
        return None
    iw = _load_json(iw_path)
    fw = _load_json(fw_path)
    assert iw is not None and fw is not None
    iw_cox = iw["cox"]
    # Prefer xgb on first-weap when present; else cox.
    fw_model_name = "xgb" if "xgb" in fw else "cox"
    fw_m = fw[fw_model_name]
    return {
        "sources": {
            "in_wild": str(iw_path.relative_to(REPO)).replace("\\", "/"),
            "first_weap": str(fw_path.relative_to(REPO)).replace("\\", "/"),
        },
        "in_wild": {
            "model": "cox",
            "c_index_ipcw": float(iw_cox["c_index_ipcw"]),
            "n_events": int(iw_cox["c_index_n_events"]),
            "ipa_180": _ipa180(iw_cox),
            "ci95": iw_cox.get("c_index_ci95"),
        },
        "first_weap": {
            "model": fw_model_name,
            "c_index_ipcw": float(fw_m["c_index_ipcw"]),
            "n_events": int(fw_m["c_index_n_events"]),
            "ipa_180": _ipa180(fw_m),
            "ci95": fw_m.get("c_index_ci95"),
        },
    }


def build_label_funnel() -> dict | None:
    lab_path = ART / "modeling_labels.parquet"
    iw_path = ART / "in_wild_labels.parquet"
    man = _load_json(ART / "manifest.json") or {}
    if not lab_path.is_file():
        return None
    lab = pd.read_parquet(lab_path, columns=["event_observed", "event_source"])
    n_all = int(len(lab))
    n_any = int(lab["event_observed"].sum())
    n_poc = int((lab["event_source"] == "poc").sum())
    n_inwild = None
    if iw_path.is_file():
        iw = pd.read_parquet(iw_path, columns=["event_observed"])
        n_inwild = int(iw["event_observed"].sum())
    elif "in_wild_observed" in man:
        n_inwild = int(man["in_wild_observed"])
    if n_inwild is None:
        return None
    return {
        "source": "artifacts/modeling_labels.parquet + in_wild_labels",
        "corpus_rows": n_all,
        "any_signal": n_any,
        "public_poc_first": n_poc,
        "in_wild_labeled": n_inwild,
        "pct_any": round(100.0 * n_any / n_all, 2),
        "pct_poc": round(100.0 * n_poc / n_all, 2),
        "pct_inwild": round(100.0 * n_inwild / n_all, 2),
        "snapshot_date": man.get("snapshot_date"),
    }


def _predisclosure_rate(path: Path) -> dict | None:
    if not path.is_file():
        return None
    df = pd.read_parquet(
        path,
        columns=["event_observed", "negative_duration_flag", "duration_days"],
    )
    obs = df[df["event_observed"] == 1]
    if obs.empty:
        return None
    # on/before publication: negative duration or duration <= 0 (same-day kept as 0.5 elsewhere)
    pre = (obs["negative_duration_flag"].astype(bool)) | (obs["duration_days"] <= 0)
    return {
        "n_observed": int(len(obs)),
        "n_predisclosure": int(pre.sum()),
        "pct": round(100.0 * float(pre.mean()), 2),
    }


def build_patch_race() -> dict | None:
    fw = _predisclosure_rate(ART / "modeling_labels.parquet")
    iw = _predisclosure_rate(ART / "in_wild_labels.parquet")
    if fw is None or iw is None:
        return None
    # 0-day arm: google_0day-first events that are pre-publication
    zero_day = None
    lab_path = ART / "modeling_labels.parquet"
    if lab_path.is_file():
        lab = pd.read_parquet(
            lab_path,
            columns=["event_source", "event_observed", "negative_duration_flag", "duration_days"],
        )
        zd = lab[(lab["event_source"] == "google_0day") & (lab["event_observed"] == 1)]
        if len(zd):
            pre = zd["negative_duration_flag"].astype(bool) | (zd["duration_days"] <= 0)
            zero_day = {
                "n": int(len(zd)),
                "pct_before_publication": round(100.0 * float(pre.mean()), 2),
            }
    # OSS commit-dated panel only if prior patch_race.json exists
    oss = None
    prior = _load_json(ART / "merged" / "patch_race.json")
    if prior:
        arm = (prior.get("descriptive_race") or {}).get("all_commit") or {}
        if arm:
            oss = {
                "n_weaponized_dated": arm.get("n_weaponized_dated"),
                "weaponized_before_patch_pct": round(
                    100.0 * float(arm["weaponized_before_patch_rate"]), 2
                )
                if arm.get("weaponized_before_patch_rate") is not None
                else None,
                "lead_days_patch_to_weapon_median": arm.get(
                    "lead_days_patch_to_weapon_median"
                ),
                "source": "artifacts/merged/patch_race.json",
            }
    return {
        "source": "live labels (pre-disclosure = neg-duration or duration<=0)",
        "first_weap_predisclosure_pct": fw["pct"],
        "first_weap": fw,
        "in_wild_predisclosure_pct": iw["pct"],
        "in_wild": iw,
        "zero_day": zero_day,
        "oss_commit_dated": oss,
        "external_vulncheck_2025_kev_predisc_pct": VULNCHECK_2025_PREDISC_PCT,
        "external_note": (
            "VulnCheck 28.96% is an external literature check, not recomputed here"
        ),
    }


def build_causal(run: bool) -> dict | None:
    prior = _load_json(ART / "merged" / "causal_characterization.json")
    if prior and prior.get("treatments"):
        return {"source": "artifacts/merged/causal_characterization.json", **_causal_rows(prior)}
    if not run:
        return None
    feat_path = ART / "publication_features.parquet"
    lab_path = ART / "modeling_labels.parquet"
    if not feat_path.is_file() or not lab_path.is_file():
        return None

    # Adjusted Cox only (skip IPW) so a live rebuild finishes in minutes on CPU.
    from temporal_exploit.causal import cox_hr, evalue

    feat = pd.read_parquet(feat_path)
    lab = pd.read_parquet(
        lab_path,
        columns=["cve_id", "duration_days", "event_observed", "negative_duration_flag"],
    )
    df = feat.merge(lab, on="cve_id", how="inner")
    df = df[~df["negative_duration_flag"].astype(bool)]
    df = df[df["duration_days"] > 0].dropna(subset=["duration_days", "event_observed"])

    cwe = [c for c in feat.columns if c.startswith("cwe_")]
    base = [c for c in ("published_year", "vendor_count", "product_count", "weakness_count") if c in df.columns]
    treatments = {
        "wormable": ("incentive_wormable", base + cwe),
        "unauth_network_high_impact": ("incentive_unauth_network_high_impact", base + cwe),
    }
    if "has_attack_chain_mapping" in df.columns:
        treatments["attack_chain_mapped"] = (
            "has_attack_chain_mapping",
            base + cwe + [c for c in ("cvss_v3_base", "cvss_v3_missing") if c in df.columns],
        )

    report: dict = {
        "n_total": int(len(df)),
        "n_events": int(df["event_observed"].sum()),
        "mode": "adjusted_cox_only_live",
        "treatments": {},
    }
    for name, (col, confs) in treatments.items():
        if col not in df.columns:
            continue
        confs = [c for c in confs if c in df.columns and c != col]
        sub = df.dropna(subset=[col] + confs).copy()
        sub[col] = sub[col].astype(int)
        print(f"  causal fitting {name} (n={len(sub):,}) …", flush=True)
        adj = cox_hr(sub, [col] + confs, col)
        report["treatments"][name] = {
            "treatment_col": col,
            "n": int(len(sub)),
            "adjusted_hr": adj,
            "evalue_adjusted": evalue(adj["hr"], adj["ci"][0], adj["ci"][1]),
        }

    (ART / "merged").mkdir(parents=True, exist_ok=True)
    (ART / "merged" / "causal_characterization.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return {"source": "computed into artifacts/merged/causal_characterization.json", **_causal_rows(report)}


def _causal_rows(report: dict) -> dict:
    rows = []
    label_map = {
        "wormable": "wormable\n(AV:N/PR:N/UI:N/AC:L)",
        "unauth_network_high_impact": "unauth-network\nhigh-impact",
        "attack_chain_mapped": "ATT&CK-chain\nmapped",
    }
    for key, lab in label_map.items():
        t = (report.get("treatments") or {}).get(key)
        if not t:
            continue
        adj = t.get("adjusted_hr") or {}
        ci = adj.get("ci") or [None, None]
        rows.append(
            {
                "key": key,
                "label": lab,
                "hr": adj.get("hr"),
                "ci_lo": ci[0],
                "ci_hi": ci[1],
                "evalue": (t.get("evalue_adjusted") or {}).get("point"),
                "refused": bool(
                    key == "attack_chain_mapped"
                    and (t.get("ipw_hr") or {}).get("overlap")
                    and _positivity_violated((t.get("ipw_hr") or {}).get("overlap"))
                ),
            }
        )
    return {
        "n_total": report.get("n_total"),
        "n_events": report.get("n_events"),
        "rows": rows,
    }


def _positivity_violated(overlap: dict | None) -> bool:
    if not overlap:
        return False
    # treated median high + control median near 0 → refuseivity failure pattern from the report
    try:
        t = overlap["ps_treated_p05_p50_p95"][1]
        c = overlap["ps_control_p05_p50_p95"][1]
        return t > 0.8 and c < 0.05
    except (KeyError, IndexError, TypeError):
        return False


def _optional_research() -> dict:
    """Load heavy research JSONs when present; omit keys when absent."""
    out: dict = {}
    parity = _load_json(ART / "inwild_epss_parity.json")
    if parity and "per_arm" in parity:
        s = parity["per_arm"]["structural"]
        e = parity["per_arm"]["epss_score"]
        nv = parity["per_arm"].get("epss_xgb_naive") or {}
        d = (parity.get("structural_vs_epss_score") or {}).get("horizon_auc_30") or {}
        out["epss_parity"] = {
            "source": "artifacts/inwild_epss_parity.json",
            "auc30": {
                "structural": s.get("auc_30"),
                "epss_raw": e.get("auc_30"),
                "epss_xgb_naive": nv.get("auc_30"),
            },
            "delta_auc30": d.get("mean_delta"),
            "delta_ci95": d.get("ci95"),
            "recall_structural": s.get("recall_at_top_30"),
            "recall_epss": e.get("recall_at_top_30"),
            "n_origins": parity.get("n_origins"),
            "test_events": s.get("test_events_total"),
        }

    abl = _load_json(ART / "inwild_epss_ablation.json") or _load_json(
        ART / "merged" / "inwild_epss_ablation.json"
    )
    if abl:
        # tolerate a few historical shapes
        deltas = abl.get("full_vs_epss_only") or abl.get("deltas") or abl
        out["epss_ablation"] = {"source": "inwild_epss_ablation.json", "raw": deltas}

    op = _load_json(ART / "operating_points.json") or _load_json(
        ART / "merged" / "defender_operating_points.json"
    )
    if op:
        out["operating_points"] = {"source": "operating_points artifact", "raw": op}

    lift = _load_json(ART / "vulncheck_lift.json") or _load_json(
        ART / "vulncheck_diagnose.json"
    )
    if lift:
        out["vulncheck_lift"] = {"source": "vulncheck artifact", "raw": lift}

    return out


def main(run_causal: bool = False) -> Path:
    ART.mkdir(parents=True, exist_ok=True)
    bundle = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_dir": str(ART),
        "two_heads": build_two_heads(),
        "label_funnel": build_label_funnel(),
        "patch_race": build_patch_race(),
        "causal": build_causal(run=run_causal),
        "research": _optional_research(),
    }
    present = [k for k, v in bundle.items() if k not in ("generated_utc", "artifact_dir", "research") and v]
    research_keys = list((bundle.get("research") or {}).keys())
    OUT.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {OUT}")
    print(f"core sections: {present}")
    print(f"optional research: {research_keys or '(none — re-run heavy scripts to unlock)'}")
    missing = [k for k in ("two_heads", "label_funnel", "patch_race") if not bundle.get(k)]
    if missing:
        raise SystemExit(f"missing required live sections: {missing}")
    return OUT


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--run-causal",
        action="store_true",
        help="Fit adjusted Cox + IPW on current artifacts (minutes; writes merged/causal JSON)",
    )
    args = p.parse_args()
    main(run_causal=args.run_causal)
