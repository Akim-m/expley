"""Generate report figures from LIVE metrics only (no hardcoded July numbers).

Prerequisite:
    .venv/Scripts/python.exe scripts/build_live_figure_metrics.py [--run-causal]

Then:
    .venv/Scripts/python.exe scripts/build_report_figures.py

Reads ``artifacts/live_figure_metrics.json``. Quantitative panels that lack live
data are skipped (printed as SKIP) rather than filled with stale report constants.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

REPO = Path(__file__).resolve().parents[1]
FIGDIR = REPO / "docs" / "figures"
METRICS_PATH = REPO / "artifacts" / "live_figure_metrics.json"
FIGDIR.mkdir(parents=True, exist_ok=True)

NAVY = "#0b3d91"
BLUE = "#1f6feb"
GREEN = "#347d39"
RED = "#cf222e"
AMBER = "#bf8700"
PURPLE = "#8957e5"
GREY = "#6e7781"

plt.rcParams.update({
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.labelsize": 10,
    "axes.edgecolor": "#888888",
    "axes.grid": True,
    "grid.color": "#e3e6ea",
    "grid.linewidth": 0.7,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})


def load_metrics() -> dict:
    if not METRICS_PATH.is_file():
        sys.exit(
            f"Missing {METRICS_PATH}\n"
            "Build it first:\n"
            "  .venv/Scripts/python.exe scripts/build_live_figure_metrics.py [--run-causal]"
        )
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def save(fig, name: str) -> None:
    path = FIGDIR / name
    fig.savefig(path, facecolor="white")
    plt.close(fig)
    print("WROTE", path)


def _caption(ax_or_fig, text: str) -> None:
    """Small live-source caption under a figure."""
    target = ax_or_fig if hasattr(ax_or_fig, "text") and not hasattr(ax_or_fig, "axes") else None
    if target is None:
        # figure
        ax_or_fig.text(
            0.5, -0.02, text, transform=ax_or_fig.transFigure,
            ha="center", va="top", fontsize=7, color=GREY, style="italic",
        )
    else:
        target.text(
            0.5, -0.18, text, transform=target.transAxes,
            ha="center", va="top", fontsize=7, color=GREY, style="italic",
        )


def fig_pipeline() -> None:
    fig, ax = plt.subplots(figsize=(10, 4.4))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 44)
    ax.axis("off")

    def box(x, y, w, h, text, color, tcolor="white", fs=9):
        ax.add_patch(FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.6,rounding_size=2",
            linewidth=0, facecolor=color))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
                color=tcolor, fontsize=fs, fontweight="bold", wrap=True)

    def arrow(x1, y1, x2, y2):
        ax.add_patch(FancyArrowPatch(
            (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14,
            linewidth=1.6, color=GREY))

    box(1, 26, 16, 9, "EXTERNAL SOURCES\nNVD · KEV · EPSS\nPoC · MSF · Nuclei\n0-day · VulnCheck", GREEN, fs=7.5)
    box(21, 26, 13, 9, "fetch / refresh\n→ live deltas", BLUE)
    box(38, 26, 13, 9, "merge\n(earliest-wins)", PURPLE)
    box(55, 26, 15, 9, "build-dataset\nlabels + features", NAVY)
    box(74, 26, 13, 9, "train /\ncompeting /\nbacktest", RED, fs=8)
    box(91, 26, 8, 9, "metrics\n+ plots", AMBER, fs=8)
    for (x1, x2) in [(17, 21), (34, 38), (51, 55), (70, 74), (87, 91)]:
        arrow(x1, 30.5, x2, 30.5)
    box(38, 8, 13, 9, "9 handover\nparquets\n(immutable)", "#2d333b", fs=8)
    arrow(44.5, 17, 44.5, 26)
    box(55, 8, 15, 9, "4 label sets\n+ feature matrix\n+ manifest", "#444c56", fs=7.5)
    arrow(62.5, 17, 62.5, 26)
    ax.text(50, 41, "Data-flow pipeline — the spine is cli.py (8 subcommands)",
            ha="center", fontsize=12, fontweight="bold", color=NAVY)
    ax.text(50, 2.5,
            "Schematic only (no metrics). Quantitative figures read artifacts/live_figure_metrics.json.",
            ha="center", fontsize=8.5, color=GREY, style="italic")
    save(fig, "fig_pipeline.png")


def fig_two_heads(m: dict) -> None:
    th = m.get("two_heads")
    if not th:
        print("SKIP fig_two_heads.png — no two_heads in live metrics")
        return
    iw, fw = th["in_wild"], th["first_weap"]
    heads = [
        f"In-wild\n({iw['model']}, {iw['n_events']:,} ev)",
        f"First-weap\n({fw['model']}, {fw['n_events']:,} ev)",
    ]
    cidx = [iw["c_index_ipcw"], fw["c_index_ipcw"]]
    ipa180 = [iw.get("ipa_180") or 0.0, fw.get("ipa_180") or 0.0]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.2))
    b1 = a1.bar(heads, cidx, color=[RED, BLUE], width=0.6)
    a1.axhline(0.5, ls="--", color=GREY, lw=1)
    a1.set_ylim(0, 1.0)
    a1.set_ylabel("IPCW c-index (ranking)")
    a1.set_title("Ranking: in-wild WINS" if cidx[0] > cidx[1] else "Ranking")
    for r, v in zip(b1, cidx):
        a1.text(r.get_x() + r.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center", fontweight="bold")

    b2 = a2.bar(heads, ipa180, color=[RED, BLUE], width=0.6)
    a2.axhline(0, color="#333", lw=1)
    lo, hi = min(ipa180) - 0.05, max(ipa180) + 0.05
    a2.set_ylim(min(lo, -0.05), max(hi, 0.05))
    a2.set_ylabel("IPA@180 (calibration)")
    a2.set_title("Calibration: first-weap WINS" if ipa180[1] > ipa180[0] else "Calibration")
    for r, v in zip(b2, ipa180):
        off = 0.012 if v >= 0 else -0.03
        a2.text(r.get_x() + r.get_width() / 2, v + off, f"{v:+.3f}", ha="center", fontweight="bold")

    fig.suptitle("Two heads, two different ceilings — LIVE from train metrics",
                 fontsize=12.5, fontweight="bold", color=NAVY, y=1.02)
    src = th.get("sources") or {}
    fig.text(0.5, -0.02,
             f"Source: {src.get('in_wild', '?')} · {src.get('first_weap', '?')} · generated {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_two_heads.png")


def fig_label_funnel(m: dict) -> None:
    lf = m.get("label_funnel")
    if not lf:
        print("SKIP fig_label_funnel.png — no label_funnel in live metrics")
        return
    stages = ["All CVEs", "Any signal", "Public PoC\n(first)", "In-wild\nlabeled"]
    vals = [lf["corpus_rows"], lf["any_signal"], lf["public_poc_first"], lf["in_wild_labeled"]]
    pcts = ["100%", f"{lf['pct_any']:.1f}%", f"{lf['pct_poc']:.1f}%", f"{lf['pct_inwild']:.2f}%"]
    cols = ["#2d333b", BLUE, PURPLE, RED]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 4.0))
    b = a1.barh(range(len(stages))[::-1], vals, color=cols, height=0.62)
    a1.set_yticks(range(len(stages))[::-1])
    a1.set_yticklabels(stages)
    a1.set_xscale("log")
    a1.set_xlabel("CVEs (log scale)")
    a1.set_title("The weaponization funnel (this checkout)")
    for r, v, pc in zip(b, vals, pcts):
        a1.text(v * 1.15, r.get_y() + r.get_height() / 2, f"{v:,}  ({pc})",
                va="center", fontsize=8.5, fontweight="bold")
    a1.set_xlim(max(1, min(vals) / 5), max(vals) * 8)

    # right panel: in-wild share vs rest
    labeled = lf["in_wild_labeled"]
    rest = lf["corpus_rows"] - labeled
    grp = ["In-wild\nlabeled", "Not in-wild\nlabeled"]
    mass = [labeled, rest]
    b2 = a2.bar(grp, mass, color=[RED, GREY], width=0.55)
    a2.set_ylabel("# CVEs")
    a2.set_title(f"In-wild base rate {lf['pct_inwild']:.2f}%")
    for r, v in zip(b2, mass):
        a2.text(r.get_x() + r.get_width() / 2, v + max(mass) * 0.01, f"{v:,}",
                ha="center", fontweight="bold")

    snap = lf.get("snapshot_date") or "?"
    fig.suptitle(f"Label funnel — LIVE labels @ snapshot {snap}",
                 fontsize=11.5, fontweight="bold", color=NAVY, y=1.02)
    fig.text(0.5, -0.02, f"Source: {lf.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_label_funnel.png")


def fig_patch_race(m: dict) -> None:
    pr = m.get("patch_race")
    if not pr:
        print("SKIP fig_patch_race.png — no patch_race in live metrics")
        return
    labels = ["First-weap\n(ours, live)", "In-wild\n(ours, live)", "VulnCheck\n2025 KEVs\n(external)"]
    pct = [
        pr["first_weap_predisclosure_pct"],
        pr["in_wild_predisclosure_pct"],
        pr["external_vulncheck_2025_kev_predisc_pct"],
    ]
    cols = [BLUE, RED, GREY]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.4, 4.0))
    b = a1.bar(labels, pct, color=cols, width=0.6)
    a1.set_ylabel("% event on/before CVE publication")
    a1.set_ylim(0, max(pct) * 1.35 + 5)
    a1.set_title("Pre-disclosure rates (live labels)")
    for r, v in zip(b, pct):
        a1.text(r.get_x() + r.get_width() / 2, v + 0.7, f"{v:.1f}%", ha="center", fontweight="bold")
    a1.text(0.5, -0.22, pr.get("external_note", ""), transform=a1.transAxes,
            ha="center", fontsize=6.5, color=GREY, style="italic")

    # right: zero-day vs optional OSS commit arm
    zd = pr.get("zero_day") or {}
    oss = pr.get("oss_commit_dated") or {}
    cohorts, before, colors, notes = [], [], [], []
    if zd:
        cohorts.append(f"0-days\n(google_0day, n={zd['n']})")
        before.append(zd["pct_before_publication"])
        colors.append(RED)
        notes.append("pre-pub among 0-day-first")
    if oss and oss.get("weaponized_before_patch_pct") is not None:
        cohorts.append(f"OSS commit-dated\n(n={oss.get('n_weaponized_dated')})")
        before.append(oss["weaponized_before_patch_pct"])
        colors.append(GREEN)
        notes.append(f"median lead {oss.get('lead_days_patch_to_weapon_median')}d")
    if not cohorts:
        a2.axis("off")
        a2.text(0.5, 0.5, "OSS commit-dated panel unavailable\n(needs data/merged + patch_race.json)",
                ha="center", va="center", color=GREY, fontsize=9)
    else:
        b2 = a2.bar(cohorts, before, color=colors, width=0.6)
        a2.set_ylabel("% (see panel notes)")
        a2.set_ylim(0, max(before) * 1.2 + 5)
        a2.set_title("Cohort slices (live / prior artifact)")
        for r, v, note in zip(b2, before, notes):
            a2.text(r.get_x() + r.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontweight="bold")
            a2.text(r.get_x() + r.get_width() / 2, max(v * 0.4, 5), note, ha="center", fontsize=7, color="white" if v > 40 else GREY)

    fig.suptitle("Patch-vs-exploit race — LIVE pre-disclosure from labels",
                 fontsize=11.5, fontweight="bold", color=NAVY, y=1.02)
    fig.text(0.5, -0.02, f"Source: {pr.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_patch_race.png")


def fig_causal_forest(m: dict) -> None:
    causal = m.get("causal")
    rows = (causal or {}).get("rows") or []
    if not rows:
        print("SKIP fig_causal_forest.png — no causal rows (re-run with --run-causal)")
        return
    fig, ax = plt.subplots(figsize=(8.8, 3.9))
    ys = range(len(rows))
    for y, row in zip(ys, rows):
        hr, lo, hi = row["hr"], row["ci_lo"], row["ci_hi"]
        col = RED if row.get("refused") or (hr is not None and hr < 1) else GREEN
        if hr is None or lo is None or hi is None:
            continue
        ax.plot([lo, hi], [y, y], color=col, lw=3, solid_capstyle="round")
        ax.plot(hr, y, "o", color=col, markersize=11)
        ev = row.get("evalue")
        tag = f"HR {hr:.2f} [{lo:.2f}, {hi:.2f}]"
        if ev is not None:
            tag += f"  E={ev:.2f}"
        if row.get("refused"):
            tag += "  (positivity caution)"
        ax.text(hi + 0.025, y, tag, va="center", fontsize=9, fontweight="bold")
    ax.axvline(1.0, ls="--", color="#333", lw=1.4)
    ax.set_yticks(list(ys))
    ax.set_yticklabels([r["label"] for r in rows])
    ax.set_ylim(-0.55, len(rows) - 0.25)
    ax.set_xlabel("Adjusted hazard ratio  (HR > 1 = faster weaponization)")
    n = causal.get("n_total")
    ne = causal.get("n_events")
    ax.set_title(f"Causal acceleration (adjusted Cox, n={n:,}, events={ne:,})", pad=22)
    ax.grid(axis="y", visible=False)
    fig.text(0.5, -0.02, f"Source: {causal.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_causal_forest.png")


def fig_epss_parity(m: dict) -> None:
    ep = (m.get("research") or {}).get("epss_parity")
    if not ep:
        print("SKIP fig_epss_parity.png — no artifacts/inwild_epss_parity.json (run scripts/inwild_epss_parity.py)")
        return
    auc = ep["auc30"]
    arms = ["Structural\n(ours, no EPSS)", "EPSS\n(raw percentile)", "EPSS xgb-naive\n(artifact)"]
    vals = [auc["structural"], auc["epss_raw"], auc["epss_xgb_naive"]]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.8, 4.3))
    bars = a1.bar(arms, vals, color=[BLUE, GREEN, GREY], width=0.62)
    bars[2].set_hatch("//")
    bars[2].set_alpha(0.5)
    a1.axhline(0.5, ls="--", color=GREY, lw=1)
    a1.set_ylim(0.45, max(v for v in vals if v is not None) + 0.12)
    a1.set_ylabel("in-wild AUC@30 (ranking)")
    a1.set_title("Ranking (LIVE parity JSON)")
    for r, v in zip(bars, vals):
        if v is None:
            continue
        a1.text(r.get_x() + r.get_width() / 2, v + 0.008, f"{v:.3f}", ha="center", fontweight="bold")
    d = ep.get("delta_auc30")
    ci = ep.get("delta_ci95")
    if d is not None and vals[0] is not None:
        a1.annotate(
            f"paired Δ {d:+.3f}\n{ci}",
            xy=(0, vals[0]), xytext=(0.7, vals[0] + 0.06),
            fontsize=8, color=NAVY, ha="center",
            arrowprops=dict(arrowstyle="->", color=NAVY, lw=1.1),
        )

    ks = ["0.01", "0.05", "0.1"]
    labels = ["top-1%", "top-5%", "top-10%"]
    rs = ep.get("recall_structural") or {}
    re_ = ep.get("recall_epss") or {}
    struct = [rs.get(k) for k in ks]
    epss = [re_.get(k) for k in ks]
    x = [0, 1, 2]
    w = 0.38
    a2.bar([xi - w / 2 for xi in x], struct, w, color=BLUE, label="Structural (ours)")
    a2.bar([xi + w / 2 for xi in x], epss, w, color=GREEN, label="EPSS (raw)")
    a2.set_xticks(x)
    a2.set_xticklabels(labels)
    a2.set_ylabel("recall @ top-k  (in-wild within 30d)")
    a2.set_title("Recall@top-k (LIVE)")
    a2.legend(fontsize=8, loc="upper left")
    for xi, s, e in zip(x, struct, epss):
        if s is not None:
            a2.text(xi - w / 2, s + 0.008, f"{s:.2f}", ha="center", fontsize=7.5, fontweight="bold")
        if e is not None:
            a2.text(xi + w / 2, e + 0.008, f"{e:.2f}", ha="center", fontsize=7.5, fontweight="bold")

    fig.suptitle(
        f"EPSS parity — LIVE ({ep.get('n_origins')} origins, {ep.get('test_events')} test events)",
        fontsize=12, fontweight="bold", color=NAVY, y=1.02,
    )
    fig.text(0.5, -0.02, f"Source: {ep.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_epss_parity.png")


def fig_operating_points(m: dict) -> None:
    op = (m.get("research") or {}).get("operating_points")
    if not op:
        print("SKIP fig_operating_points.png — no operating_points artifact")
        return
    raw = op["raw"]
    # expect L=0 / L=7 / L=30 keys from scripts/operating_points.py
    keys = [k for k in ("L=0", "L=7", "L=30") if k in raw]
    if len(keys) < 2:
        print("SKIP fig_operating_points.png — unexpected operating_points shape")
        return
    lm = keys
    recall = [raw[k].get("recall_at_top_30") for k in keys]
    lead = [raw[k].get("lead_time_days_median") for k in keys]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.0))
    b1 = a1.bar(lm, recall, color=[GREY, BLUE, GREEN][: len(lm)], width=0.6)
    a1.set_ylabel("recall @ top-30% flagged")
    a1.set_title("Catch-rate by landmark (LIVE)")
    for r, v in zip(b1, recall):
        if v is None:
            continue
        a1.text(r.get_x() + r.get_width() / 2, v + 0.012, f"{v:.0%}", ha="center", fontweight="bold")
    b2 = a2.bar(lm, lead, color=[GREY, BLUE, GREEN][: len(lm)], width=0.6)
    a2.set_ylabel("median lead time (days)")
    a2.set_title("Lead time (LIVE)")
    for r, v in zip(b2, lead):
        if v is None:
            continue
        a2.text(r.get_x() + r.get_width() / 2, v + 4, f"{v:.0f}d", ha="center", fontweight="bold")
    fig.suptitle("Operating points — LIVE", fontsize=12, fontweight="bold", color=NAVY, y=1.02)
    fig.text(0.5, -0.02, f"Source: {op.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_operating_points.png")


def fig_epss_ablation(m: dict) -> None:
    abl = (m.get("research") or {}).get("epss_ablation")
    if not abl:
        print("SKIP fig_epss_ablation.png — no inwild_epss_ablation.json")
        return
    raw = abl["raw"]
    # try common shapes: deltas at 30/90
    mean_delta, lo, hi, horizons = None, None, None, ["AUC@30", "AUC@90"]
    if isinstance(raw, dict) and "horizon_auc" in raw:
        # paired style
        h30 = raw["horizon_auc"].get("30") or raw["horizon_auc"].get(30) or {}
        h90 = raw["horizon_auc"].get("90") or raw["horizon_auc"].get(90) or {}
        mean_delta = [h30.get("mean_delta"), h90.get("mean_delta")]
        lo = [(h30.get("ci95") or [None, None])[0], (h90.get("ci95") or [None, None])[0]]
        hi = [(h30.get("ci95") or [None, None])[1], (h90.get("ci95") or [None, None])[1]]
    if not mean_delta or any(v is None for v in mean_delta):
        print("SKIP fig_epss_ablation.png — could not parse ablation JSON shape")
        return
    fig, ax = plt.subplots(figsize=(6.6, 4.0))
    x = range(len(horizons))
    yerr = [[m_ - l for m_, l in zip(mean_delta, lo)], [h - m_ for m_, h in zip(mean_delta, hi)]]
    ax.bar(x, mean_delta, color=BLUE, width=0.5, yerr=yerr, capsize=8,
           error_kw=dict(elinewidth=2, ecolor=NAVY))
    ax.axhline(0, color="#333", lw=1)
    ax.set_xticks(list(x))
    ax.set_xticklabels(horizons)
    ax.set_ylabel("Δ AUC  (full − EPSS-only)")
    ax.set_title("Cold-start ablation (LIVE)")
    for xi, md, h in zip(x, mean_delta, hi):
        ax.text(xi, h + 0.008, f"{md:+.3f}", ha="center", fontweight="bold")
    fig.text(0.5, -0.02, f"Source: {abl.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_epss_ablation.png")


def fig_vulncheck_lift(m: dict) -> None:
    lift = (m.get("research") or {}).get("vulncheck_lift")
    if not lift:
        print("SKIP fig_vulncheck_lift.png — no vulncheck_lift.json (needs merged label arms)")
        return
    raw = lift["raw"]
    arms = raw.get("arms")
    if not arms:
        print("SKIP fig_vulncheck_lift.png — unexpected vulncheck JSON shape")
        return
    names = [a["name"] for a in arms]
    cidx = [a["c_index"] for a in arms]
    lo = [a["ci_lo"] for a in arms]
    hi = [a["ci_hi"] for a in arms]
    test_ev = [a["test_events"] for a in arms]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.2, 4.2))
    x = range(len(names))
    yerr = [[c - l for c, l in zip(cidx, lo)], [h - c for c, h in zip(cidx, hi)]]
    a1.errorbar(x, cidx, yerr=yerr, fmt="o", color=NAVY, ecolor=BLUE,
                elinewidth=2.4, capsize=7, markersize=9)
    a1.set_xticks(list(x))
    a1.set_xticklabels(names)
    a1.set_ylabel("in-wild c-index  (95% CI)")
    a1.set_title("Label lift (LIVE)")
    bars = a2.bar(names, test_ev, color=[GREY, GREEN, AMBER][: len(names)], width=0.6)
    a2.set_ylabel("in-wild test events")
    for r, v in zip(bars, test_ev):
        a2.text(r.get_x() + r.get_width() / 2, v + 18, str(v), ha="center", fontweight="bold")
    fig.suptitle("VulnCheck label lift — LIVE", fontsize=12, fontweight="bold", color=NAVY, y=1.02)
    fig.text(0.5, -0.02, f"Source: {lift.get('source')} · {m.get('generated_utc', '')}",
             ha="center", fontsize=7, color=GREY, style="italic")
    fig.tight_layout()
    save(fig, "fig_vulncheck_lift.png")


def main() -> None:
    m = load_metrics()
    print(f"Loaded live metrics from {METRICS_PATH} (generated {m.get('generated_utc')})")
    fig_pipeline()
    fig_two_heads(m)
    fig_label_funnel(m)
    fig_patch_race(m)
    fig_causal_forest(m)
    fig_epss_parity(m)
    fig_operating_points(m)
    fig_epss_ablation(m)
    fig_vulncheck_lift(m)
    print("\nFigures written under", FIGDIR)


if __name__ == "__main__":
    main()
