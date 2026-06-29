"""Generate the figures for the temporal-exploit project report.

Run with the venv python:
    .venv/bin/python scripts/build_report_figures.py

Output: docs/figures/*.png  (300 dpi, report-ready).

Every numeric value below is grounded in the repo's artifacts/*.json and docs/*.md
as of 2026-06-23. Sources are named in each figure's caption in the PDF builder.
This script only reads/writes files under the repo; it touches no tokens or network.
"""

from __future__ import annotations

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

REPO = "/home/akim/Coding/Expl"
FIGDIR = os.path.join(REPO, "docs", "figures")
os.makedirs(FIGDIR, exist_ok=True)

# ---- shared palette -------------------------------------------------------
NAVY = "#0b3d91"
BLUE = "#1f6feb"
GREEN = "#347d39"
RED = "#cf222e"
AMBER = "#bf8700"
PURPLE = "#8957e5"
GREY = "#6e7781"
LIGHT = "#f5f7fa"

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


def save(fig, name):
    path = os.path.join(FIGDIR, name)
    fig.savefig(path, facecolor="white")
    plt.close(fig)
    print("WROTE", path)


# ===========================================================================
# 1. PIPELINE FLOW  — the "flow" requirement, as a clean schematic
# ===========================================================================
def fig_pipeline():
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

    # row of stages
    box(1, 26, 16, 9, "EXTERNAL SOURCES\nNVD · KEV · EPSS\nPoC · MSF · Nuclei\n0-day · VulnCheck", GREEN, fs=7.5)
    box(21, 26, 13, 9, "fetch / refresh\n→ live deltas", BLUE)
    box(38, 26, 13, 9, "merge\n(earliest-wins)", PURPLE)
    box(55, 26, 15, 9, "build-dataset\nlabels + features", NAVY)
    box(74, 26, 13, 9, "train /\ncompeting /\nbacktest", RED, fs=8)
    box(91, 26, 8, 9, "metrics\n+ plots", AMBER, fs=8)

    for (x1, x2) in [(17, 21), (34, 38), (51, 55), (70, 74), (87, 91)]:
        arrow(x1, 30.5, x2, 30.5)

    # handover parquets feeding merge
    box(38, 8, 13, 9, "9 handover\nparquets\n(immutable)", "#2d333b", fs=8)
    arrow(44.5, 17, 44.5, 26)

    # outputs under build
    box(55, 8, 15, 9, "4 label sets\n+ feature matrix\n+ manifest", "#444c56", fs=7.5)
    arrow(62.5, 17, 62.5, 26)

    ax.text(50, 41, "Data-flow pipeline — the spine is cli.py (7 subcommands)",
            ha="center", fontsize=12, fontweight="bold", color=NAVY)
    ax.text(50, 2.5,
            "Leakage firewall: build-dataset emits only publication-time-knowable features; "
            "every family is logged in feature_provenance.csv.",
            ha="center", fontsize=8.5, color=GREY, style="italic")
    save(fig, "fig_pipeline.png")


# ===========================================================================
# 2. THE TWO HEADS  — the central diagnostic
# ===========================================================================
def fig_two_heads():
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.2))
    heads = ["In-wild\n(Cox, 251 ev)", "First-weap\n(XGB-AFT, 45,947 ev)"]
    cidx = [0.849, 0.598]
    ipa180 = [-0.001, 0.291]

    b1 = a1.bar(heads, cidx, color=[RED, BLUE], width=0.6)
    a1.axhline(0.5, ls="--", color=GREY, lw=1)
    a1.set_ylim(0, 1.0)
    a1.set_ylabel("IPCW c-index (ranking)")
    a1.set_title("Ranking: in-wild WINS")
    for r, v in zip(b1, cidx):
        a1.text(r.get_x() + r.get_width() / 2, v + 0.02, f"{v:.3f}", ha="center", fontweight="bold")
    a1.text(0.5, 0.43, "chance", color=GREY, fontsize=8, ha="left")

    b2 = a2.bar(heads, ipa180, color=[RED, BLUE], width=0.6)
    a2.axhline(0, color="#333", lw=1)
    a2.set_ylim(-0.1, 0.38)
    a2.set_ylabel("IPA@180 (calibration)")
    a2.set_title("Calibration: first-weap WINS")
    for r, v in zip(b2, ipa180):
        off = 0.012 if v >= 0 else -0.03
        a2.text(r.get_x() + r.get_width() / 2, v + off, f"{v:+.3f}", ha="center", fontweight="bold")

    fig.suptitle("Two heads, two different ceilings — neither set by the model",
                 fontsize=12.5, fontweight="bold", color=NAVY, y=1.02)
    fig.tight_layout()
    save(fig, "fig_two_heads.png")


# ===========================================================================
# 3. VULNCHECK LIFT  — c-index CI narrowing as labels are added
# ===========================================================================
def fig_vulncheck_lift():
    arms = ["CISA-only", "+VulnCheck", "+VulnCheck\n+0day"]
    cidx = [0.870, 0.803, 0.763]
    lo = [0.806, 0.772, 0.740]
    hi = [0.934, 0.834, 0.786]
    test_ev = [106, 637, 1304]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.2, 4.2))
    x = range(len(arms))
    yerr = [[c - l for c, l in zip(cidx, lo)], [h - c for c, h in zip(cidx, hi)]]
    a1.errorbar(x, cidx, yerr=yerr, fmt="o", color=NAVY, ecolor=BLUE,
                elinewidth=2.4, capsize=7, markersize=9)
    a1.set_xticks(list(x))
    a1.set_xticklabels(arms)
    a1.set_ylabel("in-wild c-index  (95% CI)")
    a1.set_ylim(0.70, 0.96)
    a1.set_title("More labels → tighter, honest c-index")
    for xi, c, l, h in zip(x, cidx, lo, hi):
        a1.text(xi + 0.08, c, f"{c:.3f}", va="center", fontsize=9, fontweight="bold")
        a1.text(xi + 0.08, c - 0.028, f"w={h-l:.3f}", va="center", fontsize=7.5, color=GREY)

    bars = a2.bar(arms, test_ev, color=[GREY, GREEN, AMBER], width=0.6)
    a2.set_ylabel("in-wild test events")
    a2.set_title("Usable in-wild events (70/30 split)")
    for r, v in zip(bars, test_ev):
        a2.text(r.get_x() + r.get_width() / 2, v + 18, str(v), ha="center", fontweight="bold")

    fig.suptitle("VulnCheck wiring raises the data ceiling — reliability, not a flashier headline",
                 fontsize=12, fontweight="bold", color=NAVY, y=1.02)
    fig.tight_layout()
    save(fig, "fig_vulncheck_lift.png")


# ===========================================================================
# 4. OPERATING POINTS  — recall@top-decile & lead time across landmarks
# ===========================================================================
def fig_operating_points():
    lm = ["L=0\n(disclosure)", "L=7d", "L=30d"]
    recall = [0.284, 0.336, 0.488]
    lead = [143.5, 185.25, 226.25]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.0))
    b1 = a1.bar(lm, recall, color=[GREY, BLUE, GREEN], width=0.6)
    a1.set_ylabel("recall @ top-30% flagged")
    a1.set_ylim(0, 0.6)
    a1.set_title("Catch-rate rises with a short watch window")
    for r, v in zip(b1, recall):
        a1.text(r.get_x() + r.get_width() / 2, v + 0.012, f"{v:.0%}", ha="center", fontweight="bold")

    b2 = a2.bar(lm, lead, color=[GREY, BLUE, GREEN], width=0.6)
    a2.set_ylabel("median lead time (days)")
    a2.set_title("Lead time before in-wild exploitation")
    for r, v in zip(b2, lead):
        a2.text(r.get_x() + r.get_width() / 2, v + 4, f"{v:.0f}d", ha="center", fontweight="bold")

    fig.suptitle("Operational value: a calibrated head-start EPSS cannot give",
                 fontsize=12, fontweight="bold", color=NAVY, y=1.02)
    fig.tight_layout()
    save(fig, "fig_operating_points.png")


# ===========================================================================
# 5. CAUSAL HR FOREST  — what causally accelerates weaponization
# ===========================================================================
def fig_causal_forest():
    # (label, adjusted HR, ci_lo, ci_hi, verdict_color)
    rows = [
        ("wormable\n(AV:N/PR:N/UI:N/AC:L)", 1.293, 1.277, 1.310, GREEN),
        ("unauth-network\nhigh-impact", 1.240, 1.220, 1.250, GREEN),
        ("ATT&CK-chain\nmapped", 0.970, 0.960, 0.990, RED),
    ]
    fig, ax = plt.subplots(figsize=(8.8, 3.9))
    ys = range(len(rows))
    for y, (lab, hr, lo, hi, col) in zip(ys, rows):
        ax.plot([lo, hi], [y, y], color=col, lw=3, solid_capstyle="round")
        ax.plot(hr, y, "o", color=col, markersize=11)
        ax.text(hi + 0.025, y, f"HR {hr:.2f} [{lo:.2f}, {hi:.2f}]", va="center", fontsize=9.5, fontweight="bold")
    ax.axvline(1.0, ls="--", color="#333", lw=1.4)
    ax.text(1.0, 2.62, "no effect", color="#333", fontsize=8, ha="center")
    ax.set_yticks(list(ys))
    ax.set_yticklabels([r[0] for r in rows])
    ax.set_ylim(-0.55, 2.75)
    ax.set_xlim(0.85, 1.58)
    ax.set_xlabel("Adjusted hazard ratio  (HR > 1 = faster weaponization)")
    ax.set_title("Causal acceleration of weaponization (adjusted Cox, n=313,847)", pad=22)
    ax.text(1.575, -0.42, "wormable: E-value 1.68 · raw median 100d vs 277d",
            fontsize=8, color=GREEN, ha="right", style="italic")
    ax.text(0.905, 2.0, "positivity\nviolated →\nestimate refused", fontsize=7.5,
            color=RED, va="center", ha="left")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    save(fig, "fig_causal_forest.png")


# ===========================================================================
# 6. PATCH-VS-EXPLOIT RACE  — pre-disclosure weaponization + external check
# ===========================================================================
def fig_patch_race():
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.4, 4.0))

    labels = ["First-weap\n(ours)", "In-wild\n(ours)", "VulnCheck\n2025 KEVs"]
    pct = [28.6, 35.5, 28.96]
    cols = [BLUE, RED, GREY]
    b = a1.bar(labels, pct, color=cols, width=0.6)
    a1.set_ylabel("% exploited on/before CVE publication")
    a1.set_ylim(0, 42)
    a1.set_title("Exploit beats disclosure ~⅓ of the time")
    for r, v in zip(b, pct):
        a1.text(r.get_x() + r.get_width() / 2, v + 0.7, f"{v:.1f}%", ha="center", fontweight="bold")
    a1.annotate("independent\nexternal match", xy=(0, 28.6), xytext=(0.0, 38),
                fontsize=7.5, color=GREEN, ha="center",
                arrowprops=dict(arrowstyle="->", color=GREEN, lw=1.2))
    a1.annotate("", xy=(2, 28.96), xytext=(0.15, 37.4),
                arrowprops=dict(arrowstyle="->", color=GREEN, lw=1.2))

    # the bimodal race
    cohorts = ["OSS coordinated-\ndisclosure (n≈11k)", "0-days\n(Proj Zero, n=132)"]
    before = [0.5, 100.0]
    b2 = a2.bar(cohorts, before, color=[GREEN, RED], width=0.6)
    a2.set_ylabel("% exploited BEFORE patch")
    a2.set_ylim(0, 108)
    a2.set_title("The race is bimodal")
    for r, v in zip(b2, before):
        a2.text(r.get_x() + r.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontweight="bold")
    a2.text(0, 12, "fix lands\nmedian 14d\nBEFORE CVE", fontsize=7.5, color=GREEN, ha="center")
    a2.text(1, 60, "median 9d\ndiscovery→patch", fontsize=7.5, color="white", ha="center")

    fig.suptitle("Patch-vs-exploit race — the unbiased signal is pre-disclosure weaponization",
                 fontsize=11.5, fontweight="bold", color=NAVY, y=1.02)
    fig.tight_layout()
    save(fig, "fig_patch_race.png")


# ===========================================================================
# 7. LABEL FUNNEL  — weaponization funnel + the false-censoring gap
# ===========================================================================
def fig_label_funnel():
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 4.0))

    stages = ["All CVEs", "Any signal", "Public PoC", "In-wild\nlabeled"]
    vals = [359507, 169941, 168744, 4971]
    cols = ["#2d333b", BLUE, PURPLE, RED]
    b = a1.barh(range(len(stages))[::-1], vals, color=cols, height=0.62)
    a1.set_yticks(range(len(stages))[::-1])
    a1.set_yticklabels(stages)
    a1.set_xscale("log")
    a1.set_xlabel("CVEs (log scale)")
    a1.set_title("The weaponization funnel")
    pcts = ["100%", "47.3%", "46.9%", "1.38%"]
    for r, v, pc in zip(b, vals, pcts):
        a1.text(v * 1.15, r.get_y() + r.get_height() / 2, f"{v:,}  ({pc})",
                va="center", fontsize=8.5, fontweight="bold")
    a1.set_xlim(1e3, 2e6)

    # false-censoring: labeled vs unlabeled high-EPSS mass
    grp = ["Labeled\nin-wild set", "Calibrated unlabeled\nexploitation (EPSS)"]
    mass = [4971, 9046]
    b2 = a2.bar(grp, mass, color=[RED, AMBER], width=0.55)
    a2.set_ylabel("expected # exploited CVEs")
    a2.set_title("False-censoring: EPSS sees ~2× more")
    a2.set_ylim(0, 10500)
    for r, v in zip(b2, mass):
        a2.text(r.get_x() + r.get_width() / 2, v + 200, f"{v:,}", ha="center", fontweight="bold")

    fig.suptitle("Why the in-wild target is hard: 1.38% base rate + material false-censoring",
                 fontsize=11.5, fontweight="bold", color=NAVY, y=1.02)
    fig.tight_layout()
    save(fig, "fig_label_funnel.png")


# ===========================================================================
# 8. EPSS ABLATION  — full features vs EPSS-only (paired, walk-forward)
# ===========================================================================
def fig_epss_ablation():
    horizons = ["AUC@30", "AUC@90"]
    mean_delta = [0.176, 0.173]
    lo = [0.112, 0.116]
    hi = [0.239, 0.230]
    fig, ax = plt.subplots(figsize=(6.6, 4.0))
    x = range(len(horizons))
    yerr = [[m - l for m, l in zip(mean_delta, lo)], [h - m for m, h in zip(mean_delta, hi)]]
    ax.bar(x, mean_delta, color=BLUE, width=0.5, yerr=yerr, capsize=8,
           error_kw=dict(elinewidth=2, ecolor=NAVY))
    ax.axhline(0, color="#333", lw=1)
    ax.set_xticks(list(x))
    ax.set_xticklabels(horizons)
    ax.set_ylabel("Δ AUC  (full features − EPSS-only)")
    ax.set_title("At t=0 (cold-start), structured features beat EPSS")
    for xi, m, h in zip(x, mean_delta, hi):
        ax.text(xi, h + 0.008, f"+{m:.3f}", ha="center", fontweight="bold")
    ax.set_ylim(0, 0.27)
    fig.tight_layout()
    save(fig, "fig_epss_ablation.png")


if __name__ == "__main__":
    fig_pipeline()
    fig_two_heads()
    fig_vulncheck_lift()
    fig_operating_points()
    fig_causal_forest()
    fig_patch_race()
    fig_label_funnel()
    fig_epss_ablation()
    print("\nAll figures written to", FIGDIR)
