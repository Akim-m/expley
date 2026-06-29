"""Render the temporal-exploit project report to PDF (reportlab/platypus).

Professor-meeting edition, 2026-06-23. Consolidates the project report (with
graphs) AND the architecture flow + feature catalog into one document.

Run with the venv python:
    .venv/bin/python scripts/build_report_figures.py            # first: make figures
    .venv/bin/python scripts/build_project_report_pdf_2026-06-23.py

Output: docs/project_report_2026-06-23.pdf

Every quantitative claim is grounded in the repo's docs + artifacts/*.json as of
2026-06-23. This script only reads/writes files under the repo; it touches no tokens.
"""

from __future__ import annotations

import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

REPO = "/home/akim/Coding/Expl"
OUT_PDF = os.path.join(REPO, "docs", "project_report_2026-06-23.pdf")
PAGE_W_INNER = 6.5 * inch
DATESTR = "2026-06-23"

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
styles = getSampleStyleSheet()
TITLE = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=24, leading=28,
                       spaceAfter=6, textColor=colors.HexColor("#0b3d91"))
SUBTITLE = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=12, leading=16,
                          textColor=colors.HexColor("#555555"), spaceAfter=2)
H1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16, leading=20,
                    spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#0b3d91"))
H2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12.5, leading=16,
                    spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#1f4e79"))
BODY = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=10, leading=14.5,
                      alignment=TA_LEFT, spaceAfter=6)
BULLET = ParagraphStyle("Bullet", parent=BODY, leftIndent=16, bulletIndent=4, spaceAfter=3)
MONO = ParagraphStyle("Mono", parent=styles["Code"], fontName="Courier", fontSize=8.2, leading=10.5,
                      backColor=colors.HexColor("#f3f4f6"), borderPadding=4, spaceAfter=6,
                      textColor=colors.HexColor("#111111"))
CAPTION = ParagraphStyle("Caption", parent=styles["Italic"], fontSize=8.5, leading=11,
                         textColor=colors.HexColor("#555555"), spaceBefore=2, spaceAfter=12)
KEYFINDING = ParagraphStyle("KeyFinding", parent=BODY, backColor=colors.HexColor("#fff7e6"),
                            borderColor=colors.HexColor("#e0a800"), borderWidth=0.8, borderPadding=8,
                            leftIndent=2, rightIndent=2, spaceBefore=6, spaceAfter=10)

story = []


def h1(t): story.append(Paragraph(t, H1))
def h2(t): story.append(Paragraph(t, H2))
def p(t): story.append(Paragraph(t, BODY))
def key(t): story.append(Paragraph(t, KEYFINDING))
def spacer(h=6): story.append(Spacer(1, h))
def mono(t): story.append(Paragraph(t.replace(" ", "&nbsp;").replace("\n", "<br/>"), MONO))


def bullets(items):
    for it in items:
        story.append(Paragraph("•&nbsp;&nbsp;" + it, BULLET))
    story.append(Spacer(1, 4))


def image(rel_path, caption, width=PAGE_W_INNER):
    abspath = os.path.join(REPO, rel_path)
    if not os.path.exists(abspath):
        story.append(Paragraph(f"[plot missing: {rel_path}]", CAPTION))
        return
    from reportlab.lib.utils import ImageReader
    iw, ih = ImageReader(abspath).getSize()
    aspect = ih / float(iw)
    img = Image(abspath, width=width, height=width * aspect)
    img.hAlign = "CENTER"
    story.append(img)
    story.append(Paragraph(caption, CAPTION))


def make_table(data, col_widths=None, header=True, font=8.5):
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    ts = [
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8ccd0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
    ]
    if header:
        ts += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
               ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
               ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    t.setStyle(TableStyle(ts))
    story.append(t)
    story.append(Spacer(1, 8))


# ===========================================================================
# COVER
# ===========================================================================
story.append(Spacer(1, 50))
story.append(Paragraph("Temporal Exploit Prediction", TITLE))
story.append(Paragraph("Predicting <i>when</i> a CVE becomes weaponized — a survival-analysis modeling layer", SUBTITLE))
story.append(Spacer(1, 10))
story.append(Paragraph(f"Project report &amp; technical overview &middot; {DATESTR}", SUBTITLE))
story.append(Spacer(1, 22))
key(
    "<b>The one sentence to take away:</b> the in-the-wild prediction ceiling is "
    "<b>DATA-limited, not model-limited</b>. Across the full survival toolbox "
    "(Cox, Random Survival Forest, gradient boosting, XGBoost-AFT, mixture-cure, "
    "DeepSurv/DeepHit) <b>nothing beats a penalized Cox</b> at the ~250&ndash;400 confirmed "
    "in-wild events available — so the achievable win is more / earlier <i>labels</i>, "
    "which is exactly what the VulnCheck wiring delivered."
)
story.append(Spacer(1, 12))
p(
    "This document consolidates two things: the <b>project report with figures</b>, and a "
    "<b>technical overview of the pipeline flow and feature set</b> (sections&nbsp;3&ndash;5 and the "
    "appendices). Every headline number names its source artifact "
    "(<font face='Courier' size=8>artifacts/*.json</font>) or living doc "
    "(<font face='Courier' size=8>docs/*.md</font>) so it can be re-checked."
)
story.append(Spacer(1, 8))
p(
    "<b>Contents.</b> 1 Executive summary &middot; 2 Problem &amp; framing &middot; 3 Data &amp; "
    "architecture &middot; 4 Leakage-safety &middot; 5 Feature catalog &middot; 6 Models &middot; "
    "7 Metrics &middot; 8 The central finding &middot; 9 VulnCheck wiring &middot; "
    "10 Operational value &middot; 11 Cold-start vs EPSS &middot; 12 Causal characterization &middot; "
    "13 Patch-vs-exploit race &middot; 14 Label completeness &middot; 15 Roadmap &middot; "
    "16 Current state. Appendices: module reference, feature provenance."
)
story.append(PageBreak())

# ===========================================================================
# 1. EXECUTIVE SUMMARY
# ===========================================================================
h1("1. Executive Summary")
p(
    "This project is a <b>survival-analysis modeling layer</b> that predicts <b>when</b> a "
    "published CVE becomes publicly weaponized — a time-to-event problem — built on a "
    "pre-extracted, multi-source CVE timeline dataset (~338,000 CVEs). It is deliberately "
    "positioned as a <b>complement</b> to EPSS, not a competitor: EPSS answers “will this be "
    "exploited in the wild in the next 30 days?” as a fixed-window binary; this project "
    "characterizes the upstream <i>weaponization pipeline timing</i> (PoC &rarr; Metasploit / "
    "Nuclei &rarr; KEV / 0-day) and produces a calibrated time-to-event curve EPSS structurally "
    "cannot give."
)
p("<b>What was built.</b>")
bullets([
    "A leakage-safe dataset builder (four label sets: first-weaponization, per-signal, "
    "competing-risks, in-wild) over nine immutable handover parquets, with a feature-provenance "
    "audit trail and a content-hashed manifest.",
    "Models spanning the survival toolbox: Kaplan-Meier, penalized Cox PH, Random Survival Forest, "
    "GPU XGBoost-AFT, mixture-cure, DeepSurv/DeepHit, plus a competing-risks / Aalen-Johansen core.",
    "Rare-event-appropriate evaluation: IPCW c-index with bootstrap CIs, time-dependent AUC(t), "
    "PR-AUC, Brier/IPA, decision-curve net-benefit, and a rolling-origin (walk-forward) backtest.",
    "A <b>causal layer</b> (adjusted Cox + stabilized IPW + E-values) characterizing what "
    "<i>accelerates</i> weaponization, and a <b>patch-vs-exploit race</b> analysis.",
    "Live-fetch connectors for every documented source (CISA KEV, EPSS, NVD, Exploit-DB, PoC, "
    "Nuclei, Metasploit, Project Zero, VulnCheck KEV, MSRC, Shadowserver) and a merge layer.",
    "<b>337 tests</b> collected and green; memory held inside the &le;6&ndash;8&nbsp;GB budget on every path.",
])
p("<b>The single most important finding.</b>")
key(
    "The in-the-wild head is <b>data-limited</b>. On ~251&ndash;396 confirmed in-wild events the Cox "
    "model <b>ranks well</b> (c-index / AUC@90 &asymp; 0.82&ndash;0.85) but its absolute probabilities "
    "<b>do not beat the base-rate null</b> (IPA &asymp; 0) — and no fancier model improves on this. "
    "By contrast the first-weaponization head trains on <b>45,947 events</b>: there calibration works "
    "(IPA@180 = <b>+0.291</b>) but ranking is weak (c-index &asymp; <b>0.60</b>) because the target is "
    "mostly PoC/disclosure logistics. <b>Two heads, two different limits — neither is the model.</b>"
)

# ===========================================================================
# 2. THE PROBLEM & FRAMING
# ===========================================================================
h1("2. The Problem &amp; Framing")
p(
    "<b>The question.</b> After a CVE is published, <i>when</i> does public exploitation capability "
    "appear? The clock origin is <font face='Courier' size=8>cve_corpus.published</font>; the event is "
    "the earliest dated signal across five sources; CVEs with no signal are right-censored at the "
    "snapshot date. This is classic right-censored survival analysis, and the framing is itself a "
    "contribution: the field overwhelmingly treats exploitation as repeated 30-day binary "
    "classification (EPSS), while explicit time-to-event modeling of weaponization is "
    "under-explored (CERT/SEI 2020; Farris 2017)."
)
key(
    "<b>CRITICAL framing caveat.</b> Of all observed first-weaponization events, <b>~97% are "
    "public-PoC dates</b>. Only CISA KEV (<font face='Courier' size=8>kev_date_added</font>) and "
    "Google Project Zero 0-day are true in-the-wild signals — historically a few hundred events. "
    "<b>Any model trained on first-weaponization labels predicts time-to-public-tooling, NOT "
    "in-the-wild exploitation.</b> Keeping these two targets distinct is the backbone of every honest "
    "claim in this report."
)
p("<b>The three distinct prediction targets, and why each exists.</b>")
bullets([
    "<b>First-weaponization</b> (45,947 events) — earliest of PoC / Metasploit / Nuclei / KEV / "
    "0-day. Abundant, so it powers calibration and is where ML models can be exercised; but the "
    "target is dominated by PoC logistics, so ranking is intrinsically weak.",
    "<b>In-wild</b> (KEV + Google 0-day + VulnCheck; PoC excluded) — the project's meaningful target: "
    "actual exploitation, not tooling availability. Rare (251&ndash;396 events before VulnCheck), so it is "
    "the head whose ceiling is data-limited.",
    "<b>PoC &rarr; downstream transition heads</b> — reusable machinery to model the conditional "
    "escalation from a public PoC to genuine tooling (Metasploit / KEV), the deployable triage signal.",
])

# ===========================================================================
# 3. DATA & ARCHITECTURE  (the "flow")
# ===========================================================================
h1("3. Data &amp; Architecture (the Flow)")
p(
    "<b>Two strictly separated layers</b> — a deliberate reproducibility decision so modeling "
    "changes can never corrupt the source material:"
)
bullets([
    "<b>Immutable handover / extraction</b> — the VRS-MongoDB extraction + enrichment scripts that "
    "produced nine parquet files. Read-only reproducibility material.",
    "<b>The modeling package</b> (<font face='Courier' size=8>src/temporal_exploit/</font>) — the "
    "code developed here. It reads the handover parquets, <i>never</i> writes to them; all outputs go "
    "to a gitignored <font face='Courier' size=8>artifacts/</font> dir.",
])
image("docs/figures/fig_pipeline.png",
      "Figure 1. The data-flow pipeline. The spine is cli.py with seven subcommands; "
      "build-dataset is the integration hub that emits four label sets, the feature matrix, and a "
      "content-hashed manifest. Source: docs/architecture_flow.md.")
p("<b>The nine handover sources</b> (all wired into the dataset):")
make_table([
    ["Source", "Parquet", "Role"],
    ["CVE corpus (NVD/VulnCheck)", "cve_corpus", "Features + clock origin (published)"],
    ["PoC (Trickest + Nomi-sec)", "poc_dates", "Event source (~97% of first-weap events)"],
    ["Metasploit", "metasploit_dates", "Event source / per-signal target"],
    ["Nuclei", "nuclei_dates", "Event source / per-signal target"],
    ["CISA KEV", "kev_events", "Event source + primary in-wild label"],
    ["Google 0-day", "google_0day", "Event source + in-wild label"],
    ["EPSS history (375M rows)", "epss_history", "EPSS-at-publication feature (leakage-safe)"],
    ["ATT&CK chain", "technique_cwe_chain", "Tactic/technique one-hot features"],
    ["VRS presence", "vrs_presence", "Snapshot-only, leakage-flagged (kept separate)"],
], col_widths=[1.9 * inch, 1.5 * inch, 3.1 * inch])
p(
    "The <b>EPSS history is 375M rows / 3.7&nbsp;GB</b> (one row group per day). It is read by streaming "
    "<font face='Courier' size=8>iter_batches</font> + a fixed-size per-CVE numpy reduction "
    "(~0.6&nbsp;GB peak) — a hard-won decision: an earlier pyarrow "
    "<font face='Courier' size=8>isin(cve_ids)</font> pushdown retained ~5.8&nbsp;GB and breached the "
    "memory budget. The only safe pushdown is by <i>date</i>."
)

# ===========================================================================
# 4. LEAKAGE-SAFETY
# ===========================================================================
h1("4. Leakage-Safety Decisions (and Why Each Matters)")
p(
    "These are non-negotiable; they are <i>how the results stay valid</i>. Each excludes a concrete "
    "failure mode that would silently inflate apparent performance."
)
bullets([
    "<b>Exclude the CVE description text.</b> NVD <i>back-edits</i> descriptions after the event with "
    "phrases like “actively exploited” / “CISA” / “KEV” — pure temporal leakage. The masked, "
    "freshness-gated NLP path exists but is opt-in and off by default.",
    "<b>Exclude snapshot-time presence flags</b> (<font face='Courier' size=8>vrs_presence</font>): "
    "whether a source <i>eventually</i> listed the CVE is knowledge from the future — a near-perfect "
    "leak. Kept in a separate, leakage-flagged parquet.",
    "<b>Exclude snapshot-time EPSS.</b> Today's EPSS for an old CVE leaks the future (the literature "
    "quantifies the look-ahead: 2023 efficiency collapses 60.9% &rarr; 11.1% when scored honestly). Only "
    "the <i>first EPSS reading after publication</i> is used.",
    "<b>Time-based splits, never random K-fold.</b> A model is only ever evaluated on CVEs published "
    "later than those it trained on.",
    "<b>The feature_provenance() audit trail.</b> Every emitted feature family gets a row with its "
    "source column and a leakage_status — adding a feature requires justifying its status.",
    "<b>Timezone discipline.</b> All date columns are "
    "<font face='Courier' size=8>timestamp[ns, tz=UTC]</font>; mixing tz-aware and naive raises on "
    "subtraction — surfacing the bug rather than producing wrong durations.",
])
p(
    "<b>A real near-miss this discipline caught:</b> wrong schema column names "
    "(<font face='Courier' size=8>cvss_v3_base_score</font> vs "
    "<font face='Courier' size=8>cvss_v3_base</font>) silently produced <i>all-zero features</i> "
    "before they were caught — which is why the builder now fails loudly on missing required columns."
)

# ===========================================================================
# 5. FEATURE CATALOG  (the "features")
# ===========================================================================
h1("5. Feature Catalog")
p(
    "Features are grouped by <b>leakage status</b>. Only the publication-time-safe family is on by "
    "default; landmark and transition families are opt-in and require a matching clock restart; the "
    "snapshot family is deliberately excluded from the safe matrix (kept only for leakage audits). "
    "Source: <font face='Courier' size=8>artifacts/feature_provenance.csv</font> (37 families)."
)
make_table([
    ["Family", "Examples", "Status / when usable"],
    ["Severity & structure", "cvss_v3_base (+missing), severity one-hots,\nCVSS v3 vector components (AV/AC/PR/UI/S/C/I/A)",
     "publication-safe (default)"],
    ["Weakness & surface", "cwe_* one-hots, weakness_count, has_weakness,\nvendor_count, product_count",
     "publication-safe (default)"],
    ["ATT&CK chain", "has_attack_chain_mapping, attack_technique_count,\nattack_parent_* (CWE→CAPEC→ATT&CK)",
     "publication-safe (default)"],
    ["EPSS at publication", "epss_at_publication, epss_percentile_at_publication,\nepss_at_publication_missing",
     "publication-safe (first reading ≥ published)"],
    ["Landmark (L=7/30d)", "poc/metasploit/nuclei by/count/lag,\nepss_at_landmark (+pct/missing)",
     "landmark-safe — only with restart_clock(L)"],
    ["PoC→tooling transition", "transition labels + counts for PoC→{MSF, Nuclei, KEV}",
     "transition-safe (post-PoC clock)"],
    ["Snapshot (EXCLUDED)", "vrs_presence flags, snapshot EPSS,\nback-edited description text",
     "leakage-flagged — NOT in the safe matrix"],
], col_widths=[1.35 * inch, 3.25 * inch, 1.9 * inch])
key(
    "<b>The point of the catalog:</b> a feature is admissible only if its value is knowable at the "
    "moment the clock starts. “Publication-safe” means knowable at disclosure; “landmark-safe” means "
    "knowable at disclosure&nbsp;+&nbsp;L days <i>and</i> the model clock has been restarted to that landmark. "
    "Pairing a landmark feature with an unshifted clock would leak post-publication time — so the "
    "provenance status and the clock are checked together."
)

# ===========================================================================
# 6. MODELS & WHY
# ===========================================================================
story.append(PageBreak())
h1("6. Models &amp; Why")
p(
    "The model question was settled empirically (a prospective bake-off) and against the literature, "
    "not by preference: <b>penalized Cox is the in-wild backbone; everything fancier is a challenger "
    "that must earn its place prospectively, and so far none has.</b>"
)
h2("6.1 The classical backbone")
bullets([
    "<b>Kaplan-Meier</b> — the unconditional reference and the null any model must beat.",
    "<b>Cox PH (penalized, lifelines)</b> — the in-wild backbone. Ridge shrinkage handles the "
    "borderline events-per-variable (~9.5 EPV); the penalizer is scaled by the event rate (undoing "
    "~24&times; over-shrinkage on the rare target) with escalation on non-convergence.",
])
h2("6.2 The challengers, and why Cox won for in-wild")
make_table([
    ["Model", "AUC@90 (mean)", "sd", "recall@top-10%", "IPA@90", "fit time"],
    ["Cox (penalized)", "0.817", "0.069", "0.51", "-0.003", "78 s"],
    ["Random Survival Forest", "0.770", "0.117", "0.42", "-0.016", "384 s"],
    ["Gradient-boosted (sksurv)", "0.710", "0.093", "0.40", "-0.001", "362 s*"],
    ["Mixture-cure", "overturned", "—", "harmful", "-0.27 @180d", "—"],
], col_widths=[1.7 * inch, 1.1 * inch, 0.5 * inch, 1.1 * inch, 0.9 * inch, 0.8 * inch])
p(
    "<font size=8>* sksurv Cox-loss GBM is O(n&sup2;) per tree — only tractable after subsampling, "
    "which discards scarce events. Source: artifacts/inwild_headtohead.json "
    "(paired gbm&minus;cox AUC@90 = &minus;0.107, CI [&minus;0.154, &minus;0.061], excludes 0).</font>"
)
bullets([
    "<b>Why this matches the literature.</b> A neutral 34-dataset / 21-model benchmark finds <i>no "
    "method significantly outperforms Cox</i> on tabular survival (Burk et al. 2026); boosting needs "
    "&ge;600 events and transformers &ge;1,200 to beat Cox (Rossi et al. 2025). At ~396 events we are "
    "firmly in Cox's territory.",
    "<b>DeepSurv / DeepHit</b> are disqualified at this event count — which is also why the GPU sits "
    "idle for in-wild: Cox is CPU by design and is the best model.",
    "<b>XGBoost-AFT</b> is the headline ranker for the <i>abundant</i> first-weaponization target "
    "(c-index 0.598 vs Cox 0.565), where a tree model has enough data to shine.",
])
key(
    "<b>Mixture-cure is a documented dead-end — do not revive without a Kaplan-Meier plateau.</b> "
    "It briefly looked like the only in-wild model with positive IPA on one split, but the "
    "rolling-origin backtest overturned it (IPA@180 &rarr; &minus;0.27). The cause is theoretical: a cure "
    "fraction is only identifiable when the KM curve plateaus above zero, and our ~99.5%-censored "
    "target is <i>administratively</i> censored, not a cured population. The flat tail is missing "
    "follow-up, not immunity."
)

# ===========================================================================
# 7. METRICS
# ===========================================================================
h1("7. Metrics &amp; Why (Proper Rare-Event Evaluation)")
p(
    "At a &lt;1.5% base rate the standard accuracy/ROC-AUC instincts mislead. The evaluation panel "
    "measures the right things under heavy, potentially-informative censoring."
)
bullets([
    "<b>IPCW c-index + bootstrap CIs.</b> The truncated-at-&tau; variant equals Uno's C under "
    "administrative censoring; bootstrap CIs + paired deltas vs Cox replace single point estimates.",
    "<b>Time-dependent AUC(t) with IPCW.</b> Discrimination at each fixed horizon, reweighting rather "
    "than dropping censored rows.",
    "<b>PR-AUC over ROC-AUC.</b> Under &lt;1% imbalance ROC-AUC looks great while the model is useless "
    "on the minority; PR-AUC exposes the true positive yield.",
    "<b>Brier / IPA for calibration.</b> IPA = scaled Brier vs the train-KM null — does the "
    "<i>absolute</i> probability beat the base rate?",
    "<b>Decision-curve net-benefit.</b> Measured: the in-wild model beats both treat-all and "
    "treat-none across the realistic 0.1&ndash;3% threshold band "
    "(artifacts/inwild_decision_curve.json) — useful, but modestly.",
    "<b>Rolling-origin (walk-forward) backtest.</b> Each origin trains only on what was knowable then "
    "and scores the next period — the honest temporal-validation discipline.",
])
p(
    "<b>Calibration in practice — the two heads diverge sharply.</b> On the rare in-wild target the "
    "Cox reliability plot is nearly degenerate (predictions cluster at the base rate; little spread "
    "to calibrate). On the abundant first-weaponization target the XGBoost-AFT plot shows real, if "
    "imperfect, calibration across the full 0&ndash;1 range."
)
image("artifacts/reports/inwild_cox_7030/calibration_cox.png",
      "Figure 2. In-wild Cox calibration (70/30 split). Predicted risk barely separates from the "
      "base rate — almost nothing to calibrate at ~100 test events. "
      "Source: artifacts/reports/inwild_cox_7030/metrics.json.", width=4.7 * inch)
image("artifacts/reports/firstweap_xgb_7030/calibration_xgb.png",
      "Figure 3. First-weaponization XGBoost-AFT calibration (70/30 split). Predictions span the full "
      "range with meaningful reliability — abundance enables calibration. "
      "Source: artifacts/reports/firstweap_xgb_7030/metrics.json.", width=4.7 * inch)

# ===========================================================================
# 8. THE CENTRAL FINDING
# ===========================================================================
story.append(PageBreak())
h1("8. The Central Finding — a DATA-Limited Ceiling")
p(
    "The most important conclusion is that the in-wild ceiling is set by <b>how many confirmed "
    "in-wild events exist</b>, not by model choice. The evidence is a contrast between the two heads "
    "at the same 2024-01-01 cutoff:"
)
make_table([
    ["", "In-wild (Cox)", "First-weaponization (XGB-AFT)"],
    ["Events", "251", "45,947"],
    ["c-index (IPCW)", "0.849", "0.598"],
    ["Ranking quality", "strong (AUC@90 ≈ 0.87)", "weak (≈ 0.60)"],
    ["IPA@90 / @180", "≈ 0 (slightly negative)", "+0.176 / +0.291"],
    ["Calibration", "cannot (nothing to fit)", "works"],
    ["Binding constraint", "data scarcity", "target noise (PoC logistics)"],
], col_widths=[1.9 * inch, 2.1 * inch, 2.5 * inch])
image("docs/figures/fig_two_heads.png",
      "Figure 4. The two-heads diagnostic. The rare in-wild head ranks well but has no calibration "
      "headroom; the abundant first-weaponization head calibrates well but ranks weakly. Two "
      "different ceilings, neither set by the model. Sources: artifacts/reports/inwild_cox/metrics.json, "
      "firstweap_xgb/metrics.json.")
key(
    "Read the two heads together and the diagnosis is unambiguous: where data is abundant "
    "<i>calibration works</i> — so IPA&asymp;0 on in-wild is not a calibration bug. Where ranking is "
    "possible <i>data is scarce</i> — so weak first-weap ranking is target noise, not scarcity. Each "
    "head is limited by a different thing, and neither limit is the model. Corroborated three ways: "
    "every alternative model measured &le; Cox prospectively; ~9.5 EPV says the remedy is "
    "penalization (done), not a bigger model; neutral benchmarks need 600&ndash;1,200 events to beat Cox."
)

# ===========================================================================
# 9. VULNCHECK WIRING
# ===========================================================================
h1("9. VulnCheck Wiring — Raising the Ceiling")
p(
    "Because the ceiling is data-limited, the highest-leverage action is more / earlier in-wild "
    "<i>labels</i>. The VulnCheck KEV catalog (~173% larger than CISA KEV, ~27 days earlier, using "
    "first-reported-<i>evidence</i> dates) was fetched and wired end-to-end."
)
image("docs/figures/fig_vulncheck_lift.png",
      "Figure 5. VulnCheck lift on a 70/30 in-wild split. Adding VulnCheck takes test events "
      "106 → 637, roughly halves the c-index CI (width 0.128 → 0.062), and turns IPA@90 positive "
      "(3.3e-05 → 0.0070). The point estimate dropping 0.87 → 0.80 is small-sample optimism being "
      "corrected. Source: artifacts/reports/inwild_full_wiring.json.")
key(
    "<b>Interpretation:</b> more data buys a more <i>trustworthy</i> model, not a flashier headline. "
    "The c-index settles honestly near <b>0.80</b>, the CI halves, and calibration becomes real "
    "(IPA &gt; 0). A tighter interval and genuine calibration are the right kind of win for a "
    "rare-event model — reliability, not over-claim."
)

# ===========================================================================
# 10. OPERATIONAL VALUE
# ===========================================================================
h1("10. Operational Value — Catch-Rate and Lead Time")
p(
    "For a defender the model's worth is operational: of the CVEs it flags as highest-risk, how many "
    "of the eventual in-wild exploitations does it catch, and how much head-start does it give? A "
    "short watch window (landmark L) sharply improves both. Source: artifacts/operating_points.json."
)
image("docs/figures/fig_operating_points.png",
      "Figure 6. Operating points across landmarks. Flagging the top 30% by risk catches 28% of "
      "in-wild exploitations at disclosure (L=0), rising to 49% if you wait 30 days (L=30) — with a "
      "median 144–226 day head-start before exploitation. Source: artifacts/operating_points.json.")

# ===========================================================================
# 11. COLD-START vs EPSS
# ===========================================================================
h1("11. Where the Model Beats EPSS — the Cold-Start Regime")
p(
    "EPSS is near-chance and ~48% missing at disclosure. The defensible value proposition is the "
    "<b>t=0 cold-start in-wild head</b>: with structured publication-time features the model "
    "out-discriminates EPSS-only at exactly the moment a defender has nothing else to go on."
)
image("docs/figures/fig_epss_ablation.png",
      "Figure 7. Full features vs EPSS-only at disclosure, paired across 14 walk-forward origins. "
      "Structured features add +0.17 AUC at both 30- and 90-day horizons, winning in 93% of origins. "
      "Source: artifacts/inwild_epss_ablation.json.", width=4.6 * inch)

# ===========================================================================
# 12. CAUSAL CHARACTERIZATION
# ===========================================================================
story.append(PageBreak())
h1("12. Causal Characterization — What <i>Accelerates</i> Weaponization")
p(
    "Beyond prediction, a causal layer asks which CVE properties <i>cause</i> faster weaponization. "
    "It uses an adjusted Cox + stabilized inverse-probability weighting with overlap/positivity "
    "diagnostics and the VanderWeele-Ding E-value (unmeasured-confounding robustness). Confounders "
    "are pre-treatment common causes only — deliberately not the CVSS components that <i>define</i> a "
    "treatment. Outcome = time-to-first-weaponization (n=313,847; 147,048 events). "
    "Source: artifacts/merged/causal_characterization.json; docs/causal_and_patch_race_2026-06.md."
)
image("docs/figures/fig_causal_forest.png",
      "Figure 8. Adjusted hazard ratios. Wormable (network, no-auth, no-UI, low-complexity) and "
      "unauthenticated high-impact CVEs are causally weaponized faster (HR 1.29 and 1.24, both "
      "robust). ATT&CK-chain mapping shows no robust effect — positivity is violated, so the "
      "framework correctly refuses the estimate. Source: artifacts/merged/causal_characterization.json.")
bullets([
    "<b>Wormable: real causal acceleration.</b> Adjusted HR 1.29 [1.28, 1.31], IPW 1.41, crude 1.71; "
    "raw median time-to-weaponization 100d vs 277d. The effect survives even mediator-inclusive "
    "adjustment (HR 1.17) — it lives in 1.17&ndash;1.41 across every spec and never crosses 1. "
    "E-value 1.68: an unmeasured confounder would need HR&ge;1.68 with both treatment and outcome to "
    "explain it away.",
    "<b>ATT&CK-chain-mapped: no robust effect.</b> Treated-propensity median 0.94 vs control 0.009 — "
    "near-separation. The causal framework refusing this estimate is a feature: it is a null the "
    "prior associational log-rank study could not catch.",
])

# ===========================================================================
# 13. PATCH-VS-EXPLOIT RACE
# ===========================================================================
h1("13. The Patch-vs-Exploit Race")
p(
    "Does the patch or the exploit arrive first? The honest answer reframes the question: <b>patch-"
    "date observability is itself the selector</b>, so a naive commit-date race model is biased "
    "toward cases where the race is already won. Source: artifacts/merged/patch_race.json."
)
image("docs/figures/fig_patch_race.png",
      "Figure 9. Left: ~⅓ of weaponizations beat CVE publication — and our 28.6% first-weap rate "
      "independently matches VulnCheck's reported 28.96% of 2025 KEVs, an external validation of the "
      "label pipeline. Right: the race is bimodal — in coordinated-disclosure OSS the fix lands a "
      "median 14 days before the CVE (defenders win ~99.5%); 0-days are the mirror (100% exploited "
      "before patch). Source: artifacts/merged/patch_race.json.")
key(
    "<b>Methodological lesson:</b> the dangerous exploit-before-patch cases (0-days, "
    "vendor-advisory-only, no public commit) are <i>systematically excluded</i> from any commit-date "
    "cohort. The unbiased race signal is the <b>pre-disclosure weaponization rate</b>, computable "
    "corpus-wide from labels we already have — no fetch required."
)

# ===========================================================================
# 14. LABEL COMPLETENESS
# ===========================================================================
h1("14. Label Completeness — the False-Censoring Gap")
p(
    "The in-wild model right-censors every uncataloged CVE as “never exploited.” How many of those "
    "are actually exploited? Using EPSS (FIRST's calibrated P(exploited in 30d), trained on "
    "exploitation telemetry) as a semi-independent oracle quantifies the gap. "
    "Source: artifacts/merged/label_completeness.json; docs/label_completeness_2026-06.md."
)
image("docs/figures/fig_label_funnel.png",
      "Figure 10. Left: the weaponization funnel — 359,507 CVEs narrow to 1.38% in-wild labeled. "
      "Right: a calibrated EPSS expectation of ~9,046 exploited-but-uncataloged CVEs, ~2× the entire "
      "labeled in-wild set (97% of the high-EPSS unlabeled cohort is >1 year old, so this is genuine "
      "incompleteness, not catalog lag). Source: artifacts/merged/label_completeness.json.")
key(
    "<b>Honest bottom line:</b> the in-wild ceiling is data-bound, and a <i>material part</i> of it is "
    "label incompleteness (false-censoring), not just rarity. Closing it requires exploitation "
    "<b>telemetry</b> (GreyNoise / Shadowserver / VulnCheck ipintel — the paid/keyed modality), not "
    "more catalogs and not EPSS-relabeling (which would make the model an EPSS copy). Absent that, the "
    "defensible move is to report in-wild results as a <b>lower bound</b> and lean on the abundant, "
    "well-labeled first-weaponization / PoC→KEV heads."
)

# ===========================================================================
# 15. ROADMAP
# ===========================================================================
h1("15. Where to Get More Data (the Roadmap)")
p("Six literature sweeps converged on one meta-finding: the biggest achievable gain is more/earlier "
  "in-wild label data. The ranked roadmap:")
make_table([
    ["#", "Source / lever", "Expected effect", "Status"],
    ["1", "VulnCheck KEV (community API)", "~3x backtest / 6x 70-30 events, ~27d earlier", "DONE"],
    ["2", "Recover self-inflicted label drops", "+~1,575 pre-disclosure 0-day events", "Free / no API"],
    ["3", "GreyNoise (academic VIP = free)", "Earliest mass-exploitation date / volume", "Best telemetry; needs application"],
    ["4", "Microsoft MSRC exploited flags", "Vendor-confirmed dated exploitation", "Wired — measured 0 new (saturated)"],
    ["5", "Shadowserver honeypot feed", "Per-CVE in-wild scan attribution", "Keyed; scoped to own network"],
    ["6", "AlienVault OTX pulses", "Community in-wild indicators", "Free API; noisy"],
], col_widths=[0.3 * inch, 2.5 * inch, 2.4 * inch, 1.3 * inch])
p(
    "<b>Documented dead-ends not to revisit:</b> mixture-cure, RSF/GBM/deep nets, stacked transfer, "
    "any recalibration, TabPFN/SurvivalPFN at this scale, and aggregate per-vendor/CWE forecasting "
    "(counts measure the reporting apparatus, not attackers)."
)

# ===========================================================================
# 16. CURRENT STATE & NEXT STEPS
# ===========================================================================
h1("16. Current State &amp; Next Steps")
p("<b>Current state.</b>")
bullets([
    "Test suite: <b>337 tests collected and green</b> (deep-model tests are torch-gated).",
    "In-wild model = penalized Cox on EPSS-enriched, publication-time-safe features, evaluated by the "
    "rolling-origin backtest; VulnCheck labels now flow in.",
    "Causal + patch-race layers committed and externally validated (28.6% &asymp; VulnCheck 28.96%).",
    "Memory stays within the &le;6&ndash;8&nbsp;GB RAM / &le;7&nbsp;GB VRAM budget on every path.",
])
p("<b>Next steps (priority order).</b>")
bullets([
    "<b>Recover the ~1,575 self-inflicted negative-duration drops</b> (pre-disclosure 0-day "
    "exploitation) by flooring duration at 0.5d rather than dropping — free, ~50% more in-wild events.",
    "<b>Apply for GreyNoise academic VIP</b> — the one telemetry feed that could close the "
    "false-censoring gap (a different modality from catalogs).",
    "<b>A higher-signal transition head</b> (PoC&rarr;Metasploit/Nuclei — tooling that genuinely "
    "post-dates the PoC), reusing the existing transition machinery.",
    "<b>Build the corpus-wide pre-disclosure race model</b> — unbiased instrument, 28.6% base rate, "
    "well-powered, no fetch.",
])
spacer(8)
p(
    "<b>Closing note.</b> The defensible value proposition is the t=0 cold-start in-wild head, where "
    "the model beats EPSS by +0.17 AUC at disclosure and adds a calibrated timing curve EPSS "
    "structurally cannot give. The project's honesty — documented dead-ends, triple-verified claims, "
    "externally-validated labels, and a clear-eyed data-limited verdict — is itself a deliverable."
)

# ===========================================================================
# APPENDIX A — MODULE REFERENCE
# ===========================================================================
story.append(PageBreak())
h1("Appendix A — Module Quick-Reference")
p("Every layer of <font face='Courier' size=8>src/temporal_exploit/</font>, the role of each module:")
make_table([
    ["Layer", "Module(s)", "Role"],
    ["Spine", "cli.py", "argparse + 7 *_command() orchestrators"],
    ["Fetch", "fetch/base, cache, gitmine", "Connector ABC, ETag cache, git-history mining"],
    ["", "fetch/{kev,epss,nvd,exploitdb,zeroday}", "HTTP connectors"],
    ["", "fetch/{poc,nuclei,metasploit}", "git-mined connectors"],
    ["", "fetch/{vulncheck,shadowserver}", "token/cred-gated in-wild"],
    ["Merge", "merge.py", "merge_live() / merge_source() + MERGE_SPECS"],
    ["Load", "loaders.py, schema.py", "parquet load + column validation"],
    ["Labels", "labels.py", "4 label builders, published = clock origin"],
    ["Features", "features, attack_features, epss_features", "publication-time CVSS/CWE/CPE + ATT&CK + EPSS"],
    ["", "nlp_features, text_safety", "masked, freshness-gated text (opt-in)"],
    ["", "landmark, poc_features, presence_features", "post-pub / transition / snapshot"],
    ["Split", "splits.py", "time-based make_time_split()"],
    ["Models", "modeling.py", "Cox/RSF/GBM + evaluate + calibration + bootstrap"],
    ["", "baselines, cure, xgb, deep, deephit, survboost", "KM / cure / AFT / neural / competing-risk"],
    ["", "competing.py", "Aalen-Johansen, cause-specific Cox, transitions"],
    ["", "causal.py", "adjusted Cox + IPW + E-value"],
    ["Eval", "evaluate, backtest, simulate", "descriptive stats, walk-forward, synthetic DGP"],
    ["Artifacts", "artifacts.py, config.py", "manifest + content hashes, paths"],
], col_widths=[0.9 * inch, 2.7 * inch, 2.9 * inch], font=8)

# ===========================================================================
# APPENDIX B — FEATURE PROVENANCE
# ===========================================================================
h1("Appendix B — Feature Provenance (Leakage Audit)")
p(
    "The provenance table is the institutional memory that prevents leakage creep: 37 feature "
    "families across four leakage statuses. Counts: "
    "<b>16 publication-safe</b> (default), <b>12 landmark-safe</b> (opt-in, L=7/30d), "
    "<b>5 transition-safe</b> (post-PoC), <b>4 snapshot-leakage</b> (excluded). "
    "Full detail in <font face='Courier' size=8>artifacts/feature_provenance.csv</font>."
)
make_table([
    ["leakage_status", "# families", "default?", "guard"],
    ["publication_time_safe", "16", "YES", "knowable at disclosure"],
    ["landmark_safe", "12", "opt-in", "requires restart_clock(L)"],
    ["transition_safe_post_poc", "5", "opt-in", "post-PoC clock origin"],
    ["snapshot_leakage", "4", "NEVER", "kept separate for audit only"],
], col_widths=[2.2 * inch, 1.1 * inch, 1.1 * inch, 2.1 * inch])

# ===========================================================================
# Build
# ===========================================================================
doc = SimpleDocTemplate(
    OUT_PDF, pagesize=letter,
    leftMargin=0.9 * inch, rightMargin=0.9 * inch,
    topMargin=0.85 * inch, bottomMargin=0.8 * inch,
    title="Temporal Exploit Prediction — Project Report (2026-06-23)",
    author="temporal-exploit",
)


def _footer(canvas, doc_):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(0.9 * inch, 0.5 * inch,
                      f"Temporal Exploit Prediction — Project Report — {DATEStr_safe()}")
    canvas.drawRightString(letter[0] - 0.9 * inch, 0.5 * inch, f"Page {doc_.page}")
    canvas.restoreState()


def DATEStr_safe():
    return DATESTR


doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
print("WROTE", OUT_PDF)
print("BYTES", os.path.getsize(OUT_PDF))
