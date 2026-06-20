"""Render the temporal-exploit project report to PDF (reportlab/platypus).

Run with the venv python:
    .venv/bin/python scripts/build_project_report_pdf.py

Output: docs/project_report_2026-06-20.pdf

All numbers are grounded in the repo's docs + artifacts/*.json as of 2026-06-20.
This script only reads/writes files under the repo; it does not touch any tokens.
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
OUT_PDF = os.path.join(REPO, "docs", "project_report_2026-06-20.pdf")
PAGE_W_INNER = 6.5 * inch  # SimpleDocTemplate content width on letter w/ 0.85in margins-ish

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
styles = getSampleStyleSheet()

TITLE = ParagraphStyle(
    "ReportTitle", parent=styles["Title"], fontSize=24, leading=28,
    spaceAfter=6, textColor=colors.HexColor("#0b3d91"),
)
SUBTITLE = ParagraphStyle(
    "ReportSubtitle", parent=styles["Normal"], fontSize=12, leading=16,
    textColor=colors.HexColor("#555555"), spaceAfter=2,
)
H1 = ParagraphStyle(
    "H1", parent=styles["Heading1"], fontSize=16, leading=20,
    spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#0b3d91"),
)
H2 = ParagraphStyle(
    "H2", parent=styles["Heading2"], fontSize=12.5, leading=16,
    spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#1f4e79"),
)
BODY = ParagraphStyle(
    "Body", parent=styles["BodyText"], fontSize=10, leading=14.5,
    alignment=TA_LEFT, spaceAfter=6,
)
BULLET = ParagraphStyle(
    "Bullet", parent=BODY, leftIndent=16, bulletIndent=4, spaceAfter=3,
)
MONO = ParagraphStyle(
    "Mono", parent=styles["Code"], fontName="Courier", fontSize=8.2, leading=10.5,
    backColor=colors.HexColor("#f3f4f6"), borderPadding=4, spaceAfter=6,
    textColor=colors.HexColor("#111111"),
)
CAPTION = ParagraphStyle(
    "Caption", parent=styles["Italic"], fontSize=8.5, leading=11,
    textColor=colors.HexColor("#555555"), spaceBefore=2, spaceAfter=12,
)
KEYFINDING = ParagraphStyle(
    "KeyFinding", parent=BODY, backColor=colors.HexColor("#fff7e6"),
    borderColor=colors.HexColor("#e0a800"), borderWidth=0.8, borderPadding=8,
    leftIndent=2, rightIndent=2, spaceBefore=6, spaceAfter=10,
)

story = []


def h1(text):
    story.append(Paragraph(text, H1))


def h2(text):
    story.append(Paragraph(text, H2))


def p(text):
    story.append(Paragraph(text, BODY))


def bullets(items):
    for it in items:
        story.append(Paragraph("•&nbsp;&nbsp;" + it, BULLET))
    story.append(Spacer(1, 4))


def key(text):
    story.append(Paragraph(text, KEYFINDING))


def mono(text):
    story.append(Paragraph(text.replace(" ", "&nbsp;").replace("\n", "<br/>"), MONO))


def spacer(h=6):
    story.append(Spacer(1, h))


def image(rel_path, caption, width=PAGE_W_INNER):
    """Add an image scaled to width if it exists; skip gracefully otherwise."""
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


def make_table(data, col_widths=None, header=True):
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    ts = [
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8ccd0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
    ]
    if header:
        ts += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    t.setStyle(TableStyle(ts))
    story.append(t)
    story.append(Spacer(1, 8))


# ===========================================================================
# COVER
# ===========================================================================
story.append(Spacer(1, 60))
story.append(Paragraph("Temporal Exploit Prediction", TITLE))
story.append(Paragraph("CVE Weaponization Survival-Analysis Modeling &mdash; Project Report", SUBTITLE))
story.append(Spacer(1, 10))
story.append(Paragraph("Prepared for the project owner &middot; 2026-06-20", SUBTITLE))
story.append(Spacer(1, 24))
key(
    "<b>The one thing to internalize:</b> the in-the-wild prediction ceiling is "
    "<b>DATA-limited, not model-limited.</b> Every alternative model class "
    "(RSF, gradient-boosted survival, XGBoost-AFT, mixture-cure, DeepSurv/DeepHit, "
    "stacked transfer, temperature recalibration) has been tested prospectively and "
    "<b>none beats a penalized Cox</b> at the ~251&ndash;396 in-wild events available. "
    "The achievable win is more / earlier <i>labels</i> &mdash; which is why wiring in "
    "VulnCheck KEV (just done) is the highest-leverage step taken to date."
)
story.append(Spacer(1, 14))
p(
    "This report covers everything built so far and the reasoning behind each decision. "
    "Every quantitative claim is grounded in the repository's living docs "
    "(<font face='Courier' size=8>README.md</font>, "
    "<font face='Courier' size=8>docs/progress.md</font>, "
    "<font face='Courier' size=8>docs/modeling_methodology.md</font>, the literature and "
    "pathways reviews) and in the JSON metric artifacts under "
    "<font face='Courier' size=8>artifacts/</font>. Where a headline number is cited, the "
    "source artifact is named so it can be re-checked."
)
story.append(PageBreak())

# ===========================================================================
# 1. EXECUTIVE SUMMARY
# ===========================================================================
h1("1. Executive Summary")
p(
    "This project is a <b>survival-analysis modeling layer</b> that predicts <b>when</b> a "
    "published CVE becomes publicly weaponized &mdash; a time-to-event problem &mdash; built on a "
    "pre-extracted, multi-source CVE timeline dataset (338,015 CVEs). It is deliberately positioned "
    "as a <b>complement</b> to EPSS, not a competitor: EPSS answers “will this be exploited in the "
    "wild in the next 30 days?” as a fixed-window binary; this project characterizes the upstream "
    "<i>weaponization pipeline timing</i> (PoC &rarr; Metasploit / Nuclei &rarr; KEV / 0-day) and produces "
    "a calibrated time-to-event curve EPSS structurally cannot give."
)
p("<b>What was built.</b>")
bullets([
    "A leakage-safe dataset builder (four label sets: first-weaponization, per-signal, "
    "competing-risks, in-wild) over the nine immutable handover parquets, with a feature-provenance "
    "audit trail and a content-hashed manifest.",
    "Models spanning the survival toolbox: Kaplan-Meier, penalized Cox PH, Random Survival Forest, "
    "GPU XGBoost-AFT, mixture-cure, DeepSurv/DeepHit, plus a competing-risks / Aalen-Johansen core.",
    "Rare-event-appropriate evaluation: IPCW c-index with bootstrap CIs, time-dependent AUC(t), "
    "PR-AUC, Brier/IPA, decision-curve net-benefit, and a rolling-origin (walk-forward) backtest.",
    "Live-fetch connectors for every documented source (CISA KEV, EPSS, NVD, Exploit-DB, PoC, "
    "Nuclei, Metasploit, Project Zero, VulnCheck KEV, Shadowserver) and a merge layer.",
])
p("<b>The single most important finding.</b>")
key(
    "The in-the-wild head is <b>data-limited</b>. On ~251&ndash;396 confirmed in-wild events the Cox "
    "model <b>ranks well</b> (c-index / AUC@90 ≈ 0.82&ndash;0.85) but its absolute probabilities "
    "<b>do not beat the base-rate null</b> (IPA ≈ 0) &mdash; and no fancier model improves on this. "
    "By contrast the first-weaponization head trains on <b>45,947 events</b>: there calibration works "
    "(IPA@180 = <b>+0.291</b>) but ranking is weak (c-index ≈ <b>0.60</b>) because the target is mostly "
    "PoC/disclosure logistics. <b>Two different limits: one is data scarcity, the other is target noise.</b>"
)
p(
    "<b>Current best models.</b> For the meaningful <i>in-wild</i> target, the model is a "
    "<b>penalized Cox PH on EPSS-enriched, publication-time-safe features</b> (the rolling-origin "
    "backbone; AUC@90 ≈ 0.82, recall@top-decile ≈ 0.51). For the abundant <i>first-weaponization</i> "
    "target, <b>XGBoost-AFT</b> is the headline ranker (c-index 0.598 vs Cox 0.565), with Cox kept as "
    "the interpretable reference."
)

# ===========================================================================
# 2. THE PROBLEM & FRAMING
# ===========================================================================
h1("2. The Problem &amp; Framing")
p(
    "<b>The question.</b> After a CVE is published, <i>when</i> does public exploitation capability "
    "appear? The clock origin is <font face='Courier' size=8>cve_corpus.published</font>; the event is "
    "the earliest dated signal across five sources; CVEs with no signal are right-censored at the "
    "snapshot date. This is classic right-censored survival analysis, and that framing is itself a "
    "contribution: the field overwhelmingly treats exploitation as repeated 30-day binary "
    "classification (EPSS), while explicit time-to-event modeling of weaponization is a genuinely "
    "under-explored niche (CERT/SEI 2020; Farris 2017)."
)
p(
    "<b>How it complements EPSS.</b> EPSS is XGBoost on ~6.4M <i>in-the-wild</i> observations across "
    "~12k CVEs, predicting P(exploited in 30 days), scored on coverage/efficiency, not AUC. This "
    "project models the <i>timing</i> of the upstream tooling pipeline and a calibrated lead-time "
    "curve. The two are answering different questions; positioning this as an EPSS competitor would "
    "be a category error."
)
key(
    "<b>CRITICAL framing caveat.</b> Of all observed first-weaponization events, <b>~97% are "
    "public-PoC dates</b>. Only CISA KEV (<font face='Courier' size=8>kev_date_added</font>) and "
    "Google Project Zero 0-day are true in-the-wild signals &mdash; historically ~664 events combined "
    "(531 KEV + 133 0-day at the original snapshot). <b>Any model trained on first-weaponization "
    "labels predicts time-to-public-tooling, NOT in-the-wild exploitation.</b>"
)
p("<b>The three distinct prediction targets, and why each exists.</b>")
bullets([
    "<b>First-weaponization</b> (45,947 events) &mdash; earliest of PoC / Metasploit / Nuclei / KEV / "
    "0-day. Abundant, so it powers calibration and is where ML models can be exercised; but the "
    "target is dominated by PoC logistics, so ranking is intrinsically weak. It exists as the "
    "<i>abundant</i> head and the source for transfer experiments.",
    "<b>In-wild</b> (KEV + Google 0-day + VulnCheck only; PoC excluded) &mdash; the project's stated "
    "meaningful target: actual exploitation, not tooling availability. Rare (251&ndash;396 events "
    "before VulnCheck), so it is the one whose ceiling is data-limited.",
    "<b>PoC &rarr; downstream transition heads</b> &mdash; reusable machinery to model the conditional "
    "escalation from a public PoC to genuine tooling (Metasploit/KEV). The PoC&rarr;ExploitDB instance "
    "was tested and is near-empty because ExploitDB is <i>itself</i> a PoC source (see &sect;7), so it "
    "is label enrichment, not a target; the machinery generalizes to higher-signal transitions.",
])

# ===========================================================================
# 3. DATA & ARCHITECTURE
# ===========================================================================
h1("3. Data &amp; Architecture")
p(
    "<b>Two strictly separated layers</b> &mdash; this separation is a deliberate reproducibility "
    "decision so modeling changes can never corrupt the source material:"
)
bullets([
    "<b>Immutable handover / extraction</b> (<font face='Courier' size=8>dataset_extraction-.../"
    "dataset_extraction/</font>) &mdash; the VRS-MongoDB extraction + enrichment scripts that produced "
    "nine parquet files. Treated as read-only reproducibility material.",
    "<b>The modeling package</b> (<font face='Courier' size=8>src/temporal_exploit/</font>) &mdash; the "
    "code developed here. It reads the handover parquets, <i>never</i> writes to them; all outputs go "
    "to a gitignored <font face='Courier' size=8>artifacts/</font> dir.",
])
p("<b>The nine handover sources</b> (all now wired into the dataset):")
make_table(
    [
        ["Source", "Parquet", "Role"],
        ["CVE corpus (NVD/VulnCheck)", "cve_corpus", "Features + clock origin (published)"],
        ["PoC (Trickest + Nomi-sec)", "poc_dates", "Event source (97% of first-weap events)"],
        ["Metasploit", "metasploit_dates", "Event source / per-signal target"],
        ["Nuclei", "nuclei_dates", "Event source / per-signal target"],
        ["CISA KEV", "kev_events", "Event source + primary in-wild label"],
        ["Google 0-day", "google_0day", "Event source + in-wild label"],
        ["EPSS history (375M rows)", "epss_history", "EPSS-at-publication feature (leakage-safe)"],
        ["ATT&CK chain", "technique_cwe_chain", "Tactic/technique one-hot features"],
        ["VRS presence", "vrs_presence", "Snapshot-only, leakage-flagged (kept separate)"],
    ],
    col_widths=[1.8 * inch, 1.5 * inch, 3.2 * inch],
)
p(
    "The <b>EPSS history is 375M rows / 3.7 GB</b> (one row group per day). It is read by streaming "
    "<font face='Courier' size=8>iter_batches</font> + a fixed-size per-CVE numpy reduction "
    "(~0.6 GB peak) &mdash; a hard-won decision: an earlier pyarrow "
    "<font face='Courier' size=8>isin(cve_ids)</font> pushdown retained ~5.8 GB and breached the "
    "memory budget (see &sect;7). The only safe pushdown is by <i>date</i>."
)
p(
    "<b>Live-fetch connectors</b> refresh every documented source to today without mutating the "
    "handover parquets (HTTP connectors share an ETag/Last-Modified cache; git-mined sources share "
    "clone/pickaxe helpers; VulnCheck and Shadowserver are credential-gated). A "
    "<font face='Courier' size=8>merge</font> layer reconciles live deltas onto the handover snapshot "
    "(earliest-wins per source) into a unified dir the builder consumes."
)
p("<b>The data-flow pipeline</b> (the spine is <font face='Courier' size=8>cli.py</font>):")
mono(
    "fetch / refresh  ->  merge  ->  build-dataset  ->  train / train-competing / backtest\n\n"
    "load_parquet (loaders) -> validate_columns (schema)\n"
    "  -> build_*_labels (labels: first-weap, per-signal, competing, in-wild)\n"
    "  -> build_publication_features (+ ATT&CK / EPSS / landmark / incentive)\n"
    "  -> write parquets + content-hashed manifest (artifacts)\n"
    "  -> [optional] make_time_split / write_time_split\n"
    "  -> feature_provenance().to_csv   (the leakage audit trail)"
)

# ===========================================================================
# 4. LEAKAGE-SAFETY DECISIONS
# ===========================================================================
h1("4. Leakage-Safety Decisions (and Why Each Matters)")
p(
    "These are non-negotiable; they are <i>how the results stay valid</i>. Each excludes a concrete "
    "failure mode that would silently inflate apparent performance."
)
bullets([
    "<b>Exclude the CVE description text.</b> NVD <i>back-edits</i> descriptions after the event with "
    "phrases like “actively exploited” / “CISA” / “KEV”. A model reading the current "
    "description would see the future &mdash; pure temporal leakage. The masked, freshness-gated NLP "
    "path exists but is opt-in and off by default.",
    "<b>Exclude snapshot-time presence flags</b> (<font face='Courier' size=8>vrs_presence</font>). "
    "Whether a source <i>eventually</i> listed the CVE is knowledge from the future; used as a "
    "predictor for a historical event it is a near-perfect leak. It is kept in a separate, "
    "leakage-flagged parquet, never merged into the safe features.",
    "<b>Exclude snapshot-time EPSS.</b> Today's EPSS for an old CVE leaks the future (the literature "
    "quantifies this look-ahead bias: 2023 efficiency collapses 60.9% &rarr; 11.1% when scored "
    "honestly at publication+30d). Only the <i>first EPSS reading after publication</i> is used.",
    "<b>Time-based splits, never random K-fold.</b> A model is only ever evaluated on CVEs published "
    "later than those it trained on. Random folds would let future CVEs leak into training and "
    "produce optimistic, non-deployable numbers.",
    "<b>The feature_provenance() audit trail.</b> Every emitted feature family gets one row with its "
    "source column and a leakage_status. Adding a feature requires justifying its status &mdash; this is "
    "the institutional memory that prevents quiet leakage creep.",
    "<b>Timezone discipline.</b> All handover date columns are "
    "<font face='Courier' size=8>timestamp[ns, tz=UTC]</font>; every date is normalized with "
    "<font face='Courier' size=8>utc=True</font>. Mixing tz-aware and naive timestamps raises on "
    "subtraction &mdash; surfacing the bug rather than silently producing wrong durations.",
])
p(
    "<b>A real near-miss this discipline caught:</b> wrong schema column names "
    "(<font face='Courier' size=8>cvss_v3_base_score</font> instead of "
    "<font face='Courier' size=8>cvss_v3_base</font>, <font face='Courier' size=8>weaknesses</font> "
    "instead of <font face='Courier' size=8>cwe_ids</font>) silently produced <i>all-zero features</i> "
    "before they were caught &mdash; which is why the builder now fails loudly on missing required columns "
    "rather than degrading to empty features."
)

# ===========================================================================
# 5. MODELS & WHY
# ===========================================================================
h1("5. Models &amp; Why")
p(
    "The model question was settled empirically (a prospective bake-off) and against the literature, "
    "not by preference. The short version: <b>penalized Cox is the in-wild backbone; everything "
    "fancier is a challenger that must earn its place prospectively, and so far none has.</b>"
)
h2("5.1 The classical backbone")
bullets([
    "<b>Kaplan-Meier</b> &mdash; the unconditional reference survival curve and the null any model must beat.",
    "<b>Cox PH (penalized, lifelines)</b> &mdash; the in-wild backbone. Ridge shrinkage handles the "
    "borderline events-per-variable (~9.5 EPV); the penalizer is scaled by the event rate (undoing "
    "~24&times; over-shrinkage on the rare in-wild target) with tenfold escalation on non-convergence.",
])
h2("5.2 The challengers, and why Cox won for in-wild")
p(
    "A 15-origin rolling-origin backtest on the in-wild target (396 events) ran the model classes the "
    "survival literature flags as the real Cox challengers. Cox wins on every axis that matters:"
)
make_table(
    [
        ["Model", "AUC@90 (mean)", "sd", "recall@top-10%", "IPA@90", "fit time"],
        ["Cox (penalized)", "0.817", "0.069", "0.51", "-0.003", "78 s"],
        ["Random Survival Forest", "0.770", "0.117", "0.42", "-0.016", "384 s"],
        ["Gradient-boosted (sksurv)", "0.710", "0.093", "0.40", "-0.001", "362 s*"],
        ["Mixture-cure", "overturned", "—", "harmful", "-0.27 @180d", "—"],
    ],
    col_widths=[1.7 * inch, 1.1 * inch, 0.5 * inch, 1.1 * inch, 0.9 * inch, 0.8 * inch],
)
p(
    "<font size=8>* sksurv Cox-loss GBM is O(n&sup2;) per tree &mdash; only tractable after subsampling, "
    "which discards scarce events and tanks discrimination. Source: "
    "<font face='Courier'>artifacts/inwild_headtohead.json</font> (paired gbm&minus;cox AUC@90 = "
    "&minus;0.107, CI [&minus;0.154, &minus;0.061], excludes 0).</font>"
)
bullets([
    "<b>Why this matches the literature.</b> A neutral 34-dataset / 21-model benchmark finds <i>no "
    "method statistically significantly outperforms Cox PH</i> on tabular survival (Burk et al. 2026); "
    "boosting needs ≥600 events and transformers ≥1,200 to beat Cox (Rossi et al. 2025). At ~396 "
    "events we are firmly in Cox's territory.",
    "<b>RSF</b> overestimates survival under imbalanced censoring &mdash; the exact failure mode for a "
    "&lt;1% rare event; it is a diagnostic, not the deliverable.",
    "<b>DeepSurv / DeepHit</b> are disqualified at this event count (data-hungry, unstable; DeepHit's "
    "ranking loss degrades calibration where it matters). This is also why the GPU sits idle for "
    "in-wild &mdash; Cox is CPU by design and is the best model.",
    "<b>XGBoost-AFT</b> is the headline ranker for the <i>abundant</i> first-weaponization target "
    "(c-index 0.598 vs Cox 0.565), where there is enough data for a tree model to shine.",
])
h2("5.3 The mixture-cure dead-end (a documented negative result)")
key(
    "<b>Mixture-cure is a documented dead-end &mdash; do not revive without a Kaplan-Meier plateau.</b> "
    "It briefly looked like the only in-wild model with positive IPA on a single split, but the "
    "rolling-origin backtest overturned it (IPA@180 went to &minus;0.27). The cause is theoretical, not a "
    "tuning bug: a cure fraction is only identifiable when the KM curve plateaus above zero, and our "
    "~99.5%-censored in-wild target is <i>administratively</i> censored, not a cured population "
    "(Li/Taylor/Sy 2001). The flat tail is missing follow-up, not immunity."
)

# ===========================================================================
# 6. METRICS & WHY
# ===========================================================================
h1("6. Metrics &amp; Why (Proper Rare-Event Evaluation)")
p(
    "At a &lt;1% base rate the standard accuracy/ROC-AUC instincts mislead. The evaluation panel was "
    "chosen to measure the right things under heavy, potentially-informative censoring."
)
bullets([
    "<b>IPCW c-index + bootstrap CIs.</b> Harrell's C depends on the censoring distribution and is not "
    "comparable across origins; the truncated-at-&tau; variant equals Uno's C under administrative "
    "censoring (our design). Bootstrap CIs + paired deltas vs Cox replace single point estimates.",
    "<b>Time-dependent AUC(t) with IPCW.</b> Discrimination at each fixed horizon, reweighting rather "
    "than dropping censored rows.",
    "<b>PR-AUC over ROC-AUC.</b> Under 0.2&ndash;0.3% imbalance, ROC-AUC is dominated by the trivially-"
    "classified negatives and looks great while the model is useless on the minority; PR-AUC exposes "
    "the true positive yield.",
    "<b>Brier / IPA for calibration.</b> IPA = scaled Brier vs the train-KM null; it asks whether the "
    "<i>absolute</i> probabilities beat the base rate. (Caveat carried in the docs: the integrated "
    "Brier is not strictly proper, so RCLL is a recommended reporting add.)",
    "<b>Decision-curve / net-benefit.</b> At 0.47% prevalence a 0.82-AUC ranker can have near-zero net "
    "benefit. Measured: the in-wild model has positive net benefit and beats both treat-all and "
    "treat-none across the realistic 0.1&ndash;3% threshold band (artifacts/inwild_decision_curve.json) "
    "&mdash; useful, but modestly.",
    "<b>Rolling-origin (walk-forward) backtest over a single split.</b> Each origin trains only on what "
    "was knowable then and scores the next period &mdash; the honest temporal-validation discipline the "
    "look-ahead-bias literature demands. Origins share training data, so the per-origin trajectory is "
    "reported, not one pooled CI.",
])
p(
    "<b>Calibration in practice &mdash; the two heads diverge sharply.</b> On the rare in-wild target the "
    "Cox reliability plot is nearly degenerate (predictions cluster at the ~0.2% base rate; little "
    "spread to calibrate). On the abundant first-weaponization target the XGBoost-AFT plot shows real, "
    "if imperfect, calibration across the full 0&ndash;1 range &mdash; the visual counterpart of "
    "IPA@180 = +0.291 vs IPA ≈ 0."
)
image(
    "artifacts/reports/inwild_cox_7030/calibration_cox.png",
    "Figure 1. In-wild Cox calibration (70/30 split). Predicted risk barely separates from the "
    "~0.2% base rate — there is almost nothing to calibrate at 103 test events. "
    "Source: artifacts/reports/inwild_cox_7030/metrics.json.",
)
image(
    "artifacts/reports/firstweap_xgb_7030/calibration_xgb.png",
    "Figure 2. First-weaponization XGBoost-AFT calibration (70/30 split). Predictions span the full "
    "range with meaningful (if imperfect) reliability — abundance enables calibration. "
    "Source: artifacts/reports/firstweap_xgb_7030/metrics.json.",
)

# ===========================================================================
# 7. THE JOURNEY
# ===========================================================================
h1("7. The Journey &mdash; Waves &amp; Key Decisions")
p(
    "The system was built in waves, each ending in mandatory adversarial self-audit "
    "(reverse-engineering) rounds. Summarized chronologically, with the reasoning:"
)
bullets([
    "<b>Modeling core + critical-defect fixes.</b> Loaders/schema/labels/features/splits/baselines, "
    "then the first review caught tz-crashes and wrong column names that had silently zeroed features.",
    "<b>Source-wiring + competing-risks.</b> Per-signal, competing-risks, and in-wild labels; ATT&CK "
    "and EPSS-at-publication features; Aalen-Johansen CIFs; live-fetch connectors for all sources.",
    "<b>WSL2 migration + GPU.</b> Moved off OneDrive/Windows to WSL2 (EPSS build 2.3&times; faster, "
    "GPU cuda:0 verified); env managed with uv.",
    "<b>Statistical-validity wave.</b> Same-day events kept (0.5d) instead of silently dropped "
    "(was 11% of first-weap / 26% of in-wild events); post-snapshot events censored; c-index CIs; "
    "censoring-free horizon AUC; IPA; event-rate-scaled Cox penalizer; KEV-catalog clock floor for "
    "in-wild. Honest headlines: first-weap xgb 0.598, in-wild static Cox 0.849.",
    "<b>Memory optimization.</b> EPSS scan 5.8 GB &rarr; 0.6 GB (the pyarrow isin pushdown retained "
    "per-row-group buffers; replaced with iter_batches + fixed-size numpy reduction, output provably "
    "identical) + column projection + write-and-free. The full EPSS+landmark build went from breaching "
    "8.5 GB to peaking 1.34 GB &mdash; keeping it inside the &le;6&ndash;8 GB budget.",
    "<b>In-wild method head-to-head + literature review.</b> The bake-off above (RSF/GBM/cure all lose "
    "to Cox), tied to the rare-event survival literature. Established the data-limited verdict.",
    "<b>F1&ndash;F6 (EPSS trajectory / scan fusion / landmark circularity).</b> Single-decode EPSS "
    "fusion (one scan instead of 1+N), AUC(t) cross-checks, and a proof that the landmark backtest is "
    "<i>not</i> leaky (restart_clock closes each train CVE's window before the origin) &mdash; so F6's "
    "EPSS-distillation result is sound, not an artifact.",
])
p("<b>The N1&ndash;N6 instant / transition / non-stationarity wave (2026-06-20):</b>")
bullets([
    "<b>N4 &mdash; incentive ablation.</b> The publication-only instant head <i>beats the EPSS static floor</i> "
    "on first-weaponization (PR-AUC@30 +0.064, CI [+0.043, +0.084], win-fraction 1.0) &mdash; CVSS/CWE/CPE "
    "carry real t=0 signal. But the attacker-incentive flags from the CVSS vector add ~0 (within error) "
    "&mdash; redundant at t=0. Source: artifacts/instant_incentive_ablation.json.",
    "<b>N5 &mdash; era-stress.</b> Era-dependent and inconclusive: train≤2022/test≥2024 = &minus;0.031 "
    "(degradation) but train≤2023/test≥2025 = +0.074 (opposite sign), with a residual follow-up-"
    "window asymmetry. On this signal-starved head the dramatic median-time collapse does not surface "
    "as a clean ranking-AUC degradation. Source: artifacts/era_stress.json.",
    "<b>N6 &mdash; PoC&rarr;ExploitDB transition.</b> Near-empty: 68 events / 162,730 PoC'd CVEs (0.04%), "
    "because 99.4% of verified-ExploitDB entries <i>precede</i> the aggregated PoC date &mdash; ExploitDB "
    "<i>is</i> an early PoC source. So ExploitDB-verified is label enrichment, not a downstream target; "
    "the transition machinery is reusable for the higher-signal PoC&rarr;Metasploit / PoC&rarr;KEV heads. "
    "Source: artifacts/transition_poc_to_exploitdb.json.",
])
p(
    "<b>Two adversarial reverse-engineering audit rounds</b> closed the wave (a 5-agent review with 13 "
    "findings, and a model-improvement + edge-case audit whose 13 concrete claims were each "
    "triple-verified by independent agents). These produced the era-stress de-confounding fix and the "
    "self-inflicted-label-loss discovery (&sect;10), among others."
)

# ===========================================================================
# 8. THE CENTRAL FINDING
# ===========================================================================
story.append(PageBreak())
h1("8. The Central Finding &mdash; a DATA-Limited Ceiling")
p(
    "The most important conclusion of the project is that the in-wild ceiling is set by <b>how many "
    "confirmed in-wild events exist</b>, not by model choice or calibration technique. The evidence is "
    "a contrast between the two heads at the same 2024-01-01 cutoff:"
)
make_table(
    [
        ["", "In-wild (Cox)", "First-weaponization (XGB-AFT)"],
        ["Events", "251", "45,947"],
        ["c-index (IPCW)", "0.849", "0.598"],
        ["Ranking quality", "strong (AUC@90 ≈ 0.87)", "weak (≈ 0.60)"],
        ["IPA@90 / @180", "≈ 0 (slightly negative)", "+0.176 / +0.291"],
        ["Calibration", "cannot (nothing to fit)", "works"],
        ["Binding constraint", "data scarcity", "target noise (PoC logistics)"],
    ],
    col_widths=[1.9 * inch, 2.1 * inch, 2.5 * inch],
)
p(
    "<font size=8>Sources: artifacts/reports/inwild_cox/metrics.json (251 events, c-index 0.849, "
    "IPA@180 &minus;0.0014); artifacts/reports/firstweap_xgb/metrics.json (45,947 events, c-index 0.598, "
    "IPA@180 +0.291, IPA@90 +0.176).</font>"
)
key(
    "<b>Read the two heads together and the diagnosis is unambiguous:</b> where data is abundant "
    "(first-weap, 45,947 events) <i>calibration works</i> &mdash; so IPA≈0 on in-wild is not a "
    "calibration bug. Where ranking should be possible (in-wild, AUC≈0.85) <i>data is scarce</i> &mdash; "
    "so weak first-weap ranking is target noise, not scarcity. Each head is limited by a different "
    "thing, and neither limit is the model."
)
p(
    "This is corroborated three ways: (1) <b>empirically</b> &mdash; every alternative model "
    "(RSF, GBM, XGBoost-AFT, mixture-cure, DeepSurv/DeepHit) and every output-side flow-change "
    "(stacked transfer, temperature recalibration) measured &le; baseline Cox prospectively; "
    "(2) by the <b>events-per-variable literature</b> &mdash; ~9.5 EPV is borderline and the remedy is "
    "penalization (in place), not a bigger model; (3) by <b>neutral benchmarks</b> &mdash; boosting/"
    "transformers need 600&ndash;1,200 events to beat Cox, and we are below that."
)
image(
    "artifacts/reports/diagnostic_two_heads.png",
    "Figure 3. The two-heads diagnostic. The abundant first-weaponization head has good calibration "
    "(IPA) but weak ranking; the rare in-wild head has good ranking but no calibration headroom. "
    "Two different ceilings, neither set by the model. Source: artifacts/reports/diagnostic_two_heads.png.",
)

# ===========================================================================
# 9. VULNCHECK WIRING
# ===========================================================================
h1("9. VulnCheck Wiring (Just Done) &mdash; Raising the Ceiling")
p(
    "Because the ceiling is data-limited, the highest-leverage action is more / earlier in-wild "
    "<i>labels</i>. The VulnCheck KEV catalog was fetched and wired end-to-end. It is ~173% larger "
    "than CISA KEV and ~27 days earlier on average, and it uses first-reported-<i>evidence</i> dates "
    "rather than catalog-add dates."
)
bullets([
    "<b>Catalog fetched:</b> 4,969 CVEs (data/live/vulncheck_kev.parquet).",
    "<b>Usable in-wild events lifted ~454 &rarr; ~3,105 at the snapshot level</b> &mdash; but this ~6-7&times; "
    "combines TWO coupled effects: adding VulnCheck AND the source-aware clock-floor removal it enables "
    "(the CISA-launch floor was wrongly discarding VulnCheck's first-evidence dates). The cleanly-"
    "attributable VulnCheck lift alone is the two figures below.",
    "<b>~3&times; on the rolling-origin backtest</b> (396 &rarr; 1,201 in-wild events; the robust eval harness).",
    "<b>6&times; on the 70/30 time split:</b> test in-wild events go 106 &rarr; 637.",
    "<b>The c-index confidence interval roughly halves:</b> [0.806, 0.934] &rarr; [0.772, 0.834] "
    "(width 0.128 &rarr; 0.062).",
    "<b>IPA@90 turns positive:</b> 0.000033 &rarr; 0.0070 (and the same pattern at 7/30/180d).",
])
p(
    "<font size=8>Source: artifacts/reports/vulncheck_lift.json. CISA-only arm: 106 test events, "
    "c-index 0.870 CI [0.806, 0.934], IPA@90 3.3e-05. +VulnCheck arm: 637 test events, c-index 0.803 "
    "CI [0.772, 0.834], IPA@90 0.0070.</font>"
)
key(
    "<b>Interpretation:</b> more data buys a more <i>trustworthy</i> model, not a flashier headline. "
    "The c-index settles honestly near <b>0.80</b> (the small-sample 0.87 was optimistic), the CI "
    "halves, and calibration becomes real (IPA &gt; 0). A tighter interval and genuine calibration are "
    "the right kind of win for a rare-event model &mdash; reliability, not over-claim."
)
image(
    "artifacts/reports/vulncheck_lift.png",
    "Figure 4. VulnCheck lift. CISA-only vs +VulnCheck on a 70/30 in-wild split: 6× more test "
    "events, a roughly-halved c-index CI, and IPA turning positive. The point estimate dropping from "
    "0.87 to 0.80 is the small-sample optimism being corrected. Source: artifacts/reports/vulncheck_lift.json.",
)

# ===========================================================================
# 10. WHERE TO GET MORE DATA
# ===========================================================================
h1("10. Where to Get More Data (the Roadmap)")
p(
    "Six parallel literature sweeps (60+ papers, 2022&ndash;2026) converged on one meta-finding: the "
    "biggest achievable gain is more/earlier in-wild label data. The ranked roadmap:"
)
make_table(
    [
        ["#", "Source / lever", "Expected effect", "Status"],
        ["1", "VulnCheck KEV (free community API)", "~3x backtest / 6x 70-30 events, ~27d earlier", "DONE (this session)"],
        ["2", "Recover self-inflicted label drops", "+~1,575 pre-disclosure 0-day events", "FREE / no API -- best next lever"],
        ["3", "Microsoft MSRC exploited flags", "Vendor-confirmed, dated exploitation", "Free; needs a scraper"],
        ["4", "AlienVault OTX pulses", "Community in-wild indicators", "Free API; noisy"],
        ["5", "GreyNoise vuln-prioritization", "Earliest mass-exploitation date", "Paid for bulk; free 1-CVE lookups"],
        ["6", "Shadowserver honeypot feed", "DEAD END: data scoped to your own network", "No global feed exists"],
    ],
    col_widths=[0.3 * inch, 2.6 * inch, 2.3 * inch, 1.3 * inch],
)
key(
    "<b>A large part of the “data limit” is self-inflicted by label processing.</b> Two filters "
    "discard ~70% of fetched VulnCheck events and <b>100% of the Google 0-day signal</b> (132/133 "
    "0-days are exploited <i>before</i> disclosure &rarr; negative duration &rarr; dropped). The model "
    "currently trains on effectively no 0-day timing. The CISA-launch clock floor was also "
    "mis-applied to VulnCheck's first-evidence dates; making the floor source-aware "
    "(EVIDENCE_SOURCES) recovered events and lifted AUC@90 0.808 &rarr; 0.827 (paired CI excludes 0)."
)
p(
    "<b>Important contrast:</b> the <i>first-weaponization</i> head is NOT data-limited (45,947 "
    "events). Its weakness is target noise, so the lever there is a cleaner target / better features, "
    "not more rows. Documented dead-ends not to revisit: mixture-cure, RSF/GBM/deep nets, stacked "
    "transfer, any recalibration, TabPFN/SurvivalPFN at this scale."
)

# ===========================================================================
# 11. CURRENT STATE & NEXT STEPS
# ===========================================================================
h1("11. Current State &amp; Next Steps")
p("<b>Current state.</b>")
bullets([
    "Test suite green: 288 passed, 3 skipped (the skips are torch-gated deep-model tests).",
    "The in-wild model is penalized Cox on EPSS-enriched, publication-time-safe features, evaluated by "
    "the rolling-origin backtest; VulnCheck labels now flow in.",
    "The reusable PoC&rarr;downstream transition machinery "
    "(<font face='Courier' size=8>build_transition_labels</font> + "
    "<font face='Courier' size=8>transition_cindex</font>) is in place and generalizes to "
    "PoC&rarr;Metasploit / PoC&rarr;KEV escalation heads.",
    "Memory stays within the &le;6&ndash;8 GB RAM / &le;7 GB VRAM budget for every build/train path.",
])
p("<b>Next steps (in priority order).</b>")
bullets([
    "<b>Recover the ~1,575 self-inflicted negative-duration drops</b> (pre-disclosure 0-day "
    "exploitation) by flooring duration at 0.5d (“exploited at disclosure”) rather than dropping &mdash; "
    "the best remaining lever: FREE, no API, ~50% more in-wild events (verify VulnCheck dates are genuine first).",
    "<b>External in-wild feeds are largely gated.</b> VulnCheck (done) was the accessible win; "
    "Shadowserver is scoped to your own network (no global feed exists); GreyNoise's bulk per-CVE feed is "
    "paid. Free-but-needs-a-scraper options remain: Microsoft MSRC exploited flags, AlienVault OTX.",
    "<b>Aggregate the backtest c-index.</b> A known gap: rolling_origin_backtest computes per-origin "
    "IPCW + truncated c-index but never extracts them into the aggregate (the transition head works "
    "around it with an explicit held-out c-index). Cheap fix, deferred because it touches shared code.",
    "<b>Follow-up-matched era-stress.</b> Administratively cap both test windows to the same follow-up "
    "length before scoring, so era degradation becomes a clean measurement rather than directional.",
    "<b>A higher-signal transition head</b> (PoC&rarr;Metasploit/Nuclei &mdash; tooling that genuinely "
    "post-dates the PoC), reusing the existing machinery.",
])
spacer(8)
p(
    "<b>Closing note.</b> The defensible value proposition is the t=0 <i>cold-start</i> in-wild head, "
    "where the model beats EPSS by +0.13&ndash;0.25 AUC at disclosure (EPSS is ~48% missing and "
    "near-chance there) and adds a calibrated timing curve EPSS structurally cannot give. The fancier "
    "in-wild-at-landmark regime is EPSS-saturated and should not be headlined. The project's honesty "
    "&mdash; documented dead-ends, triple-verified claims, and a clear-eyed data-limited verdict &mdash; is "
    "itself a deliverable."
)

# ===========================================================================
# Build
# ===========================================================================
doc = SimpleDocTemplate(
    OUT_PDF,
    pagesize=letter,
    leftMargin=0.9 * inch,
    rightMargin=0.9 * inch,
    topMargin=0.85 * inch,
    bottomMargin=0.8 * inch,
    title="Temporal Exploit Prediction — Project Report",
    author="temporal-exploit",
)


def _footer(canvas, doc_):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(
        0.9 * inch, 0.5 * inch,
        "Temporal Exploit Prediction — Project Report — 2026-06-20",
    )
    canvas.drawRightString(letter[0] - 0.9 * inch, 0.5 * inch, f"Page {doc_.page}")
    canvas.restoreState()


doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
print("WROTE", OUT_PDF)
print("BYTES", os.path.getsize(OUT_PDF))
