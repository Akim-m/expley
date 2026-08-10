"""Figure-embedded variant of the supervisor-meeting handout (reportlab).

Same sourced content as build_meeting_handout_2026-06-30.py, plus the EPSS-parity
chart (docs/figures/fig_epss_parity.png) as the visual anchor. Targets <=2 pages.

Run with the venv python:
    .venv/bin/python scripts/build_meeting_handout_fig_2026-06-30.py

Output: docs/meeting_update_2026-06-30_with_figure.pdf
"""

from __future__ import annotations

import json
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

REPO = "/home/akim/Coding/Expl"
OUT_PDF = os.path.join(REPO, "docs", "meeting_update_2026-06-30_with_figure.pdf")
FIG = os.path.join(REPO, "docs", "figures", "fig_epss_parity.png")

# ---------------------------------------------------------------------------
# Numbers straight from the artifact (no hand-typing).
# ---------------------------------------------------------------------------
parity = json.load(open(os.path.join(REPO, "artifacts", "inwild_epss_parity.json")))
pa = parity["per_arm"]
d30 = parity["structural_vs_epss_score"]["horizon_auc_30"]
d90 = parity["structural_vs_epss_score"]["horizon_auc_90"]
ci_lo = d30["mean_delta"] - 1.96 * d30["se"]
ci_hi = d30["mean_delta"] + 1.96 * d30["se"]
n_org = parity["n_origins"]
S = {
    "auc30_struct": pa["structural"]["auc_30"], "auc30_epss": pa["epss_score"]["auc_30"],
    "auc30_naive": pa["epss_xgb_naive"]["auc_30"],
    "d30": d30["mean_delta"], "d30_lo": ci_lo, "d30_hi": ci_hi,
    "d30_win": round(d30["win_frac"] * n_org),
    "d90": d90["mean_delta"], "d90_win": round(d90["win_frac"] * n_org),
    "rec_struct": pa["structural"]["recall_at_top_30"]["0.1"],
    "rec_epss": pa["epss_score"]["recall_at_top_30"]["0.1"],
    "n_evt": pa["structural"]["test_events_total"], "n_org": n_org,
}

# ---------------------------------------------------------------------------
# Styles (slightly tighter than the text-only version to make room for the figure).
# ---------------------------------------------------------------------------
ss = getSampleStyleSheet()
TITLE = ParagraphStyle("T", parent=ss["Title"], fontSize=17, leading=20, spaceAfter=2,
                       textColor=colors.HexColor("#0b3d91"))
SUB = ParagraphStyle("S", parent=ss["Normal"], fontSize=8.7, leading=11.5,
                     textColor=colors.HexColor("#555555"), spaceAfter=4)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=10, leading=12, spaceBefore=6,
                    spaceAfter=2, textColor=colors.HexColor("#1f4e79"))
BODY = ParagraphStyle("B", parent=ss["BodyText"], fontSize=8.4, leading=10.8, alignment=TA_LEFT,
                      spaceAfter=2)
BULLET = ParagraphStyle("U", parent=BODY, leftIndent=12, bulletIndent=2, spaceAfter=2.5)
HEAD = ParagraphStyle("Head", parent=BODY, fontSize=8.8, leading=11.6, backColor=colors.HexColor("#fff7e6"),
                      borderColor=colors.HexColor("#e0a800"), borderWidth=0.8, borderPadding=6,
                      spaceBefore=2, spaceAfter=5)
CAP = ParagraphStyle("Cap", parent=ss["Italic"], fontSize=7.8, leading=9.8,
                     textColor=colors.HexColor("#555555"), spaceBefore=1, spaceAfter=6)
FOOT = ParagraphStyle("F", parent=BODY, fontSize=7.5, leading=9.3, textColor=colors.HexColor("#555555"))

story = []


def b(items):
    for it in items:
        story.append(Paragraph("•&nbsp;&nbsp;" + it, BULLET))


story.append(Paragraph("Temporal Exploit Prediction &mdash; Progress Update", TITLE))
story.append(Paragraph(
    "Predicting <i>when</i> a published CVE becomes weaponized (survival analysis; complements EPSS) "
    "&nbsp;&middot;&nbsp; week of 23&ndash;30 June 2026 &nbsp;&middot;&nbsp; supervisor meeting, 1 July 2026", SUB))

story.append(Paragraph(
    "<b>Headline.</b> The in-wild head was re-targeted into a <i>measurable</i> comparison against EPSS "
    "and adversarially verified: at disclosure (cold-start), structured publication-time features "
    f"out-rank EPSS by <b>+{S['d30']:.3f} AUC@30</b> (95% CI [{S['d30_lo']:.3f}, {S['d30_hi']:.3f}], "
    f"wins {S['d30_win']}/{S['n_org']} time-splits); PR-AUC is tied. The project is now consolidated "
    "into a 19-page, fully-cited report.", HEAD))

# -- figure ----------------------------------------------------------------
iw, ih = ImageReader(FIG).getSize()
w = 5.7 * inch
img = Image(FIG, width=w, height=w * ih / iw)
img.hAlign = "CENTER"
story.append(img)
story.append(Paragraph(
    f"In-wild ranking on the same target as EPSS ({S['n_evt']:,} test events, {S['n_org']} walk-forward "
    "origins). <b>Left:</b> structural features (0.795) modestly beat raw-EPSS (0.695); wrapping EPSS in "
    "a model collapses it to chance (0.501) &mdash; the baseline bug we fixed. <b>Right:</b> we win at "
    "top-5/10% depth, EPSS is sharper at the very top-1%. Source: artifacts/inwild_epss_parity.json.", CAP))

# -- what's new ------------------------------------------------------------
story.append(Paragraph("What&rsquo;s new since last week", H2))
b([
    f"<b>Concrete win over EPSS at t=0:</b> structural AUC@30 <b>{S['auc30_struct']:.3f}</b> vs raw-EPSS "
    f"<b>{S['auc30_epss']:.3f}</b> (&Delta;+{S['d30']:.3f}); AUC@90 &Delta;<b>+{S['d90']:.3f}</b> "
    f"({S['d90_win']}/{S['n_org']}); top-decile recall <b>{S['rec_struct']:.2f}</b> vs {S['rec_epss']:.2f}. "
    "Value = the cold-start regime where EPSS is near-chance / ~48% missing.",
    "<b>GreyNoise telemetry connector built</b> (verified API, TDD, 6 tests, passed an RE audit) &mdash; "
    "next lever for scarce in-wild labels. Caveat: <i>prospective-only</i> (rolling &le;30d, no backfill).",
    "<b>Report is literature-grounded:</b> 40 verified citations + References integrated into the 19-page "
    "PDF (checked against DOI / arXiv / venue).",
])

# -- rigor -----------------------------------------------------------------
story.append(Paragraph("Why the result is trustworthy (rigor corrections)", H2))
b([
    f"<b>Fixed a baseline bug that would have inflated the win:</b> EPSS must be ranked by its raw score "
    f"(in-model = {S['auc30_naive']:.3f}, chance). The +{S['d30']:.3f} is measured against a <i>strong</i> EPSS.",
    "<b>Corrected the target framing (honesty):</b> the &ldquo;in-wild&rdquo; label is ~93% VulnCheck "
    "catalog-add dates &mdash; an administrative proxy (median ~+175d lag; ~22% within 30d), not true "
    "onset. Claim = &ldquo;cold-start ranking advantage,&rdquo; not &ldquo;predicts real-world "
    "exploitation.&rdquo; Adversarial RE (2 agents): no leakage / handicap.",
    "<b>Caught 3 errors in the report&rsquo;s own draft citations</b> (wrong year, samples-vs-events unit, "
    "wrong journal volume); flagged 1 non-peer-reviewed source.",
])

# -- decisions -------------------------------------------------------------
story.append(Paragraph("Decisions to discuss", H2))
b([
    "<b>Framing:</b> is &ldquo;cold-start ranking advantage over EPSS&rdquo; the right thesis claim, "
    "given the proxy label (+175d lag)?",
    "<b>Telemetry:</b> GreyNoise is forward-only &mdash; wire it for prospective evaluation, or accept the "
    "retrospective ~396-event ceiling as the wall?",
    "<b>Dissertation angle:</b> continue toward the epidemiological mixture model for pre-disclosure dynamics?",
    "<b>Logistics:</b> merge the <font face='Courier' size=8>inwild-epss-parity</font> branch to master.",
])
story.append(Spacer(1, 3))

status = Table([[
    Paragraph("<b>Status:</b> 337 tests green &middot; report 19pp / 40 refs &middot; parity work pushed "
              "(branch <font face='Courier' size=7>inwild-epss-parity</font>)", FOOT),
    Paragraph("<b>Sources:</b> artifacts/inwild_epss_parity.json; commits 79d4213, cf3348d, 872b588 "
              "(parity), bace8e8/fdb2541 (GreyNoise); docs/project_report_2026-06-23.pdf", FOOT),
]], colWidths=[3.4 * inch, 3.6 * inch])
status.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f7fa")),
    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#c8ccd0")),
    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c8ccd0")),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
]))
story.append(status)

doc = SimpleDocTemplate(
    OUT_PDF, pagesize=letter,
    leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    topMargin=0.55 * inch, bottomMargin=0.5 * inch,
    title="Temporal Exploit Prediction — Progress Update with figure (1 July 2026)",
    author="temporal-exploit",
)
doc.build(story)
print("WROTE", OUT_PDF)
print("BYTES", os.path.getsize(OUT_PDF))
