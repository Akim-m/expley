"""Render a plain-language, no-jargon explainer of the project to PDF (reportlab).

Audience: a smart person with NO cybersecurity background who has to explain the
project to a professor. Every term is defined with an everyday analogy, and the
last page is a "if the professor asks..." cheat sheet.

Headline numbers are read live from artifacts/inwild_epss_parity.json so they match
the technical report and the meeting handouts.

Run:  .venv/bin/python scripts/build_plain_explainer_2026-06-30.py
Out:  docs/explainer_plain_language_2026-06-30.pdf
"""

from __future__ import annotations

import json
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

REPO = "/home/akim/Coding/Expl"
OUT_PDF = os.path.join(REPO, "docs", "explainer_plain_language_2026-06-30.pdf")

p = json.load(open(os.path.join(REPO, "artifacts", "inwild_epss_parity.json")))
A = p["per_arm"]
D = p["structural_vs_epss_score"]["horizon_auc_30"]["mean_delta"]
STRUCT = A["structural"]["auc_30"]
EPSS = A["epss_score"]["auc_30"]
NAIVE = A["epss_xgb_naive"]["auc_30"]

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
ss = getSampleStyleSheet()
TITLE = ParagraphStyle("T", parent=ss["Title"], fontSize=21, leading=25, spaceAfter=3,
                       textColor=colors.HexColor("#0b3d91"))
SUB = ParagraphStyle("S", parent=ss["Normal"], fontSize=10, leading=13,
                     textColor=colors.HexColor("#555555"), spaceAfter=8)
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontSize=14, leading=18, spaceBefore=12,
                    spaceAfter=5, textColor=colors.HexColor("#0b3d91"))
BODY = ParagraphStyle("B", parent=ss["BodyText"], fontSize=10.2, leading=14.5, alignment=TA_LEFT,
                      spaceAfter=7)
BULLET = ParagraphStyle("U", parent=BODY, leftIndent=15, bulletIndent=3, spaceAfter=4)
BIG = ParagraphStyle("Big", parent=BODY, fontSize=11, leading=15, backColor=colors.HexColor("#fff7e6"),
                     borderColor=colors.HexColor("#e0a800"), borderWidth=0.8, borderPadding=9,
                     spaceBefore=4, spaceAfter=10)
ANALOGY = ParagraphStyle("An", parent=BODY, fontSize=9.8, leading=13.5, backColor=colors.HexColor("#eaf2fb"),
                         borderColor=colors.HexColor("#9cc3ea"), borderWidth=0.6, borderPadding=8,
                         leftIndent=2, rightIndent=2, spaceBefore=2, spaceAfter=9)
QA = ParagraphStyle("QA", parent=BODY, fontSize=10, leading=13.8, spaceAfter=8, leftIndent=2)

story = []


def bullets(items):
    for it in items:
        story.append(Paragraph("•&nbsp;&nbsp;" + it, BULLET))


def analogy(text):
    story.append(Paragraph("<b>Think of it like this.</b> " + text, ANALOGY))


# ===========================================================================
# COVER
# ===========================================================================
story.append(Paragraph("The Project, Explained in Plain Language", TITLE))
story.append(Paragraph(
    "A no-jargon guide so you can confidently explain this work to a professor &mdash; even with no "
    "cybersecurity background. Read it once; the last page is a cheat sheet for likely questions.", SUB))

story.append(Paragraph(
    "<b>The whole thing in one breath:</b> When a new software flaw is announced publicly, nobody knows "
    "how urgent it is yet. This project built a tool that, on day one, predicts <i>how soon</i> that flaw "
    "is likely to be attacked &mdash; and at that critical first moment it does a measurably better job "
    "than the industry-standard scoring system used today.", BIG))

# ===========================================================================
# GLOSSARY
# ===========================================================================
story.append(Paragraph("First, the 8 words you need", H1))
story.append(Paragraph(
    "If you understand these eight terms, you understand the whole project. Don&rsquo;t memorize "
    "definitions &mdash; remember the analogy in the right-hand column.", BODY))

g = [
    ["Term", "What it really means", "Everyday analogy"],
    ["CVE", "A public ID number for one known software flaw (e.g. CVE-2024-1234).",
     "A recall notice for a car defect — every flaw gets a catalog number."],
    ["Vulnerability", "A weakness in software that someone could abuse.",
     "An unlocked window in a house."],
    ["Exploit", "Actual code or a technique that abuses the weakness.",
     "The burglar’s tool kit made for that exact window."],
    ["“In the wild”", "The flaw is being attacked for real, not just in theory.",
     "A confirmed break-in — not a security demo."],
    ["PoC", "“Proof of concept” — a demo showing the flaw <i>can</i> be abused.",
     "A locksmith proving the lock can be picked. No theft yet."],
    ["EPSS", "An industry score (0–100%): “will this be attacked in the next 30 days?”",
     "A weather forecast: “30% chance of rain.”"],
    ["KEV", "An official US-government list of flaws confirmed to be attacked.",
     "A police blotter of confirmed crimes."],
    ["Survival\nanalysis", "Math for predicting <i>how long until</i> an event happens — even for cases where it hasn’t yet.",
     "How doctors predict “time until relapse.”"],
]
gt = Table([[Paragraph(c, ParagraphStyle("gc", parent=BODY, fontSize=9, leading=11.5, spaceAfter=0))
             for c in row] for row in g],
           colWidths=[0.95 * inch, 3.0 * inch, 2.55 * inch], hAlign="LEFT")
gt.setStyle(TableStyle([
    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8ccd0")),
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
    ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
]))
story.append(gt)

story.append(PageBreak())

# ===========================================================================
# THE PROBLEM
# ===========================================================================
story.append(Paragraph("The problem this project tackles", H1))
story.append(Paragraph(
    "Every day, hundreds of new software flaws (CVEs) are published. Defenders &mdash; the people who "
    "keep companies safe &mdash; cannot fix all of them at once. They must guess which few will actually "
    "be attacked, and how soon. Today the main tool for this, <b>EPSS</b>, answers a yes/no question: "
    "“will this flaw be attacked in the next 30 days?” This project asks a richer question: "
    "<b>WHEN will it be attacked &mdash; days, weeks, or months from now?</b>", BODY))
analogy(
    "EPSS is like a smoke alarm: it tells you <i>whether</i> there’s a fire right now. This project "
    "is more like a <i>weather forecast</i> that says the storm will probably hit Thursday afternoon. "
    "Knowing the <i>timing</i> lets defenders line up and fix the most urgent flaws first.")

story.append(Paragraph("What was actually built", H1))
bullets([
    "A prediction tool that, the moment a flaw is announced, estimates how soon it is likely to be "
    "weaponized &mdash; using only facts known on day one (how severe it is, what type of weakness it is, "
    "which vendor made the software, and so on).",
    "It learned from a large history of about <b>338,000 past flaws</b> and what happened to each one.",
    "It uses <b>survival analysis</b> &mdash; the same kind of math doctors use to predict “time "
    "until a patient relapses.” Here the “patient” is a software flaw and the “relapse"
    "” is the first attack.",
])

# ===========================================================================
# THE RESULT
# ===========================================================================
story.append(Paragraph("The main result, in plain English", H1))
story.append(Paragraph(
    "To grade a tool that <i>ranks</i> things by risk, researchers use a number called <b>AUC</b>. "
    "It runs from <b>0.5</b> (a coin flip &mdash; useless) to <b>1.0</b> (perfect). Our tool scores about "
    "<b>0.80</b>, which is good.", BODY))
story.append(Paragraph(
    f"We put our tool head-to-head against EPSS on the exact same task. Our tool scored "
    f"<b>+{D:.2f} higher</b> ({STRUCT:.2f} versus EPSS&rsquo;s {EPSS:.2f}). The gap is biggest at "
    "<b>“day zero”</b> &mdash; the moment a flaw is first announced, when EPSS has barely any "
    "information to work with. That is exactly the moment a defender most needs a good guess.", BODY))
analogy(
    "Imagine 100 brand-new flaws announced today, and only a few will ever be attacked. Line them up "
    "from “most likely to be attacked” to “least.” Our tool puts the truly dangerous "
    "ones nearer the top of that list than EPSS does &mdash; on the very first day, before anyone else "
    "knows which is which.")

story.append(PageBreak())

# ===========================================================================
# WHY TRUST IT
# ===========================================================================
story.append(Paragraph("Why a professor should trust the result", H1))
story.append(Paragraph(
    "Good science is mostly about being honest, especially about your own work. Two things here show that "
    "honesty &mdash; and they are the strongest points to make:", BODY))
bullets([
    "<b>We found and fixed a mistake that was making us look TOO good.</b> By accident, EPSS was being "
    f"run through an extra step that crippled it down to {NAIVE:.2f} (a coin flip), which would have made "
    "our win look enormous. We corrected the comparison so EPSS is judged <i>fairly</i> &mdash; and we "
    "still win, just by a sensible, believable amount.",
    "<b>We are upfront that our “real attack” data is a stand-in.</b> Perfect records of exactly "
    "when each flaw was first attacked don’t fully exist. We use the best available list, which tends "
    "to lag reality by about <b>6 months</b>. So we describe the result carefully: “better at ranking "
    "at the start,” not “we perfectly predict real attacks.”",
    "<b>An independent double-check.</b> A separate adversarial review was run specifically to look for "
    "cheating or hidden shortcuts in the result. It found none. (We also checked the report’s academic "
    "references and quietly fixed three small errors in them.)",
])

story.append(Paragraph("What comes next", H1))
bullets([
    "Try a new live data source (called GreyNoise) that watches real internet attacks as they happen. "
    "Catch: it only sees attacks <i>going forward</i>, not in the past, so it helps future predictions, "
    "not the historical test.",
    "Agree on the honest headline for the thesis: “a better early-warning ranking than the industry "
    "standard,” while being clear about the 6-month data limitation.",
])

# ===========================================================================
# CHEAT SHEET
# ===========================================================================
story.append(Paragraph("If the professor asks… (cheat sheet)", H1))
story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#c8ccd0"), spaceAfter=6))

qa = [
    ("“Isn’t this just EPSS again?”",
     "No. EPSS gives a yes/no 30-day probability. Ours predicts the <i>timing</i> and works noticeably "
     "better at the very first moment a flaw is announced, when EPSS has little to go on."),
    ("“How much better is it, really?”",
     f"About +{D:.2f} on a 0.5-to-1.0 scale ({STRUCT:.2f} vs {EPSS:.2f}), and the advantage is largest at "
     "day zero. Modest but real, and carefully verified."),
    ("“How do you know it isn’t a fluke or cheating?”",
     "It was tested across 15 separate time periods, always training on the past and predicting the "
     "future &mdash; never peeking ahead. An independent adversarial review also looked for shortcuts "
     "and found none."),
    ("“What’s the catch?”",
     "True ‘real-world attack’ data is scarce, so we use a stand-in list that lags by about "
     "6 months. The honest claim is an early-warning <i>ranking</i> advantage, and the real limit is the "
     "<i>data</i>, not the method."),
    ("“Why does this matter?”",
     "Defenders can’t fix everything at once. Pointing to the flaws most likely to be attacked "
     "<i>soon</i> &mdash; right when they appear &mdash; saves time and reduces risk."),
    ("“Why this kind of model and not fancy AI?”",
     "They tested many models, including deep-learning ones. With this little confirmed-attack data, the "
     "simpler, classical survival model did just as well or better. More data — not a fancier model "
     "— is what would help."),
]
for q, a in qa:
    story.append(Paragraph(f"<b>Q: {q}</b><br/>A: {a}", QA))

story.append(Spacer(1, 4))
story.append(Paragraph(
    "<b>Your one-sentence pitch:</b> “We built a tool that, the moment a software flaw is announced, "
    "predicts how soon it’s likely to be attacked &mdash; and at that critical first moment it beats "
    "the industry-standard forecast, which we proved carefully and honestly.”", BIG))

# ===========================================================================
# Build
# ===========================================================================
doc = SimpleDocTemplate(
    OUT_PDF, pagesize=letter,
    leftMargin=0.85 * inch, rightMargin=0.85 * inch,
    topMargin=0.7 * inch, bottomMargin=0.65 * inch,
    title="The Project, Explained in Plain Language (1 July 2026)",
    author="temporal-exploit",
)
doc.build(story)
print("WROTE", OUT_PDF)
print("BYTES", os.path.getsize(OUT_PDF))
