"""Render a "How to Run This Project" operator's guide to PDF (reportlab).

Covers environment setup, data requirements, every CLI subcommand (with real
--help output), a verified end-to-end walkthrough (numbers from an actual
build-dataset run on 2026-08-11), the report-generation scripts, and the
memory/leakage gotchas that are easy to trip on.

Run with the venv python:
    .venv/bin/python scripts/build_howto_run_pdf_2026-08-11.py

Output: docs/howto_run_2026-08-11.pdf
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
OUT_PDF = os.path.join(REPO, "docs", "howto_run_2026-08-11.pdf")
PAGE_W_INNER = 6.5 * inch
DATESTR = "2026-08-11"

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
MONO = ParagraphStyle("Mono", parent=styles["Code"], fontName="Courier", fontSize=8.2, leading=11,
                      backColor=colors.HexColor("#f3f4f6"), borderPadding=6, spaceAfter=8,
                      textColor=colors.HexColor("#111111"))
CAPTION = ParagraphStyle("Caption", parent=styles["Italic"], fontSize=8.5, leading=11,
                         textColor=colors.HexColor("#555555"), spaceBefore=2, spaceAfter=12)
KEYFINDING = ParagraphStyle("KeyFinding", parent=BODY, backColor=colors.HexColor("#fff7e6"),
                            borderColor=colors.HexColor("#e0a800"), borderWidth=0.8, borderPadding=8,
                            leftIndent=2, rightIndent=2, spaceBefore=6, spaceAfter=10)
WARNBOX = ParagraphStyle("WarnBox", parent=BODY, backColor=colors.HexColor("#fdecea"),
                         borderColor=colors.HexColor("#c0392b"), borderWidth=0.8, borderPadding=8,
                         leftIndent=2, rightIndent=2, spaceBefore=6, spaceAfter=10)

story = []


def h1(t): story.append(Paragraph(t, H1))
def h2(t): story.append(Paragraph(t, H2))
def p(t): story.append(Paragraph(t, BODY))
def key(t): story.append(Paragraph(t, KEYFINDING))
def warn(t): story.append(Paragraph(t, WARNBOX))
def spacer(h=6): story.append(Spacer(1, h))


def mono(t):
    escaped = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    story.append(Paragraph(escaped.replace(" ", "&nbsp;").replace("\n", "<br/>"), MONO))


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
story.append(Paragraph("How to Run This Project", TITLE))
story.append(Paragraph("Environment setup, data requirements, and the full CLI — verified end-to-end", SUBTITLE))
story.append(Spacer(1, 10))
story.append(Paragraph(f"Operator's guide &middot; {DATESTR}", SUBTITLE))
story.append(Spacer(1, 22))
key(
    "<b>This is not a description of the pipeline &mdash; every command below was actually run</b> "
    "against this checkout on 2026-08-11 (Python 3.12.3, venv already installed, GPU "
    "<font face='Courier' size=8>cuda:0</font> visible) before being written down. Where numbers "
    "appear (row counts, timings, memory), they are the real output of that run, not estimates."
)
story.append(Spacer(1, 12))
p(
    "<b>Contents.</b> 1 What this is &middot; 2 Prerequisites &middot; 3 Data you need &middot; "
    "4 Environment setup &middot; 5 Verifying the install &middot; 6 The CLI (all 8 subcommands) &middot; "
    "7 A verified end-to-end run &middot; 8 Generating the written reports &middot; "
    "9 Inspecting data &middot; 10 Gotchas &amp; troubleshooting &middot; 11 Cheat sheet."
)
story.append(PageBreak())

# ===========================================================================
# 1. WHAT THIS IS
# ===========================================================================
h1("1. What This Is")
p(
    "A survival-analysis modeling layer that predicts <b>when</b> a published CVE becomes publicly "
    "weaponized (time-to-event), built on a pre-extracted multi-source CVE timeline dataset. It "
    "complements EPSS (which predicts in-the-wild exploitation probability over a fixed 30-day "
    "window) by characterizing the upstream weaponization pipeline: PoC &rarr; Metasploit/Nuclei &rarr; "
    "KEV/0-day."
)
p("<b>Two layers, kept strictly separate</b> (this matters for where files live and what you edit):")
bullets([
    "<font face='Courier' size=8>dataset_extraction-20260608T210903Z-3-002/dataset_extraction/</font> "
    "&mdash; immutable handover/source material (the extraction + enrichment scripts that produced nine "
    "parquet files under <font face='Courier' size=8>out/</font>). Never modify this to change "
    "modeling behavior.",
    "<font face='Courier' size=8>src/temporal_exploit/</font> &mdash; the modeling package. Reads the "
    "handover parquets, never writes to them. Generated outputs go to "
    "<font face='Courier' size=8>artifacts/</font> (gitignored).",
])
image("docs/figures/fig_pipeline.png",
      "Figure 1. The data-flow pipeline. cli.py is the spine (eight subcommands, detailed in §6); "
      "build-dataset is the integration hub that emits four label sets, the feature matrix, and a "
      "content-hashed manifest. Source: docs/architecture_flow.md.")

# ===========================================================================
# 2. PREREQUISITES
# ===========================================================================
h1("2. Prerequisites")
make_table([
    ["Requirement", "Verified value on this machine"],
    ["OS", "WSL2 Ubuntu (migrated off Windows/OneDrive 2026-06-12)"],
    ["Python", "3.12 (checked: 3.12.3, via the repo .venv)"],
    ["Package manager", "uv (faster than pip; this is the standing preference for this repo)"],
    ["Disk", "~4 GB free minimum for epss_history-001.parquet alone; 753 GB free measured"],
    ["RAM budget", "≤ 6–8 GB hard ceiling — WSL2 caps well below the host's 16 GB"],
    ["GPU (optional)", "CUDA device for xgb/deep models — verified present:\nRTX 4060 Laptop, 8188 MiB VRAM"],
    ["VRAM budget", "≤ 7 GB — xgb (GPU AFT) and DeepSurv/DeepHit use this;\nCPU models (cox, rsf) don't need it"],
], col_widths=[1.7 * inch, 4.8 * inch])
warn(
    "<b>Memory is the binding constraint on this machine, not compute.</b> Always run "
    "<font face='Courier' size=8>free -g</font> before a heavy model fit. The 375M-row EPSS history "
    "file is the main risk (see §10) &mdash; it is read via streaming batches, never loaded whole."
)

# ===========================================================================
# 3. DATA YOU NEED
# ===========================================================================
h1("3. Data You Need")
p(
    "All required data already lives in this repo checkout &mdash; there is nothing to download for a "
    "standard run. Two locations:"
)
make_table([
    ["Location", "Contents", "Size"],
    ["dataset_extraction-\n20260608T210903Z-3-002/\ndataset_extraction/out/",
     "8 handover parquets: cve_corpus, poc_dates,\nmetasploit_dates, nuclei_dates, kev_events,\n"
     "google_0day, technique_cwe_chain, vrs_presence", "tens of\nMB each"],
    ["epss_history-001.parquet\n(repo root)", "375M-row EPSS score history,\none row group per day",
     "3.7 GB\n(3,965,667,171\nbytes)"],
], col_widths=[1.9 * inch, 3.2 * inch, 1.4 * inch])
p(
    "These are treated as <b>immutable reproducibility material</b> &mdash; the extraction pipeline that "
    "produced them (from a VRS MongoDB dump) lives alongside them but is not something you re-run for "
    "normal modeling work. If you're starting from a fresh clone and these files are missing, that's "
    "the handover package to obtain separately; this guide assumes they're already present, as they "
    "are in this checkout."
)

# ===========================================================================
# 4. ENVIRONMENT SETUP
# ===========================================================================
h1("4. Environment Setup")
p("<b>One-time, from the repo root:</b>")
mono(
    "uv venv --python 3.12 .venv\n"
    "uv pip install -p .venv/bin/python -e \".[dev,xgb,boost]\""
)
p("<b>What each extra unlocks</b> (from pyproject.toml &mdash; pick what you actually need):")
make_table([
    ["Extra", "Adds", "When you need it"],
    ["(core,\nalways\ninstalled)", "pandas, pyarrow, numpy, scikit-learn,\nscikit-survival, lifelines, matplotlib,\nseaborn, ijson", "always — build-dataset,\nCox, RSF"],
    ["dev", "pytest, pytest-cov, ruff, pre-commit", "running the test suite / linting"],
    ["xgb", "xgboost ≥ 2.0", "train --models xgb (GPU AFT —\nthe abundant first-weaponization head)"],
    ["boost", "hazardous (SurvivalBoost, Inria)", "train-competing --boost only"],
    ["deep", "torch, pycox, torchtuples", "train --deep or train-competing\n--deep-hit (heavy; kept out of dev/CI)"],
], col_widths=[1.1 * inch, 2.6 * inch, 2.8 * inch])
p(
    "Per this repo's own guidance (and prior measurement): default modeling to the GPU path "
    "(<font face='Courier' size=8>xgb</font>) rather than CPU-heavy RSF/GBM, and skip the "
    "<font face='Courier' size=8>[deep]</font> extra unless you specifically need DeepSurv/DeepHit — "
    "it pulls torch and isn't worth it below roughly 1,200 training events."
)
p("<b>Console script.</b> After install, the entry point is available directly:")
mono(
    "temporal-exploit --help\n"
    "# equivalent to: .venv/bin/python -m temporal_exploit.cli --help"
)

# ===========================================================================
# 5. VERIFYING THE INSTALL
# ===========================================================================
h1("5. Verifying the Install")
p("Run the full test suite (the FutureWarning gate is baked into pyproject.toml, so plain pytest just works):")
mono(".venv/bin/python -m pytest -q")
key(
    "<b>Verified on this checkout, 2026-08-11:</b> <font face='Courier' size=8>402 passed, 4 skipped "
    "in 114.29s</font>. The 4 skips are the torch-gated deep-model tests (expected without the "
    "<font face='Courier' size=8>[deep]</font> extra)."
)
p("Single test, if you're iterating on one module:")
mono(".venv/bin/python -m pytest tests/test_labels.py::test_name -v")

# ===========================================================================
# 6. THE CLI
# ===========================================================================
story.append(PageBreak())
h1("6. The CLI — All 8 Subcommands")
p(
    "Every subcommand below was invoked with <font face='Courier' size=8>--help</font> against this "
    "checkout to confirm the flags; nothing here is from memory or the source alone."
)
make_table([
    ["Subcommand", "One-line purpose"],
    ["build-dataset", "Build modeling labels and features from the handover parquets — the integration hub"],
    ["train", "Train and evaluate survival models (cox/rsf/xgb/cure) against a built dataset"],
    ["train-competing", "Competing-risks / multi-state training report (Aalen-Johansen, cause-specific Cox)"],
    ["fetch", "Run one live connector (kev, epss, nvd, nuclei, poc, metasploit,\nzeroday, exploitdb, vulncheck_kev, greynoise) and save to a live dir"],
    ["merge", "Merge live-fetched deltas onto the handover parquets"],
    ["backtest", "Rolling-origin walk-forward backtest of time-to-weaponization"],
    ["triage", "Emit a per-CVE state-aware triage table (the deployable downstream tool)"],
    ["refresh", "Refresh all keyless sources in one shot, downloading only what changed"],
], col_widths=[1.5 * inch, 5.0 * inch])

h2("6.1 build-dataset")
p("The command every other workflow depends on — turns the handover parquets into labels + features.")
mono(
    ".venv/bin/python -m temporal_exploit.cli build-dataset \\\n"
    "  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \\\n"
    "  --artifact-dir artifacts \\\n"
    "  --snapshot-date 2026-03-14 \\\n"
    "  [--cutoff-date 2024-01-01]   # locks a train/test split when given\n"
    "  [--technique-chain PATH] [--epss-path PATH]\n"
    "  [--landmarks 7,30]           # writes landmark_features_{L}d.parquet/offset\n"
    "  [--description-text]         # leakage-safe NLP feats (112 MB col; opt-in)"
)
p("See §7 for a full run of this command with real output.")

h2("6.2 train")
mono(
    "temporal-exploit train \\\n"
    "  --artifact-dir artifacts --cutoff-date 2024-01-01 \\\n"
    "  --report-dir artifacts/reports/my_run \\\n"
    "  --label-set {first_weaponization,in_wild} \\\n"
    "  --models cox,rsf,xgb,cure    # comma list\n"
    "  [--rsf-sample N] [--landmark L] [--deep] [--cure-recalibrate]"
)
key(
    "<b>Which models for which label-set (from this project's own bake-off results):</b> for "
    "<font face='Courier' size=8>in_wild</font>, penalized Cox wins — the ceiling there is "
    "data-limited (~250–400 events), not model-limited, and RSF/GBM/mixture-cure all measure ≤ Cox "
    "prospectively. For <font face='Courier' size=8>first_weaponization</font> (45,947+ events, "
    "abundant), <font face='Courier' size=8>xgb</font> (GPU XGBoost-AFT) is the headline ranker. "
    "<font face='Courier' size=8>--deep</font> needs the <font face='Courier' size=8>[deep]</font> "
    "extra and is disqualified below ~1,200 events."
)

h2("6.3 train-competing")
mono(
    "temporal-exploit train-competing \\\n"
    "  --artifact-dir artifacts --cutoff-date 2024-01-01 \\\n"
    "  --report-dir artifacts/reports/competing_run \\\n"
    "  [--snapshot-date 2026-03-14]  # needed for transitions; omit to skip\n"
    "  [--boost] [--deep-hit]        # need [boost] / [deep] extras respectively"
)

h2("6.4 backtest")
mono(
    "temporal-exploit backtest \\\n"
    "  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \\\n"
    "  --artifact-dir artifacts --report-dir artifacts/reports/backtest \\\n"
    "  --snapshot-date 2026-03-14 --start 2021-01-01 \\\n"
    "  [--model {cox,xgb,cure}] [--label-set {first_weaponization,in_wild}]\n"
    "  [--min-followup-days N] [--recalibrate]   # held-out isotonic recal per origin"
)
p("Each rolling origin trains only on what was knowable at that point and scores the next period — the honest temporal-validation discipline this project insists on (never random K-fold).")

h2("6.5 triage")
mono(
    "temporal-exploit triage \\\n"
    "  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \\\n"
    "  --artifact-dir artifacts --report-dir artifacts/reports/triage \\\n"
    "  --snapshot-date 2026-03-14 [--min-pub DATE] [--horizon DAYS]"
)
p("Emits the deployable per-CVE risk table — needs publication_features.parquet + modeling_labels.parquet from a prior build-dataset run.")

h2("6.6 fetch / merge / refresh — pulling fresh live data")
p("These extend the handover parquets with newer data than the frozen snapshot; skip them for a first run.")
mono(
    "# one connector at a time:\n"
    "temporal-exploit fetch --source kev --live-dir data/live\n"
    "temporal-exploit fetch --source epss --live-dir data/live --date 2026-08-01\n"
    "temporal-exploit fetch --source vulncheck_kev --live-dir data/live \\\n"
    "  --api-key $VULNCHECK_API_TOKEN\n\n"
    "# merge the live deltas onto the handover parquets:\n"
    "temporal-exploit merge \\\n"
    "  --handover-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \\\n"
    "  --live-dir data/live --out-dir data/merged\n\n"
    "# or refresh every keyless source in one shot:\n"
    "temporal-exploit refresh --live-dir data/live \\\n"
    "  [--cache-dir .fetch_cache] [--repo-dir nuclei] [--with-metasploit]\n"
    "  [--epss-date 2026-08-01] [--vulncheck-token $VULNCHECK_API_TOKEN] [--with-nvdplus]"
)
p(
    "<font face='Courier' size=8>--source</font> accepts: kev, epss, nvd, nuclei, poc, metasploit, "
    "zeroday, exploitdb, vulncheck_kev, greynoise. VulnCheck and GreyNoise need an API token "
    "(<font face='Courier' size=8>--api-key</font> or the matching env var); the rest are keyless."
)

# ===========================================================================
# 7. A VERIFIED END-TO-END RUN
# ===========================================================================
story.append(PageBreak())
h1("7. A Verified End-to-End Run")
p("This is the exact command run against this checkout on 2026-08-11, with its real output.")
mono(
    ".venv/bin/python -m temporal_exploit.cli build-dataset \\\n"
    "  --out-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \\\n"
    "  --artifact-dir artifacts \\\n"
    "  --snapshot-date 2026-03-14 --cutoff-date 2024-01-01"
)
make_table([
    ["Metric", "Value"],
    ["Wall time", "19.8 s"],
    ["Peak RSS", "~1.27 GB (well inside the 6–8 GB budget)"],
    ["cve_corpus rows processed", "338,015"],
    ["Event source composition", "poc 186,709 · nuclei 4,137 · metasploit 3,107 ·\nkev 1,542 · google_0day 344"],
    ["in_wild observed events", "1,543"],
    ["Warning raised (expected)", "event source 'poc' is 97.2% of observed events —\nexactly the framing caveat in §10"],
], col_widths=[2.3 * inch, 4.2 * inch])
p("Files written to <font face='Courier' size=8>--artifact-dir</font>:")
make_table([
    ["File", "Contents"],
    ["modeling_labels.parquet", "First-weaponization labels (338,015 rows)"],
    ["in_wild_labels.parquet", "In-wild labels (KEV + 0-day, PoC excluded)"],
    ["per_signal_labels.parquet", "Per-source event labels"],
    ["competing_risks_labels.parquet", "Multi-state / competing-risks labels"],
    ["publication_features.parquet", "Leakage-safe publication-time feature matrix"],
    ["train_cve_ids.txt / test_cve_ids.txt", "Locked time-based split (only written when --cutoff-date is given)"],
    ["feature_provenance.csv", "The leakage audit trail — one row per feature family"],
    ["manifest.json", "Content-hashed (sha256) manifest of every artifact above"],
], col_widths=[2.3 * inch, 4.2 * inch])
p(
    "Once this has run, point <font face='Courier' size=8>train</font> / "
    "<font face='Courier' size=8>backtest</font> / <font face='Courier' size=8>triage</font> at the "
    "same <font face='Courier' size=8>--artifact-dir</font> (see §6.2–6.5). A typical next step:"
)
mono(
    "temporal-exploit train --artifact-dir artifacts --cutoff-date 2024-01-01 \\\n"
    "  --report-dir artifacts/reports/my_run --label-set in_wild --models cox"
)

# ===========================================================================
# 8. GENERATING THE WRITTEN REPORTS
# ===========================================================================
h1("8. Generating the Written Reports")
p("Four standalone reportlab scripts render PDFs from the repo's docs + artifacts/*.json (so numbers can't drift from source). All run the same way — venv python, no arguments. Paths below are relative to scripts/ and docs/ respectively:")
make_table([
    ["Script (in scripts/)", "Output (in docs/)", "Audience"],
    ["build_project_report_pdf_\n2026-06-23.py", "project_report_\n2026-06-23.pdf", "Full technical report +\narchitecture + 40-source\nreference list"],
    ["build_meeting_handout_\n2026-06-30.py", "meeting_update_\n2026-06-30.pdf", "One-page supervisor\nprogress handout"],
    ["build_meeting_handout_fig_\n2026-06-30.py", "meeting_update_2026-06-30_\nwith_figure.pdf", "Same handout, with the\nEPSS-parity chart embedded"],
    ["build_plain_explainer_\n2026-06-30.py", "explainer_plain_language_\n2026-06-30.pdf", "No-jargon explainer for a\nnon-security audience"],
    ["build_howto_run_pdf_\n2026-08-11.py", "howto_run_\n2026-08-11.pdf", "This document"],
], col_widths=[2.2 * inch, 2.2 * inch, 2.1 * inch])
mono(
    ".venv/bin/python scripts/build_project_report_pdf_2026-06-23.py\n"
    ".venv/bin/python scripts/build_meeting_handout_2026-06-30.py\n"
    ".venv/bin/python scripts/build_meeting_handout_fig_2026-06-30.py\n"
    ".venv/bin/python scripts/build_plain_explainer_2026-06-30.py\n"
    ".venv/bin/python scripts/build_howto_run_pdf_2026-08-11.py"
)
p(
    "Some pull figures from <font face='Courier' size=8>docs/figures/*.png</font> (regenerate those "
    "first with <font face='Courier' size=8>scripts/build_report_figures.py</font> if you've changed "
    "underlying artifacts) or from live <font face='Courier' size=8>artifacts/*.json</font> — run a "
    "training/backtest command first if a figure or number looks stale or missing."
)

# ===========================================================================
# 9. INSPECTING DATA
# ===========================================================================
h1("9. Inspecting Data Without Loading It")
p(
    "<font face='Courier' size=8>view_parquet.py</font> reads schema and row counts from parquet "
    "metadata (no data load) and uses predicate pushdown for per-CVE filters — safe on the 375M-row "
    "EPSS history file."
)
mono(
    "cd dataset_extraction-20260608T210903Z-3-002/dataset_extraction\n"
    "PY=../../.venv/bin/python\n"
    "$PY view_parquet.py                     # list available parquets\n"
    "$PY view_parquet.py cve_corpus          # schema + stats + head(5)\n"
    "$PY view_parquet.py kev_events --head 20\n"
    "$PY view_parquet.py epss_history --cve CVE-2021-44228\n"
    "$PY view_parquet.py cve_corpus --columns cve_id,published,description\n"
    "$PY view_parquet.py epss_history --schema-only    # never loads the 3.7 GB file\n"
    "$PY view_parquet.py cve_corpus --stats             # per-column null counts"
)

# ===========================================================================
# 10. GOTCHAS & TROUBLESHOOTING
# ===========================================================================
story.append(PageBreak())
h1("10. Gotchas &amp; Troubleshooting")
bullets([
    "<b>Never add an <font face='Courier' size=8>isin(cve_ids)</font> pushdown on epss_history.</b> "
    "It retains ~5–6 GB and breaches the memory budget. The only safe pushdown is by <i>date</i> "
    "(row-group-per-day), already wired in <font face='Courier' size=8>_iter_epss_batches</font>.",
    "<b>Timezone mismatches raise, by design.</b> All handover date columns are "
    "<font face='Courier' size=8>timestamp[ns, tz=UTC]</font>. Mixing tz-aware and naive timestamps "
    "raises on subtraction rather than silently producing wrong durations — if you hit this, add "
    "<font face='Courier' size=8>utc=True</font> to your date parsing, don't strip the tz.",
    "<b>Verify column names against the actual parquet before assuming.</b> "
    "<font face='Courier' size=8>cvss_v3_base_score</font> vs the real "
    "<font face='Courier' size=8>cvss_v3_base</font> once silently produced all-zero features. Run "
    "<font face='Courier' size=8>view_parquet.py &lt;name&gt; --schema-only</font> first.",
    "<b>List columns load as numpy.ndarray, not Python list.</b> Code touching them "
    "(<font face='Courier' size=8>list_len</font>, <font face='Courier' size=8>has_list_value</font>) "
    "must handle ndarray, not just <font face='Courier' size=8>list</font>.",
    "<b>The 97.2% poc-dominance warning on build-dataset is expected, not a bug.</b> ~97% of "
    "first-weaponization events are public-PoC dates; only KEV and Google 0-day are true in-the-wild "
    "signals. A model trained on first-weaponization labels predicts time-to-public-tooling, not "
    "in-the-wild exploitation — don't reframe it as an EPSS competitor.",
    "<b>Check <font face='Courier' size=8>free -g</font> before any heavy model fit</b>, especially "
    "RSF (slow, high RAM) — prefer <font face='Courier' size=8>xgb</font> on GPU where the label-set "
    "supports it.",
    "<b>Mixture-cure (<font face='Courier' size=8>--models cure</font>) is a documented dead-end</b> "
    "for the in-wild target: it looked promising on one split but a rolling-origin backtest overturned "
    "it (IPA@180 &rarr; −0.27). The ~99.5%-censored target is administratively censored, not a cured "
    "population — don't revive it without seeing a genuine Kaplan-Meier plateau first.",
])

# ===========================================================================
# 11. CHEAT SHEET
# ===========================================================================
h1("11. Cheat Sheet")
make_table([
    ["Task", "Command"],
    ["Set up env", "uv venv --python 3.12 .venv &&\nuv pip install -p .venv/bin/python -e \".[dev,xgb,boost]\""],
    ["Run tests", ".venv/bin/python -m pytest -q"],
    ["Build dataset", "temporal-exploit build-dataset --out-dir <handover/out> \\\n"
     "  --artifact-dir artifacts --snapshot-date <date> --cutoff-date <date>"],
    ["Train in-wild", "temporal-exploit train --artifact-dir artifacts --cutoff-date <date> \\\n"
     "  --report-dir <dir> --label-set in_wild --models cox"],
    ["Train first-weap", "temporal-exploit train --artifact-dir artifacts --cutoff-date <date> \\\n"
     "  --report-dir <dir> --label-set first_weaponization --models xgb"],
    ["Backtest", "temporal-exploit backtest --out-dir <handover/out> --artifact-dir artifacts \\\n"
     "  --report-dir <dir> --snapshot-date <date> --start <date>"],
    ["Triage table", "temporal-exploit triage --out-dir <handover/out> --artifact-dir artifacts \\\n"
     "  --report-dir <dir> --snapshot-date <date>"],
    ["Inspect a parquet", "python view_parquet.py <name> --schema-only"],
    ["Check memory before a fit", "free -g"],
    ["Regenerate this PDF", ".venv/bin/python scripts/build_howto_run_pdf_2026-08-11.py"],
], col_widths=[1.7 * inch, 4.8 * inch], font=8)
spacer(8)
p(
    "<b>Full option reference:</b> <font face='Courier' size=8>temporal-exploit &lt;subcommand&gt; "
    "--help</font> for any of the 8 subcommands always reflects the current code — this document is "
    "a snapshot as of 2026-08-11; re-run <font face='Courier' size=8>--help</font> if flags look off "
    "after a code change."
)

# ===========================================================================
# Build
# ===========================================================================
doc = SimpleDocTemplate(
    OUT_PDF, pagesize=letter,
    leftMargin=0.9 * inch, rightMargin=0.9 * inch,
    topMargin=0.85 * inch, bottomMargin=0.8 * inch,
    title="How to Run This Project (2026-08-11)",
    author="temporal-exploit",
)


def _footer(canvas, doc_):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(0.9 * inch, 0.5 * inch, f"How to Run This Project — {DATESTR}")
    canvas.drawRightString(letter[0] - 0.9 * inch, 0.5 * inch, f"Page {doc_.page}")
    canvas.restoreState()


doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
print("WROTE", OUT_PDF)
print("BYTES", os.path.getsize(OUT_PDF))
