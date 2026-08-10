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
# REFERENCES — numbered [N], assigned in order of first appearance.
# Every entry below was verified in 2026-06 against its DOI / arXiv ID / official
# venue page (the verification trail is in the commit message). Nothing here is
# invented: any claim for which no real source could be confirmed was reworded
# rather than given a fabricated citation.
# ===========================================================================
REF = ParagraphStyle("Ref", parent=BODY, fontSize=8.6, leading=11.5,
                     leftIndent=20, firstLineIndent=-20, spaceAfter=4)

REFDB = {
    # -- domain: exploit / vulnerability-exploitation prediction ----------
    "epss-2021": 'J. Jacobs, S. Romanosky, B. Edwards, M. Roytman, and I. Adjerid. '
        '"Exploit Prediction Scoring System (EPSS)." <i>Digital Threats: Research and '
        'Practice</i>, 2(3):Article 20, 2021. doi:10.1145/3436242.',
    "epss-v3-2023": 'J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, and A. Sarabi. '
        '"Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with '
        'Community-Driven Insights." In <i>2023 IEEE European Symposium on Security and '
        'Privacy Workshops (EuroS&amp;PW)</i>, pp. 194&ndash;206, 2023. arXiv:2302.14172.',
    "first-epss-model": 'FIRST.org EPSS Special Interest Group. "The EPSS Model." Forum of '
        'Incident Response and Security Teams. https://www.first.org/epss/model (accessed 2026).',
    "cisa-kev": 'Cybersecurity and Infrastructure Security Agency (CISA). "Known Exploited '
        'Vulnerabilities Catalog." https://www.cisa.gov/known-exploited-vulnerabilities-catalog '
        '(accessed 2026).',
    "sabottke-2015": 'C. Sabottke, O. Suciu, and T. Dumitras. "Vulnerability Disclosure in the '
        'Age of Social Media: Exploiting Twitter for Predicting Real-World Exploits." In '
        '<i>24th USENIX Security Symposium (USENIX Security 15)</i>, 2015.',
    "allodi-massacci-2014": 'L. Allodi and F. Massacci. "Comparing Vulnerability Severity and '
        'Exploits Using Case-Control Studies." <i>ACM Transactions on Information and System '
        'Security (TISSEC)</i>, 17(1):Article 1, 2014. doi:10.1145/2630069.',
    "householder-cset-2020": 'A. D. Householder, J. Chrabaszcz, T. Novelly, D. Warren, and '
        'J. M. Spring. "Historical Analysis of Exploit Availability Timelines." In <i>13th '
        'USENIX Workshop on Cyber Security Experimentation and Test (CSET 20)</i>, 2020.',
    "farris-vulcon-2018": 'K. A. Farris, A. Shah, S. Jajodia, R. Ganesan, and G. Cybenko. '
        '"VULCON: A System for Vulnerability Prioritization, Mitigation, and Management." '
        '<i>ACM Transactions on Privacy and Security (TOPS)</i>, 21(4):Article 16, 2018. '
        'doi:10.1145/3196884.',
    "epss-lookahead-2026": 'S. Paul. "How Good Is EPSS, Really? A Five-Year Empirical '
        'Evaluation Correcting for Look-Ahead Bias." IEEE DataPort, 2026. doi:10.21227/bhhs-0994. '
        '(Non-peer-reviewed dataset/report.)',
    "vulncheck-kev-2025": 'VulnCheck, Inc. "VulnCheck KEV Surges to Track More than 3,600 Known '
        'Exploited Vulnerabilities." Press release, May 2025. '
        'https://www.vulncheck.com/press/vulncheck-kev-10000.',
    "vulncheck-soe-2026": 'P. Garrity. "State of Exploitation: A Look at 2025 Vulnerability '
        'Exploitation." VulnCheck, Jan. 2026. https://www.vulncheck.com/blog/state-of-exploitation-2026.',
    # -- survival models --------------------------------------------------
    "cox-1972": 'D. R. Cox. "Regression Models and Life-Tables." <i>Journal of the Royal '
        'Statistical Society: Series B (Methodological)</i>, 34(2):187&ndash;202, 1972. '
        'doi:10.1111/j.2517-6161.1972.tb00899.x.',
    "kaplan-meier-1958": 'E. L. Kaplan and P. Meier. "Nonparametric Estimation from Incomplete '
        'Observations." <i>Journal of the American Statistical Association</i>, 53(282):457&ndash;481, '
        '1958. doi:10.1080/01621459.1958.10501452.',
    "ishwaran-rsf-2008": 'H. Ishwaran, U. B. Kogalur, E. H. Blackstone, and M. S. Lauer. "Random '
        'Survival Forests." <i>The Annals of Applied Statistics</i>, 2(3):841&ndash;860, 2008. '
        'doi:10.1214/08-AOAS169.',
    "katzman-deepsurv-2018": 'J. L. Katzman, U. Shaham, A. Cloninger, J. Bates, T. Jiang, and '
        'Y. Kluger. "DeepSurv: Personalized Treatment Recommender System Using a Cox Proportional '
        'Hazards Deep Neural Network." <i>BMC Medical Research Methodology</i>, 18:Article 24, 2018. '
        'doi:10.1186/s12874-018-0482-1.',
    "lee-deephit-2018": 'C. Lee, W. R. Zame, J. Yoon, and M. van der Schaar. "DeepHit: A Deep '
        'Learning Approach to Survival Analysis with Competing Risks." In <i>Proceedings of the '
        'AAAI Conference on Artificial Intelligence</i>, 32(1):2314&ndash;2321, 2018. '
        'doi:10.1609/aaai.v32i1.11842.',
    "chen-xgboost-2016": 'T. Chen and C. Guestrin. "XGBoost: A Scalable Tree Boosting System." '
        'In <i>Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery '
        'and Data Mining (KDD 16)</i>, pp. 785&ndash;794, 2016. doi:10.1145/2939672.2939785.',
    "barnwal-xgboost-aft-2022": 'A. Barnwal, H. Cho, and T. Hocking. "Survival Regression with '
        'Accelerated Failure Time Model in XGBoost." <i>Journal of Computational and Graphical '
        'Statistics</i>, 31(4):1292&ndash;1302, 2022. doi:10.1080/10618600.2022.2067548.',
    "hothorn-2006": 'T. Hothorn, P. Buhlmann, S. Dudoit, A. Molinaro, and M. J. van der Laan. '
        '"Survival Ensembles." <i>Biostatistics</i>, 7(3):355&ndash;373, 2006. '
        'doi:10.1093/biostatistics/kxj011.',
    "simon-glmnet-2011": 'N. Simon, J. Friedman, T. Hastie, and R. Tibshirani. "Regularization '
        'Paths for Cox\'s Proportional Hazards Model via Coordinate Descent." <i>Journal of '
        'Statistical Software</i>, 39(5):1&ndash;13, 2011. doi:10.18637/jss.v039.i05.',
    "farewell-cure-1982": 'V. T. Farewell. "The Use of Mixture Models for the Analysis of '
        'Survival Data with Long-Term Survivors." <i>Biometrics</i>, 38(4):1041&ndash;1046, 1982. '
        'doi:10.2307/2529885.',
    "davidson-pilon-lifelines-2019": 'C. Davidson-Pilon. "lifelines: Survival Analysis in '
        'Python." <i>Journal of Open Source Software</i>, 4(40):1317, 2019. doi:10.21105/joss.01317.',
    # -- benchmarks & sample-size ----------------------------------------
    "burk-2026": 'L. Burk, J. Zobolas, B. Bischl, A. Bender, M. N. Wright, and R. Sonabend. '
        '"A Large-Scale Neutral Comparison Study of Survival Models on Low-Dimensional Data." '
        '<i>Bioinformatics</i>, 42(5), 2026. arXiv:2406.04098; doi:10.1093/bioinformatics/btag186.',
    "rossi-2025": 'I. Rossi, F. Sartori, C. Rollo, G. Birolo, P. Fariselli, and T. Sanavia. '
        '"Beyond Cox Models: Assessing the Performance of Machine-Learning Methods in '
        'Non-Proportional Hazards and Non-Linear Survival Analysis." arXiv:2504.17568, 2025.',
    "concato-peduzzi-1995": 'P. Peduzzi, J. Concato, A. R. Feinstein, and T. R. Holford. '
        '"Importance of Events per Independent Variable in Proportional Hazards Regression '
        'Analysis. II. Accuracy and Precision of Regression Estimates." <i>Journal of Clinical '
        'Epidemiology</i>, 48(12):1503&ndash;1510, 1995.',
    "vittinghoff-mcculloch-2007": 'E. Vittinghoff and C. E. McCulloch. "Relaxing the Rule of Ten '
        'Events per Variable in Logistic and Cox Regression." <i>American Journal of '
        'Epidemiology</i>, 165(6):710&ndash;718, 2007. doi:10.1093/aje/kwk052.',
    "survtrace-2022": 'Z. Wang and J. Sun. "SurvTRACE: Transformers for Survival Analysis with '
        'Competing Events." In <i>Proceedings of the 13th ACM International Conference on '
        'Bioinformatics, Computational Biology and Health Informatics (ACM-BCB)</i>, 2022. '
        'arXiv:2110.00855.',
    "tabpfn-2023": 'N. Hollmann, S. Muller, K. Eggensperger, and F. Hutter. "TabPFN: A '
        'Transformer That Solves Small Tabular Classification Problems in a Second." In '
        '<i>International Conference on Learning Representations (ICLR)</i>, 2023. (Extended as '
        '"Accurate Predictions on Small Data with a Tabular Foundation Model," <i>Nature</i>, '
        '637:319&ndash;326, 2025, doi:10.1038/s41586-024-08328-6.)',
    "survivalpfn-2026": 'S.-A. Qi, V. Balazadeh, M. Cooper, R. Greiner, and R. G. Krishnan. '
        '"SurvivalPFN: Amortizing Survival Prediction via In-Context Bayesian Inference." '
        'arXiv:2605.15488, 2026.',
    # -- evaluation & causal methods -------------------------------------
    "uno-2011": 'H. Uno, T. Cai, M. J. Pencina, R. B. D\'Agostino, and L. J. Wei. "On the '
        'C-Statistics for Evaluating Overall Adequacy of Risk Prediction Procedures with Censored '
        'Survival Data." <i>Statistics in Medicine</i>, 30(10):1105&ndash;1117, 2011. doi:10.1002/sim.4154.',
    "blanche-2013": 'P. Blanche, J.-F. Dartigues, and H. Jacqmin-Gadda. "Estimating and Comparing '
        'Time-Dependent Areas Under Receiver Operating Characteristic Curves for Censored Event '
        'Times with Competing Risks." <i>Statistics in Medicine</i>, 32(30):5381&ndash;5397, 2013. '
        'doi:10.1002/sim.5958.',
    "heagerty-zheng-2005": 'P. J. Heagerty and Y. Zheng. "Survival Model Predictive Accuracy and '
        'ROC Curves." <i>Biometrics</i>, 61(1):92&ndash;105, 2005. doi:10.1111/j.0006-341X.2005.030814.x.',
    "graf-1999": 'E. Graf, C. Schmoor, W. Sauerbrei, and M. Schumacher. "Assessment and Comparison '
        'of Prognostic Classification Schemes for Survival Data." <i>Statistics in Medicine</i>, '
        '18(17&ndash;18):2529&ndash;2545, 1999.',
    "kattan-gerds-2018": 'M. W. Kattan and T. A. Gerds. "The Index of Prediction Accuracy: An '
        'Intuitive Measure Useful for Evaluating Risk Prediction Models." <i>Diagnostic and '
        'Prognostic Research</i>, 2:Article 7, 2018. doi:10.1186/s41512-018-0029-2.',
    "vickers-elkin-2006": 'A. J. Vickers and E. B. Elkin. "Decision Curve Analysis: A Novel Method '
        'for Evaluating Prediction Models." <i>Medical Decision Making</i>, 26(6):565&ndash;574, '
        '2006. doi:10.1177/0272989X06295361.',
    "vanderweele-ding-2017": 'T. J. VanderWeele and P. Ding. "Sensitivity Analysis in Observational '
        'Research: Introducing the E-Value." <i>Annals of Internal Medicine</i>, 167(4):268&ndash;274, '
        '2017. doi:10.7326/M16-2607.',
    "robins-2000": 'J. M. Robins, M. A. Hernan, and B. Brumback. "Marginal Structural Models and '
        'Causal Inference in Epidemiology." <i>Epidemiology</i>, 11(5):550&ndash;560, 2000. '
        'doi:10.1097/00001648-200009000-00011.',
    "fine-gray-1999": 'J. P. Fine and R. J. Gray. "A Proportional Hazards Model for the '
        'Subdistribution of a Competing Risk." <i>Journal of the American Statistical '
        'Association</i>, 94(446):496&ndash;509, 1999. doi:10.1080/01621459.1999.10474144.',
    "aalen-johansen-1978": 'O. O. Aalen and S. Johansen. "An Empirical Transition Matrix for '
        'Non-Homogeneous Markov Chains Based on Censored Observations." <i>Scandinavian Journal '
        'of Statistics</i>, 5(3):141&ndash;150, 1978. JSTOR:4615704.',
    "polsterl-2020": 'S. Polsterl. "scikit-survival: A Library for Time-to-Event Analysis Built on '
        'Top of scikit-learn." <i>Journal of Machine Learning Research</i>, 21(212):1&ndash;6, 2020. '
        'https://jmlr.org/papers/v21/20-729.html.',
}

_ref_order = []   # citation keys in order of first appearance
_ref_num = {}     # key -> assigned reference number


def cite(*keys):
    """Return an inline IEEE-style marker like [3] or [3, 5] for the given keys,
    registering each (in first-appearance order) for the References section."""
    nums = []
    for k in keys:
        if k not in REFDB:
            raise KeyError(f"unknown citation key: {k!r}")
        if k not in _ref_num:
            _ref_order.append(k)
            _ref_num[k] = len(_ref_order)
        nums.append(_ref_num[k])
    return "[" + ",&nbsp;".join(str(n) for n in nums) + "]"


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
    "positioned as a <b>complement</b> to EPSS "
    + cite("epss-2021", "first-epss-model")
    + ", not a competitor: EPSS answers “will this be "
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
    "Models spanning the survival toolbox: Kaplan-Meier "
    + cite("kaplan-meier-1958")
    + ", penalized Cox PH " + cite("cox-1972", "simon-glmnet-2011")
    + ", Random Survival Forest " + cite("ishwaran-rsf-2008")
    + ", GPU XGBoost-AFT " + cite("chen-xgboost-2016", "barnwal-xgboost-aft-2022")
    + ", mixture-cure " + cite("farewell-cure-1982")
    + ", DeepSurv/DeepHit " + cite("katzman-deepsurv-2018", "lee-deephit-2018")
    + ", plus a competing-risks / Aalen-Johansen core "
    + cite("fine-gray-1999", "aalen-johansen-1978") + ".",
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
    "classification (EPSS) "
    + cite("epss-v3-2023", "sabottke-2015", "allodi-massacci-2014")
    + ", while explicit time-to-event modeling of weaponization is under-explored "
    + cite("householder-cset-2020", "farris-vulcon-2018") + "."
)
key(
    "<b>CRITICAL framing caveat.</b> Of all observed first-weaponization events, <b>~97% are "
    "public-PoC dates</b>. Only CISA KEV (<font face='Courier' size=8>kev_date_added</font>) "
    + cite("cisa-kev")
    + " and Google Project Zero 0-day are true in-the-wild signals — historically a few hundred events. "
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
    "<b>Exclude snapshot-time EPSS.</b> Today's EPSS for an old CVE leaks the future (a recent "
    "empirical re-evaluation quantifies the look-ahead: 2023 efficiency collapses 60.9% &rarr; 11.1% "
    "when scored honestly "
    + cite("epss-lookahead-2026")
    + "). Only the <i>first EPSS reading after publication</i> is used.",
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
    "<b>Cox PH (penalized, lifelines "
    + cite("davidson-pilon-lifelines-2019")
    + ")</b> — the in-wild backbone. Ridge shrinkage handles the "
    "borderline events-per-variable (~9.5 EPV "
    + cite("concato-peduzzi-1995", "vittinghoff-mcculloch-2007")
    + "); the penalizer is scaled by the event rate (undoing "
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
    "<font size=8>* sksurv Cox-loss GBM "
    + cite("hothorn-2006", "polsterl-2020")
    + " is O(n&sup2;) per tree — only tractable after subsampling, "
    "which discards scarce events. Source: artifacts/inwild_headtohead.json "
    "(paired gbm&minus;cox AUC@90 = &minus;0.107, CI [&minus;0.154, &minus;0.061], excludes 0).</font>"
)
bullets([
    "<b>Why this matches the literature.</b> A neutral 34-dataset / 21-model benchmark finds <i>no "
    "method significantly outperforms Cox</i> on tabular survival "
    + cite("burk-2026")
    + "; in controlled ablations gradient boosting needs ~600 training samples (~420 events) and the "
    "transformer / Cox-likelihood neural models ~1,200 samples (~840 events) to surpass Cox-type "
    "linear models "
    + cite("rossi-2025", "survtrace-2022")
    + ". At ~396 events we are firmly in Cox's territory.",
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
    "<b>IPCW c-index + bootstrap CIs.</b> The truncated-at-&tau; variant equals Uno's C "
    + cite("uno-2011")
    + " under administrative censoring; bootstrap CIs + paired deltas vs Cox replace single point estimates.",
    "<b>Time-dependent AUC(t) with IPCW "
    + cite("blanche-2013", "heagerty-zheng-2005")
    + ".</b> Discrimination at each fixed horizon, reweighting rather "
    "than dropping censored rows.",
    "<b>PR-AUC over ROC-AUC.</b> Under &lt;1% imbalance ROC-AUC looks great while the model is useless "
    "on the minority; PR-AUC exposes the true positive yield.",
    "<b>Brier / IPA for calibration "
    + cite("graf-1999", "kattan-gerds-2018")
    + ".</b> IPA = scaled Brier vs the train-KM null — does the "
    "<i>absolute</i> probability beat the base rate?",
    "<b>Decision-curve net-benefit "
    + cite("vickers-elkin-2006")
    + ".</b> Measured: the in-wild model beats both treat-all and "
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
    "penalization (done), not a bigger model; neutral benchmarks need many hundreds of events "
    "(roughly 600&ndash;1,200 training samples) before ML or transformer models beat Cox "
    + cite("burk-2026", "rossi-2025") + "."
)

# ===========================================================================
# 9. VULNCHECK WIRING
# ===========================================================================
h1("9. VulnCheck Wiring — Raising the Ceiling")
p(
    "Because the ceiling is data-limited, the highest-leverage action is more / earlier in-wild "
    "<i>labels</i>. The VulnCheck KEV catalog (~173% larger than CISA KEV, ~27 days earlier "
    + cite("vulncheck-kev-2025")
    + ", using first-reported-<i>evidence</i> dates) was fetched and wired end-to-end."
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
    "It uses an adjusted Cox + stabilized inverse-probability weighting "
    + cite("robins-2000")
    + " with overlap/positivity diagnostics and the VanderWeele-Ding E-value "
    + cite("vanderweele-ding-2017")
    + " (unmeasured-confounding robustness). Confounders "
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
      "independently matches VulnCheck's reported 28.96% of 2025 KEVs "
      + cite("vulncheck-soe-2026")
      + ", an external validation of the "
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
    "are actually exploited? Using EPSS (FIRST's calibrated P(exploited in 30d) "
    + cite("epss-v3-2023", "first-epss-model")
    + ", trained on exploitation telemetry) as a semi-independent oracle quantifies the gap. "
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
    "any recalibration, TabPFN/SurvivalPFN "
    + cite("tabpfn-2023", "survivalpfn-2026")
    + " at this scale, and aggregate per-vendor/CWE forecasting "
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
# REFERENCES  (rendered last, after every cite() call has registered)
# ===========================================================================
story.append(PageBreak())
h1("References")
p(
    "Each source below was verified against its DOI, arXiv identifier, or official venue page "
    "during preparation of this report (2026-06); none is auto-generated or unverified. "
    "Citations are numbered in order of first appearance. Method papers ground the survival / "
    "evaluation / causal machinery; domain references ground the exploitation-timing and EPSS / "
    "KEV claims."
)
for _i, _k in enumerate(_ref_order, 1):
    story.append(Paragraph(f"[{_i}]&nbsp;&nbsp;{REFDB[_k]}", REF))
story.append(Spacer(1, 6))

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
