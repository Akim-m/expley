# How others model CVE exploitation — and what we should steal

**Date:** 2026-06-20 · **Method:** deep-research workflow (5 angles → 22 primary sources →
106 claims → adversarial verification) + direct cross-checks. The workflow's final
synthesis + most verification votes were throttled by API rate-limiting, so confidence is
labelled per claim:

- **[VERIFIED]** — survived 2–3 independent adversarial votes.
- **[PRIMARY]** — direct quote from a primary source but its vote was lost to rate-limiting.
- **[REFUTED]** — a verifier knocked it down; shown only as a caution.

> **Re-verification pass (paced batches of 5, to dodge the rate-limit that broke the original
> run):** every initially-unaudited claim was re-checked by a dedicated adversarial verifier.
> Net result — the EE/Bozorgi/Iannone/POLAR claims **all CONFIRMED**; the one genuine
> correction was the **EE-vs-EPSS AUC numbers** (≈0.93 vs ≈0.75 at 30 days, not 0.73/0.45),
> and the Sabottke-Twitter "refute" was **overturned** (it's the paper's own finding). EPSS-v1
> exact counts remain [PRIMARY]. So the recommendations below stand unchanged.

Our system = the survival/competing-risks layer in `src/temporal_exploit/` (Cox primary +
RSF/GBM/XGB-AFT/cure/DeepSurv/DeepHit/SurvivalBoost, publication clock origin,
leakage-safe features, rolling-origin backtest).

---

## 1. The landscape in one table

Everyone in this space makes the **same three choices** differently: (a) target definition,
(b) how time is handled, (c) label source. We are the only line that uses a true
**hazard/time-to-event** model. Almost everyone else uses **binary classification on a fixed
window**.

| System | Target / label | Time handling | Model | Features | Eval |
|---|---|---|---|---|---|
| **Ours** | earliest of PoC/MSF/Nuclei/KEV/0-day | **survival**, publication clock origin, censoring | Cox + cure + competing-risks (+RSF/GBM/XGB/deep) | publication-time-safe: CVSS, CWE, CPE, ATT&CK, 1st EPSS | C-index, Brier, IPA, calibration, rolling-origin |
| **EPSS v1** (Jacobs 2021) | in-wild exploit ≤12 mo | binary, fixed window | **Elastic-net logistic regression** | ~hundreds, NVD + feeds | PR, PR-AUC, BIC |
| **EPSS v3** (Jacobs 2023) | in-wild activity ≤**30 days** | binary, fixed window | **XGBoost** | **1,477** incl. social media, scanner presence, exploit code, KEV/ZDI/P0, keywords | PR-AUC **0.78**, Brier **0.016** |
| **EPSS v4** (2025) | in-wild ≤30 days | binary, fixed window | XGBoost (+ richer feeds) | further expanded | PR-AUC reported higher |
| **Bozorgi** (KDD 2010) | exploit-available (OSVDB) | **bag of "exploited within t days" classifiers** (t=2/7/14/30) | **linear SVM** (~94k-dim BoW) | disclosure-report text | accuracy ~90% offline |
| **Sabottke** (USENIX'15) | Symantec sig / real-world | binary | **linear SVM** | **67 incl. Twitter** | precision/recall |
| **Expected Exploitability** (Suciu, USENIX'22) | **functional** exploit ≤1yr | **time-varying** (recomputed as artifacts arrive) | supervised classifier | **PoC code complexity (AST) + PoC/write-up NLP** | PR-AUC **≈0.93** vs EPSS ≈0.75 (30d); **86% vs 49% precision** |
| **Iannone** (TOSEM 2024) | exploit-available (ExploitDB) | binary, disclosure-time only | logistic regression best | CVE desc + SecurityFocus text | weighted-F **0.49** under time-aware CV |
| **POLAR** (2025) | exploit ≤30 days (EPSS-aligned) | **LLM reasoning over a temporal narrative** of events | LLM, no fitted distribution | time-ordered event gaps as text | vs EPSS window |
| **Tenable VPR / Kenna-RAND** | risk prioritisation | score, not time | proprietary GBT / logistic | threat-intel + CVSS | effort-vs-coverage |

---

## 2. What each does, and how it differs from us

### EPSS — the reference point (and our explicit complement)
- **[VERIFIED]** EPSS v3 is **binary classification of in-the-wild activity in the next 30
  days, via XGBoost** — *not* a hazard model. The 30-day window was a SIG decision to match
  enterprise patch cycles. → This is the core framing contrast: we model *when*, they model
  *probability within a fixed window*. We are complementary, not competing (as CLAUDE.md
  already states).
- **[VERIFIED]** v3 uses **1,477 features / 11 categories**: in-wild labels, published
  exploit code (ExploitDB/GitHub/Metasploit), public lists (CISA-KEV, Google P0, ZDI),
  **Twitter mentions (3 time-windowed counts)**, **offensive-tool/scanner presence (nuclei,
  jaeles, intrigue, sn1per)**, 17 reference-tag counts, **147 description keywords**, 15 CVSS
  metrics, 188 CWE, 1,096 vendor labels, vuln age. → **Several of these we don't use** (social
  media, scanner presence, reference-tag counts, keyword bag).
- **[VERIFIED]** Ground truth = **honeypot/IDS sensor networks (Fortinet, AlienVault OTX,
  Shadowserver, GreyNoise)** as a daily boolean. Corpus 2016→2022, **6.4M observations,
  12,243 exploited CVEs = only 6.4%** of published. → Confirms our in-wild scarcity is
  intrinsic, not a data-collection failure. We already wired Shadowserver — same family.
- **[VERIFIED]** Held-out Dec-2022: **PR-AUC 0.7795, F1 0.728, Brier 0.0162**; CVSS base
  PR-AUC 0.051. → Their **Brier + PR-AUC + efficiency/coverage** reporting is the industry
  vernacular; we should report in the same units for the in-wild head so results are
  comparable.
- **[PRIMARY]** v1 (2021) was **elastic-net logistic regression**, ≤12-month window, 3.7%
  base rate (921/25,159). The v1→v3 arc is *logistic → XGBoost + many more features*: the
  gains came from **features and labels, not model sophistication**. ← the single most
  important strategic lesson for us.

### Expected Exploitability (Suciu, USENIX'22) — the closest cousin, and our biggest gap
- **[PRIMARY/REFUTED-on-a-technicality]** EE is **time-varying exploitability**, recomputed as
  post-disclosure artifacts arrive — conceptually parallel to our landmarking, but per-day
  probability rather than a hazard. (The verifier abstained on the "directly analogous"
  wording, not the substance.)
- **[PRIMARY]** Target = **functional** exploit (CVSS Exploit-Code-Maturity Functional/High),
  not mere PoC existence — a **stricter, more in-wild-relevant label** than our PoC-dominated
  event.
- **[PRIMARY]** **Central innovation: features extracted from PoC *content*** — PoC **code
  complexity via program analysis** and PoC **text/comments via NLP** — because functional
  exploits correlate strongly with PoC publication, while *mere PoC existence* is a weak
  predictor. → **We use PoC only as a label-date, never as content.** This is the richest
  unexploited signal available — but note `fetch/poc.py` clones the *index* repos
  (trickest/cve, nomi-sec/PoC-in-GitHub) with `blob:none` and stores only a `poc_path` string
  + first-seen date; the **exploit-code content is not on disk**. Capturing it first requires
  fetching the actual PoC code the indexes point to.
- **[PRIMARY]** **Label-noise mitigation for the collection cutoff**: exploits appearing after
  the window become wrong-negative, class- and feature-dependent noise; their method keeps
  performance stable even with evidence about ~20% of exploits missing. → Directly relevant to
  our right-censoring; a transferable robustness technique.
- **[VERIFIED]** EE beats EPSS and static metrics on functional-exploit prediction: at 30 days
  post-disclosure EE **PR-AUC ≈0.93 vs EPSS ≈0.75**, and **86% precision vs 49%** for the
  best prior classifier; static metrics cap out far lower (CVSSv3 Exploitability ≤0.19,
  RedHat Severity ≤0.45, MS Exploitability Index ≤0.45). *(The earlier 0.73-vs-0.45 figure
  was an operating-point/version artifact; the 30-day AUCs above are the paper's headline.)*
  PoC-code features alone reach **0.93 precision at 50% recall**.

### Bozorgi (KDD 2010) — the original, and a time-handling cautionary tale
- **[PRIMARY]** Linear SVM on ~94k-dim bag-of-words from disclosure reports; **~90% offline
  accuracy but ~14% error online** (walk-forward). → The offline/online gap is the whole
  reason we do rolling-origin backtest; cite it.
- **[PRIMARY]** They handled timing by **stacking "exploited within t days" classifiers
  (t=2/7/14/30)** and *explicitly noted SVMs can't model the distribution over exploit days*.
  → This is precisely the limitation our survival model removes — a clean way to frame our
  contribution.
- **[PRIMARY]** Labels = OSVDB "Exploit Available/Rumored/Private" → exploit-*availability*,
  not in-wild. Same label-quality caveat we carry.

### Iannone (TOSEM 2024) — the honest performance ceiling
- **[PRIMARY]** Binary classification using **only disclosure-time data** (CVE description +
  SecurityFocus/BugTraq discussion text); deliberately avoids post-disclosure features.
- **[PRIMARY]** **Label-confidence cleaning**: CVEs published within a **532-day uncertainty
  window** (90th pct of exploitation-time distribution) with no exploit yet are **excluded**,
  not labelled negative — they solve our right-censoring problem by *data removal in a
  classifier*. We solve it *correctly* via censoring; good validation that our framing is the
  principled one.
- **[PRIMARY]** Under **time-aware validation (22 rounds, test published after train)** the
  best model is **plain logistic regression, weighted-F only 0.49, MCC 0.36**. → A sobering
  ceiling for text-only disclosure-time prediction, and strong evidence that **simple linear
  models + honest temporal CV** is the right baseline discipline.

### POLAR (2025) — the LLM frontier
- **[PRIMARY]** Same target as EPSS (30-day exploit probability), but estimates it by having
  an **LLM reason over a "temporal narrative"** of time-ordered events (CVE pub → PoC → KEV →
  in-wild) with explicit inter-event gaps — weaponization timeline as natural-language
  reasoning, no fitted distribution. → Interesting but orthogonal to our needs; a possible
  feature-encoder idea (turn our event cascade into structured text), not a model swap.

### Verification corrections
- **[VERIFIED — earlier refute overturned]** "Twitter improves precision ~an order of
  magnitude over vuln-DBs / detects a median 2 days ahead" (Sabottke). On a paced re-check
  this is the paper's *own* claim: CVSS-only detection precision ≤9%, lifted ~10× with the
  Twitter signal, median 2-day lead over existing datasets. The first pass's auto-refute was
  a rate-limit artifact, not a real refutation. *(Caveat: the absolute precision the detector
  reaches isn't cleanly stated in open sources; the 10× and 2-day figures are the authors'.)*
- **[CORRECTED]** EPSS-v1 specifics: the **elastic-net logistic-regression framing is solid**,
  but the exact `921/25,159 (3.7%)` counts, the Jun-2016→Jun-2018 window, and the "60% less
  remediation effort" figure are **[PRIMARY/unaudited]** — the re-verifier couldn't reach the
  original paper text, so treat those numbers as indicative, not nailed.

---

## 3. Where they genuinely beat us — ranked gaps

1. **PoC-content features (EE).** We hold only the *index* (paths + first-seen dates from
   trickest/nomi-sec), not the exploit-code content, and reduce even that to a date +
   file-extension. Code-complexity + text/NLP features are the single best-evidenced lift
   available to us — but they require **fetching the actual PoC code first** (the indexes only
   point to it).
2. **Feature breadth (EPSS v3).** Scanner/offensive-tool presence, reference-tag counts,
   social-media counts, description-keyword bag — cheap, public, and proven. We use almost
   none.
3. **Reporting in the field's units (EPSS).** PR-AUC, Brier, and efficiency/coverage curves —
   we lead with C-index/IPA. Adding the classification-style metrics on the in-wild head makes
   us directly benchmarkable against EPSS.
4. **The strategic lesson (EPSS v1→v3, Iannone).** Returns came from **labels + features**,
   and **simple models under honest temporal CV** are the real baseline. We have arguably
   *over-invested in model variety* (8+ model families) relative to feature/label expansion —
   exactly what `inwild-ceiling-is-data-limited.md` already concluded.
5. **Label-noise-under-censoring robustness (EE).** A concrete technique for the wrong-negative
   problem our late events create.

Where **we are ahead** (keep and emphasise): a *true hazard model* (everyone else stacks
window-classifiers or does one-shot binary), *competing-risks* decomposition (nobody else
separates PoC vs MSF vs KEV causes), *mixture-cure* for the never-exploited mass (the
honest way to model 94% structural zeros), and *strict publication-time leakage control with
a provenance audit trail*.

---

## 4. Prioritized recommendations

| # | Adopt | Why it's better | Effort | Where it lands |
|---|---|---|---|---|
| **1** | **PoC-content features** — code complexity + NLP on PoC code (must fetch it first; today we hold only an index) | Best-evidenced lift (EE **86% vs 49% precision**, PR-AUC ≈0.93 vs ≈0.75) | **L** | extend `poc_features.py` (today only counts/lags/exts) + first teach `fetch/poc.py` to fetch real PoC content (currently `blob:none`, paths only) |
| **2** | **Report PR-AUC + Brier + efficiency/coverage on the in-wild head** | Makes us benchmarkable vs EPSS; Brier already implied by our IPA | **S** | `evaluate.py` / `modeling.evaluate_survival` add classification-metric block at horizons |
| **3** | **Cheap EPSS-style features**: scanner/offensive-tool presence (we already fetch nuclei!), reference-tag counts, description-keyword bag | Proven, public, low-risk; nuclei presence is in-repo | **S–M** | new `*_features.py`; mind leakage — gate to publication-time-knowable only |
| **4** | **Functional-exploit label tier** (CVSS Exploit-Code-Maturity / richer KEV) as a stricter target than PoC | Closes the "we predict tooling not in-wild" gap EE solves | **M** | `labels.py` new builder; pairs with VulnCheck/Shadowserver already wired |
| **5** | **EE-style label-noise-under-cutoff robustness** + keep our censoring | Hardens late-event handling | **M** | `labels.py` / backtest origins |
| **6** | **Lead-time framing borrowed from Bozorgi/EE** in reporting | Sharpens our "we add *when*, they give *whether*" story | **S** | docs + `backtest.operational_metrics` (already has lead-time-days) |
| **7** | *(watch, don't build)* POLAR LLM temporal-narrative encoder | Frontier, unproven vs our regime; high cost | **L** | n/a yet |

**Bottom line:** the literature validates our *framing* (a true survival/competing-risks model
is more principled than everyone's window-classifiers) but says our *next win is not another
model* — it's **PoC-content features (#1) + cheap public feature breadth (#3) + a stricter
functional-exploit label (#4) + benchmarkable reporting (#2)**. That is the same conclusion
your own `inwild-ceiling-is-data-limited` memo reached, now triangulated against EPSS, EE,
Bozorgi and Iannone.

### Key sources
- EPSS v3 — Jacobs et al. 2023, arXiv [2302.14172](https://arxiv.org/pdf/2302.14172) · WEIS'23 [pdf](https://weis2023.econinfosec.org/wp-content/uploads/sites/11/2023/06/weis23-jacobs.pdf)
- EPSS v1 — Jacobs et al. 2021, [ACM DTRAP 10.1145/3436242](https://dl.acm.org/doi/10.1145/3436242)
- EPSS v4 — Empirical Security 2025, [intro](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- Expected Exploitability — Suciu et al., USENIX Sec'22 [paper](https://www.usenix.org/system/files/sec22-suciu.pdf) · [slides](https://www.usenix.org/system/files/sec22_slides-suciu.pdf) · [tech report 2102.07869](https://arxiv.org/pdf/2102.07869)
- Bozorgi et al., KDD 2010 [pdf](https://cseweb.ucsd.edu/~savage/papers/KDD10.pdf)
- Sabottke et al., USENIX Sec'15 [page](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/sabottke)
- Iannone et al., TOSEM 2024 [pdf](https://giuliasellitto7.github.io/pdf/Iannone-TOSEM2024-Early-and-Realistic-Exploitability-Prediction-of-Just-Disclosed-Sotware-Vulnerabilities.pdf)
- POLAR (LLM), 2025 [2510.01552](https://arxiv.org/pdf/2510.01552)
- RAND/Kenna exploitability — [RR1751](https://www.rand.org/content/dam/rand/pubs/research_reports/RR1751.html) · Cyentia [report](https://library.cyentia.com/report/report_002993.html)
- Tenable VPR — [methodology](https://www.tenable.com/blog/enhancements-to-tenable-vpr-and-how-it-compares-to-other-prioritization)
- Vuln-management chaining framework, 2025 [2506.01220](https://arxiv.org/pdf/2506.01220)
