# Research: how to improve the system (2026-06)

Deep-research sweep of the 2022–2026 exploit-prediction literature and industry
practice, adversarially verified against primary sources (23/25 claims
confirmed 3-0 or 2-1). Each recommendation is mapped to this codebase.

## Priority 1 — Replace independent per-signal models with competing-risks / multi-state estimation

**Finding (unanimous across Therneau's survival vignette, scikit-survival docs,
and Alberge et al. 2024):** treating competing weaponization signals as
censoring violates non-informative censoring; per-cause Kaplan-Meier and
independent per-signal survival fits systematically **overestimate** per-cause
incidence. The unbiased estimator is the cumulative incidence function
(Aalen-Johansen), computed jointly across causes.

**Nuance:** the bias hits probability/CIF estimates (our KM-based calibration
and horizon probabilities), not hazard ratios or pure ranking (C-index), so our
current numbers are not worthless — but every per-signal probability we report
is inflated.

**Because the cascade PoC → Metasploit/Nuclei → KEV is sequential and
non-terminal, the fully principled frame is a multi-state model:** fit one
hazard model per transition (published→PoC, PoC→Metasploit, PoC→KEV, …) —
which preserves our existing per-model code — but compute
probability-in-state jointly (Aalen-Johansen). Do **not** default to Fine-Gray
(its assumptions conflict with cause-specific PH, multi-cause predictions can
sum past 100%, and it doesn't extend to multi-state).

**Codebase mapping:** `labels.build_competing_risks_labels` already emits the
long-format cause-coded frame this needs. Concrete steps:
1. Aalen-Johansen CIF baseline (lifelines `AalenJohansenFitter`) over the
   competing-risks labels — replaces per-signal KM as the calibration reference.
2. Cause-specific Cox per transition + joint state-occupancy probabilities.
3. Evaluate **SurvivalBoost** (`hazardous` library, Inria; AISTATS 2025) — a
   gradient-boosted competing-risks model with an IPCW-proper scoring rule;
   best Integrated Brier vs 11 baselines (author-reported), and the natural
   fit for our existing XGBoost/Brier workflow.

## Priority 2 — Add timestamped post-publication artifact features (landmarking)

**Finding (Suciu et al., USENIX Sec '22 — Expected Exploitability):**
time-varying features from post-disclosure artifacts dominate static metadata.
EE raised precision 49%→86%; PoC-code AST features alone hit 0.93 precision on
half the exploited vulns; **handcrafted EPSS-v1-style features (≈ our current
feature set) were the worst-performing category**; Twitter/social features were
not useful for functional-exploit prediction. Artifacts arrive early: 71% of
PoCs land on disclosure day; write-ups precede exploits for >92% of vulns
(while only 9% of CVSS scores exist at disclosure).

**Leakage caveat specific to us:** ~97% of our events ARE PoC dates, so
PoC-existence features are label leakage for the PoC endpoint — but valid for
downstream transitions (Metasploit/Nuclei/KEV given PoC). Write-up/reference
features are valid throughout if snapshotted at dated landmarks.

**Codebase mapping:**
- Landmark design: features as-of `published + {1, 7, 30}d`, with the
  prediction clock restarted at the landmark. Reference counts/tags from NVD
  (`references` are dated in the corpus chain) are the cheapest start.
- For PoC→Metasploit/Nuclei/KEV transition models: PoC repo metadata (language,
  stars at first-seen, file counts) as features — leakage-safe for those
  endpoints since the PoC already exists at transition-clock start.
- `text_safety.py` already provides the masking/freshness gate for description
  text features (EE found write-up text valuable).

## Priority 3 — Broaden and de-noise labels

**Findings:**
- EE aggregates **12 label sources** (X-Force/Tenable temporal-CVSS
  Functional/High, Metasploit, Canvas, D2, VirusTotal, Symantec, Skybox,
  AlienVault, Contagio…) → 32k functional-exploit labels. EPSS v4 collects
  ~12k vulns/month of exploitation telemetry (proprietary). Our in-the-wild
  label is ~664 KEV+0-day events — extremely sparse.
- **All 12 ground-truth sources examined by EE are statistically biased** on
  ≥4 vulnerability features each (chi-squared, Bonferroni p<0.01). KEV's
  federal-relevance selection bias is an instance of this. EE handles it with
  a Feature Forward Correction loss (binary-classification form; adapting to
  survival likelihoods is open work).

**Codebase mapping:** candidate public label sources to add as connectors:
VulnCheck KEV (broader than CISA KEV), Exploit-DB verified flags, Shadowserver/
GreyNoise honeypot observation feeds. Each reduces in-wild sparsity and
KEV-only selection bias.

## Evaluation changes implied

- Calibration should move from per-signal KM to CIF-based (Austin-style) per
  cause/transition.
- IPCW C-index remains fine for ranking within a cause; report per-transition.
- Keep the strict time split (the literature's leakage findings vindicate it).

## Verified sources (primary)

- Suciu et al., "Expected Exploitability: Predicting the Development of
  Functional Vulnerability Exploits", USENIX Security 2022.
- EPSS v4 announcement, Empirical Security / FIRST.org, 2025.
- Therneau, "Multi-state models and competing risks" (survival package vignette).
- scikit-survival competing-risks user guide.
- Alberge et al., "Survival Models: Proper Scoring Rule and Stochastic
  Optimization with Competing Risks" (SurvivalBoost/hazardous), AISTATS 2025.
- Jeanselme et al., "Neural Fine-Gray", CHIL 2023.
- Monterrubio-Gomez et al., review of statistical/ML survival methods,
  Biometrical Journal 2024.
- Llopis-Cardona et al., multi-state models tutorial, Int. J. Epidemiology.

## Open questions (not settled by the literature)

1. Which redistributable label feeds best substitute for EE/EPSS proprietary
   telemetry, and how much sparsity do they actually remove?
2. How to combine landmarking with multi-state transitions on vulnerability
   data (no verified source demonstrates the combination).
3. Can Feature Forward Correction be adapted to censored survival likelihoods
   for KEV selection bias / git-mined PoC date error, or is interval-censoring
   the better formulation?
4. Right censoring-distribution estimator for IPCW under our administrative
   snapshot censoring when moving to multi-state evaluation.
