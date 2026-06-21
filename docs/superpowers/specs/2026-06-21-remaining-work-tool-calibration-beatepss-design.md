# Design — Remaining Work: Downstream Tool + Calibration-at-Horizons + Beat-EPSS Push

**Date:** 2026-06-21
**Status:** approved-by-default (autonomous spec-and-plan; standing user authorization to work all phases without review-gate)
**Author:** modeling agent (`/effort max`)

## Why this, why now

Against the professor's framing doc (`temporal_exploit_prediction.md` §"What success could
look like"), the project already satisfies every **core** criterion (defensible labels;
survival models on a time split with C-index + integrated Brier; the §Framing treatment of
PoC-dominance and informative censoring; a defender-facing interpretation) and two of the
three **"exceptional work"** bonus bullets (multi-state/competing-risks; EPSS reconciliation
/ RQ4). Three items remain, and the user selected all three, sequenced certain→speculative:

1. **D1 — downstream tool integration.** The single un-done "exceptional work" bullet
   ("integration of the predictions into a downstream tool").
2. **D2 — calibration at concrete horizons.** A *soft gap in the core list*: the doc asks for
   "calibration assessed at concrete horizons (e.g. 7/30/90/180 days)". We have discrimination
   (C-index) and integrated Brier and the scoring primitives (`proper_scoring.rcll`,
   `calibration.fit_temperature`), but **no horizon-wise reliability deliverable** and nothing
   wired into an artifact. Confirmed by grep: no `calibration_by_horizon` artifact exists.
3. **D3 — beat-EPSS push.** A stretch attempt to (a) beat EPSS at the sharp top-k with a
   top-k-optimized publication-time ranker, and (b) fix the DeepHit imbalance collapse. Both
   may end as honest negatives — that is an acceptable outcome and must be reported as such.

These ship independently; each banks value before the next.

## Non-negotiable constraints (inherited; apply to all three)

- **Leakage safety.** Publication-time-knowable features only (CVSS, CWE, CPE vendors/products,
  ATT&CK from the stable MITRE chain, first EPSS reading *after* publication). No `description`
  text, no snapshot-time presence flags, no snapshot-time EPSS. Every new feature gets a
  `feature_provenance()` row with a justified `leakage_status`. The PoC→KEV escalation model
  (D1 state 2) must use no KEV/snapshot features.
- **Time-based splits only**, never random K-fold. Reuse the locked `train/test_cve_ids.txt`
  where applicable; otherwise a `published`-quantile cut as in `defender_score.py`.
- **RAM ≤ 6–8 GB.** Column pushdown on loads; int8 downcast of flag features
  (`downcast_int_features`); never an `isin(cve_ids)` pushdown on `epss_history-001.parquet`
  (date pushdown only). `free -g` check before any heavy fit.
- **Immutable handover.** Never write to `dataset_extraction-*/`. Outputs go to `artifacts/`
  (gitignored) and committed docs under `docs/`.
- **Secrets.** VulnCheck token only via `VULNCHECK_API_TOKEN` / `--api-key`; run the token-leak
  grep (`git diff --cached | grep -ciE "vulncheck_[0-9a-f]{16}|gh[pousr]_[A-Za-z0-9]{20}"`)
  before *every* commit. `data/live/`, `data/merged/`, `artifacts/`, `.venv*` stay gitignored.
- **TDD.** Failing test → minimal impl → green → commit, using the tiny fixtures.
- **Aggressive RE floor (new work):** ≥10 reverse-engineering rounds per sub-project, multi-seed,
  1000-resample bootstrap CIs, and ≥1 adversarial null (label/risk shuffle) per headline claim.
  **RE delivery rule (user, 2026-06-21):** dispatch the RE via **at most 2 subagents**, each
  running **3–5 RE loops** (so ≥6–10 independent loops per sub-project across ≤2 agents).
- **Push after each commit** (standing authorization).

## D1 — Downstream triage tool

### What it does
Turns the validated state-aware logic (currently loose in `scripts/defender_score.py`) into a
reusable package module + CLI subcommand that emits a per-CVE triage table a defender can act on.

### Interface
- New module `src/temporal_exploit/triage.py`:
  - `assign_state(row) -> {"PUBLISHED","POC_PRESENT"}` — pure function of observable signals
    (a public PoC seen at/before the scoring date ⇒ `POC_PRESENT`, else `PUBLISHED`).
  - `score_triage(corpus, feats, event_frames, models, *, snapshot, min_pub, horizon) -> DataFrame`
    with columns: `cve_id, published, state, epss_at_pub, structural_risk, structural_tier,
    poc_to_kev_risk, escalation_flag, est_lead_days, recommended_action`.
  - `recommended_action` is a small rule table: PUBLISHED+high-EPSS ⇒ "patch in first wave";
    PUBLISHED + Defense-Evasion/Persistence tactic (RQ3) ⇒ "fast-weaponizer, prioritize";
    POC_PRESENT + high PoC→KEV risk ⇒ "escalate: pre-emptive patch before KEV listing".
  - `tier()` buckets `structural_risk`/`poc_to_kev_risk` into Low/Med/High by test-set quantiles.
- CLI: `temporal-exploit triage --out-dir <merged-or-handover> --artifact-dir artifacts/...
  --snapshot-date 2026-03-14 [--min-pub 2021-01-01]` → writes `triage_scored.parquet` + a
  human-readable `triage_top.csv` (top-N by tier) + reuses `defender_operating_points.json`.

### Reuse, don't duplicate
Reuse `_fit`, `_risk_scores`, `prepare_modeling_frame`, `time_split_frame`,
`build_transition_labels`, `EVENT_SOURCES`, `load_optional_event`. The `operating_points`
function moves from the script into `triage.py` (single source of truth); the script imports it.

### Tests
- `assign_state` truth table (PoC before/after/absent).
- `tier` monotonicity + quantile edges.
- `recommended_action` rule coverage (each branch hit).
- End-to-end on tiny fixtures: round-trips to parquet, schema-stable, no leaky columns present.

### RE (≥10)
state-assignment vs raw dates spot-check; tier-boundary stability across seeds; escalation-flag
recall reproduces `defender_interpretation` numbers (0.52 @ top-10%); adversarial risk-shuffle
collapses escalation recall to ~base rate; RAM trace; leaky-column scan on the output.

## D2 — Calibration at horizons

### What it does
Produces the missing horizon-wise reliability deliverable for the chosen models.

### REUSE FINDING (2026-06-21, scope-shrinking)
The repo **already has** the hard parts, just unwired into any artifact:
- `modeling.calibration_table(pred_event, frame, horizon, n_bins, min_events_per_bin)` — already
  does censoring-aware **KM-within-bin** reliability per horizon (adaptive bin count). Reuse as-is.
- `modeling.evaluate_survival(...)` — already returns **per-horizon Brier at 7/30/90/180** +
  integrated Brier + IPCW/truncated C-index with CIs. Reuse as-is.
- `modeling.survival_at(model, X, horizons, kind)` — S(t) per horizon → `pred_event = 1 - S`.
So D2's genuine delta is small: (a) **wire** these into a calibration artifact across the four
horizons for Cox + XGB-AFT, (b) add the **one missing estimator** — a calibration
**slope + intercept** (calibration-in-the-large), (c) **bootstrap CIs**, (d) the **doc**.

### Interface
- New `src/temporal_exploit/calibration.py::calibration_slope_intercept(pred_event, frame,
  horizon) -> dict` (the only new estimator): censoring-aware calibration-in-the-large
  (intercept) + slope via a weighted fit on KM-observed-vs-predicted bins from
  `calibration_table`. Bootstrap (1000) CIs.
- Script `scripts/calibration_by_horizon.py`: loads the locked time-split test set, fits Cox +
  XGB-AFT (the two chosen classical models), builds survival grids, calls the function, writes
  `artifacts/.../calibration_by_horizon.json` and a markdown table; optional reliability-curve
  PNG if matplotlib is cheap (text table is the primary artifact — no plotting dependency gate).
- Doc `docs/calibration_by_horizon_2026-06.md` interpreting slope (≈1 good), intercept (≈0
  good), and Brier vs KM-baseline at each horizon, with the small-sample caveat.

### Tests
- Perfectly-calibrated synthetic input ⇒ slope≈1, intercept≈0, observed≈predicted per bin.
- Mis-calibrated input (S inflated) ⇒ slope detectably ≠1 in the right direction.
- Censoring-aware bin estimate ≠ naive mean when heavy censoring present (guards the KM path).

### RE (≥10)
KM-within-bin vs naive mean delta under varied censoring; bin-count sensitivity (5/10/20);
horizon monotonicity sanity; bootstrap CI brackets point estimate; compare XGB-AFT vs Cox
calibration; temperature-recal (existing `fit_temperature`) before/after as a cross-check.

## D3 — Beat-EPSS push (stretch)

### (a) Top-k-optimized publication-time ranker
- `scripts/topk_ranker.py`: train an XGBoost ranker (`rank:pairwise` and a class-weighted
  binary `logistic` variant) on the **30-day first-weaponization** label using the same
  publication-time-safe feature matrix, on the locked time split. Compare top-1/5/10% precision
  and recall against (i) EPSS-only and (ii) the survival-model ranking from `defender_score.py`.
  Honest framing: if EPSS still wins, that strengthens the existing concession, not weakens it.

### (b) DeepHit imbalance-fix attempt
- `scripts/deephit_imbalance_fix.py`: re-run DeepHit with (i) class/rare-event re-weighting,
  (ii) ranking-loss `alpha`/`sigma` sweep, (iii) focal-style emphasis on the rare cause. Evaluate
  CIF vs Aalen-Johansen truth (the 0.19 ground truth that the prior run missed at 3e-6) and
  `concordance_td`. GPU sidecar `.venv-deep`; VRAM ≤7 GB. If it still collapses, report the
  honest negative with the diagnosis (extreme imbalance, not a config typo).

### Tests
- Ranker: top-k precision computed correctly on a synthetic ranking (known TP positions).
- DeepHit: CIF sums to ≤1 across causes; AJ-truth comparison harness returns the known 0.19 on
  the validation slice.

### RE (≥10)
multi-seed ranker stability; EPSS-in/out ablation (is the ranker just distilling EPSS?);
adversarial label-shuffle null on the ranker; DeepHit CIF-vs-AJ at multiple horizons;
calibration of the ranker's top bin; RAM/VRAM traces.

## Outputs / definition of done

- D1: `triage.py` + `triage` CLI + tests green + `triage_scored.parquet`/`triage_top.csv` +
  README "downstream tool" section. Committed + pushed.
- D2: `reliability_by_horizon` + tests + `calibration_by_horizon.json` + doc. Committed + pushed.
- D3: ranker + deephit-fix scripts + honest results doc (`docs/beat_epss_attempt_2026-06.md`),
  whether positive or negative. Committed + pushed.
- Full suite green after each sub-project; `docs/progress.md` + README Project-status updated.

## Risks / mitigations

- **D3 may produce no improvement.** Acceptable; the deliverable is the honest, RE-verified
  comparison, not a win. Time-box D3 — if (a) and (b) both clearly lose after the RE floor, stop.
- **DeepHit GPU env drift.** Sidecar `.venv-deep`, `--torch-backend=auto`; if VRAM blows the cap,
  fall back to CPU mini-batch or report env-limited.
- **Calibration small-sample noise** (in-wild events sparse). Report bootstrap CIs; lean on the
  PoC-dominant first-weaponization label where events are plentiful, caveat the in-wild slice.
- **Scope creep across three sub-projects.** Each is independently shippable and committed before
  the next starts; no cross-dependencies except D1 reusing existing functions.
