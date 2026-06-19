# Wave-improvements program (2026-06-19)

> Self-reviewed design + plan (user delegated review — memory
> `autonomous-spec-and-plan`). Four phases, sequenced by leverage: rigor first
> (so the rest is measured soundly), then the cure model, NLP features, DeepHit.
> TDD + commit + push per task. Hard budget: ≤6–8 GB RAM, ≤7 GB VRAM
> (`memory-budget-constraint`). Env via uv.

## Global constraints
- Tests green (`.venv/bin/python -m pytest -q`, FutureWarning→error baked in).
- Leakage discipline preserved; new features get a `feature_provenance` row.
- tz-aware UTC; never modify the immutable handover dir; `artifacts/`,
  `data/*` gitignored.
- Memory-gate (`free -g`) before any real-data build/train; cox+xgb+cure for
  in-wild; never full-corpus RSF; deep models sampled-eval + GPU.

---

## Phase A — Evaluation rigor (bootstrap CIs + truncated c-index)

**Why:** the wave quotes a Noether-approximation c-index CI; the cure-vs-cox gap
is ~half an SE, so the comparison needs proper resampling uncertainty.

**`modeling.py` additions:**
- `bootstrap_cindex_ci(y_train, y_test, risk, tau, n_boot=500, seed=0) -> dict`:
  percentile 95% CI + SE by resampling test rows **with replacement, stratified
  on `event_observed`** (so each resample keeps ~the same event count) and
  recomputing `concordance_index_ipcw` on the resampled `(y_test, risk)` — **no
  refit**. Returns `{ci95, se, n_boot}`.
- `paired_cindex_delta_ci(y_train, y_test, risk_a, risk_b, tau, n_boot=500,
  seed=0) -> dict`: the **same** bootstrap indices applied to both models →
  distribution of `c_a − c_b` → `{delta, ci95, p_gt0}`. This is what answers
  "is cure better than cox" honestly.
- `truncated_cindex(durations, events, risk, tau) -> float`: exact Harrell C
  restricted to comparable pairs with the earlier (event) time ≤ tau — under
  administrative censoring the comparability is exact, sidestepping the IPCW
  weight degeneracy. (Bonus; horizon-AUC already covers discrimination.)

**Wiring:** `evaluate_survival` adds `c_index_bootstrap_ci95` (keeps the Noether
one, labelled) + `c_index_truncated`. `train_command` computes paired deltas
(each model vs `cox`) on shared indices → `metrics["paired_cindex_vs_cox"]`.

**Tests:** bootstrap CI brackets the point estimate and shrinks as n_boot grows;
paired delta of a model vs itself is ~0 with a CI straddling 0; truncated
c-index in [0,1] and ≈ Harrell C on uncensored data. **Success:** in-wild report
carries bootstrap CIs + a paired cure-vs-cox delta CI.

---

## Phase B — Cure model: flexible latency + recalibration

**Why:** Weibull's monotone hazard may misfit weaponization timing; the in-wild
IPA sits at the null with EPSS features.

**`cure.py` changes:**
- Add `latency` param to `fit_cure` / `_objective`: `"weibull"` (current) |
  `"loglogistic"`. Log-logistic: `S_u = 1/(1+(t/scale)^k)`,
  `f_u = (k/scale)(t/scale)^{k-1}/(1+(t/scale)^k)^2` — non-monotone hazard.
  Analytic gradient for the log-logistic NLL (finite-difference-checked, incl.
  the clipped region, mirroring the Weibull guard).
- `latency="auto"` (default): fit both, select by **AIC** (`2·nll + 2·k_params`),
  record the choice on the model (`CureModel.latency_`).
- **Recalibration (optional, `recalibrate=True`):** hold out 25% of train, fit
  per-horizon **isotonic** regression of predicted `P(event by h)` vs the
  censoring-free outcome (`observed | duration≥h`); store `{h: IsotonicRegression}`
  on the model and apply in `survival_at`. Improves Brier/IPA if mis-calibrated.

**Tests:** log-logistic recovers a synthetic cure fraction + non-monotone shape;
gradient matches finite differences; `auto` picks the generating family on
synthetic data; recalibration is monotone and leaves ranking unchanged.
**Success:** in-wild run reports the AIC-selected latency and IPA at 90/180d ≥
the Weibull cure model (measured with Phase A bootstrap CIs).

---

## Phase C — NLP description features (leakage-safe)

**Why:** `text_safety.py` is ready but unused; structured text signal may lift
discrimination, and the wave promised to wire it.

**`nlp_features.py`:** `build_description_features(corpus, epsilon_days=7)` using
`text_safety.build_safe_descriptions` (freshness-gated + leakage-masked). Bounded,
interpretable, leakage-safe columns: `desc_char_len`, `desc_word_count`,
`description_fresh`, and a small fixed set of generic security-keyword indicators
(`desc_kw_remote/local/auth/overflow/injection/bypass/dos/rce`) — **no** KEV/
exploited terms (masked) and **no** high-dim TF-IDF (memory). `description_feature_provenance()`
with `leakage_status="publication_time_safe_freshness_gated"`.

**Build wiring:** `build-dataset --description-text` loads only `cve_id,
published, description, last_modified` (a second projected load, so the default
build stays light — description is 112 MB), merges the features, appends
provenance. Manifest flag `description_features_enabled`.

**Tests:** masked leakage terms never produce a keyword hit; back-edited (stale)
descriptions blank out (length 0, fresh=0); keyword indicators fire on fixture
text. **Success:** features build behind the flag; a train run shows the
discrimination delta (reported either way, leakage caveat documented).

---

## Phase D — DeepHit competing-risks

**Why:** complement Aalen-Johansen / cause-specific Cox with a learned joint
competing-risks model; the wave's competing-risks layer has no deep variant.

**`deephit.py`** (mirrors `deep.py`: lazy torch, `[deep]` extra, GPU,
sampled eval, scipy.simps shim): `fit_deephit(competing_train, ...)` using
pycox `DeepHit` with `LabTransDiscreteTime` (discretized durations, cause codes
as events). `DeepHitModel` wrapper holds the net + transform + standardization.
`evaluate_deephit(model, test, horizons)` → per-cause time-dependent c-index +
the cause-specific CIF at horizons. Wire into `train-competing --deep-hit`.

**Tests (gated like `test_deep.py`, skip without torch):** fit + predict CIF
shapes correct; CIFs in [0,1] and non-decreasing in t; eval returns per-cause
metrics. **Success:** `train-competing --deep-hit` runs on GPU within VRAM,
emits per-cause DeepHit metrics beside the AJ/Cox numbers.

---

## Closeout
Code-review the program diff; update `docs/progress.md` + README; final pytest;
commit + push.

## Self-review
- **Coverage:** A→bootstrap/truncated; B→latency/recalib; C→nlp_features; D→
  deephit; each has tests + a measurable success gate. ✓
- **Placeholders:** none — every interface has concrete signatures/returns. ✓
- **Type consistency:** `bootstrap_cindex_ci`/`paired_cindex_delta_ci`/
  `truncated_cindex` signatures identical across A's wiring; `fit_cure(latency=…)`
  + `CureModel.latency_` consistent in B; `build_description_features` consistent
  in C; `fit_deephit`/`DeepHitModel`/`evaluate_deephit` consistent in D. ✓
- **Memory:** A/B light (resampling/scipy); C loads description only behind the
  flag; D sampled-eval + GPU. ✓
- **Risk:** B's log-logistic gradient and D's pycox discretization are the
  trickiest — both get finite-difference / shape tests as guards.
