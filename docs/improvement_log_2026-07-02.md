# Pipeline improvement log — 2026-07-02

Running record of every change made in the whole-pipeline improvement effort
(accuracy + memory + speed), **with the reason for each and the measurement
that justifies it**. Updated as work lands, not retroactively.

Rules of engagement for this effort:

- **Hard memory gates:** ≤6 GB peak RSS per process (red line; standing budget
  6–8 GB), ≤7 GB VRAM on the RTX 4060. Every run is measured with
  `/usr/bin/time -v`; a speedup that raises RSS toward the ceiling is rejected.
- **Every accuracy claim** goes through the 15-origin rolling backtest, never a
  single split.
- **Every refactor of a numeric path** must reproduce the prior output
  (bit-identical where feasible) before it counts as done.
- **Do-not-touch list** honored: the 13 already-verified optimizations
  (EPSS 5.8 GB→565 MB streaming rewrite, fused single scan, date row-group
  pushdown, backtest earliest-event hoist, vectorized KM/NLL/Breslow, int8
  flag downcast, bootstrap cap, PH-test sampling, RSF batching, GBM cap,
  deep batch sizing, column projection) are documented in `docs/progress.md`
  and are not re-done here.

## Decisions

- **2026-07-02 — The model must not use EPSS data in training (user directive).**
  EPSS is the baseline we test against; an EPSS-free model keeps the
  "structural beats EPSS" claim clean (not EPSS-vs-itself). EPSS appears only
  as the raw-score baseline arm (never wrapped in a model — the wrapped arm
  collapses to 0.50 AUC). Empirical support that nothing is lost on the XGB
  path: `inwild_epss_ablation.json` shows adding publication-EPSS features to
  structural XGB **hurts** (AUC@30 −0.114, CI [−0.201, −0.027]); the landmark
  variant is a statistical wash. Accuracy work therefore targets model/config
  levers on structural features only.

## Baselines (before any change)

| Path | Wall clock | Peak RSS | Notes |
|---|---|---|---|
| `build-dataset` (fast path, no EPSS) | 21.3 s | 858 MB | `/usr/bin/time -v`, snapshot 2026-03-14 |
| `build-dataset --epss-path` (375M-row stream) | 4 m 13 s | 1.21 GB | dominated by the EPSS scan (~3 m 52 s over fast path) |
| 15-origin in-wild backtest (xgb, CUDA) | 38.5 s | 1.03 GB | cheap alone — the cost multiplier is hill-climb loops (O(candidates²) backtests) |
| Test suite (334 passed, 4 skipped) | 1 m 47 s | 613 MB | 959 warnings pass the FutureWarning gate — cleanup candidate, low priority |

## Changes landed

_(none yet — investigation phase; entries below move up here as they land,
each with before/after numbers)_

## Investigation phase (done)

| What was done | Why |
|---|---|
| Baseline `/usr/bin/time -v` measurements started for every pipeline path | No optimization claim is credible without a before-number; RSS is measured because the standing memory budget (≤6 GB red line) is an acceptance criterion, not an afterthought. |
| Full perf/memory hot-spot map of all 37 modules (file:line evidence) | Optimizing without a map wastes effort on cold paths; the map found the cost center is redundant IO/merges, **not** model training. |
| Do-not-touch list of 13 verified optimizations compiled | Re-"optimizing" verified numeric code is the main way regressions enter research pipelines. |
| Literature/methods survey (2024–26) launched before choosing accuracy levers | Standing rule: check current best methods rather than rely on training-set knowledge; avoids re-inventing or picking stale techniques. |

## Investigation phase — additions (2026-07-03)

| What was done | Why |
|---|---|
| Methods survey (2024–26) reported; findings folded into the design | Reframes the headline: EPSS v5 shipped 2026-06-15 (claims must state the version tested); the PR-AUC "tie" is inside the noise band at 1310 positives (Boyd 2013); nobody published time-to-in-wild survival modeling 2024–26 — the framing is the differentiator. |
| Design spec committed (`docs/superpowers/specs/2026-07-03-pipeline-improvement-design.md`, commit 69371c1) | Locks scope, ordering (S1–S4 → A1–A3 → L1), memory gates, and the evidence-based rejected list before any code changes. |
| Implementation plan for the speed bundle written (`docs/superpowers/plans/2026-07-03-speed-memory-bundle.md`) | Bite-sized TDD tasks with complete code, identity gates against the recorded baseline artifacts, and a mandatory improvement-log step per task. |
| Discovered S1 is smaller than mapped: build-dataset already persists `landmark_features_{L}d.parquet`; only two scripts still re-stream | Avoids building new persistence machinery (YAGNI); the fix is a guarded cache loader + repointing two scripts. |
| Discovered the persisted landmark artifacts are stale (2026-06-12, missing the 8 trajectory columns) | The cache loader needs a column-completeness guard with streaming fallback; live artifacts get refreshed in the plan's final task. |

## Planned levers (ranked, with reasons)

1. **Persist the fused EPSS landmark bundle to parquet; scripts read it instead
   of re-streaming.** *Why:* 5+ scripts each re-scan the whole 375M-row file —
   the single largest repeated IO cost in any multi-analysis session. Output
   must be byte-identical to the streamed path.
2. **Hoist the feature→label merge out of the backtest per-origin loop.**
   *Why:* two full ~360k-row merges per origin × 15 origins are pure repeated
   work; merge once, boolean-mask per origin. Identical results required.
3. **Fix the XGB validation split so early stopping is usable, then enable it.**
   *Why:* 500 fixed boosting rounds per origin per candidate config dominates
   hill-climb compute; the current tail-split early stop is documented to
   underfit (stops at iter 57, c-index 0.607→0.537), so the split must be fixed
   first — this is a speed *and* accuracy lever.
4. **Parallelize hill-climb candidate evaluations.** *Why:* embarrassingly
   parallel, currently serial; worker count capped so total RSS stays under the
   6 GB red line.
5. **Vectorize CVSS/CWE/incentive feature builders; parse the CVSS vector
   once.** *Why:* the same vector string is parsed independently in two
   modules, and ~30 Python `.map(lambda)` passes run over 360k rows where one
   vectorized parse + `get_dummies`/`explode` suffices.
6. **Accuracy config gaps (pending methods survey):** no hyperparameter search
   anywhere, single seed=0 everywhere (no seed-variance estimate), Cox
   penalizer fixed at 0.1 with a silent ×10 ridge-escalation loop, per-origin
   IPCW c-index computed but never aggregated (known reporting gap). Which of
   these to act on — and how — is decided after the literature survey reports,
   honestly weighed against the ~396-event label ceiling.
