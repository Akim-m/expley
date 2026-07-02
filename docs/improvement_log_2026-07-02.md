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

| Change | Why | Measured effect |
|---|---|---|
| Shared vectorized CVSS parse — `parse_cvss_vectors` (one `str.extract` pass per metric), consumed by `build_publication_features`, `build_incentive_features`, and the build CLI (branch `speed-memory-bundle`) | The same vector string was parsed twice (per-row dict `.map` in features.py, again in incentive_features.py + 8 more `.map` passes); one vectorized parse feeds both builders | Outputs pinned identical by tests (duplicate-key last-wins, missing→None, 'S' vs 'CVSS:' prefix); wall-clock delta measured at Task 7 rebuild; suite 350 passed |
| CWE top-k membership via one `explode`+`crosstab` (was one `.map` pass per top-k CWE — 20 passes × 360k rows) | Membership testing was the last multi-pass Python loop in the publication feature builder | Set semantics (per-CVE dedup) and (-count, name) ranking pinned by test; explode needs `reset_index` (crosstab rejects duplicate labels — caught by the test, not in prod); suite 350 passed |

## What's better than before — and where it can still improve

Updated as work lands (user request 2026-07-03). "Model" here = the whole
modeling pipeline; the in-wild ranking model itself is unchanged so far — the
current wins are pipeline-level (correctness-preserving speed/memory work) and
decision-quality (measured framing, evidence-based rejections).

**Better than the old state:**

1. **Every performance claim is now measured, not asserted** — recorded
   `/usr/bin/time -v` baselines for all four pipeline paths (build 21.3 s/858 MB,
   EPSS build 4 m 13 s/1.21 GB, backtest 38.5 s/1.03 GB, suite 1 m 47 s/613 MB);
   the old state had scattered per-fix numbers but no whole-pipeline scoreboard.
2. **The EPSS-comparison methodology is locked clean** — no EPSS data in
   training (directive + measured support: EPSS features *hurt* XGB-AFT,
   −0.114 AUC@30), raw-score-only baseline arm. The old ablations had a
   model-wrapped EPSS arm that overstated the margin.
3. **A validated do-not-do list** — focal/SMOTE/deep-swaps/TabPFN/LLM-embeddings/
   GNN/polars/external-memory each rejected with a citable negative result at
   our scale, so future sessions don't burn time re-testing fashions.
4. **CVSS parsing does one vectorized pass instead of ~10 per-row passes**
   (Task 1, landed) — same outputs, pinned by tests.

**Where it can still improve (honest list):**

1. **The headline metric is the wrong idiom** — PR-AUC@30 "tie" is inside the
   noise band at 1310 positives; the field uses coverage/effort curves and
   recall@K with CIs (workstream A1, next after the speed bundle).
2. **EPSS version staleness** — all claims are vs v3/v4 history; EPSS v5
   (2026-06-15) must be named in claims and re-tested when history accumulates.
3. **Label count is still the binding constraint** — ~396 true in-wild events;
   the only statistics-approved PR-AUC lever is more labels (L1: Vulnrichment
   SSVC git history, timestamped `active` transitions, backfill to mid-2024).
4. **No hyperparameter search / single seed everywhere** — the +0.100 AUC win
   has no seed-variance estimate yet (A3).
5. **Top-of-list precision** — EPSS still wins recall@top-1%; LambdaRank
   top-push (A2) targets exactly that band.
6. **IPCW c-index computed per origin but never aggregated** — a known
   reporting gap (A1).
7. **Speed bundle in flight** — backtest merge hoist, cached landmark-EPSS
   loader, early stopping, parallel hill-climb (Tasks 3–6 of the plan).

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
