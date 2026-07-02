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
| Cached landmark-EPSS loader `landmark.load_epss_at_landmark` (guards: snapshot match, trajectory columns present, corpus coverage; else streams) + repointed `operating_points.py` / `inwild_epss_ablation_landmark.py` | Both scripts re-streamed the whole 375M-row file (~4 min each) although build-dataset already persists the identical bundle; stale 2026-06-12 artifacts lack the trajectory columns so a column guard is mandatory | 6 loader tests incl. corpus-order alignment + 4 fallback modes; cache benefit becomes real after the Task 7 artifact refresh (~4 min → seconds per script); suite 356 passed |
| Backtest hoist: `validate_feature_matrix` once + final-snapshot test frame prepared once, per-origin test sets are boolean slices; train side skips the redundant per-call NaN scan | Two full ~360k-row `prepare_modeling_frame` calls per origin × 15 origins re-did the same merge + NaN scan + downcast | 15-origin in-wild xgb backtest: **38.5 s → 35.15 s (−8.7%)**, RSS 1.03 → 1.06 GB (hoisted frame, 18% of gate); report values bit-identical to baseline (0 change/delete diff hunks; add-only hunks are the parity PR's multi-k field, not this change); suite 359 passed |
| XGB `validation="random"` (event-stratified 10% early-stop split) + `model_kwargs` plumbed through `rolling_origin_backtest` — **shipped opt-in, adoption REJECTED for the headline config** | The tail split is documented to underfit; a representative-event-rate split was the hypothesis for making early stopping usable | Measured A/B (15 origins, in-wild): 25% faster (32.8→24.5 s) but significantly worse ranking — AUC@30 −0.043 [−0.081,−0.006], AUC@90 −0.043 [−0.066,−0.021]. Root cause: ~99.5% censoring leaves tens of val events per origin → noisy aft-nloglik stops boosting early. Defaults unchanged (500 rounds, no early stop); negative result feeds A3 (tune rounds on train-era origins with the real metric instead). `artifacts/xgb_earlystop_ab.json` |
| Hill-climb `n_workers` thread-parallel candidate evaluation (`greedy_forward_select`), `beat_epss_hillclimb.py` set to 2 workers | Each greedy round runs one full backtest per remaining candidate, serially; threads share the frames zero-copy and xgboost releases the GIL (a process pool would multiply ~1 GB RSS per worker toward the 6 GB gate) | Selection + trial order proven identical to serial (submission-order map + determinism test); wall-clock benefit realized per hill-climb run; suite 365 passed |
| Verification gate: full-corpus identity + artifact refresh | No refactor counts without proof | Fast build: all 7 parquets frame-identical, 21.1 s/864 MB (≈ baseline — honest: the .map passes were a smaller cost share than mapped). EPSS build: all parquets identical, 4 m 05 s/1.23 GB (≈ baseline). Live `artifacts/` refreshed; **cached landmark-EPSS load: 0.23 s vs ~4 min streamed (~1000×)** for 338k rows × 12 cols |
| RE round (2 adversarial reviewers × 5 loops, per standing rule) — **6 real breaks found and fixed** | The refactors claimed output-identical behavior; full-corpus identity can't cover out-of-corpus inputs | Fixed with regression tests: (1) CVSS `[^/]+`→`[^/]*` — empty values (`"AV:"`) silently flipped `incentive_network`/one-hot columns; (2) bytes vectors parsed where old `isinstance(str)` rejected — str-gate restored; (3) CWE crash on `None` inside the ndarray (realistic nullable `list<string>` parquet load) — `dict.fromkeys` dedup; (4) CWE silent cross-row contamination on duplicate/NaN `cve_id` — crosstab keyed by row position; (5) cache could serve wrong values under published-date drift between corpora (62 drifted ids exist between handover and merged corpora TODAY) — `published` now stamped into the artifact and exact-matched, None-snapshot hits refused; (6) `validation="random"` could steal ≤5 (even the only) events into validation — fit keeps ≥1 event. Plus: plural `load_epss_at_landmarks` (miss-path had regressed to 2 scans instead of 1 fused — reviewer caught it), loud guards for silently-ignored `model_kwargs`, CPU-fallback warning in xgb, `n_skipped_origins` surfaced in backtest results. HOLDS verdicts: backtest hoist (empirical filter/prepare commutation), thread-parallel hill-climb (byte-identical at 4–8 threads, <1 GB VRAM of 8 GB) |
| Process note: the verification gate caught my own artifact-refresh mistake | The first refresh omitted `--technique-chain`, silently dropping the attack-feature columns; the backtest identity re-check flagged non-identical metrics immediately | Artifacts rebuilt with the full original flag set (81 feature cols: 12 attack, 3 EPSS; 4 m 22 s / 1.46 GB). This is why every step re-runs the gate |
| All-models comparison report (`docs/model_comparison_report_2026-07-03.pdf`, generator `scripts/build_model_comparison_report_2026-07-03.py`) | User request: one report comparing every model family tried, with regime and verdict; numbers read LIVE from artifacts at build time, doc-cited numbers labelled | 2-page PDF: 5 tables (in-wild families incl. XGB-AFT scale-flip row, EPSS-baseline arms, first-weap at scale, competing-risks/deep + PoC→KEV head, config variants) + standing verdicts. RE round (2 verifiers, 6 loops total, 41 number checks): 1 BLOCKER (recal row conflated Booth baseline-refit artifact with the cross-fit temperature experiment), 3 WRONG (hand-typed DeepHit CIF row → now a live read; "rare causes unscoreable"; "recent clean cohort" qualifier), 3 OVERSTATED ("wins every axis", PH-violation sourcing, discrimination-headline metric-dependence) — **all fixed before delivery** |
| Final state (2026-07-03, branch merged) | — | Hardened cache: **plural load 0.57 s vs ~4 min streamed (~450×)** under the published-guard. New backtest reference on refreshed 81-col artifacts (handover labels, 396 events): AUC@30 0.693 / AUC@90 0.724, 36.4 s / 1.15 GB, 14 origins + **1 threshold-skip now visible** via `n_skipped_origins`. Note: the 81-col set supersedes the 72-col 2026-06-12 artifacts (adds incentive flags + `published` in landmark files); like-for-like identity claims all compared same inputs and stand |

## What Fable improves on itself (process self-corrections, user-requested)

Mistakes the assistant made during this effort, how each was caught, and the
rule now applied. Recorded so the process compounds, not just the code.

| Mistake | How it was caught | Rule applied going forward |
|---|---|---|
| Piped `/usr/bin/time -v` through `tail -12` and clipped the Elapsed/RSS lines — burned a 4-minute EPSS baseline re-run | Read the truncated output | Always `-o file` for time output, grep the file afterwards |
| Refreshed live `artifacts/` without `--technique-chain`, silently dropping 12 attack-feature columns | The backtest identity gate flagged non-identical metrics on the very next run | Before any rebuild, read `manifest.json` (it records `attack_features_enabled`, `landmarks`, `epss_features_enabled`) and reproduce the full original flag set |
| Assumed workstream S1 needed new persistence machinery | Reading cli.py showed build-dataset already persists the bundle; S1 shrank to a guarded loader + two repoints | Scout the existing code before sizing a task (YAGNI applies to plans too) |
| Trusted full-corpus identity as proof of semantic identity | Adversarial RE found 6 real breaks on inputs outside the corpus (empty CVSS values, bytes, None-in-list, duplicate ids, published drift, lone-event steal) | Identity checks and adversarial RE are complementary — a refactor needs both |
| Designed cache guards around coverage+snapshot; missed that `published` determines the cached values | Reviewer constructed a passing-guards wrong-data repro; 62 published-drifted ids exist between the repo's own corpora | A cache guard must bind EVERY input that determines the cached value, not just identity/coverage |
| Wrote test constructions with pandas footguns (`.at[]` unpacks 1-element ndarrays; chained `iloc` made "mismatched" indexes equal) | The tests failed against correct code | Verify a regression test fails/passes for the intended REASON before trusting it |
| Ranked the feature-builder vectorization as a top-5 speed lever from code reading | Measured wash on build wall-clock (21.3→21.1 s) — the `.map` passes were a small cost share | Rank levers by measured share, not by how inefficient the code looks; record honest washes |
| Hypothesized a random event-stratified split would make early stopping usable | The A/B rejected it (−0.043 AUC, CI excl. 0): tens of val events per origin at 99.5% censoring | Behavior changes ship behind measured adoption gates; negatives get recorded, not retried |

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
7. ~~Speed bundle in flight~~ **DONE 2026-07-03** — all six tasks landed +
   RE-audited (6 breaks found and fixed); see §Changes landed. Remaining axes
   are the accuracy workstreams A1–A3 and the L1 label connector (specced in
   the design doc, not started).

## A1 re-metric workstream (in progress, 2026-07-03)

| Change | Why | Measured effect |
|---|---|---|
| `top_fracs` passthrough in `rolling_origin_backtest` + per-origin `c_index_ipcw` stored and aggregated with a mandatory caveat | A1: coverage/effort curves need a dense effort grid; the IPCW c-index was computed every origin and thrown away (known reporting gap) — but train/test censoring regimes differ across the origin split, so it aggregates as SECONDARY only | Test-pinned; suite 374 passed |
| `effort_metrics.py` (stratified pooled-bootstrap PR-AUC CIs, coverage paired deltas) + `keep_scores` flag + `scripts/inwild_remetric.py` → `artifacts/inwild_remetric.json`, `docs/figures/fig_coverage_effort.png` | A1 core: restate the headline in the field's idiom; the "PR-AUC tied" claim needed its noise band | **HEADLINE CHANGED: the tie dissolves in structural's favor.** Pooled PR-AUC@30 structural 0.0071 [0.0058,0.0095] vs EPSS 0.0040 [0.0032,0.0054] — bands don't overlap (same @90: 0.0134 vs 0.0078). Coverage crossover: EPSS holds top-1% (Δ−0.003 n.s.), structural wins from 5–10% effort (Δ+0.200 [0.104,0.296] @30, +0.238 win 15/15 @90). Sanity gate: AUC@30 delta +0.0998 reproduces parity's +0.1001. EPSS-version stamped (pre-v5). 3 m 17 s / 1.33 GB |
| A2 LambdaRank top-push (`fit_xgb_rank`, `model="xgb_rank"`, measured A/B) — **adoption REJECTED** | Survey lever for the top-K deliverable: rank:ndcg with top-heavy |ΔNDCG| gradients | Loses to AFT everywhere: AUC@30 −0.126 [−0.202,−0.050], AUC@90 −0.164 (win 0/15), coverage negative at almost every effort. Binary within-h labels discard the survival-time signal; ~0.1% positives starve pair sampling. Ships opt-in; `artifacts/a2_lambdarank_ab.json` |
| L1 Vulnrichment SSVC miner (`fetch/vulnrichment.py`): streamed git-log parser for Exploitation transitions, earliest-wins, label-only doctrine in the module docstring | The one statistics-approved PR-AUC lever: timestamped `active` assessments with backfill since mid-2024 | Parser + frame contract test-pinned (split-line values, deletes, non-CVE files, ns-UTC dtype); repo clone + full-history mine in progress |

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
