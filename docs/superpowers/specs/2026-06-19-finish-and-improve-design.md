# Design: finish-and-improve wave (2026-06-19)

> Self-reviewed design (the user delegated spec/plan review — see memory
> `autonomous-spec-and-plan`). Hard constraint throughout: ≤6–8 GB system RAM,
> ≤7 GB VRAM (memory `memory-budget-constraint`). Env via uv; commit + push per
> unit of work.

## Goal

Close the substantive backlog from `docs/audit_2026-06-12.md` and the README
"Scope for improvement", and honour the explicit mandate to **fetch from every
documented source**. Four sequenced sub-projects, each TDD'd, code-reviewed,
committed, and pushed independently.

## Why these four (and not the rest)

The binding limitation today is the **in-wild target**: 1,543 positives vs 336k
censored, and IPA ≈ 0 (ranking is good, absolute probabilities don't beat the
base rate). Two levers move that needle — *more positives* (label broadening,
which needs the live fetches) and *a model that represents the cure fraction*
(mixture-cure). A third item (CIF headline eval) fixes a correctness gap in how
per-cause probabilities are reported. Everything else (DeepHit, NLP features,
scheduled refresh, exact-truncated c-index) is deferred as documented backlog —
lower value-per-risk and not what the user asked for.

## Sub-project 1 — Live-fetch every source, merge, rebuild

**Intent:** satisfy "fetch from all the places specified in the documents" and
produce a current unified dataset the builder consumes.

Sources (all wired in `fetch_command` already): `kev`, `epss`, `nvd`, `nuclei`,
`poc` (Trickest + Nomi-sec), `zeroday` (Project Zero), `exploitdb`,
`vulncheck_kev`, `metasploit`.

**Code change — `merge.py`:** add `MERGE_SPECS` entries so re-fetches reconcile
deterministically instead of silently passing through as `copy_live_only`:
- `exploitdb`: key `["cve_id", "exploitdb_id"]`, order `exploitdb_date_published`, keep `first`.
- `vulncheck_kev`: key `cve_id`, order `vulncheck_kev_date_added`, keep `first`.

**Runtime (memory-gated, `free -g` before each):**
- Lightweight (network + small parquet): `kev`, `epss` (today), `nvd` (recent
  `lastMod` window), `nuclei`, `poc`, `zeroday`, `exploitdb`. Run these first.
- `vulncheck_kev`: needs `VULNCHECK_API_TOKEN`. Check env; if absent, the wiring
  is built+tested but the live pull is **flagged as blocked**, not faked.
- `metasploit`: the heavy blob-clone + `git log -G` mine (~1 hr). Run in
  background with a `free -g` watch; abort if available RAM < 2 GB. If it can't
  run safely, record it as skipped — do not exceed the budget for it.

**Output:** `data/live/*.parquet` + `fetch_manifest.json`; then
`merge --handover-dir … --live-dir data/live --out-dir data/merged`. Rebuild the
modeling dataset from `data/merged`. All of `data/live`, `data/merged`,
`artifacts/` stay gitignored.

**Success:** every non-credential source fetches current-to-today and lands a
non-empty parquet; merge manifest shows the deltas; `fetch_manifest.json`
records row counts + blocked/skipped sources honestly.

## Sub-project 2 — In-wild label broadening + Exploit-DB tooling source

**Intent:** raise the in-wild positive count (the binding constraint) without
breaking the framing discipline.

**Framing decision (load-bearing):**
- **VulnCheck KEV → in-wild source.** It is a known-exploited catalog (broader
  than CISA KEV), a genuine in-the-wild signal. Add to `IN_WILD_SOURCES` and
  `EVENT_SOURCES`.
- **Exploit-DB → tooling source, NOT in-wild.** A verified exploit is public
  tooling, not confirmed in-the-wild use. Add to `EVENT_SOURCES` only (flows
  into first-weaponization + competing risks). Document the distinction.

**Code changes:**
- `cli.EVENT_SOURCES`: `+ "exploitdb": ("exploitdb", "exploitdb_date_published")`,
  `+ "vulncheck_kev": ("vulncheck_kev", "vulncheck_kev_date_added")`.
- `labels.IN_WILD_SOURCES`: `+ "vulncheck_kev"`.
- **Clock-start guard.** The KEV-backfill problem (`train_command`'s
  `KEV_CATALOG_START` filter) recurs for VulnCheck KEV (its own catalog launch
  spike). Generalize the single hard-coded date to a per-source
  `CATALOG_START` lookup and filter the in-wild risk set to `published >=
  max(catalog_start for active sources that have one)` — the conservative date
  after which every included CVE's window is observable by all active catalog
  sources. Notes: (a) **Google 0-day has no catalog artifact** — its dates are
  genuine discovery dates, so it contributes no constraint and is absent from
  the lookup; (b) CISA KEV stays 2021-11-03; (c) **VulnCheck's start is
  determined empirically** from the fetched `date_added` distribution (find the
  launch spike, exactly as the audit found CISA's 246/975 @ 2021-11-03), not
  guessed — the plan pins the value once the data is in hand.
- Builder picks the new sources up automatically (absent parquet → skipped), so
  no change to `build_dataset_command` beyond the dict entries.

**Success:** rebuild shows a higher `in_wild_observed`; `train --label-set
in_wild` runs clean; report the c-index + IPA delta vs the 0.849 baseline
honestly (with CI — a few hundred extra events may or may not move it past
noise, and the spec commits to reporting either way).

## Sub-project 3 — Mixture-cure model for in-wild absolute calibration

**Intent:** fix IPA ≈ 0 — give absolute probabilities that beat the base rate by
modelling that most CVEs are *never* weaponized in-wild (a cure fraction).

**Model (`src/temporal_exploit/cure.py`):** parametric mixture-cure, MLE via
`scipy.optimize.minimize` (L-BFGS-B). Pure numpy/scipy — memory-flat, no new
heavy dependency.
- Incidence (cure) component: `p(x) = sigmoid(x'γ)` = P(susceptible).
- Latency component among susceptibles: Weibull `S_u(t|x) = exp(-(t/λ(x))^k)`
  with `log λ(x) = x'β` (AFT form), shape `k > 0`.
- Population survival: `S(t|x) = (1 − p(x)) + p(x)·S_u(t|x)`.
- P(event by t | x) = `p(x)·(1 − S_u(t|x))`.
- Negative log-likelihood over (duration, event), standardized features, ridge
  on γ,β for stability; analytic or numerical gradient (L-BFGS-B tolerates
  numerical). Guard against overflow in the Weibull term.

**Integration:** a `CureModel` object exposing the same surface the evaluator
already dispatches on — `feature_cols_`, `risk_scores(X)` = `P(event by the
max-horizon)` = `p(x)·(1 − S_u(τ|x))` (monotone, well-defined ranking score),
`survival_at(X, horizons)` = the population `S(t|x)` above. Wire `kind="cure"`
into `modeling._risk_scores` / `survival_at`, and `fit_cure` into
`train_command`'s model selection (`--models … ,cure`).

**Success (measurable):** on in-wild test (cutoff 2024-01-01), **IPA > 0 at 90d
and 180d** (beats the train-KM null — the thing static Cox fails), while c-index
stays within the Cox CI [0.805, 0.893]. Calibration plot shows the top-decile
compression reduced. If IPA stays ≤ 0, that's a reportable negative result, not
a silent failure — document it.

## Sub-project 4 — CIF-based headline evaluation

**Intent:** the default per-signal probabilities use independent-KM (inflated:
they ignore competing events). `train-competing` already computes unbiased
Aalen-Johansen CIFs — surface them as the headline.

**Code changes (`competing.py` / `cli.train_competing_command`):**
- Add per-cause CIF discrimination: a cause-specific time-dependent AUC (or
  Harrell's C on the cause-specific risk) on the test set, so each transition
  has a discrimination number, not just train-set coefficients.
- Emit a headline block in `competing_metrics.json` that states, per cause and
  horizon, the AJ CIF vs the naive independent-KM probability side by side, with
  the inflation gap — making the bias visible and the unbiased number the
  default citation.

**Success:** `competing_metrics.json` carries the AJ-vs-independent comparison
and a per-cause test discrimination metric; the README headline for per-cause
probabilities cites the AJ CIF.

## Cross-cutting: testing, memory, docs

- **TDD** for every code change: failing test against the tiny fixtures
  (`tests/fixtures/tiny_parquets.py`, tz-aware UTC, ndarray lists) → minimal
  impl → green. Live fetches mocked in tests; real network only in the gated
  runtime steps.
- **Memory:** `free -g`/`nvidia-smi` gate before every heavy step; cox+xgb for
  in-wild training; never full-corpus RSF; Metasploit mine watched and abortable.
- **Leakage discipline preserved:** new event sources are *labels*, not
  features; Exploit-DB/VulnCheck dates never enter the publication-time feature
  set. Add `feature_provenance`/audit notes where relevant.
- **Docs:** update `docs/progress.md`, README (Project status + Scope for
  improvement), and append a status block to `docs/audit_2026-06-12.md` as each
  sub-project lands. Code-review (`/code-review`) each sub-project before commit.

## Out of scope (documented backlog, deferred)

DeepHit competing-risks deep model; NLP description features via `text_safety`;
scheduled incremental NVD refresh; exact truncated-c-index variant; full
bootstrap CIs (Noether approximation stands). These remain in the README backlog.
