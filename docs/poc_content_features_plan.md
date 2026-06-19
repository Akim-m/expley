# Scoping plan — PoC-content features (the Expected-Exploitability lift)

Status: **scoping only** (2026-06-20). No code yet. This is the #1 gap surfaced by the
2026-06 competitive-methods review; it is an **L-effort** item gated on data acquisition we
do not currently have. Read this before starting — the obvious framing is a leakage trap.

## 1. Why (the evidence)

Expected Exploitability (Suciu, USENIX'22) is the closest cousin to our model and its central
result is that **features extracted from PoC *content*** — code complexity (program analysis)
and PoC text/comments (NLP) — are the single best-evidenced lift in this problem space.
Verified against the paper abstract (2026-06-20): EE raises **precision from 49% → 86%** for
functional-exploit-within-1-year over the best prior classifier (incl. EPSS), at **PR-AUC
≈ 0.90**; *mere PoC existence is a weak predictor — the content is what carries signal*.

We currently throw this away: `poc_features.py` reduces each PoC to a count, a first-seen lag,
and a one-hot of the file **extension** of `poc_path` (`poc_features.py:36`). No PoC body is
ever read.

## 2. The hard reality — we do not have the data

The competitive-methods doc originally claimed "we already clone the PoC repos." **That is
false** (corrected 2026-06-20). `fetch/poc.py` clones two *index* repos — `trickest/cve` and
`nomi-sec/PoC-in-GitHub` — with `blob:none` (`fetch/poc.py:24`), and stores only
`{cve_id, poc_source, poc_first_seen, poc_path}` (a path/metadata string). The actual exploit
code lives in **thousands of third-party GitHub repos** the indexes merely point to. So:

- **Step 0 is data acquisition**, not feature engineering. We must resolve index entries to
  their upstream repos and fetch content. This is the real cost (bandwidth, disk, and the
  per-repo cloning the `memory-budget-constraint` warns about — never clone unbounded blobs).
- A cheaper entry point worth checking first: the **nomi-sec index JSON already carries repo
  metadata** (description, stars, created_at) per PoC — that is text/signal we can mine
  *without* cloning any code. Confirm what fields the index holds before committing to full
  code retrieval.

## 3. The leakage gate — which clock, decided first (NON-NEGOTIABLE)

~97% of first-weaponization **events are the PoC date itself**. A feature computed from PoC
content is therefore observed *at or after* the event on the `published → first-PoC` clock —
**pure temporal leakage**. PoC-content features are leakage-safe ONLY where the PoC is a *past*
fact relative to the prediction origin:

| Target head | PoC-content legitimate? | Why |
|---|---|---|
| first-weaponization (published→PoC) | **NO** | the PoC *is* the event — leakage |
| transition heads (PoC→Metasploit / →Nuclei) | **YES** | PoC precedes the event |
| in-wild head **with landmark clock** (`landmark.restart_clock`) | **YES** | features as-of `published+L`, PoC observed by L |

So this feature family belongs in the `transition_safe` provenance class (cf.
`poc_features.py:5-9` `_TRANSITION_NOTE`) and/or the landmark family — **not** the default
publication-time matrix. Any feature builder must ship a `feature_provenance()` row marked
accordingly and be wired only into those heads.

## 4. Honest expected payoff (tempered by the data ceiling)

`inwild-ceiling-is-data-limited`: the in-wild head has ~396 events; that caps how much *any*
feature can move it. PoC-content features most plausibly help the **transition/cascade**
modeling (more events, PoC genuinely upstream) and the **landmarked in-wild** head — not the
headline in-wild number directly. Frame success as transition-head discrimination + lead-time,
not a single in-wild AUC bump.

## 5. Phased plan

- **P0 — feasibility (S, no clone).** Inventory what the nomi-sec/trickest indexes already
  hold (repo description, language, stars, file list?). If usable text/metadata exists,
  prototype features from it alone. Decide full-code retrieval only if P0 underwhelms.
- **P1 — bounded code retrieval (M–L).** If needed, resolve index→upstream repo, fetch with a
  hard size/time cap (sample first; never unbounded `git clone`). Cache like other connectors
  (`fetch/cache.py`). Record dropped/over-cap repos (`no silent caps`).
- **P2 — features (M).** Text: reuse `text_safety` masking + bounded keyword/length signals
  (NOT raw TF-IDF — memory). Code: LOC, token count, language, simple complexity proxies;
  full AST/cyclomatic only if P2-lite shows signal. Each with a provenance row.
- **P3 — wire + evaluate (M).** Add to transition + landmark heads only. Evaluate via the
  rolling-origin backtest with `paired_origin_deltas` vs the no-PoC-content baseline — the
  feature earns its place only if the paired CI excludes 0.

## 6. Decision points (for the user)

1. **Entry cost:** start with index-metadata-only features (P0, cheap) — recommended — or go
   straight to code retrieval (P1, expensive)?
2. **Target:** transition heads (more events, cleaner signal) — recommended first — vs the
   landmarked in-wild head?
3. **Acquisition bound:** sample N PoC repos to prove signal before any full pull (recommended,
   respects the RAM/disk budget) vs full retrieval up front?

Recommendation: **P0 first** (index-metadata features, no cloning) and evaluate on the
**transition heads** with the paired-CI test. Only fund P1 code retrieval if P0 shows a
CI-excludes-0 lift. This keeps the first step inside the memory budget and fails cheap.
