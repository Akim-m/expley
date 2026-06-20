# Integrate Fetched Data + EPSS-Dynamics Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fold the live-fetched data (VulnCheck KEV in-wild labels ≈3× events, NVD++ refreshed 359k corpus) and the new EPSS-dynamics landmark features into the modeling dataset, then re-evaluate the in-wild model on the expanded label set — so the data work done in `data/live/` actually reaches the model.

**Architecture:** Three stages, each verified before the next. (1) `merge` the `data/live/` deltas onto the handover parquets into `data/merged/` (the merge layer keeps latest `last_modified` for the corpus and unions live-only label sources). (2) `build-dataset` from `data/merged/` with EPSS + landmarks (7,30) so the new EPSS-dynamics columns and the VulnCheck-expanded in-wild labels both materialise. (3) Re-run the in-wild rolling-origin backtest on the rebuilt artifacts, comparing — with `paired_origin_deltas` — the expanded labels and EPSS-dynamics features against the current baseline, on the project's new success bar (PR-AUC vs an EPSS-only model). No new model code; the win is data reaching the model, measured honestly.

**Tech Stack:** Python 3.12 (`.venv`, managed with uv), `temporal-exploit` CLI (`merge` / `build-dataset` / `backtest`), pyarrow streaming for the 375M-row EPSS file, lifelines Cox + GPU XGBoost-AFT.

## Global Constraints

- **RAM ≤ 6–8 GB, VRAM ≤ 7 GB** — hard ceiling for every build/fetch/model step. `free -g` before each heavy stage. The EPSS-at-publication + landmark scans are the only memory-sensitive step; they use the streamed `iter_batches` + date-pushdown path (peak ~1.34 GB). **Never** add an `isin(cve_ids)` pushdown on the EPSS file (retained ~5.8 GB).
- **Strict point-in-time / no leakage** — EPSS-dynamics features are `landmark_safe` ONLY with `restart_clock` (clock starts at L); never pair landmark features with the unshifted publication clock.
- **Snapshot date stays `2026-03-14`** — the bundled EPSS history (`epss_history-001.parquet`) ends 2026-03-14, so features can't extend past it. Holding the snapshot fixed also makes the in-wild label expansion the *only* changed variable (apples-to-apples vs the existing backtest). VulnCheck evidence dates after 2026-03-14 are censored at snapshot — acceptable (using them needs a fresh EPSS pull, a later task).
- **Token never committed**; `data/live/` and `data/merged/` are gitignored; `artifacts/` is gitignored.
- **Paths:** handover = `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out`; EPSS = `epss_history-001.parquet`; technique chain = `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/technique_cwe_chain.parquet`.

---

### Task 1: Pre-flight — verify the staged live data

**Files:**
- Read: `data/live/vulncheck_kev.parquet`, `data/live/cve_corpus.parquet`

**Interfaces:**
- Produces: confidence that the inputs to `merge` are present and well-formed (no code).

- [ ] **Step 1: Verify staged parquets exist and are sane**

Run:
```bash
.venv/bin/python -c "
import pandas as pd
vc = pd.read_parquet('data/live/vulncheck_kev.parquet')
cp = pd.read_parquet('data/live/cve_corpus.parquet', columns=['cve_id','published','cvss_v3_base','cwe_ids'])
assert list(vc.columns) == ['cve_id','vulncheck_kev_date_added'], vc.columns
assert len(vc) > 4000, len(vc)
assert len(cp) > 350000, len(cp)
print('vulncheck_kev:', len(vc), '| nvd++ corpus:', len(cp))
"
```
Expected: `vulncheck_kev: 4969 | nvd++ corpus: 359507` (±, both well above the asserts).

- [ ] **Step 2: Check RAM headroom**

Run: `free -g | awk 'NR<=2'`
Expected: `available` ≥ 4 GB before proceeding. If not, stop and free RAM (kill stray python).

---

### Task 2: Merge live deltas onto the handover → `data/merged/`

**Files:**
- Create: `data/merged/*.parquet` (merged dataset; gitignored)
- Use: `temporal_exploit.cli merge` → `temporal_exploit.merge.merge_live` (MERGE_SPECS already cover `cve_corpus`, `vulncheck_kev`, `kev_events`, `exploitdb`, `poc_dates`, …)

**Interfaces:**
- Consumes: handover dir + `data/live/`
- Produces: `data/merged/` with a corpus that includes NVD++ updates and a `vulncheck_kev.parquet` present for the in-wild label build.

- [ ] **Step 1: Run the merge**

Run:
```bash
.venv/bin/python -m temporal_exploit.cli merge \
  --handover-dir dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out \
  --live-dir data/live \
  --out-dir data/merged
```
Expected: completes without error; prints per-source merged row counts.

- [ ] **Step 2: Verify the merged outputs**

Run:
```bash
.venv/bin/python -c "
import pandas as pd, os
m = 'data/merged'
corpus = pd.read_parquet(f'{m}/cve_corpus.parquet', columns=['cve_id','last_modified'])
assert corpus['cve_id'].is_unique, 'dup cve_id in merged corpus'
assert len(corpus) >= 359000, len(corpus)
assert os.path.exists(f'{m}/vulncheck_kev.parquet'), 'vulncheck_kev missing from merge'
vc = pd.read_parquet(f'{m}/vulncheck_kev.parquet')
print('merged corpus:', len(corpus), '| vulncheck_kev:', len(vc), '| kev exists:', os.path.exists(f'{m}/kev_events.parquet'))
"
```
Expected: `merged corpus: ~359507 | vulncheck_kev: ~4969 | kev exists: True`. If `vulncheck_kev.parquet` is absent, the in-wild expansion won't happen — fix the merge spec before continuing.

---

### Task 3: Rebuild the modeling dataset from `data/merged/`

**Files:**
- Create: `artifacts/merged/` (modeling_labels, in_wild_labels, publication_features, landmark_features_{7,30}d, manifest; gitignored)
- Use: `temporal_exploit.cli build-dataset` (already wires labels → features → EPSS → landmarks → provenance)

**Interfaces:**
- Consumes: `data/merged/` + the EPSS file + the technique chain
- Produces: `artifacts/merged/in_wild_labels.parquet` (expanded), `landmark_features_30d.parquet` (with the new `epss_velocity_to_landmark` / `epss_rising_to_landmark` / `epss_max_to_landmark` + any mean/std/threshold columns the landmark builder now emits).

- [ ] **Step 1: Re-check RAM, then build (the one memory-heavy stage)**

Run:
```bash
free -g | awk 'NR==2'
.venv/bin/python -m temporal_exploit.cli build-dataset \
  --out-dir data/merged \
  --artifact-dir artifacts/merged \
  --snapshot-date 2026-03-14 \
  --epss-path epss_history-001.parquet \
  --technique-chain dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/technique_cwe_chain.parquet \
  --landmarks 7,30
```
Expected: completes; peak RSS ≤ ~1.5 GB (the streamed EPSS scan). If RSS climbs linearly past ~3 GB, abort — a non-streaming EPSS path regressed.

- [ ] **Step 2: Verify expanded labels + EPSS-dynamics columns + no NaN**

Run:
```bash
.venv/bin/python -c "
import pandas as pd
iw = pd.read_parquet('artifacts/merged/in_wild_labels.parquet')
ev = int(iw['event_observed'].astype(bool).sum())
print('in-wild events (merged):', ev)
assert ev > 2500, f'expected the VulnCheck expansion (~3x), got {ev}'
lm = pd.read_parquet('artifacts/merged/landmark_features_30d.parquet')
dyn = [c for c in lm.columns if c.startswith('epss_') and c not in ('epss_at_landmark','epss_percentile_at_landmark','epss_at_landmark_missing')]
print('EPSS-dynamics cols:', dyn)
assert 'epss_velocity_to_landmark' in dyn and 'epss_rising_to_landmark' in dyn
assert lm.isna().sum().sum() == 0, 'NaN in landmark features'
"
```
Expected: `in-wild events (merged): ~3000+` and the dynamics columns listed, zero NaN. (The exact event count depends on the snapshot censoring of VulnCheck dates; > 2500 confirms the expansion landed.)

---

### Task 4: Re-evaluate the in-wild model on the expanded labels

**Files:**
- Create: `artifacts/merged/backtest_inwild.json` (or a one-off comparison script under `scripts/`)
- Use: `temporal_exploit.backtest.rolling_origin_backtest` + `paired_origin_deltas`; `modeling.evaluate_survival` (PR-AUC already added per the GPU-pivot direction)

**Interfaces:**
- Consumes: `artifacts/merged/` (publication + landmark features, in-wild labels)
- Produces: the honest verdict — does ~3× events + EPSS-dynamics move AUC@90 / recall@top-decile / **PR-AUC** / variance, vs the 396-event baseline and vs an EPSS-only model.

- [ ] **Step 1: Baseline-vs-expanded in-wild backtest (publication-time features)**

Run:
```bash
.venv/bin/python scripts/inwild_method_headtohead.py cox \
  2>/dev/null  # uses artifacts/bt_epss; adapt ARTIFACT_DIR/out-dir to data/merged + artifacts/merged
```
(If the script's paths are hard-coded, copy it to `scripts/inwild_merged_backtest.py` and point `OUT_DIR=data/merged`, `ARTIFACT_DIR=artifacts/merged`.)
Expected: `n_test_events` ≈ 1,200–1,400 (was 396); record AUC@90 mean/median/sd, recall@top-decile, IPA, PR-AUC.

- [ ] **Step 2: Landmark (L=30) model WITH EPSS-dynamics, restart_clock applied**

Run a backtest variant that merges `landmark_features_30d.parquet` and applies `landmark.restart_clock` (the only leakage-safe way to use the dynamics features), comparing it to the publication-time model with `paired_origin_deltas(challenger, baseline, metric='horizon_auc', horizon=90)`.
Expected: a paired mean Δ with CI95 and win_frac — the rigorous statement of whether EPSS-dynamics help, not an eyeballed mean.

- [ ] **Step 3: PR-AUC vs an EPSS-only baseline (the new success bar)**

Compare the model's PR-AUC at 30/90d against a model whose only feature is `epss_at_publication` (or `epss_at_landmark` for the L=30 variant). Because EPSS is itself an in-wild model, **beating EPSS-only on PR-AUC** — not beating cox — is the real bar.
Expected: a clear table (model vs EPSS-only) at 30/90d PR-AUC; honest call on whether the survival layer adds over EPSS.

- [ ] **Step 4: GPU re-test (xgb-AFT) on the expanded labels**

The "xgb ≤ cox" verdict was measured at 396 events; re-run `model='xgb'` on the 1,368-event labels (GPU). Record whether the extra events change the cox-vs-xgb verdict.
Expected: cox-vs-xgb numbers at the new event count; update the recommendation only if the data supports it.

---

### Task 5: Document + commit

**Files:**
- Modify: `docs/progress.md` (detailed), `README.md` (Project status + Scope), `docs/superpowers/plans/2026-06-20-integrate-fetched-data.md` (mark done)
- Update memory: `inwild-ceiling-is-data-limited.md` with the post-integration numbers.

- [ ] **Step 1: Write the integrated-data results**

Record: merged corpus size, in-wild event count (expanded), AUC@90 / recall / PR-AUC / variance deltas, the EPSS-dynamics paired-delta verdict, the cox-vs-xgb re-test, and the EPSS-only-baseline comparison. State plainly whether the survival layer beats EPSS-only.

- [ ] **Step 2: Commit (no data/token in git)**

```bash
git add docs/progress.md README.md docs/superpowers/plans/2026-06-20-integrate-fetched-data.md
git commit -m "docs: integrate VulnCheck + NVD++ + EPSS-dynamics — results"
git push origin master
```
Expected: only docs committed; `data/merged/`, `artifacts/`, token never staged (`git diff --cached | grep -c vulncheck_42c5` → 0).

---

## Self-Review

- **Spec coverage:** merge (T2) → rebuild with EPSS-dynamics + expanded labels (T3) → re-evaluate incl. PR-AUC/EPSS-only/xgb (T4) → document (T5). Pre-flight (T1) guards the inputs. Covered.
- **Memory:** T1 Step 2 and T3 Step 1 both gate on `free -g`; the only heavy stage (EPSS scan) uses the streamed path with an explicit abort threshold. Covered.
- **Leakage:** T4 Step 2 requires `restart_clock` for the landmark/EPSS-dynamics features — the non-negotiable. Stated.
- **Honesty:** the success bar is PR-AUC vs EPSS-only (not vs cox), because EPSS is itself an in-wild predictor — avoids the circularity trap. Stated.
- **Open risk:** if `merge` drops `vulncheck_kev` or the corpus schema mismatches, the expansion silently won't happen — T2 Step 2 asserts both explicitly.

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-06-20-integrate-fetched-data.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session with checkpoints for review.

**Which approach?**
