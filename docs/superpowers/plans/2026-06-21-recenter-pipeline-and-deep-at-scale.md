# Re-center on the Multi-State Pipeline + Deep-Survival-at-Scale Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-center the deliverable on the professor's recommended thesis spine (`temporal_exploit_prediction.md` §Framing + §Directions): characterize the multi-state weaponization **pipeline** (PoC→MSF→Nuclei→KEV — independent vs cascade?) and run the **deep-survival-vs-Cox head-to-head at first-weaponization scale** (~45k–170k events), the AI artefact the viva requires — instead of the data-starved in-wild head where everything ties.

**Architecture:** Two phases, each ending in a results artifact + a docs synthesis. Phase 1 (torch-free) runs the *existing* multi-state machinery (`cascade_order_stats`, `cif_vs_independent`, `fit_cause_specific_cox`, `transition_frame`, `build_transition_labels`) on the real data to answer RQ2 and produce the "stronger thesis" result. Phase 2 installs the `[deep]` extra in a sidecar venv and runs Cox / XGBoost-AFT / DeepSurv (single-event) + DeepHit / Aalen-Johansen / cause-specific-Cox (competing-risks) on a **locked time-based split**, reporting discrimination (C-index, AUC@h) and calibration (IBS/IPA at 7/30/90/180) and **characterizing where deep wins and loses** — the doc's explicit framing for the AI artefact. No new modelling library code is required; the gap is *running the right comparison on the right (large) target* and synthesizing it. Small additions (a head-to-head driver script, a pipeline-characterization script) follow the existing `scripts/inwild_method_headtohead.py` pattern.

**Tech Stack:** Python 3.12 (`.venv`, uv); `temporal-exploit` CLI (`train`, `train-competing`); lifelines (Cox, Aalen-Johansen); GPU XGBoost-AFT; pycox DeepSurv/DeepHit (torch, sidecar venv); existing `competing.py` / `evaluate.py` / `deep.py` / `deephit.py`.

## Global Constraints

- **RAM ≤ 6–8 GB, VRAM ≤ 7 GB** — hard ceiling for every step (`free -g` before heavy work). DeepSurv/DeepHit eval already caps at 20k sampled rows; keep batch sizes small. The 375M-row EPSS scan uses the streamed `iter_batches` path; **never** add an `isin(cve_ids)` pushdown (retains ~5.8 GB).
- **Cox PH is the required baseline.** The `[[gpu-only-models]]` preference (default to XGBoost-AFT / deep) still holds for the *headline* model, but the professor's spec makes **Cox the reference the deep models are measured against** — Cox MUST be in every head-to-head, even though it is CPU.
- **Leakage discipline (non-negotiable, per `CLAUDE.md` + the doc's two gotchas):** publication-time-safe features only; **no `description` text** unless leakage-gated (`last_modified ≤ published+ε`); no snapshot-time presence/EPSS; **time-based split only, never random K-fold**; for any landmark/transition feature use `restart_clock` (clock starts at the landmark).
- **Snapshot date `2026-03-14`** (bundled EPSS ends there). Use the merged build (`data/merged` / `artifacts/merged`, 359k corpus, the freshest features) for new runs; fall back to handover artifacts only where a merged equivalent is absent.
- **Honesty bar:** report C-index/AUC (powered) AND calibration (IPA/IBS) at 7/30/90/180; at low event rates a PR-AUC/calibration tie is *underpowered*, not evidence of equivalence (the lesson from the 2026-06-21 landmark correction). State PoC-dominance + informative-censoring caveats in every writeup (the doc requires both in the viva).
- **Paths:** merged corpus = `data/merged`; merged artifacts = `artifacts/merged`; handover = `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out`; EPSS = `epss_history-001.parquet`.

---

## Phase 1 — Multi-state pipeline characterization (RQ2, torch-free)

Answers the doc's RQ2: *conditional on a PoC, what predicts (and when) advancement to MSF/Nuclei/KEV — are the transitions independent or a cascade?* All functions exist; this phase runs and synthesizes them on the real data.

### Task 1: Cascade-order + independence evidence (does the pipeline cascade?)

**Files:**
- Create: `scripts/pipeline_cascade_characterization.py`
- Create (output): `artifacts/merged/pipeline_cascade.json`
- Use: `temporal_exploit.evaluate.cascade_order_stats(per_signal_labels, stages=("poc","metasploit","nuclei","kev"))`; `temporal_exploit.competing.cif_vs_independent(frame, horizons)`; `prepare_competing_frame`, `fit_aalen_johansen`, `cif_table`.
- Read: `artifacts/merged/per_signal_labels.parquet`, `artifacts/merged/competing_risks_labels.parquet`, `artifacts/merged/publication_features.parquet`.

**Interfaces:**
- Consumes: `cascade_order_stats(per_signal_labels, stages) -> DataFrame` (one row per adjacent stage pair with `% a-precedes-b among CVEs seen in both`); `cif_vs_independent(frame, horizons) -> DataFrame` (per-cause CIF vs the independent-KM product, the deviation = competing-risks dependence).
- Produces: `artifacts/merged/pipeline_cascade.json` — cascade-order table + CIF-vs-independent deviations + Aalen-Johansen CIF@{7,30,90,180} per cause.

- [ ] **Step 1: Write the script (run existing functions, emit JSON)**

```python
"""RQ2 — does the weaponization pipeline cascade (PoC->MSF->Nuclei->KEV) or are
the transitions independent? Runs the existing cascade-order + competing-risks
machinery on the merged build and emits a single JSON for the thesis spine."""
import json
from pathlib import Path
import pandas as pd
from temporal_exploit.evaluate import cascade_order_stats
from temporal_exploit.competing import (
    prepare_competing_frame, fit_aalen_johansen, cif_table, cif_vs_independent,
)

ART = Path("artifacts/merged")
HZ = [7, 30, 90, 180]
per_signal = pd.read_parquet(ART / "per_signal_labels.parquet")
cr = pd.read_parquet(ART / "competing_risks_labels.parquet")
feats = pd.read_parquet(ART / "publication_features.parquet")

cascade = cascade_order_stats(per_signal, stages=("poc", "metasploit", "nuclei", "kev"))
frame = prepare_competing_frame(cr, feats)
fitters = fit_aalen_johansen(frame)
cif = cif_table(fitters, HZ)
indep = cif_vs_independent(frame, HZ)

out = {
    "cascade_order": cascade.to_dict(orient="records"),
    "aalen_johansen_cif": cif.to_dict(orient="records"),
    "cif_vs_independent": indep.to_dict(orient="records"),
}
ART.mkdir(parents=True, exist_ok=True)
(ART / "pipeline_cascade.json").write_text(json.dumps(out, indent=2, default=str))
print("cascade-order:\n", cascade.to_string(index=False), flush=True)
print("\nCIF vs independent (deviation = competing dependence):\n", indep.to_string(index=False), flush=True)
print("\nwrote artifacts/merged/pipeline_cascade.json", flush=True)
```

- [ ] **Step 2: Run it, capturing the cascade evidence**

Run: `.venv/bin/python scripts/pipeline_cascade_characterization.py 2>&1 | grep -v "terminate called\|core dumped"`
Expected: a cascade-order table where, if the pipeline cascades, `poc` precedes `metasploit`/`nuclei`/`kev` in a large majority of co-observed CVEs (e.g. >80%); a `cif_vs_independent` table whose deviations are non-trivial (competing risks are NOT independent). Records both regardless of direction.

- [ ] **Step 3: Verify the artifact is well-formed**

Run:
```bash
.venv/bin/python -c "import json; d=json.load(open('artifacts/merged/pipeline_cascade.json')); print('keys', list(d)); assert d['cascade_order'] and d['aalen_johansen_cif']; print('rows', len(d['cascade_order']), len(d['cif_vs_independent']))"
```
Expected: keys present, non-empty tables.

- [ ] **Step 4: Commit**

```bash
git add scripts/pipeline_cascade_characterization.py
git commit -m "feat(pipeline): cascade-order + CIF-vs-independent characterization (RQ2)"
```

### Task 2: Cause-specific transition models — what predicts each PoC→{MSF,Nuclei,KEV} transition?

**Files:**
- Create: `scripts/pipeline_transition_models.py`
- Create (output): `artifacts/merged/pipeline_transitions.json`
- Use: `temporal_exploit.competing.transition_frame(...)` (clock-restarted PoC→target frame), `fit_cause_specific_cox`, `cause_specific_cindex`; OR `temporal_exploit.labels.build_transition_labels(corpus, event_frames, snapshot, from_source="poc", to_source=<target>, competing_sources=...)` + `prepare_modeling_frame` + `fit_cox`/`fit_xgb_aft` + held-out `transition_cindex` (the N6 pattern in `scripts/transition_poc_to_exploitdb.py`).
- Read: merged corpus + the dated event frames (`data/merged`), `artifacts/merged/publication_features.parquet`.

**Interfaces:**
- Consumes: `build_transition_labels(corpus, event_frames, snapshot_date, from_source, to_source, competing_sources=()) -> DataFrame` (clock origin = `poc` date; competing sources censor cause-specifically); `transition_cindex(durations, risk, events) -> float|None`.
- Produces: `artifacts/merged/pipeline_transitions.json` — per transition (`poc_to_metasploit`, `poc_to_nuclei`, `poc_to_kev`): n eligible / n events / median lag / held-out time-based-split C-index for Cox and XGBoost-AFT, plus the top cause-specific Cox coefficients (which features drive each transition).

- [ ] **Step 1: Write the script following the N6 single-load pattern**

```python
"""RQ2 cont. — model each forward pipeline transition (PoC -> MSF / Nuclei / KEV)
on the clock-restarted (post-PoC) cohort: who advances, how fast, what predicts it.
Cause-specific (competing sources censor), time-based split, Cox + XGBoost-AFT,
held-out transition c-index. Mirrors scripts/transition_poc_to_exploitdb.py (N6)."""
import json
from pathlib import Path
import pandas as pd
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import build_transition_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import (
    prepare_modeling_frame, time_split_frame, fit_cox, fit_xgb_aft,
    _risk_scores, survival_at, transition_cindex,
)

OUT = Path("data/merged")
SNAP, HZ = "2026-03-14", (7, 30, 90, 180)
TARGETS = ["metasploit", "nuclei", "kev"]
COMPETING = {"metasploit": ("nuclei", "kev"), "nuclei": ("metasploit", "kev"), "kev": ("metasploit", "nuclei")}

corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
feats = pd.read_parquet("artifacts/merged/publication_features.parquet")
# load every dated source once (poc + the three targets)
frames = {}
for s in ["poc", *TARGETS]:
    name, col = EVENT_SOURCES[s]
    fr = load_optional_event(OUT, name, col)
    if fr is not None:
        frames[s] = (fr, col)

results = {}
for tgt in TARGETS:
    comp = tuple(c for c in COMPETING[tgt] if c in frames)
    labels = build_transition_labels(corpus, frames, SNAP, from_source="poc", to_source=tgt, competing_sources=comp)
    frame = prepare_modeling_frame(labels, feats)
    n_ev = int(frame["event_observed"].sum())
    cutoff = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
    train, test = time_split_frame(frame, str(cutoff.date()))
    row = {"n_eligible": len(frame), "n_events": n_ev,
           "median_lag_days": float(frame.loc[frame["event_observed"].astype(bool), "duration_days"].median())}
    for kind, fit in (("cox", fit_cox), ("xgb", fit_xgb_aft)):
        try:
            model = fit(train)
            x = test[list(model.feature_cols_)].astype(float)
            risk = _risk_scores(model, x, kind)
            row[f"{kind}_cindex"] = transition_cindex(
                test["duration_days"].to_numpy(), risk, test["event_observed"].to_numpy().astype(bool))
        except Exception as e:  # small/degenerate transition cohorts
            row[f"{kind}_cindex"] = None
            row[f"{kind}_error"] = str(e)[:120]
    results[f"poc_to_{tgt}"] = row
    print(f"poc->{tgt}: n_ev={n_ev} median_lag={row['median_lag_days']:.0f}d "
          f"cox_c={row.get('cox_cindex')} xgb_c={row.get('xgb_cindex')}", flush=True)

Path("artifacts/merged").mkdir(parents=True, exist_ok=True)
Path("artifacts/merged/pipeline_transitions.json").write_text(json.dumps(results, indent=2, default=str))
print("\nwrote artifacts/merged/pipeline_transitions.json", flush=True)
```

- [ ] **Step 2: Run it**

Run: `.venv/bin/python scripts/pipeline_transition_models.py 2>&1 | grep -v "terminate called\|core dumped"`
Expected: three transitions characterized. PoC→KEV is the in-wild-relevant one (expect modest events, fast median lag); PoC→MSF / PoC→Nuclei should have more events. Some may be small — `transition_cindex` returns `None` on all-censored, handled.

- [ ] **Step 3: Verify the artifact**

Run: `.venv/bin/python -c "import json; d=json.load(open('artifacts/merged/pipeline_transitions.json')); [print(k, v['n_events'], v.get('cox_cindex'), v.get('xgb_cindex')) for k,v in d.items()]"`
Expected: a row per transition with event counts + c-indices (or null with an error string for degenerate ones).

- [ ] **Step 4: Commit**

```bash
git add scripts/pipeline_transition_models.py
git commit -m "feat(pipeline): cause-specific PoC->MSF/Nuclei/KEV transition models (RQ2)"
```

### Task 3: Synthesize the pipeline-characterization results into the docs

**Files:**
- Modify: `docs/progress.md` (add a 2026-06-21 pipeline-characterization entry), `README.md` (Project status bullet).
- Create: `docs/pipeline_characterization_2026-06.md` (the thesis-spine writeup).

**Interfaces:**
- Consumes: `artifacts/merged/pipeline_cascade.json`, `artifacts/merged/pipeline_transitions.json`.
- Produces: a defensible RQ2 answer (cascade vs independent; per-transition predictability) with the PoC-dominance + informative-censoring caveats stated.

- [ ] **Step 1: Write `docs/pipeline_characterization_2026-06.md`** — state, with the numbers from both artifacts: (a) does the pipeline cascade (cascade-order %s)? (b) are the transitions independent (CIF-vs-independent deviations)? (c) which transitions are predictable and what drives them (per-transition C-index + top Cox coefficients)? (d) the two required caveats. No placeholders — fill from the JSONs.

- [ ] **Step 2: Add the `docs/progress.md` entry + the README bullet** (high-level), per the `CLAUDE.md` "update both" rule.

- [ ] **Step 3: Token-leak grep, then commit**

```bash
git add docs/pipeline_characterization_2026-06.md docs/progress.md README.md
git diff --cached | grep -ciE "vulncheck_[0-9a-f]{16}|gh[pousr]_[A-Za-z0-9]{20}" && echo LEAK || echo clean
git commit -m "docs(pipeline): RQ2 multi-state characterization — cascade vs independent + per-transition predictability"
```

---

## Phase 2 — Deep-survival-vs-Cox head-to-head at first-weaponization scale (the AI artefact)

The doc: deep survival (DeepHit/DeepSurv) "head-to-head against a Cox PH baseline … characterise where they win and lose, at this dataset scale." Currently only single-split DeepSurv numbers exist and the rigorous head-to-head ran on the 396-event in-wild set. This phase runs it on the large first-weaponization target with a locked time-based split.

### Task 4: Provision the `[deep]` extra in a sidecar venv (prerequisite)

**Files:**
- Create: `.venv-deep/` (gitignored; torch + pycox sidecar so the core `.venv` stays torch-free per `deep.py`'s design).

**Interfaces:**
- Produces: a python interpreter (`.venv-deep/bin/python`) that imports `torch` (CUDA) + `pycox` + the editable `temporal_exploit` package.

- [ ] **Step 1: Check VRAM/RAM headroom and create the sidecar**

```bash
free -g | awk 'NR==2'; nvidia-smi --query-gpu=memory.free --format=csv,noheader
uv venv --python 3.12 .venv-deep
uv pip install -p .venv-deep/bin/python -e ".[dev,xgb,boost,deep]"
```
Expected: install completes; VRAM free ≥ 4 GB before any fit. The CUDA torch wheel is large (~2–3 GB download) — if disk/VRAM is tight, install the CPU torch wheel instead (DeepSurv/DeepHit still run, slower). If `.[deep]` lacks a torch index, use `uv pip install -p .venv-deep/bin/python torch --index-url https://download.pytorch.org/whl/cu121` then the package.

- [ ] **Step 2: Verify the import**

Run: `.venv-deep/bin/python -c "import torch, pycox, temporal_exploit; print('torch', torch.__version__, 'cuda', torch.cuda.is_available())"`
Expected: prints a torch version; `cuda True` on the RTX 4060 (CPU fallback acceptable).

- [ ] **Step 3: Confirm `.venv-deep` is gitignored**

Run: `git check-ignore .venv-deep && echo ignored || echo "ADD .venv-deep TO .gitignore"`
Expected: `ignored` (add the line if not).

### Task 5: First-weaponization head-to-head — Cox vs XGBoost-AFT vs DeepSurv on a locked split

**Files:**
- Run: `temporal_exploit.cli train` (existing; no code change) on `--label-set first_weaponization` with `--models cox,xgb --deep`.
- Create (output): `artifacts/report_fw_headtohead/metrics.json` + the locked split files under `artifacts/merged`.

**Interfaces:**
- Consumes: `train --artifact-dir <art> --cutoff-date <date> --report-dir <dir> --label-set first_weaponization --models cox,xgb --deep` — fits Cox, XGBoost-AFT and DeepSurv on the same locked time-based split, writing per-model C-index + per-horizon calibration to `metrics.json`.
- Produces: discrimination (C-index, AUC@{7,30,90,180}) + calibration (IPA/IBS) for all three on the 45k+-event first-weaponization target.

- [ ] **Step 1: Confirm the locked split exists (or create it), then run the head-to-head**

```bash
free -g | awk 'NR==2'
.venv-deep/bin/python -m temporal_exploit.cli train \
  --artifact-dir artifacts/merged \
  --cutoff-date 2024-01-01 \
  --report-dir artifacts/report_fw_headtohead \
  --label-set first_weaponization \
  --models cox,xgb --deep 2>&1 | grep -viE "terminate called|core dumped"
```
Expected: completes within the RAM/VRAM budget (DeepSurv eval samples 20k rows); `artifacts/report_fw_headtohead/metrics.json` has `cox`, `xgb`, `deepsurv` blocks each with `c_index*` + calibration. Re-run with the CPU sidecar if VRAM is exceeded.

- [ ] **Step 2: Verify all three models produced metrics**

Run:
```bash
.venv/bin/python -c "
import json; m=json.load(open('artifacts/report_fw_headtohead/metrics.json'))
for k in ('cox','xgb','deepsurv'):
    assert k in m, f'missing {k}'
    print(k, {kk:vv for kk,vv in m[k].items() if 'c_index' in kk or 'ipa' in kk or 'brier' in kk})
"
```
Expected: a discrimination + calibration line for each of cox/xgb/deepsurv.

- [ ] **Step 3: Commit the report (metrics only; `artifacts/` is gitignored, so commit a copied summary if needed)**

```bash
mkdir -p docs/results && cp artifacts/report_fw_headtohead/metrics.json docs/results/fw_headtohead_metrics_2026-06-21.json
git add docs/results/fw_headtohead_metrics_2026-06-21.json
git commit -m "measure(deep): first-weaponization Cox vs XGBoost-AFT vs DeepSurv (locked split)"
```

### Task 6: Competing-risks deep head-to-head — DeepHit vs Aalen-Johansen / cause-specific Cox

**Files:**
- Run: `temporal_exploit.cli train-competing --deep-hit` (existing; no code change).
- Create (output): `artifacts/report_competing_deep/` metrics.

**Interfaces:**
- Consumes: `train-competing --artifact-dir artifacts/merged --cutoff-date 2024-01-01 --report-dir <dir> --deep-hit` — fits the joint DeepHit CIF model + the Aalen-Johansen / cause-specific Cox layer on the same split; emits per-cause concordance + CIF calibration.
- Produces: a learned-joint (DeepHit) vs classical-competing-risks (AJ / cause-specific Cox) comparison on the PoC/MSF/Nuclei/KEV causes.

- [ ] **Step 1: Run the competing-risks head-to-head**

```bash
free -g | awk 'NR==2'
.venv-deep/bin/python -m temporal_exploit.cli train-competing \
  --artifact-dir artifacts/merged \
  --cutoff-date 2024-01-01 \
  --report-dir artifacts/report_competing_deep \
  --deep-hit 2>&1 | grep -viE "terminate called|core dumped"
```
Expected: completes; per-cause concordance for DeepHit and the cause-specific Cox baseline.

- [ ] **Step 2: Verify metrics for both the deep and classical competing-risks models**

Run: `.venv/bin/python -c "import json,glob; f=sorted(glob.glob('artifacts/report_competing_deep/*.json'))[-1]; m=json.load(open(f)); print(list(m))"`
Expected: keys covering DeepHit + the AJ/cause-specific layer.

- [ ] **Step 3: Commit a copied summary**

```bash
cp $(ls -t artifacts/report_competing_deep/*.json | head -1) docs/results/competing_deep_metrics_2026-06-21.json
git add docs/results/competing_deep_metrics_2026-06-21.json
git commit -m "measure(deep): DeepHit vs Aalen-Johansen/cause-specific Cox (competing risks)"
```

### Task 7: Synthesize the deep-at-scale verdict — where do deep models win and lose?

**Files:**
- Create: `docs/deep_survival_headtohead_2026-06.md`.
- Modify: `docs/progress.md`, `README.md`, and the memory `[[gpu-only-models]]` / `[[inwild-ceiling-is-data-limited]]` with the at-scale verdict.

**Interfaces:**
- Consumes: `docs/results/fw_headtohead_metrics_2026-06-21.json`, `docs/results/competing_deep_metrics_2026-06-21.json`.
- Produces: the doc's required framing — NOT "do neural nets beat Cox" but **where they win and lose at scale**: discrimination parity/gap, calibration differences, and the cost (train time, tuning, GPU) vs Cox/xgb.

- [ ] **Step 1: Write `docs/deep_survival_headtohead_2026-06.md`** — a table of {cox, xgb, deepsurv} × {C-index, AUC@{7,30,90,180}, IPA/IBS} on first-weaponization, plus {deephit vs AJ/cause-specific} on the pipeline, and a 3–5 sentence honest verdict on where deep wins/loses and whether the extra cost is justified. Fill from the JSONs; no placeholders.

- [ ] **Step 2: Update `docs/progress.md` + README bullet + the two memory files** with the at-scale verdict (the in-wild head-to-head was the wrong scale; this is the right one).

- [ ] **Step 3: Commit**

```bash
git add docs/deep_survival_headtohead_2026-06.md docs/progress.md README.md
git commit -m "docs(deep): at-scale Cox-vs-deep verdict — where deep wins/loses on first-weaponization + pipeline"
```

---

## Phase 3 (optional) — Tactic conditioning (RQ3)

Only if Phases 1–2 leave time. The doc's RQ3: *do CVEs mapped to particular ATT&CK tactics transition faster/slower?* Stratify the Phase-1 transition cohorts by ATT&CK tactic (from `technique_cwe_chain` → tactic) and compare KM/median-lag per tactic. Deferred by default — Phases 1–2 are the spine.

---

## Self-Review

- **Spec coverage:** RQ2 multi-state pipeline (cascade + independence + per-transition models) = Phase 1 (Tasks 1–3); the AI artefact "deep survival head-to-head vs Cox at scale, characterise win/lose" = Phase 2 (Tasks 4–7); RQ3 tactic conditioning = Phase 3 (optional). The two non-negotiable methodology pitfalls (KM-first, locked time-split) are honored: Phase 1 uses Aalen-Johansen CIF (the multi-state KM), Phase 2 uses `--cutoff-date` locked splits. Both required viva caveats (PoC dominance, informative censoring) are mandated in the Task 3 / Task 7 writeups. Covered.
- **Placeholder scan:** scripts are complete and runnable; doc tasks say "fill from the JSONs" with the exact source files named — no "TBD"/"add error handling"/"similar to". The transition script catches degenerate-cohort failures explicitly.
- **Type consistency:** `build_transition_labels(... from_source, to_source, competing_sources)`, `transition_cindex(durations, risk, events)`, `cascade_order_stats(per_signal_labels, stages)`, `cif_vs_independent(frame, horizons)`, `train --models cox,xgb --deep --label-set first_weaponization`, `train-competing --deep-hit` — all verified against the current source this session.
- **Open risks:** (1) the `[deep]` install (CUDA wheel size / VRAM) — Task 4 gives a CPU fallback. (2) `transition_frame` vs `build_transition_labels` — the plan uses `build_transition_labels` (the N6-proven path) for Task 2; `transition_frame`/`cif_vs_independent` (Task 1) are the competing-risks view. (3) if PoC→KEV is event-thin, its C-index may be `None` — handled, and the cascade/CIF evidence (Task 1) carries RQ2 regardless.

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-06-21-recenter-pipeline-and-deep-at-scale.md`.** Phase 1 is torch-free and runs on existing artifacts (fast result, the thesis spine); Phase 2 is gated on the `[deep]` sidecar install.
