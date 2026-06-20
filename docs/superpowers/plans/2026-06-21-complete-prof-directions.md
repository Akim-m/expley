# Complete the Professor's Remaining Directions (Time-to-PoC + Tactic Conditioning + Defender Interpretation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the still-open items in `temporal_exploit_prediction.md` §Directions worth exploring + §What success could look like — **Direction 1 (Time-to-PoC, clean)**, **Direction 3 (Tactic conditioning)**, and the **required defender-facing interpretation** ("what would a defender do differently knowing these predictions?") — so the deliverable satisfies the professor's success checklist, not just the modeling parts already done (Directions 2 + 4, deep-survival artefact).

**Architecture:** Three phases, each ending in a results artifact + a docs synthesis, each gated by an **aggressive reverse-engineering audit** (see Global Constraints — RE is bumped from the standing ≥5/≥6 to **≥10 rounds + multi-seed + adversarial cross-checks** per deliverable). Phase A models time-to-first-PoC on the **clean recent cohort** (the data's strength, with the PoC-date artifact controlled), reports feature importance + a model-class comparison, and optionally adds leakage-gated description embeddings (the AI direction #2). Phase B stratifies weaponization timing by ATT&CK tactic. Phase C synthesizes everything into a defender-facing interpretation + a deployable publication-time score. No changes to the immutable `dataset_extraction/` handover; all work in `src/temporal_exploit/` + `scripts/`.

**Tech Stack:** Python 3.12 (`.venv`, uv); `temporal-exploit` CLI; lifelines Cox; GPU XGBoost-AFT (`.venv-deep` for any deep/embedding work); sentence-transformers (optional, leakage-gated); existing `competing.py` / `landmark.py` / `evaluate.py`.

## Global Constraints

- **AGGRESSIVE reverse-engineering (user directive 2026-06-21):** every deliverable gets **≥10 RE rounds** (was ≥6), and each headline number is verified by **≥2 independent re-derivations**, **≥3 seeds** where stochastic, and **bootstrap CIs with ≥1000 resamples** (was 200–500). At least one round per phase must be **adversarial** — actively try to falsify the result (wrong-sign check, leakage probe, label-shuffle null, subgroup stability). Log what was checked, not just the verdict. Run the full test suite at each phase end.
- **RAM ≤ 6–8 GB / VRAM ≤ 7 GB.** `free -g` / `nvidia-smi` before heavy work. Use the lossless `downcast_int_features` path (already wired into `prepare_modeling_frame`). Column/row pushdown on every parquet read; never re-load a parquet already in memory; never `isin(cve_ids)` on the 375M-row EPSS file.
- **Leakage discipline (the professor's two gotchas, non-negotiable):** publication-time-safe features only; **description text is leaky** (NVD back-edits it) — use it ONLY on the gated subset `last_modified ≤ published + ε` OR with masked leakage terms; **time-based split only, never random K-fold**; snapshot stays `2026-03-14`.
- **Clean cohort for PoC timing:** restrict time-to-PoC analyses to **CVE published ≥ 2021** (the PoC-date bulk-index artifact corrupts older CVEs — see `pipeline_characterization_2026-06.md`). Report the all-cohort number too, labelled as artifact-affected.
- **Don't touch the immutable handover** (`dataset_extraction/`); update `docs/progress.md` + README when work lands (CLAUDE.md rule). Token never committed; `data/`, `artifacts/`, `.venv*` gitignored.
- **Paths:** merged corpus = `data/merged`; merged artifacts = `artifacts/merged`; technique chain = `dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/technique_cwe_chain.parquet`; EPSS = `epss_history-001.parquet`.

---

## Phase A — Direction 1: Time-to-PoC (clean cohort, feature importance, model comparison)

The doc's RQ1: *which features (severity, weakness type, ATT&CK tactic, vendor/product family, EPSS-at-publication, learned description embeddings) predict the days from publication to first public PoC, and how do model classes compare?*

### Task A1: Build the clean time-to-PoC label + a focused analysis

**Files:**
- Create: `scripts/time_to_poc_analysis.py`
- Create (output): `artifacts/merged/time_to_poc.json`
- Use: `temporal_exploit.labels.build_transition_labels(corpus, frames, snapshot, from_source="published"...)` is NOT the shape here — time-to-PoC clock origin is `published` and the event is `poc`. Reuse `build_first_weaponization_labels`-style logic but single-source = `poc`: load `poc_dates`, compute `duration = poc_date - published`, censor at snapshot, restrict to published ≥ 2021.

**Interfaces:**
- Consumes: merged corpus (`cve_id`, `published`), `poc_dates` (live/merged), `artifacts/merged/publication_features.parquet`.
- Produces: `artifacts/merged/time_to_poc.json` — n eligible / n PoC events / median time-to-PoC, Cox + XGBoost-AFT held-out c-index (clean cohort vs all-cohort), and the top feature importances.

- [ ] **Step 1: Write the analysis script (clean cohort, model comparison, feature importance)**

```python
"""Direction 1 (RQ1) — time-to-first-PoC on the clean recent cohort (published>=2021,
PoC-date artifact controlled). Which publication-time features predict days-to-PoC,
and how do Cox vs XGBoost-AFT compare? Held-out time split, feature importance."""
import json
from pathlib import Path
import numpy as np, pandas as pd
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.loaders import load_parquet
from temporal_exploit.modeling import prepare_modeling_frame, time_split_frame, _risk_scores, evaluate_survival, survival_at
from temporal_exploit.backtest import _fit

OUT = Path("data/merged"); SNAP = "2026-03-14"; MIN_PUB = "2021-01-01"; HZ = (7, 30, 90, 180)
corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
feats = pd.read_parquet("artifacts/merged/publication_features.parquet")
name, col = EVENT_SOURCES["poc"]
poc = load_optional_event(OUT, name, col)

# single-source time-to-PoC labels: clock origin = published, event = first poc
m = corpus.merge(poc.rename(columns={col: "poc_date"})[["cve_id", "poc_date"]], on="cve_id", how="left")
pub = pd.to_datetime(m["published"], utc=True); pd_ = pd.to_datetime(m["poc_date"], utc=True)
snap = pd.Timestamp(SNAP, tz="UTC")
m["event_observed"] = pd_.notna() & (pd_ <= snap)
m["duration_days"] = np.where(m["event_observed"], (pd_ - pub).dt.days, (snap - pub).dt.days)
m["negative_duration_flag"] = m["event_observed"] & ((pd_ - pub).dt.days < 0)
labels = m[["cve_id", "published", "duration_days", "event_observed", "negative_duration_flag"]]

def run(min_pub_filter, tag):
    frame = prepare_modeling_frame(labels, feats)
    if min_pub_filter:
        p = pd.to_datetime(frame["published"], utc=True)
        frame = frame[p >= pd.Timestamp(MIN_PUB, tz="UTC")].reset_index(drop=True)
    cut = pd.to_datetime(frame["published"], utc=True).quantile(0.70)
    tr, te = time_split_frame(frame, str(cut.date()))
    out = {"tag": tag, "n": len(frame), "n_events": int(frame["event_observed"].sum()),
           "median_ttp_days": float(frame.loc[frame["event_observed"].astype(bool), "duration_days"].median())}
    for kind in ("cox", "xgb"):
        model = _fit(kind, tr)
        x = te[list(model.feature_cols_)].astype(float)
        ev = evaluate_survival(model, tr, te, horizons=HZ, kind=kind,
                               surv_at_horizons=survival_at(model, x, list(HZ), kind),
                               risk=_risk_scores(model, x, kind))
        out[f"{kind}_cindex"] = ev["c_index_ipcw"]; out[f"{kind}_cindex_ci"] = ev["c_index_ci95"]
    # feature importance: cox |coef|, xgb gain
    cox = _fit("cox", tr)
    out["top_cox_coef"] = (cox.params_.abs().sort_values(ascending=False).head(15)).to_dict()
    print(f"[{tag}] n={out['n']} ev={out['n_events']} med={out['median_ttp_days']:.0f}d "
          f"cox={out['cox_cindex']:.3f} xgb={out['xgb_cindex']:.3f}", flush=True)
    return out

results = {"clean_recent": run(True, "published>=2021"), "all_cohort": run(False, "all (artifact-affected)")}
Path("artifacts/merged/time_to_poc.json").write_text(json.dumps(results, indent=2, default=str))
print("\nwrote artifacts/merged/time_to_poc.json", flush=True)
```

- [ ] **Step 2: Run it**

Run: `.venv/bin/python scripts/time_to_poc_analysis.py 2>&1 | grep -v "terminate called\|core dumped"`
Expected: clean-cohort c-index for cox + xgb, median time-to-PoC, top features. The clean number should differ from all-cohort (artifact effect).

- [ ] **Step 3 (AGGRESSIVE RE, ≥10 rounds): verify before documenting**

Run, logging each: (1) **label-shuffle null** — permute `duration_days`, refit, assert c-index → ~0.5 (no leakage); (2) **feature-importance stability** across 3 seeds of the xgb fit; (3) **bootstrap c-index CI (1000 resamples)** on the held-out set; (4) **clean-vs-all delta** — does removing pre-2021 actually change the median/c-index as the artifact predicts; (5) **wrong-sign check** — higher risk ↔ shorter time-to-PoC; (6) **subgroup stability** — c-index within the top-3 vendor families; (7) **EPSS-ablation** — drop EPSS, confirm structural features still carry it (consistency with the in-wild finding); (8) **negative-duration count** sane on the clean cohort; (9) **no duplicate cve_id / train-test overlap=0**; (10) **adversarial leakage probe** — grep the feature columns for any snapshot-time or post-publication field. Record all ten.

- [ ] **Step 4: Commit**

```bash
git add scripts/time_to_poc_analysis.py
git commit -m "feat(rq1): time-to-PoC on clean cohort — model comparison + feature importance"
```

### Task A2 (optional): Leakage-gated description embeddings (AI direction #2)

**Files:**
- Create: `scripts/ttp_description_embeddings.py`
- Use: sentence-transformers `all-MiniLM-L6-v2` (in `.venv-deep` or a sidecar), gated to `last_modified ≤ published + 7d` CVEs.

**Interfaces:**
- Consumes: the clean time-to-PoC frame restricted to the leakage-safe subset; description text.
- Produces: whether description embeddings add c-index over structured features on the gated subset (honest, small-cohort).

- [ ] **Step 1: Gate, embed, ablate** — restrict to `last_modified ≤ published + 7d` (publication-time-safe text), embed descriptions, add as a feature family, compare held-out c-index structured vs structured+embeddings. **AGGRESSIVE RE:** masked-term control (mask "exploited"/"CISA"/"KEV"), 3 seeds, 1000-resample bootstrap, label-shuffle null. Document honestly (likely small/mixed per prior `--description-text`).
- [ ] **Step 2: Commit** (or record a negative result if it doesn't help).

---

## Phase B — Direction 3: Tactic conditioning

The doc's RQ3: *do CVEs mapped to particular ATT&CK tactics show systematically faster/slower transitions through the weaponization pipeline?*

### Task B1: Tactic-stratified weaponization timing

**Files:**
- Create: `scripts/tactic_conditioning.py`
- Create (output): `artifacts/merged/tactic_conditioning.json`
- Use: `technique_cwe_chain.parquet` → map `cve_id` → ATT&CK tactic(s); KM/median time-to-weaponization per tactic; per-tactic event rate.

**Interfaces:**
- Consumes: technique chain (cve→technique→tactic), the first-weaponization (or time-to-PoC) labels, `has_attack_chain_mapping`.
- Produces: per-tactic median time + KM at 7/30/90/180 + a log-rank/CI across tactics, with the ~25%-ATT&CK-coverage caveat (a `has_mapping` stratum, not implied absence).

- [ ] **Step 1: Write the script** — join technique chain → tactic, stratify the labels by tactic (handle multi-tactic CVEs explicitly: one row per (cve, tactic) or primary tactic — document the choice), compute per-tactic median time-to-event + KM survival at horizons + n. Include a `has_attack_chain_mapping` vs not comparison (coverage is ~25%).

```python
# skeleton — fill the join + per-tactic KM
import json
from pathlib import Path
import pandas as pd
from lifelines import KaplanMeierFitter
from temporal_exploit.loaders import load_parquet
CHAIN = "dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/technique_cwe_chain.parquet"
chain = pd.read_parquet(CHAIN, columns=["cve_id", "tactic"])  # verify real col names first
labels = pd.read_parquet("artifacts/merged/modeling_labels.parquet",
                         columns=["cve_id", "duration_days", "event_observed", "negative_duration_flag"])
labels = labels[~labels["negative_duration_flag"].astype(bool) & (labels["duration_days"] > 0)]
df = labels.merge(chain.drop_duplicates(["cve_id", "tactic"]), on="cve_id", how="left")
df["tactic"] = df["tactic"].fillna("(no_attack_mapping)")
rows = []
for tac, g in df.groupby("tactic"):
    if len(g) < 50:  # log the dropped small tactics, don't silently omit
        continue
    km = KaplanMeierFitter().fit(g["duration_days"], g["event_observed"])
    med = g.loc[g["event_observed"].astype(bool), "duration_days"].median()
    rows.append({"tactic": tac, "n": len(g), "n_events": int(g["event_observed"].sum()),
                 "median_days": float(med) if pd.notna(med) else None,
                 "surv_30": float(km.predict(30)), "surv_90": float(km.predict(90))})
Path("artifacts/merged/tactic_conditioning.json").write_text(json.dumps(rows, indent=2, default=str))
for r in sorted(rows, key=lambda r: r["median_days"] or 1e9):
    print(f"  {r['tactic']:28s} n={r['n']:6d} ev={r['n_events']:6d} median={r['median_days']}", flush=True)
```

- [ ] **Step 2: Run + verify the real chain column names first** (`view_parquet.py technique_cwe_chain --schema-only`) — the join key/tactic column must be confirmed (CLAUDE.md: wrong names silently produce zeros).
- [ ] **Step 3 (AGGRESSIVE RE, ≥10 rounds):** (1) confirm tactic column real name + non-null coverage; (2) multi-tactic handling doesn't double-count events (assert event sum vs labels); (3) per-tactic median stable on a bootstrap (1000); (4) log-rank across tactics (are differences real?); (5) the `no_attack_mapping` stratum vs mapped — is "has mapping" itself confounded with recency/severity?; (6) small-tactic drops logged (no silent truncation); (7) re-derive 2 tactics' medians independently; (8) check the chain join didn't explode rows (1:many is expected — handle); (9) sensitivity to the published≥2021 clean cohort; (10) adversarial — shuffle tactic labels → differences vanish. Record all.
- [ ] **Step 4: Commit.**

---

## Phase C — The required defender-facing interpretation + deployable score

The doc's §What success could look like: *"An interpretation of results that connects back to vulnerability-management practice — what would a defender do differently knowing these predictions?"* This is the missing required deliverable.

### Task C1: Defender interpretation + a publication-time priority score

**Files:**
- Create: `docs/defender_interpretation_2026-06.md`
- Create: `scripts/defender_score.py` (+ `artifacts/merged/defender_operating_points.json`)
- Use: the Phase A/B results + existing `decision_curve.py` / operating-points machinery.

**Interfaces:**
- Consumes: time-to-PoC model (Phase A), PoC→KEV conditional model (the strong 0.87 signal), tactic conditioning (Phase B), decision-curve net benefit.
- Produces: a concrete defender playbook — e.g. "at publication, a CVE with [structural profile] has P(PoC within 7d) = X and P(in-wild within 90d | PoC) = Y → triage tier Z," with operating points (precision/recall at deployable thresholds) and the honest limits.

- [ ] **Step 1: Build the publication-time priority score** — combine the leakage-safe time-to-PoC risk + the conditional PoC→KEV risk into a single triage score; emit operating points (recall@top-1%/5%/10%, precision, lead-time) + decision-curve net benefit at realistic base rates.
- [ ] **Step 2 (AGGRESSIVE RE, ≥10 rounds):** operating points reproduce on held-out; threshold stability across 3 seeds; net-benefit sign vs treat-all/treat-none; 1000-resample CI on recall@top-decile; the score adds over EPSS-only (circularity control); no leakage in the score's inputs; calibration of the combined score; subgroup fairness (does the score collapse for low-ATT&CK-coverage CVEs?); lead-time honesty; adversarial label-shuffle. Record all.
- [ ] **Step 3: Write `docs/defender_interpretation_2026-06.md`** — the practitioner story with numbers, operating points, and the framing caveats (PoC-tooling not in-wild; informative censoring). Fill from artifacts; no placeholders.
- [ ] **Step 4: Commit.**

---

## Phase D (optional) — Downstream tool integration (the "exceptional" tier)

Only if A–C land with time left. A minimal CLI/notebook that takes a CVE id (or its publication-time features) and returns the triage tier + survival curve + tactic context — the doc's "integration into a downstream tool." Deferred by default.

---

## Final synthesis + README/progress/memory sync

- [ ] Update `docs/progress.md` (detailed) + README Project status (Directions 1+3 done, defender interpretation done) + the relevant memories. Map every §"What success could look like" bullet to where it's satisfied.
- [ ] Full test suite green; token-leak grep clean; everything committed + pushed.

## Self-Review

- **Spec coverage:** Direction 1 = Phase A (clean time-to-PoC + feature importance + model comparison + optional embeddings); Direction 3 = Phase B (tactic conditioning); the required defender interpretation = Phase C; downstream tool = Phase D (optional). Directions 2 + 4 + deep artefact already done. The two methodology non-negotiables (KM-first via Phase B KM + tactic survival; locked time-split throughout) and both gotchas (description gating in A2; no snapshot leakage) are honored. Covered.
- **Placeholder scan:** A1/B1 scripts are complete; C1 says "fill from artifacts" with named sources; B1 flags "verify real chain column names" (a known CLAUDE.md trap) rather than assuming. No "TBD"/"add error handling".
- **Type consistency:** `prepare_modeling_frame`, `time_split_frame`, `_fit(kind, frame)`, `evaluate_survival(..., surv_at_horizons, risk)`, `_risk_scores(model, X, kind)`, `survival_at(model, X, horizons, kind)`, `EVENT_SOURCES`, `load_optional_event` — all verified against current source this session.
- **Aggressive-RE coverage:** each phase has a ≥10-round RE step with multi-seed + 1000-resample bootstraps + ≥1 adversarial (label-shuffle/leakage-probe) — meets the user's "more aggressive, more runs" directive. The standing memory of ≥5/≥6 is the floor; this plan's floor is ≥10.
- **Open risks:** (1) `technique_cwe_chain` column names unverified — Task B1 Step 2 gates on it. (2) leakage-gated embedding cohort may be small — A2 is explicitly optional + honest-negative-tolerant. (3) the PoC-date artifact — controlled by the published≥2021 cohort, with all-cohort reported as the labelled contrast.

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-06-21-complete-prof-directions.md`.** Phases A→B→C are sequential (C synthesizes A+B); within each, the script + its ≥10-round RE are one reviewable unit. Two execution options: (1) subagent-driven (fresh subagent per task, review between — recommended for the aggressive-RE volume); (2) inline with checkpoints.
