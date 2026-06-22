# Causal characterization + patch-vs-exploit race (2026-06)

New scope added after the in-wild label ceiling saturated (see
[[scope-broadening-probes]] / `docs/scope_broadening_*`). Two synergistic
directions chosen by the user: **causal characterization** of what accelerates
weaponization, and the **patch-vs-exploit race**. Both run on the abundant
first-weaponization target (~97% public PoC/tooling), which is well-powered where
the rare in-wild target is not.

## Phase 1 — Causal characterization (what *causally* accelerates weaponization)

`src/temporal_exploit/causal.py` (adjusted Cox + stabilized IPW + overlap
diagnostics + VanderWeele-Ding E-value), `scripts/causal_characterization.py`,
`tests/test_causal.py`. Outcome = time-to-first-weaponization (n=313,847; 147,048
events). HR>1 = faster. Confounders are pre-treatment **common causes** only
(deliberately NOT the CVSS components that *define* a vector treatment).

| Treatment | crude HR | adjusted HR | IPW HR | E-value | overlap | verdict |
|---|---|---|---|---|---|---|
| wormable (AV:N/PR:N/UI:N/AC:L) | 1.71 | **1.29** [1.28,1.31] | 1.41 | 1.68 | good | real causal acceleration |
| unauth-network-high-impact | 1.56 | **1.24** [1.22,1.25] | 1.38 | 1.58 | good | real causal acceleration |
| ATT&CK-chain-mapped | 1.09 | **0.97** [0.96,0.99] | 1.07 | 1.16 | **poor (near-separation)** | confounded by CWE — no robust effect |

Validation: raw median time-to-weaponization wormable **100d vs 277d**; the
wormable effect survives even a stricter mediator-inclusive adjustment (add CVSS
base+severity) at HR 1.17 [1.15,1.18] — so the effect lives in 1.17–1.41 across
the whole adjustment spectrum, never crossing 1. The ATT&CK-mapping positivity
failure (treated propensity median 0.94 vs control 0.009) is the causal framework
correctly refusing an unsupported estimate — a null the prior associational
log-rank tactic study could not catch.

## Phase 2 — Patch-vs-exploit race (the honest reframe)

Foundation: re-fetched NVD references (`scripts/fetch_nvd_references.py` ->
`data/merged/nvd_references.parquet`, 359,627 CVEs; 24.8% `Patch`-tagged, 20.5k
with fix-commit URLs), then mined fix-commit dates via GitHub GraphQL
(`scripts/mine_commit_dates.py` -> `data/merged/commit_dates.parquet`, 20,549
CVEs, 67.7% dated). Analysis: `scripts/patch_race_analysis.py` ->
`artifacts/merged/patch_race.json`.

**Headline: the race is bimodal, and patch-date *observability* is itself the selector.**

1. **Where fix-commit dates are observable (coordinated-disclosure OSS, n≈11k):**
   the fix lands a **median 14 days BEFORE** the CVE is published; only **1.0%**
   (114/11,227) are patched after publication. Defenders win the race ~99.5% of
   the time *if they patch*; public PoCs trail the fix by a **median ~155 days**
   (p25 23d). → This cohort can't measure the race — it measures n-day PoC lag in
   well-behaved OSS. The time-varying Cox for the "patches enable n-day exploits"
   hypothesis is **underpowered/inconclusive** here (HR 0.63 but only ~65
   identifying transitions = 1% of the cohort).
2. **0-days (Google Project Zero, n=132):** the mirror image — **100%** exploited
   before any patch, median **9 days** discovery→patch.
3. **Unbiased corpus-wide (no commit dates needed):** **28.6%** of
   first-weaponizations and **35.5%** of in-wild exploitations occur **on/before**
   the CVE's publication date — the exploit beat coordinated disclosure. This
   **independently matches VulnCheck's reported 28.96%** of 2025 KEVs exploited
   on/before CVE publication → external validation of our labels.

**Methodological lesson:** a commit-date-based race model is the wrong instrument —
it is selection-biased toward the cases where the race is already won; the
dangerous exploit-before-patch cases (0-days, vendor-advisory-only, no public
commit) are systematically excluded. The unbiased race signal is the
**pre-disclosure weaponization rate**, computable corpus-wide from labels we
already have — no fetch required.

## Deliverables
- `src/temporal_exploit/causal.py` + `tests/test_causal.py` (4 tests)
- `scripts/causal_characterization.py` -> `artifacts/merged/causal_characterization.json`
- `scripts/fetch_nvd_references.py` -> `data/merged/nvd_references.parquet`
- `scripts/mine_commit_dates.py` -> `data/merged/commit_dates.parquet`
- `scripts/patch_race_analysis.py` -> `artifacts/merged/patch_race.json`
