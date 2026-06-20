# Data-Expansion Roadmap — More In-Wild CVEs (VulnCheck → NVD++ → 0-day → paid)

> **Companion to** `2026-06-20-integrate-fetched-data.md`, which holds the *execution mechanics*
> (merge → rebuild → re-evaluate). This document is the **strategy / decision record**: where the
> extra exploitation signal comes from, what already landed this session, what's next, and the
> honest measured tradeoff. Read both; do not duplicate the integration task list here.

**Why this exists.** The in-wild head (real exploitation, not PoC tooling) is **data-limited, not
method-limited** — Cox already ranks at AUC≈0.85 but PR-AUC≈0.01 / IPA≈0 on ~250–400 events. The
only lever that moves the needle is **more labeled in-wild events**. This plan enumerates every
viable source, marks what's wired, and records the measured effect.

## The bar that matters

EPSS is itself an in-wild predictor over a 30-day window. So the success bar is **PR-AUC vs an
EPSS-only model**, not beating Cox. Beating Cox is necessary but circular; beating EPSS-only is the
real claim. Every evaluation in the companion plan compares against EPSS-only for this reason.

---

## Source roadmap — status and verdict

| Source | Access | In-wild? | Status | Verdict |
|---|---|---|---|---|
| **CISA KEV** (`kev_events`) | free, no auth | yes (cataloged exploited) | wired (handover) | baseline in-wild signal; ~350 train events |
| **Google Project Zero 0-day** (`google_0day`) | free | yes (ITW 0-day) | wired (handover) | small but gold; some are negative-duration (exploited before disclosure) |
| **VulnCheck KEV** (`vulncheck_kev`) | free **community token** | yes (superset of CISA KEV) | ✅ **fetched this session** — 4,969 CVEs through 2026-06-17 | **biggest free win**: ~3× train events, ~6× at 70/30 |
| **VulnCheck NVD++** (`nist-nvd2`) | same community token | no (it's metadata) | ✅ **connector landed** (`fetch/nvdplus.py`), not yet refreshed into corpus | refreshes the 359k-CVE corpus → better *features* (CVSS/CWE/CPE), not more labels |
| **0-day recovery** (negative-duration events) | n/a — derived | yes | ✅ **landed** (`recover_negative_duration` in `modeling.py`, committed `34134fd`) | recovers ~900 events exploited at/before disclosure; floors duration to `SAME_DAY_DURATION=0.5` instead of dropping |
| **Shadowserver** (`fetch/shadowserver.py`) | free, but **scoped to your own ASN/netblock** | yes (honeypot/scan telemetry) | connector stubbed; **dead-end** | no *global* CVE feed — you only see attacks against IPs you own. Confirmed via docs/web. Do not pursue for corpus expansion. |
| **GreyNoise** | **paid** for bulk/tags | yes (mass-scan telemetry) | not wired | paid tier needed for bulk CVE tags; revisit only if budget appears |
| **VulnCheck paid tier** | **paid** | yes | not wired | adds exploit/IP intel + higher rate limits beyond the community KEV; the community token already gives the label expansion that matters |
| MSRC / AlienVault OTX | free-ish, scrape/API | partial | not wired | possible future scrapers; lower priority than landing what's fetched |

**Bottom line on sourcing:** the free VulnCheck community token is the single highest-leverage
source and it is **already fetched**. NVD++ improves features, not label count. Paid sources
(GreyNoise, VulnCheck paid) are the only remaining lever after that, and only if a budget exists.

### Why NVD++ comes from VulnCheck
NVD's own 2.0 API is heavily rate-limited (≈50 req / 30 s even with a key) and frequently degraded.
VulnCheck mirrors the full NVD 2.0 corpus as a single backup file at the `nist-nvd2` endpoint —
one streamed download of ~359k CVEs vs tens of thousands of paginated calls. Same data, no
rate-limit pain. It backfills CVSS / CWE / CPE for the publication-time feature set; it adds **no**
in-wild labels (it is metadata, not exploitation evidence).

---

## What landed this session (✅ done — recorded for the next agent)

1. **VulnCheck KEV fetched** → `data/live/vulncheck_kev.parquet` (4,969 CVEs, through 2026-06-17).
   Token passed only via `VULNCHECK_API_TOKEN` / `--api-key`; **never committed**. `data/live/`,
   `data/merged/`, `artifacts/` are gitignored.
2. **NVD++ connector** `src/temporal_exploit/fetch/nvdplus.py` (`NvdPlusConnector`) — streams the
   `nist-nvd2` backup, ijson-parses into the `cve_corpus` schema. Wired via `refresh --with-nvdplus`.
   `data/live/cve_corpus.parquet` (359k) is staged but **not yet merged/built**.
3. **0-day recovery** — `prepare_modeling_frame(..., recover_negative_duration=True)` floors
   negative-duration in-wild events to day-0 instead of dropping them (commit `34134fd`). TDD-covered
   (`test_prepare_modeling_frame_recovers_negative_duration_0days`). 308 tests collected, green.
4. **Full-wiring demo** `scripts/inwild_full_wiring.py` — 3-arm 70/30 Cox, results below.

### The honest measured tradeoff (70/30 Cox, `artifacts/reports/inwild_full_wiring.json`)

| Arm | train ev | test ev | c-index (95% CI) | PR-AUC@90 | IPA@90 |
|---|---:|---:|---|---:|---:|
| CISA-only | 348 | 106 | 0.870 [0.806, 0.934] | 0.026 | ~0.000 |
| +VulnCheck | 2,468 | 637 | 0.803 [0.772, 0.834] | 0.023 | 0.0070 |
| +VulnCheck +0day | 3,376 | **1,304** | 0.763 [0.740, 0.786] | **0.067** | **0.0135** |

**Read both directions, don't cherry-pick:**
- **Wins:** 12× test events; CI width shrinks from ±0.064 to ±0.023; PR-AUC@90 ↑ 0.026→0.067;
  IPA@90 (calibration value over a marginal model) goes from ~0 to a genuinely positive 0.0135.
- **Apparent loss:** ranking c-index drops 0.870→0.763. This is **not** lost skill — the 0.870 was
  small-sample optimism on 106 events (CI reached 0.934), and the day-0 recovered events are
  tie-ranked (every "exploited before disclosure" CVE shares duration=0.5), which c-index penalizes
  even though those are the highest-value labels. The calibration metrics (IPA, PR-AUC) are the ones
  that improve, and those are what matter for a rare-event in-wild model.

---

## Next steps (open work — execute via the companion plan)

- [ ] **Refresh NVD++ into the corpus** — run `refresh --with-nvdplus` (needs `VULNCHECK_API_TOKEN`),
      then the companion plan's **Task 2 (merge)** folds it + VulnCheck KEV into `data/merged/`.
- [ ] **Rebuild + re-evaluate** — companion plan **Tasks 3–4**: build from `data/merged/`, then the
      in-wild rolling-origin backtest with `paired_origin_deltas` and the **PR-AUC-vs-EPSS-only** bar
      at 30/90d, plus the GPU xgb-AFT re-test at the new event count.
- [ ] **Make `recover_negative_duration=True` the default for the in-wild head** once the backtest
      confirms the calibration win holds out-of-sample (it is off by default today; the full-wiring
      demo turns it on explicitly). Gate the flip on the companion plan's Task 4 verdict.
- [ ] **Decide on paid sources** — only if the EPSS-only bar is still not cleared after the free
      expansion. GreyNoise bulk tags or the VulnCheck paid tier are the candidates; document the
      cost/benefit before any spend. No action until the free path is fully measured.

## Constraints (carried from the companion plan — non-negotiable)

- **RAM ≤ 6–8 GB / VRAM ≤ 7 GB.** `free -g` before each heavy stage. EPSS scan uses the streamed
  `iter_batches` + date-pushdown path (peak ~1.3 GB). **Never** add an `isin(cve_ids)` pushdown on
  the 375M-row EPSS file (retains ~5.8 GB).
- **Leakage:** EPSS-dynamics / landmark features are safe **only with `restart_clock`**; time-based
  splits only, never random K-fold. Snapshot stays `2026-03-14` (the bundled EPSS history ends there,
  so the label expansion is the only changed variable — apples-to-apples vs the existing backtest).
- **Token never committed.** `data/live/`, `data/merged/`, `artifacts/` gitignored. Run a
  token-leak grep on the staged diff before every push.

## Framing caveat (unchanged)
Even fully expanded, this predicts **time to cataloged in-wild exploitation** (KEV/VulnCheck/0-day),
not silent exploitation no one has observed. It is a complement to EPSS, not a replacement. See
`docs/modeling_methodology.md` §9/§11.
