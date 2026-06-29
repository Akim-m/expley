# GreyNoise as an in-wild label source: API reality + prospective connector (2026-06-30)

**TL;DR.** GreyNoise free access (Research Community / VIP) is real and grants Enterprise
CVE-API access, **but the data shape defeats historical backfill**: in-the-wild observation is a
**rolling ≤30-day window** (`threat_ip_count_1d/10d/30d`), with **no per-CVE cumulative "first
observed exploited" date**. The one historical per-CVE date (`first_known_published_date`) is
*first exploit-code published* — exploit **tooling**, our existing first-weaponization signal, not
in-the-wild. So GreyNoise **cannot retroactively label** when a 2022–2025 CVE was first exploited;
it is a **prospective** stream. We built a connector that treats it as exactly that — a
forward-accumulating in-wild stamp — so the project can start banking onset-accurate labels the
moment a token arrives. It will **not** change today's EPSS-parity numbers (see
[`inwild_epss_parity_2026-06.md`](inwild_epss_parity_2026-06.md)).

## What the API actually exposes (verified against authoritative docs)

Cross-confirmed from `docs.greynoise.io/docs/cve-response`, the `GET /v1/cve/{id}` reference, and
GreyNoise's own MCP `enterprise-api.md` (all 2026-06-30):

| Field group | Content | Usable as historical in-wild date? |
|---|---|---|
| `exploitation_activity.threat_ip_count_{1d,10d,30d}` | # threat IPs seen exploiting the CVE, **rolling window** | ❌ window only — no first-seen, no cumulative history |
| `exploitation_activity.benign_ip_count_*` | benign scanners (not exploitation) | ❌ not in-wild |
| `timeline.first_known_published_date` | "date the first **exploit was published**" (PoC/exploit code) | ❌ = exploit **tooling** = our first-weaponization signal, not in-wild |
| `timeline.cve_published_date`, `cisa_kev_date_added` | NVD publish / CISA KEV add | already have these |

**There is no field giving "first date GreyNoise observed this CVE exploited in the wild."** The
paid **Recall** time-series product can query historical ranges, but that is a commercial tier, not
the free Research Community grant.

## Access model

- **Research Community / VIP** — free, non-commercial; eligible: students, teachers, independent
  researchers, integration devs. Apply at `info.greynoise.io/community/research-program-request`;
  a team member confirms. Grants "full access to the Enterprise API" incl. CVE endpoints + GNQL.
- Auth header is `key: <token>` (GreyNoise convention), **not** `Authorization: Bearer`.
- Bulk CVE lookup: `POST /v3/cves`, up to **10,000 CVEs/request**.

## The connector (`src/temporal_exploit/fetch/greynoise.py`)

A **prospective accumulator**, the only honest design given rolling-window data:

1. Bulk-query `POST /v3/cves` for the corpus CVE universe (chunked at 10k).
2. Stamp every CVE with ≥`threat_threshold` threat IPs in `window` (default 30d) as
   **observed-in-wild as of the snapshot date** (`greynoise_inwild_first_seen`).
3. Deliberately **ignore** `first_known_published_date` (tooling — would contaminate the in-wild target).
4. Run on a schedule. The earliest-wins **merge layer** (`merge.py`) collapses repeated daily
   snapshots into a true **first-observation date** per CVE over time — the architecture already in
   place turns a dumb daily snapshot into a first-seen dataset for free.

Tested in `tests/test_greynoise_fetch.py` (parse contract, window/threshold, dedupe, empty-data
envelope, token + empty-list short-circuits). Network is not exercised in CI (no live token).

```bash
# one prospective snapshot (needs the free Research Community token):
GREYNOISE_API_TOKEN=…  # or pass --api-key
.venv/bin/python -m temporal_exploit.cli fetch --source greynoise \
  --api-key "$GREYNOISE_API_TOKEN" --live-dir data/live --date 2026-06-30 \
  --cve-source dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out/cve_corpus.parquet
# then (later, after accumulating snapshots): merge -> build-dataset -> backtest
```

## Honest verdict / next step

- **Today:** GreyNoise adds **zero** historical in-wild events, so it does not move the +0.100
  parity gap or the PR-AUC tie. The connector is groundwork, ready and tested.
- **Forward:** if the project commits to scheduled polling (cron/daily) for months, GreyNoise yields
  **onset-accurate** in-wild first-seen dates — the timing-clean signal that the catalog-add labels
  (VulnCheck median +107d, CISA +329d) lack, and the one lever with a chance of breaking the
  precision tie. Wiring `greynoise` into `IN_WILD_SOURCES` + a `merge.py` spec is the explicit
  follow-up, deferred until labels have accumulated (wiring an empty source now would only confuse
  the validated parity build).
- **Not** a substitute for the historical comparison; **is** the right long-horizon investment.
