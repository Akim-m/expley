# In-wild label source sweep: is there anything free + historical left? (2026-06-30)

**Question.** Beyond CISA KEV + VulnCheck KEV + Google 0-day + MSRC (all integrated) — and after
ruling out Shadowserver (region-locked) and GreyNoise (prospective-only, [`greynoise_inwild_2026-06.md`](greynoise_inwild_2026-06.md)) —
is there any **free, historical, non-redundant, programmatic** in-wild label source that would grow
the parity's labels or fix their timing?

**Answer (decision-grade, after a 5-agent web sweep + a measured MSRC check).** For **event count:
no — the label space is saturated.** Every free/historical/programmatic candidate is either a
re-aggregator of CISA KEV + VulnCheck or carries the wrong/expired signal. This confirms the
project's standing finding: the ~396–1,310-event in-wild ceiling is **data-limited**, and growing
the *count* needs prospective telemetry (GreyNoise academic / Shadowserver) we've already ruled out
for backfill. The only remaining lever is **onset-date quality on events we already label**, and it
is **bounded** (a few days on ~20 CVEs/yr).

## The redundancy yardstick

Our `VulncheckKevConnector` already takes the **earliest** `vulncheck_reported_exploitation[].date_added`
per CVE. VulnCheck's free Community KEV is itself a **fusion** of the broad primary in-wild evidence
base — CISA KEV + SANS ISC + Shadowserver honeypots + vendor advisories (it names Microsoft, Google,
Apple, Cisco, Ivanti, Fortinet/F5, Tenable, Imperva) + researcher posts + GitHub PoCs — each with a
`{url, date_added}` evidence object, tracking **~3,672 exploited CVEs vs CISA's ~1,345 (~80% more),
~27 days ahead of CISA**. So **any vendor-advisory / news / honeypot / national-CERT scrape is
redundant by construction** unless it beats VulnCheck on a *specific date* or covers a vendor it omits.

## Per-candidate verdict (all SKIP unless noted)

| Candidate | Free | Historical | Non-redundant vs KEV+VulnCheck | Verdict |
|---|---|---|---|---|
| Phoenix Intelligence Blue | exploit fields = Pro/Enterprise | — | No (fuses sources we have) | SKIP |
| Zero Day Clock | view-only | borrowed | No (viz of KEV + VulnCheck XDB); no API/export | SKIP |
| AlienVault OTX | yes | yes | weak — "CVE mentioned", high FP, few new events | UNCERTAIN (pilot only) |
| abuse.ch ThreatFox | yes | **no** (6-mo expiry since 2025-05) | marginal | SKIP |
| abuse.ch URLhaus | yes | yes | malware URLs, ~no CVE tags | SKIP |
| OpenCVE | yes | desc only | No (KEV + EPSS passthrough) | SKIP |
| ENISA EUVD | yes | partial; no exploitation-date field | **negative** (1,270 < CISA 1,345) | SKIP |
| JPCERT / CERT-EU / ACSC / NCSC | yes | prose | No (feed *into* CISA KEV) | SKIP |
| Vulners `wildExploited` | paid field | yes | No (re-aggregator) | SKIP |
| AttackerKB (Rapid7) | **yes (free key)** | yes | partial — independent expert flags, but dates = assessment not onset | cross-check only |
| CIRCL Vuln-Lookup | yes | thin (~2024+) | mostly no | SKIP |
| Vendor advisories (Apple/Adobe/Cisco/Ivanti/Fortinet/Android/Chrome) | yes | yes | mostly **no** (6/7 ingested by VulnCheck) | mostly SKIP; 2 cheap exceptions |
| **MSRC** (already integrated) | yes | yes | **measured negligible** (see below) | already wired; ~0 marginal |

### MSRC, measured (not assumed)

Of 146 MSRC `Exploited:Yes` CVEs: **98.6% already in KEV∪VulnCheck**, only **2 net-new** (both
unusable — no publication date), and MSRC's date is earlier than the current `min(KEV, VulnCheck)`
for just **17 CVEs (11.8%) by a median of 7 days** (max 19). Effectively fully redundant for the
parity; its `data/merged/msrc.parquet` isn't even loaded by the parity (which reads `data/live`/`out`),
and wiring it in would change nothing material.

## Ranked shortlist — the only things worth (maybe) wiring, all date-quality not count

1. ~~VulnCheck evidence-URL canonical-date back-fill~~ — **MEASURED DEAD-END (2026-06-30, with the
   token).** Re-fetched the raw catalog (4,998 CVEs) and inspected the schema directly:
   each `vulncheck_reported_exploitation[]` object carries **only `{url, date_added}`** — there is
   **no earlier canonical date field** in the response, and the canary field
   (`reported_exploited_by_vulncheck_canaries`) is a **boolean** (457 true), not dated telemetry
   (the dated canary stream is the paid `ipintel` tier). Our `_best_date` already takes the
   **earliest evidence `date_added`**, which is **197 days median earlier than CISA's catalog-add**
   for 75% of overlapping CVEs — i.e. the cheap onset-date win is *already captured*. The only path
   to earlier dates is fetching the **387,130** evidence URLs and parsing each one's publish date —
   disproportionate effort for a now-confirmed-bounded payoff (the current best-date already sits at
   ~109d median lag; most of that is genuine detection lag, not ingest lag). **Not worth building.**
2. **Cisco openVuln API** — the one vendor with a clean *independent* `firstPublished` timestamp
   (free OAuth2, full CSAF archive 2022–2025); exploitation status is prose (text-match). ~10
   exploited Cisco CVEs/yr.
3. **Android Security Bulletins harvester** — stable monthly URLs, regex "limited, targeted
   exploitation"; deterministic vendor date that can predate CISA + completeness on older
   GPU/Mali CVEs. ~handful/yr.

**Do NOT wire:** Apple (0–2d, fully in VulnCheck), Chrome (≈ Project Zero `Date patched`, already
integrated; P0 `Date discovered` is often earlier anyway), Ivanti (scrape-walled, ~0 gain), Fortinet
(unreliable "Known Exploited" boolean), and every aggregator / national-CERT above.

## Conclusion

The honest result of "check for other sources": **the free + historical + non-redundant in-wild
label space is saturated** — no new source grows the event count, confirming the data-limited
ceiling yet again. And with the VulnCheck token in hand (2026-06-30), the best date-quality lever
(#1) was **measured to a dead-end**: VulnCheck's free catalog has no earlier date than the evidence
`date_added` we already use (197d median better than CISA), and its canary telemetry is boolean, not
dated. The only remaining levers are two tiny vendor scrapes (#2 Cisco, #3 Android) worth a few days
on ~20 CVEs/yr. The token also showed the catalog is fresh through 2026-06-29 (4,998 CVEs, +29 vs
our shipped snapshot) — but those 29 are recent-2026 CVEs outside the backtest's origin window, so a
refresh adds **0 test events** to the parity; not worth disturbing the validated 2026-06-20 artifact.

**Bottom line:** every free/historical lever for this comparison is now exhausted *and measured*.
A materially bigger win requires a fundamentally larger/earlier in-wild **modality** — prospective
sensor telemetry (GreyNoise academic, accumulated forward via the connector we built) — not another
catalog or a date-scraper.
