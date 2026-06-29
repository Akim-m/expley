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

1. **VulnCheck evidence-URL canonical-date back-fill (highest leverage, no new source).** Our
   `fetch/vulncheck.py::_best_date` reads `vulncheck_reported_exploitation[].date_added` but
   **discards the sibling `.url`**. Those `date_added` values are VulnCheck's *ingest* dates; the
   URLs point at original advisories whose *publish* dates can be earlier. Capture the `url`, fetch
   each one's canonical publish date, take `min(...)`. Tightens onset dates on the **existing**
   events using data already in the response — no new dependency. **Caveat:** the payoff is
   **unmeasured and likely bounded** (VulnCheck is already 27d ahead of CISA and evidence-dated, so
   most of the parity's +107d median lag is genuine detection lag, not ingest lag). Needs the
   VulnCheck token to re-fetch the raw catalog (not in this env) + a fragile URL→publish-date scraper.
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
ceiling yet again. The remaining levers refine *date quality* on existing events and are bounded to
a few days on ~20 CVEs/yr; #1 is the best of them but needs the token + a scraper and has unmeasured,
likely-small payoff. **Recommendation: do not build speculative scrapers; the count-ceiling is
confirmed.** A materially bigger win still requires a fundamentally larger/earlier in-wild *modality*
(prospective sensor telemetry — GreyNoise academic, accumulated forward), not another catalog.
