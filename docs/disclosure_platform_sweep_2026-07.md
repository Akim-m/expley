# Disclosure/exploit-platform sweep — can any add in-wild labels?

*2026-07-04. Follows the HackerOne check (`docs/hackerone_epss_reconciliation_2026-07.md`) and the
in-wild label-source sweep (`docs/inwild_label_source_sweep_2026-06.md`). Empirically verified 7
platforms "like HackerOne" (4 parallel research agents, live requests). **Question that decides
value:** does it add IN-THE-WILD exploitation labels (the ~396-event ceiling), or is it
coordinated-disclosure/advisory already covered?*

## Verdict table

| Platform | Accessible | Signal | CVE-mapped volume | Adds in-wild labels? | Verdict |
|---|---|---|---|---|---|
| **GitHub Security Advisories** | Y (REST 60/hr unauth; GraphQL 5k/hr authed) | advisory/disclosure | ~23–26k CVEs | **No** (only exploit field is `epss`) | reject-redundant |
| **Zero Day Initiative (ZDI)** | Y (RSS + per-year HTML, no auth) | coordinated-disclosure | ~15–20k, ~93% mapped | **No** | complement-only (niche covariate) |
| **Bugcrowd CrowdStream** | Y (open JSON API, no auth) | coordinated-disclosure | **~34** CVE-tagged / 766 | **No** | reject-redundant |
| **Open Bug Bounty** | **No** (Cloudflare wall) | domain-instance XSS | ~0 (host-keyed, not CVE) | **No** | hard reject |
| **Intigriti** | **No** (no public feed) | — | 0 | **No** | reject |
| **YesWeHack** | Partial (PAT, own programs) | coordinated-disclosure | auth-gated | **No** | reject-redundant |
| **Patchstack** | Free DB yes; **flag = paid API** | ecosystem-advisory + `is_exploited` | ~49k, partial CVE | **Yes — qualified** | **complement-only ★** |

## The one genuine lever: Patchstack `is_exploited`

Patchstack's paid Threat-Intel API (`GET patchstack.com/database/api/v2/all`, header `PSKey`; free
public DB does **not** expose the flag) carries a per-advisory **`is_exploited` boolean** — a real
in-the-wild observation — alongside `cve`, `disclosed_at`, `cvss`. Why it matters: **WordPress
plugin/theme/npm CVEs are almost entirely absent from CISA KEV**, so `is_exploited=true` is in-wild
evidence in a domain the project's ceiling does *not* cover. This is the only sweep candidate that
could add **net-new** in-wild labels.

**Caveats (why it's "complement-only", not "adopt"):** (a) paywalled — no free tier, live
`/api/v2/all` → 401; (b) WordPress/npm ecosystem only; (c) volume of `is_exploited=true` unverified
without a key; (d) **scope question** — how many WordPress-plugin CVEs are even in the project's
general corpus, and is that ecosystem in the dissertation's scope? Recommend: flag to supervisor as
a *future* lever; quantify net-new only if a key is obtained and WP-ecosystem is in scope.

## Minor note: ZDI reported-to-vendor date
ZDI advisories expose a **reported-to-vendor date** ~2–4 months before public disclosure — a
publication-safe *covariate* (bug-latency / researcher-attention) for the ZDI-tracked subset, but a
private responsible-disclosure event, **not** a weaponization label. Historical backfill needs
~15–20k per-advisory page fetches. Low priority.

## Conclusion
Consistent with the saturated in-wild sweep: **six of seven disclosure platforms add 0 in-wild
labels** — they are coordinated-disclosure/advisory, redundant with the existing 187k-PoC / NVD
layer. The ceiling stands. The only crack is **Patchstack's paid `is_exploited`** for the WordPress
ecosystem. The next real in-wild win remains a known-exploited/telemetry source (VulnCheck already
wired; GreyNoise prospective), not another bug-bounty/disclosure platform.
