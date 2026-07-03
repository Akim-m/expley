"""Full scrape of HackerOne's ranked_cve_entries table (~363k CVEs) — rate-limit-safe.

The `cve_discovery` table is served by GraphQL `ranked_cve_entries` (unauthenticated).
Page size is hard-capped at 100; pagination is search_after cursor (`{"rank","id"}`),
so it goes deep past the ES 10k offset wall. HackerOne's limiter (measured 2026-07-04):
~1 req/1.5-2s is safe; bursting trips a 429 with Retry-After:120. Strategy = stay under
the refill rate (never trip) + honor Retry-After + CHECKPOINT the cursor so any stop
resumes exactly with no re-fetch and no gaps.

Per-CVE fields kept (compact, meaningful): identity, report volume, severity mix,
CVSS/CWE/EPSS, publication, remediation-SLA buckets, recent-activity summary. The 48
rolling submission_*_weeks_ago date fields are skipped (rolling window, low value).

Output (append-only, resumable):
  artifacts/hackerone_cve_table.jsonl   — one CVE per line
  artifacts/hackerone_cve_table.state   — {"cursor","pages","rows"} checkpoint

Run (resumes automatically if state exists):
  .venv/bin/python scripts/hackerone_cve_table_scrape.py
"""
from __future__ import annotations
import json, sys, time, urllib.request, urllib.error
from pathlib import Path

URL = "https://hackerone.com/graphql"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
OUT = Path("artifacts/hackerone_cve_table.jsonl")
STATE = Path("artifacts/hackerone_cve_table.state")

BASE_DELAY = 2.0        # sustained pace, comfortably under the limiter's refill
MAX_DELAY = 6.0         # adaptive ceiling after repeated 429s
PAGE = 100              # hard server cap
SAFETY_MAX_PAGES = 4200 # 363k/100 ≈ 3631; headroom, not infinite

FIELDS = """cve_id rank score reports_submitted_count
  severity_count_critical severity_count_high severity_count_medium
  severity_count_low severity_count_none severity_count_unknown
  cvss_score cvss_rating cwe_id cwe_name epss
  cve_published_date cve_age_in_days affected_products_count
  remediation_time_24_hours remediation_time_48_hours remediation_time_72_hours
  remediation_time_1_week remediation_time_1_month remediation_time_1_quarter
  remediation_time_1_year remediation_time_1_year_plus remediation_time_pending
  submission_count_trailing_12_weeks submission_count_trailing_12_to_24_weeks
  submission_pct_delta_trailing_12_weeks"""
QUERY = ("query($first:Int!,$after:String){ranked_cve_entries(first:$first,after:$after){"
         "pageInfo{hasNextPage endCursor} edges{node{" + FIELDS + "}}}}")


def _post(variables, delay):
    """One request with adaptive politeness. Returns (data|None, new_delay)."""
    time.sleep(delay)
    req = urllib.request.Request(
        URL, data=json.dumps({"query": QUERY, "variables": variables}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.loads(r.read().decode()), delay
    except urllib.error.HTTPError as e:
        if e.code in (429, 503):
            wait = int(e.headers.get("Retry-After", "120")) + 2
            new_delay = min(MAX_DELAY, delay + 0.5)   # permanently ease off after a trip
            print(f"  [429] Retry-After {wait}s; easing base delay -> {new_delay}s", file=sys.stderr, flush=True)
            time.sleep(wait)
            return None, new_delay                    # signal caller to retry same cursor
        raise


def main():
    cursor, pages, rows = None, 0, 0
    if STATE.exists():                                # resume
        st = json.loads(STATE.read_text())
        cursor, pages, rows = st.get("cursor"), st.get("pages", 0), st.get("rows", 0)
        print(f"RESUME from page {pages}, {rows} rows, cursor={cursor!r}", flush=True)
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text("")                            # fresh start

    delay = BASE_DELAY
    with OUT.open("a") as fh:
        while pages < SAFETY_MAX_PAGES:
            data, delay = _post({"first": PAGE, "after": cursor}, delay)
            if data is None:                          # got 429; retry same cursor
                continue
            if "errors" in data:
                print("GraphQL error:", json.dumps(data["errors"])[:300], flush=True)
                break
            conn = data["data"]["ranked_cve_entries"]
            for e in conn["edges"]:
                fh.write(json.dumps(e["node"]) + "\n")
            rows += len(conn["edges"]); pages += 1
            cursor = conn["pageInfo"]["endCursor"]
            fh.flush()
            STATE.write_text(json.dumps({"cursor": cursor, "pages": pages, "rows": rows}))
            if pages % 25 == 0:
                print(f"page {pages} rows {rows} delay {delay}s", flush=True)
            if not conn["pageInfo"]["hasNextPage"]:
                print(f"DONE — {rows} rows over {pages} pages", flush=True)
                break
    print(f"stopped at page {pages}, {rows} rows (state saved for resume)", flush=True)


if __name__ == "__main__":
    main()
