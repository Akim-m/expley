#!/usr/bin/env bash
#
# Run the full extract → enrich pipeline that produces the nine handover
# parquets under out/. Override paths with env vars:
#
#   PY=.venv/bin/python OUT_DIR=out2 ./run_pipeline.sh
#
# Why this script exists rather than the README's per-command list:
#
#   - `set -eo pipefail` so a failing stage actually stops the pipeline. A
#     naive `python step.py 2>&1 | tee log` masks the python exit code (tee
#     always returns 0), which is exactly how an earlier run produced an
#     incomplete output by silently swallowing a stage failure.
#   - PIPESTATUS[0] is also checked explicitly as a belt-and-braces guard
#     against any future change that drops pipefail.
#   - Per-stage timing in the log so re-runs let you see what got faster
#     after upstream cache warmups (Metasploit clone in particular).
#
set -eo pipefail

cd "$(dirname "$0")"

PY="${PY:-.venv/bin/python}"
OUT_DIR="${OUT_DIR:-out}"
LOG_DIR="${LOG_DIR:-logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/pipeline.log}"

mkdir -p "$OUT_DIR" "$LOG_DIR"

run() {
    local label="$1"; shift
    printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$label" | tee -a "$LOG_FILE"
    # pipefail makes this propagate the python exit code; PIPESTATUS check
    # is the belt+braces guard in case pipefail is ever turned off.
    "$@" 2>&1 | tee -a "$LOG_FILE"
    local rc="${PIPESTATUS[0]}"
    if [[ "$rc" -ne 0 ]]; then
        printf '[%s] FAILED: %s (exit %d)\n' "$(date '+%H:%M:%S')" "$label" "$rc" \
            | tee -a "$LOG_FILE" >&2
        exit "$rc"
    fi
}

printf '[%s] === START pipeline (out=%s) ===\n' \
    "$(date '+%H:%M:%S')" "$OUT_DIR" | tee -a "$LOG_FILE"

# --- Stage 1: extract from VRS MongoDB ---
run "01_cve_corpus"            $PY extract/01_cve_corpus.py            --out "$OUT_DIR/cve_corpus.parquet"
run "02_kev_events"            $PY extract/02_kev_events.py            --out "$OUT_DIR/kev_events.parquet"
run "03_vrs_presence_flags"    $PY extract/03_vrs_presence_flags.py    --out "$OUT_DIR/vrs_presence.parquet"

# --- Stage 2: enrich with external timestamps ---
run "07_google_0day"           $PY enrich/07_google_0day.py            --out "$OUT_DIR/google_0day.parquet"
run "09_techniques_cwe_chain"  $PY enrich/09_techniques_cwe_chain.py   --corpus "$OUT_DIR/cve_corpus.parquet" --out "$OUT_DIR/technique_cwe_chain.parquet"
run "05_nuclei_dates"          $PY enrich/05_nuclei_dates.py           --out "$OUT_DIR/nuclei_dates.parquet"
run "06_poc_dates"             $PY enrich/06_poc_dates.py              --out "$OUT_DIR/poc_dates.parquet"
run "08_epss_history"          $PY enrich/08_epss_history.py --concat-only --out "$OUT_DIR/epss_history.parquet"
run "04_metasploit_dates"      $PY enrich/04_metasploit_dates.py       --out "$OUT_DIR/metasploit_dates.parquet" --checkpoint "$OUT_DIR/.metasploit_checkpoint.json"

printf '[%s] === DONE pipeline ===\n' "$(date '+%H:%M:%S')" | tee -a "$LOG_FILE"
