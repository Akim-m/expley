# Dataset Extraction — Temporal Exploit Prediction

This toolkit produces the nine handover parquets described in
`./temporal_exploit_prediction.md`. It is meant to be run **once**, by the
project owner, to produce a handover pack that an MSc student can use
without spinning up the rest of the CyberAI stack.

## Why this exists

The VRS MongoDB snapshot we work from contains four exploitation-signal feeds
(Metasploit, Nuclei, VulnCheck KEV, Google 0-day) as *presence-only*
collections — CVE IDs with no timestamps. Only CISA KEV `dateAdded` is a true
event-time label. VRS architecturally supports Trickest and Nomi-sec PoC feeds
too (controllers, schedulers and Mongo models are all present), but the dev
Spring profile this dump was taken from disables those schedulers
(`schedule.startup=false`, `schedule.cron.{trickest,nomisec}=-`), so those
collections are empty in our archive. We pick those feeds up separately via
`enrich/06_poc_dates.py`, which clones the upstream PoC repos and mines
first-commit dates per CVE — richer than the presence flags VRS would produce
anyway. To answer "when will a CVE be exploited?" we need event timestamps
from each source, which is what the `enrich/` scripts mine from the GitHub
repositories' commit histories and from FIRST.org's EPSS daily archive.

## Layout

```
dataset_extraction/
├── extract/                      # pulls flat tables out of VRS MongoDB (fast)
│   ├── 01_cve_corpus.py
│   ├── 02_kev_events.py
│   └── 03_vrs_presence_flags.py
├── enrich/                       # mines external timestamps (slow, network)
│   ├── 04_metasploit_dates.py
│   ├── 05_nuclei_dates.py
│   ├── 06_poc_dates.py
│   ├── 07_google_0day.py
│   ├── 08_epss_history.py
│   ├── 09_techniques_cwe_chain.py
│   └── _git_helpers.py
├── handover/
│   └── README.md                 # student-facing data dictionary
├── out/                          # all parquet outputs land here
├── view_parquet.py               # CLI inspector for any parquet under out/
├── compare_outputs.py            # diff two output dirs (reproducibility check)
├── run_pipeline.sh               # end-to-end driver (set -eo pipefail, per-stage logging)
└── requirements.txt
```

## Handover pack scope — what the student gets

The pipeline produces nine parquet files under `out/` — all of them ship
to the student as raw material for their survival analysis. The data
engineering behind them (git mining of Metasploit, downloading 1,787 days
of EPSS, the MITRE CWE→CAPEC→ATT&CK chain) is what they don't have to
redo. What survival labels to construct, which fields to extract from
each parquet, and how to join them is the student's research work.

When zipping the handover pack: ship the nine parquets plus
`handover/README.md` and (one level up) `temporal_exploit_prediction.md`.
Leave `extract/`, `enrich/`, and the cache directories out.

## A note on corporate AV

The Metasploit Framework repository ships **real exploit payloads** under
`data/` — SQL Server CLR injection DLLs, Windows AV-evasion samples, compiled
CVE exploit artefacts, plus the EICAR antivirus test file. Any commercial AV
will quarantine these on sight, and rightfully so: they are malware artefacts,
just held by a legitimate offensive-security project.

Our git-mining is designed to be AV-safe: every clone uses `--no-checkout`,
which keeps blobs inside `.git/objects/pack/*.pack` (compressed, opaque to AV
scanners) and never extracts them to the working tree. We read the manifest
and any other needed files via `git show HEAD:<path>`, which streams content
from the object store without touching disk.

If you re-clone Metasploit *without* `--no-checkout` (e.g. by running
`git checkout` inside `.cache/metasploit-framework`), you will trip your
corporate AV. **Don't do that.** If you need to inspect a specific file's
contents, use `git show HEAD:<path>` instead of checking it out.

## Prerequisites

1. **MongoDB** populated from the VRS dump:
   ```bash
   cd ..
   docker compose up -d mongodb
   ./scripts/ci/vrs_data.sh local-restore
   ```
2. **Python 3.12+**, virtualenv created with `requirements.txt`:
   ```bash
   python3 -m venv venv && source venv/bin/activate
   pip install -r requirements.txt
   ```
3. **Disk**: ~5 GB free for the cloned upstream repos and EPSS daily archive.
4. **Network**: required during `enrich/04..08` (clones GitHub repos and
   downloads ~1500 daily EPSS files).
5. **GitHub PAT** (recommended): create `dataset_extraction/.env` (see
   `.env.example`) with `GITHUB_TOKEN=ghp_…` so the git-mining scripts avoid
   anonymous rate limits, especially on `nomi-sec/PoC-in-GitHub` (tens of
   thousands of files). A classic PAT with `public_repo` scope, or a
   fine-grained PAT with "Public repositories: read-only", is sufficient.
   The file is loaded automatically by `enrich/_git_helpers.py`; no `source`
   step is needed.

## End-to-end run order

Each script is idempotent. Outputs land under `out/`. Long-running scripts
checkpoint to `.cache/` so reruns resume.

The simplest way to run the whole pipeline:

```bash
./run_pipeline.sh                # defaults: out/
OUT_DIR=out2 ./run_pipeline.sh   # route to a fresh dir
```

The wrapper runs every stage with `set -eo pipefail` plus an explicit
`PIPESTATUS` check, so a failing stage actually stops the pipeline — a naive
`python step.py 2>&1 | tee log` chain masks the python exit code (tee always
returns 0). Per-stage timing goes to `logs/pipeline.log`.

To re-run individual stages:

```bash
# --- Stage 1: extract from VRS MongoDB (minutes) ---
python extract/01_cve_corpus.py
python extract/02_kev_events.py
python extract/03_vrs_presence_flags.py

# --- Stage 2: enrich with external timestamps (hours, mostly cloning) ---
python enrich/04_metasploit_dates.py     # ~15 min: auto-clones + per-CVE pickaxe (resumable; pass --skip-clone to reuse the existing clone)
python enrich/05_nuclei_dates.py         # ~10 min
python enrich/06_poc_dates.py            # ~30 min: two PoC repos
python enrich/07_google_0day.py          # seconds: VRS already ships the CSV
python enrich/08_epss_history.py \
    --start 2021-04-14 --end 2025-01-01  # ~2 hrs first run, resumes if killed
python enrich/09_techniques_cwe_chain.py    # ~5 s — deterministic MITRE chain
```

The nine resulting parquets in `out/` plus the docs in `handover/` are
what the student receives.

## Reproducibility check

To verify a re-run produces the same outputs, route them to a fresh
directory and diff:

```bash
OUT_DIR=out2 ./run_pipeline.sh
python compare_outputs.py --a out --b out2
```

The Mongo-sourced parquets (`cve_corpus`, `kev_events`, `vrs_presence`,
`technique_cwe_chain`, `google_0day`) and the EPSS concat are deterministic and
should be byte-identical. The three git-mined parquets (`metasploit_dates`,
`nuclei_dates`, `poc_dates`) drift in proportion to upstream activity — new
CVEs/templates/PoCs committed since the previous run will appear as additional
rows. That's expected, not a pipeline bug.

## Inspecting parquets

A small CLI (`view_parquet.py`) is included for quick inspection of any of the
output files without writing pandas one-liners:

```bash
python view_parquet.py                       # list all parquets with sizes
python view_parquet.py cve_corpus            # schema + head(5)
python view_parquet.py kev_events --head 20 --stats
python view_parquet.py cve_corpus --cve CVE-2021-44228
python view_parquet.py epss_history --schema-only      # safe on 3.7 GB file
python view_parquet.py epss_history --cve CVE-2021-44228   # predicate pushdown
```

The CVE filter uses pyarrow predicate pushdown so it's safe on the EPSS
history (375M rows) — only matching rows are deserialised.

## Caveats and honest gotchas

- **Negative durations**. A handful of CVEs have an exploitation timestamp
  *before* the recorded publication date (PoC published pre-disclosure, KEV
  catalog backdating, etc.). The join script flags these via
  `duration_days < 0`; decide with the student whether to drop or floor at 0.
- **Snapshot date matters**. Censoring is right-aligned to `--snapshot`. EPSS
  history must cover up to that date or the at-snapshot EPSS columns will be
  null for recent CVEs. Default snapshot is the latest observed event date.
- **Metasploit dating is inferred from git history.** Metasploit records no
  native "MSF added support for this CVE on date X" field. `enrich/04_metasploit_dates.py`
  uses the earliest commit whose diff introduced the CVE reference into the
  manifest-declared module file (path-scoped `git log -G`). An earlier naive
  proxy — first commit of the module file itself — was discarded after we
  showed it over-credited MSF's response speed for ~30% of CVEs whose module
  pre-existed and was later extended to reference them.
- **EPSS coverage starts 2021-04-14**. CVEs published earlier have
  `epss_at_publication = NaN`; the student should treat that as a known
  missing-value pattern, not a bug.
- **The PoC repos are big**. `nomi-sec/PoC-in-GitHub` is several GB. Use the
  `--cache .cache/` flag to keep clones outside the project directory if disk
  space is tight.

## Re-running selectively

```bash
# Refresh only KEV after a new VRS snapshot:
python extract/02_kev_events.py

# Extend EPSS history to a later date (skips already-cached daily files):
python enrich/08_epss_history.py --start 2025-01-01 --end 2025-05-01
```
