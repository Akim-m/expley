# Temporal Exploit Prediction — Student Handover

This folder is the data pack for an open-ended research project on
predicting **when** a CVE becomes weaponized. It is raw material, not a
recipe — how you turn these parquets into a survival analysis is your
work. Read `../temporal_exploit_prediction.md` first for the framing,
glossary, and the problem space; this README is the per-file data
dictionary you'll come back to whenever you need to know what's in a
specific parquet.

You'll work entirely in Python on parquet files. You do **not** need to
stand up the rest of the CyberAI platform.

## What you have

Nine parquet files — extracted, dated, and joined ahead of time. Which
fields you extract from each, how you join them, and what modelling
dataset you build are your decisions.

| File | What it contains | Rows |
|---|---|---|
| `cve_corpus.parquet` | Base CVE table (description, CWE, CVSS, vendor/product, publication date). | ~338k |
| `kev_events.parquet` | CISA KEV with `dateAdded`. | 1.5k |
| `metasploit_dates.parquet` | First-seen date per CVE in the Metasploit Framework, derived from the earliest commit whose diff introduced the CVE reference (see "Metasploit dating quality" below). Includes `metasploit_commit_sha` and `metasploit_commit_path` for traceability. | 3.1k |
| `nuclei_dates.parquet` | First-seen date per CVE in Nuclei templates. | 4.1k |
| `poc_dates.parquet` | First-seen date per CVE in Trickest/Nomi-sec PoC repos. | 187k |
| `google_0day.parquet` | Google Project Zero "0day in the Wild" entries. | 344 |
| `epss_history.parquet` | Daily EPSS scores per CVE since 2021-04-14. | ~375M |
| `technique_cwe_chain.parquet` | Deterministic CVE→CWE→CAPEC→ATT&CK chain using MITRE-published mappings only (traceable provenance via `capec_via`). | ~778k |
| `vrs_presence.parquet` | Boolean presence flags per CVE across the six exploitation feeds. | 9k |

## Quick look

```python
import pandas as pd

corpus = pd.read_parquet("cve_corpus.parquet")
print(corpus.shape, corpus.columns.tolist())

kev = pd.read_parquet("kev_events.parquet")
print(kev.head())
print(f"{kev['cve_id'].nunique():,} CVEs in KEV")
```

The `view_parquet.py` tool one folder up is the quickest way to browse:

```bash
python view_parquet.py --list
python view_parquet.py cve_corpus --head 5
python view_parquet.py epss_history --cve CVE-2021-44228   # predicate pushdown
```

## Three dataset facts that affect any analysis

These aren't prescriptive — they're properties of the data you need to
know to use it responsibly.

1. **Right-censoring is informative**, not random. CVEs without any
   dated weaponization signal in these parquets are not "never
   exploited" — they're "no public signal observed in any of these
   feeds by your snapshot date." Standard survival models assume
   non-informative censoring; if you build on that assumption, the
   write-up has to acknowledge it.

2. **Temporal leakage is the easiest way to invalidate results.** The
   presence flags (`in_metasploit`, etc.) and any EPSS score read at
   snapshot time are observed *after* most events in your dataset. Used
   naively as predictors they leak future information into past
   predictions. The safe predictors are the ones knowable at publication:
   CVSS, CWE, CPE-derived vendors/products, ATT&CK techniques (from the
   MITRE chain), the first EPSS reading after publication. The
   `description` text needs its own caveat — see the gotcha section in
   `../temporal_exploit_prediction.md`.

3. **Train/test splits must be time-based, not random.** Vulnerability
   data has strong dataset-wide trends over time; random K-fold leaks
   those trends and inflates metrics. Train on CVEs published before a
   cutoff date, test on later CVEs.

## Metasploit dating quality (read before treating MSF dates as ground truth)

Metasploit does **not** record a "MSF added support for CVE X on date Y" field
anywhere. `metasploit_first_seen` in `metasploit_dates.parquet` is *inferred*
from git history: for each (CVE, module file) pair in MSF's manifest
(`db/modules_metadata_base.json`), we take the earliest commit whose diff
introduced the CVE reference into that file, via `git log -G` regex search
scoped to the manifest-declared module path.

### Why this proxy and not a simpler one

An earlier version of this pipeline used the *file's first-commit date* as
the proxy. We discarded it after measuring its bias on this corpus:

| Comparison | Result | Interpretation |
|---|---|---|
| CVEs where file-first-commit = diff-introduced | 69.5% | Module born for one CVE, committed in one go |
| CVEs where the file existed *before* the CVE reference was added | 30.4% (946) | The file-first-commit proxy would credit MSF with weaponizing the CVE years before the reference was actually added |
| Median delta between the two | 0 days | Most cases agree |
| Mean delta over the disagreeing 30% | hundreds-to-thousands of days | Bias always shortens apparent time-to-exploit |
| Maximum delta observed | ~6,850 days (~18 years) | Pre-2010 CVEs added to MSF only recently |

For a survival model whose labels *are* these timestamps, a 30% downward
bias matters. The diff-introduced proxy we use here is correct in those
cases and recovers ~99.8% of the CVEs in MSF's manifest (3,107 of 3,114).
The 7 missing CVEs are ones whose introducing commit was squashed in MSF's
pre-git SVN history or whose source encoding our regex doesn't match.

### What this means for your research

1. **MSF dates are "capability availability", not "in-the-wild exploitation".**
   They tell you when public weaponization was published to a popular OSS
   framework. A CVE can be exploited in the wild long before MSF carries a
   module; KEV `dateAdded` is closer to a true "exploitation observed"
   signal. Frame your modelling and writeup accordingly.

2. **Other dating sources have analogous limitations.** Nuclei and PoC
   dates are derived from filename-based git mining and measure
   "publication to the upstream repo," not "first exploitation." The same
   "capability availability" framing applies — they are weaker than KEV /
   zeroday signals for in-wild claims.

## ATT&CK techniques — deterministic chain, with honest absence

There is no public dataset of (CVE → ATT&CK technique) ground-truth labels at
scale. We use MITRE's own published mappings end-to-end:

    CVE.weaknesses → CWE IDs                        # from VulnCheck/NVD
    mitreCweReference.relatedAttackPatterns         # CWE → CAPEC, per MITRE
    mitreCapecPatternsReference.taxonomyMappings    # CAPEC → ATT&CK, per MITRE

Every (CVE, technique) row is traceable back to a specific CAPEC pattern
(stored in `technique_cwe_chain.parquet`'s `capec_via` column).

- **Coverage**: ~25% of CVEs (84,865 in this dataset). The gap is CVEs whose
  CWE has no MITRE-published CAPEC mapping, or whose CAPEC has no published
  ATT&CK mapping. We **deliberately don't fill the gap with heuristics** —
  honest absence is better than fabricated data.
- **Failure mode**: false negatives (missing techniques), never false
  positives. A row in `attack_techniques` is something MITRE has explicitly
  associated through the published chain.
- **Top techniques** in this dataset look domain-plausible: T1574.007/006
  (path / linker hijacking), T1562.003 (impair logging), T1082 (system info
  discovery), T1027 (obfuscated files).

### Suggestions for use

- **Per-tactic aggregation often beats per-technique.** Map each technique to
  its parent tactic (e.g. T1027.* → Defense Evasion) and use tactic-level
  one-hot features. Coverage stays the same but feature dimensionality drops
  and the noise from rare sub-techniques disappears.
- **The ~75% of CVEs with no `attack_techniques`** are not "no technique" —
  they're "no MITRE-published mapping." Treat this as a feature
  (`has_attack_chain_mapping` boolean) rather than implying absence of
  exploitation strategy.
- **Provenance is preserved**: `technique_cwe_chain.parquet` has `capec_via`
  per row, so you can drill back to the exact MITRE mapping underlying any
  technique assignment if a reviewer challenges it.

## Reading order

1. `../temporal_exploit_prediction.md` — framing, glossary, and the
   research directions the dataset supports.
2. This README — per-parquet data dictionary, plus the deeper sections
   below on MSF dating and the ATT&CK chain.
3. Jacobs et al. 2021 (EPSS paper) — the system this work complements.
4. Suciu et al. USENIX Security 2022 — "Expected Exploitability" — the
   closest methodological precedent.
5. [lifelines](https://lifelines.readthedocs.io/) and
   [scikit-survival](https://scikit-survival.readthedocs.io/) docs — the
   immediate Python toolkit.
6. [pycox](https://github.com/havakv/pycox) docs for DeepSurv / DeepHit
   if you go deep.