# Chapter 3 writing scaffold — Data & label sources

*2026-07-04. Writing scaffold (plan + verified numbers), not prose. Sources:
`docs/modeling_methodology.md` §11, `docs/label_completeness_2026-06.md`,
`docs/inwild_label_source_sweep_2026-06.md`, `docs/disclosure_platform_sweep_2026-07.md`,
`docs/hackerone_epss_reconciliation_2026-07.md`. Re-read before final.*

**Chapter thesis:** the modelling rests on nine pre-extracted, all-public sources joined on the CVE
corpus; the event labels are dominated by public-PoC dates, and the in-the-wild signal is scarce
(~396 events) — a scarcity this chapter documents as the project's binding constraint, having
*measured* (not assumed) that no free source relieves it.

### 3.1 The nine handover sources
- Corpus 338k CVEs; PoC 187k dates; Metasploit ~3.1k; Nuclei ~4.1k; CISA KEV ~1.5k; Google 0-day
  ~340; EPSS history ~375M daily rows to Mar 2026; technique/CWE chain (~25% of CVEs); vrs_presence.
- Table: source → row count → date column → role (event vs feature vs context). All public → no
  data-acquisition risk (plan slide 5).

### 3.2 Label construction & composition
- `published` is the clock origin; event = earliest dated signal across five sources; else
  right-censored at snapshot. Negative durations flagged + preserved (not dropped).
- **Composition (snapshot 2026-03-14):** ~97% of events are public-PoC dates; KEV + Google 0-day are
  the only true in-the-wild signals (~664 combined, ~396 usable after negative-duration drop).
  → the honest target is *public exploitation capability*, not in-the-wild attack (state this here).

### 3.3 The in-the-wild scarcity and the label-source search (this session's contribution)
- Frame the ceiling: ~396 in-wild events; discrimination/calibration are data-limited, not
  model-limited (forward-ref Ch6 negative result).
- **Measured, not assumed, saturation.** The in-wild label space was swept and is saturated
  (`inwild_label_source_sweep_2026-06.md`): VulnCheck-KEV wired (~+1.7k, the one real gain);
  GreyNoise prospective-only (no history); Shadowserver region-locked; MSRC negligible; every
  aggregator re-packages CISA KEV + VulnCheck.
- **Disclosure-platform sweep (`disclosure_platform_sweep_2026-07.md`).** Seven platforms "like
  HackerOne" verified empirically — GHSA, ZDI, Bugcrowd, Open Bug Bounty, Intigriti, YesWeHack,
  Patchstack. **All coordinated-disclosure/advisory class → 0 new in-wild labels**, EXCEPT
  Patchstack's paid `is_exploited` flag (WordPress/npm ecosystem, ~absent from KEV — a scoped future
  lever). HackerOne specifically: 1,725 CVE-tagged reports, 68 KEV overlap, 0 net-new — but a real
  EPSS blind-spot lens (→ Ch7).
- Methodological point worth making: *the value of a source is set by its signal class (in-wild vs
  disclosure) and its historical/CVE-mapped structure, not by whether it is fetchable* — several
  fetchable sources add nothing.

### 3.4 Leakage-relevant data properties
- tz-aware UTC dates; list columns as ndarray; real column names verified; NVD back-edits the
  description post-event (temporal leakage) → text masked (`text_safety`). Forward-ref Ch4 controls.

**Tables:** nine-source inventory; label composition by event source; label-source verdict table
(from the two sweep docs). **Figures:** `fig_label_funnel.png` (§3.2).
