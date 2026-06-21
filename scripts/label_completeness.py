"""Label-completeness / false-censoring estimate.

The in-wild model treats every CVE with no catalog entry as right-censored
("never exploited"). If a CVE WAS exploited but isn't in any catalog, that's a
false negative that biases the model. This quantifies the magnitude using EPSS
(FIRST's calibrated P(exploited in 30 days)) as a semi-independent oracle: among
UNLABELED CVEs, how much exploitation mass does EPSS see that our catalogs miss?

Uses the SNAPSHOT EPSS (latest reading per CVE) — the current exploitation
likelihood, not the stale publication-time value. Read-only.
Run: .venv/bin/python -u scripts/label_completeness.py
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.labels import IN_WILD_SOURCES
from temporal_exploit.loaders import load_parquet

OUT, ART = Path("data/merged"), Path("artifacts/merged")


def cve_set(source):
    nm, c = EVENT_SOURCES[source]
    fr = load_optional_event(OUT, nm, c)
    return set(fr["cve_id"]) if fr is not None else set()


def main() -> None:
    corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
    epss = pd.read_parquet("/tmp/epss_snapshot.parquet")  # latest reading per CVE
    inwild = set().union(*[cve_set(s) for s in IN_WILD_SOURCES])
    poc, msf, nuc = cve_set("poc"), cve_set("metasploit"), cve_set("nuclei")
    anysig = poc | msf | nuc | inwild
    N = len(corpus)

    print(f"=== weaponization funnel (N={N} CVEs) ===")
    print(f"  any signal (PoC/MSF/Nuclei/in-wild): {len(anysig):>7} ({100*len(anysig)/N:.1f}%)")
    print(f"  public PoC:                          {len(poc):>7} ({100*len(poc)/N:.1f}%)")
    print(f"  Metasploit module:                   {len(msf):>7}")
    print(f"  Nuclei template:                     {len(nuc):>7}")
    print(f"  in-wild labeled (KEV/VC/0day/MSRC):  {len(inwild):>7} ({100*len(inwild)/N:.2f}%)")

    m = corpus.merge(epss, on="cve_id", how="left")
    m["epss"] = m["epss"].fillna(0.0)
    m["inwild"] = m["cve_id"].isin(inwild)
    m["has_poc"] = m["cve_id"].isin(poc)
    e_lab = m.loc[m.inwild, "epss"]
    e_unl = m.loc[~m.inwild, "epss"]
    cov = float((m["epss"] > 0).mean())

    print(f"\n=== EPSS as exploitation oracle (snapshot 2026-03-14; EPSS coverage {100*cov:.0f}%) ===")
    print(f"  median EPSS  labeled={e_lab.median():.4f}  unlabeled={e_unl.median():.5f}")
    print("  count of CVEs above EPSS threshold (labeled vs UNLABELED):")
    out = {"funnel": {"N": N, "any_signal": len(anysig), "poc": len(poc),
                      "inwild": len(inwild), "inwild_rate": len(inwild) / N}, "epss_thresholds": {}}
    for thr in (0.1, 0.3, 0.5, 0.7, 0.9):
        n_lab = int((e_lab >= thr).sum())
        n_unl = int((e_unl >= thr).sum())
        out["epss_thresholds"][thr] = {"labeled": n_lab, "unlabeled": n_unl}
        print(f"    EPSS>={thr}:  labeled={n_lab:>5}   UNLABELED={n_unl:>6}  <- candidate missed-exploited")

    # calibrated expectation: sum(EPSS) ~= expected # exploited in a 30-day window
    exp_unl = float(e_unl.sum())
    exp_lab = float(e_lab.sum())
    out["expected_exploited_30d"] = {"labeled": exp_lab, "unlabeled": exp_unl}
    print(f"\n  sum(EPSS) = expected exploited in a 30d window:")
    print(f"    over labeled   = {exp_lab:>8.0f}")
    print(f"    over UNLABELED = {exp_unl:>8.0f}  <- expected currently-exploited CVEs with NO catalog entry")

    # PoC-present but never reached an in-wild catalog
    poc_only = m[m.has_poc & ~m.inwild]
    hi = int((poc_only["epss"] >= 0.5).sum())
    out["poc_not_inwild"] = {"n": len(poc_only), "frac_of_poc": len(poc_only) / max(len(poc), 1),
                             "high_epss_ge_0.5": hi}
    print(f"\n=== PoC-present but NO in-wild label ===")
    print(f"  {len(poc_only)} CVEs ({100*len(poc_only)/len(poc):.0f}% of PoC'd CVEs) have a public PoC but no in-wild catalog entry")
    print(f"  of those, {hi} have EPSS>=0.5 (high-confidence likely-exploited but uncataloged)")

    (ART / "label_completeness.json").write_text(json.dumps(out, indent=2, default=str))
    print(f"\nwrote {ART/'label_completeness.json'}")


if __name__ == "__main__":
    main()
