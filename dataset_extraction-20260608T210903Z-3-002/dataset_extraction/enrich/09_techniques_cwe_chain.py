#!/usr/bin/env python3
"""Deterministic CVE→ATT&CK technique mapping via the CWE→CAPEC→ATT&CK chain.

Uses MITRE's own published mappings end-to-end:

    CVE → CWE                 — from VulnCheck/NVD `weaknesses` field
    CWE → CAPEC               — from mitreCweReference.relatedAttackPatterns
    CAPEC → ATT&CK technique  — from mitreCapecPatternsReference.taxonomyMappings
                                ∪ mitreCapecMechanismsReference.taxonomyMappings

Every (CVE, technique) row is traceable back to a specific CAPEC pattern
recorded in the output's `capec_via` column. Failure mode is false negatives
(CVEs whose CWE has no MITRE-published CAPEC mapping), never false positives.

Output columns:
    cve_id, technique_id (e.g. "T1574.010"), capec_via, source ("cwe_chain")

Run:
    python enrich/09_techniques_cwe_chain.py \\
        --corpus out/cve_corpus.parquet \\
        --out out/technique_cwe_chain.parquet
"""
import argparse
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
import pymongo
from tqdm import tqdm

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://root:example@localhost:27017/?directConnection=true",
)
DB_NAME = os.getenv("VRS_DB_NAME", "threatAssessmentEngineData")

# CAPEC pattern strings are like '::209::588::591::' — IDs delimited by '::'.
CAPEC_RE = re.compile(r"(\d+)")
# Technique entry IDs in taxonomyMappings look like 'ENTRY ID:1574.010:'.
TECH_ENTRY_RE = re.compile(r"TAXONOMY NAME:ATTACK:ENTRY ID:([0-9.]+)")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cwe_chain")


def load_cwe_to_capec(db) -> dict[str, set[str]]:
    """{CWE id (str, no prefix): set of CAPEC ids (str, no prefix)}"""
    mapping: dict[str, set[str]] = {}
    for doc in db.mitreCweReference.find(
        {"relatedAttackPatterns": {"$ne": ""}},
        {"_id": 1, "relatedAttackPatterns": 1},
    ):
        cwe_id = str(doc["_id"])
        raw = doc.get("relatedAttackPatterns") or ""
        capecs = {m for m in CAPEC_RE.findall(raw) if m}
        if capecs:
            mapping[cwe_id] = capecs
    log.info("CWE→CAPEC: %d CWEs map to >=1 CAPEC", len(mapping))
    return mapping


def load_capec_to_techniques(db) -> dict[str, set[str]]:
    """{CAPEC id (str): set of ATT&CK technique ids with T prefix, e.g. 'T1574.010'}"""
    mapping: dict[str, set[str]] = defaultdict(set)
    for coll_name in ("mitreCapecPatternsReference", "mitreCapecMechanismsReference"):
        for doc in db[coll_name].find(
            {"taxonomyMappings": {"$regex": "ATTACK"}},
            {"_id": 1, "taxonomyMappings": 1},
        ):
            capec_id = str(doc["_id"])
            raw = doc.get("taxonomyMappings") or ""
            for tech_id in TECH_ENTRY_RE.findall(raw):
                mapping[capec_id].add(f"T{tech_id}")
    log.info("CAPEC→ATT&CK: %d CAPECs map to >=1 technique", len(mapping))
    return dict(mapping)


def load_technique_names(db) -> dict[str, str]:
    return {
        doc["_id"]: doc.get("name", "")
        for doc in db.mitreAttackTechniqueReference.find({}, {"_id": 1, "name": 1})
    }


def normalise_cwe(cwe: str) -> str | None:
    """Pull numeric id out of 'CWE-79' / 79 / 'CWE-79 ' → '79'."""
    if not cwe:
        return None
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        s = s[len("CWE-"):]
    return s if s.isdigit() else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="out/cve_corpus.parquet")
    parser.add_argument("--out", default="out/technique_cwe_chain.parquet")
    args = parser.parse_args()

    log.info("Connecting to MongoDB %s", MONGODB_URI)
    client = pymongo.MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10_000)
    db = client[DB_NAME]

    cwe_to_capec = load_cwe_to_capec(db)
    capec_to_tech = load_capec_to_techniques(db)
    tech_names = load_technique_names(db)
    client.close()

    log.info("Reading corpus %s", args.corpus)
    corpus = pd.read_parquet(args.corpus, columns=["cve_id", "cwe_ids"])
    corpus = corpus[corpus["cwe_ids"].str.len() > 0].copy()
    log.info("CVEs with at least one CWE: %d / %d",
             len(corpus), len(pd.read_parquet(args.corpus, columns=["cve_id"])))

    rows: list[dict] = []
    stats = defaultdict(int)
    for cve_id, cwe_ids in tqdm(zip(corpus["cve_id"], corpus["cwe_ids"]),
                                 total=len(corpus), unit="cve"):
        produced_for_cve: set[tuple[str, str]] = set()  # (tech, capec) pairs already emitted
        for raw_cwe in cwe_ids:
            cwe_num = normalise_cwe(raw_cwe)
            if not cwe_num:
                continue
            capecs = cwe_to_capec.get(cwe_num, set())
            if not capecs:
                stats["cwe_without_capec"] += 1
                continue
            stats["cwe_with_capec"] += 1
            for capec_id in capecs:
                techs = capec_to_tech.get(capec_id, set())
                for tech in techs:
                    key = (tech, capec_id)
                    if key in produced_for_cve:
                        continue
                    produced_for_cve.add(key)
                    rows.append({
                        "cve_id": cve_id,
                        "technique_id": tech,
                        "technique_name": tech_names.get(tech, ""),
                        "capec_via": f"CAPEC-{capec_id}",
                        "source": "cwe_chain",
                    })
        if produced_for_cve:
            stats["cve_with_at_least_one_technique"] += 1
        else:
            stats["cve_with_no_technique"] += 1

    df = pd.DataFrame(rows, columns=[
        "cve_id", "technique_id", "technique_name", "capec_via", "source",
    ])
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)

    log.info("Wrote %s rows → %s", f"{len(df):,}", out_path)
    if not df.empty:
        log.info("  unique CVEs with a technique: %s", f"{df['cve_id'].nunique():,}")
        log.info("  unique techniques: %s", df["technique_id"].nunique())
        log.info("  top 5 techniques:")
        for tech, n in df["technique_id"].value_counts().head().items():
            name = tech_names.get(tech, "")[:60]
            log.info("    %s %5d %s", tech, n, name)
    for k, v in stats.items():
        log.info("  %s: %s", k, f"{v:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
