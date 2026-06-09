#!/usr/bin/env python3
"""Mine first-seen dates per CVE in the Metasploit Framework.

For each (CVE, module file) pair in MSF's manifest (db/modules_metadata_base.json),
find the earliest commit whose diff *introduced* the CVE reference in that file
via `git log -G<regex> -- <path>`. The minimum across all module files
referencing a CVE is that CVE's "first weaponized by MSF" timestamp.

Why this proxy rather than the module file's first-commit date: many MSF
modules pre-existed for one CVE and were later extended to reference additional
CVEs. The file's creation date would credit MSF with weaponizing the new CVE
years before the reference was actually added — biasing apparent response time
downward for ~30% of MSF-covered CVEs.

Why not `git log -S` (pickaxe by count): it's repo-wide and slow (17s per CVE),
and noisily returns manifest-regeneration commits that shouldn't count. `-G`
regex against the manifest-declared module path is fast (~1 s) and accurate.

Output: parquet with (cve_id, metasploit_first_seen, metasploit_commit_sha,
metasploit_commit_path).

Performance: ~1 s per (CVE, file) × ~3,500 pairs sequentially → ~1 hour. The
script runs queries in parallel (default 8 workers) and checkpoints results to
a JSON file, so reruns resume.

Run:
    python enrich/04_metasploit_dates.py \\
        --repo .cache/metasploit-framework \\
        --out out/metasploit_dates.parquet
    python enrich/04_metasploit_dates.py --limit 20   # quick validation
"""
import argparse
import json
import logging
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent))
from _git_helpers import file_content_at_head, shallow_clone

REPO_URL = "https://github.com/rapid7/metasploit-framework.git"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("metasploit")


def cves_from_module(module: dict) -> set[str]:
    out: set[str] = set()
    for ref in module.get("references", []) or []:
        if isinstance(ref, str) and ref.upper().startswith("CVE-"):
            out.add(ref.upper())
        elif isinstance(ref, dict) and (ref.get("type") or "").upper() == "CVE":
            v = ref.get("ref")
            if v:
                out.add(f"CVE-{v}")
    return out


def earliest_introduction_in_path(repo: Path, cve_id: str, path: str) -> tuple[int, str] | None:
    """Earliest commit that introduced `cve_id` in `path`, via path-scoped -G search.

    Matches both common Ruby source encodings:
        ['CVE', '2021-44228']         # 2-tuple form (most common in modules/)
        'CVE-2021-44228'              # concatenated form

    Plus the bare-suffix form (no enclosing quotes) just in case. Returns
    (unix_ts, sha) of the first commit whose diff line matches, or None.
    """
    suffix = cve_id[len("CVE-"):]  # e.g. "2021-44228"
    pattern = rf"(CVE-{suffix}|['\"]{suffix}['\"])"
    result = subprocess.run(
        [
            "git", "-C", str(repo), "log", "--all", "--no-renames",
            "-E", "-G", pattern, "--reverse", "--format=%at %H",
            "--", path,
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        return int(parts[0]), parts[1]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".cache/metasploit-framework")
    parser.add_argument("--out", default="out/metasploit_dates.parquet")
    parser.add_argument("--checkpoint", default="out/.metasploit_checkpoint.json")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=None,
                        help="Process only first N CVEs (smoke testing)")
    parser.add_argument("--skip-clone", action="store_true",
                        help="Skip the clone/fetch step (assume repo is already up to date)")
    args = parser.parse_args()

    repo = Path(args.repo)
    if not args.skip_clone:
        # Always pulls with --no-checkout; with_blobs=True keeps the working
        # tree empty (AV-safe) while making blobs available for `git log -G`
        # to walk the diff history. Matches the auto-clone behaviour in
        # 05_nuclei_dates and 06_poc_dates.
        shallow_clone(REPO_URL, repo, with_blobs=True)

    # Manifest is read from the git object store, not the working tree (which
    # is intentionally not checked out — Metasploit's data/ ships real exploit
    # payloads that AV will quarantine if extracted).
    raw = file_content_at_head(repo, "db/modules_metadata_base.json")
    if raw is None:
        log.error("could not read db/modules_metadata_base.json from HEAD of %s "
                  "(re-run without --skip-clone, or check the clone succeeded)", repo)
        return 1
    manifest = json.loads(raw)

    pairs: list[tuple[str, str]] = []  # (cve_id, manifest_path)
    for module in manifest.values():
        cve_ids = cves_from_module(module)
        if not cve_ids:
            continue
        path = (module.get("path") or "").lstrip("/")
        if not path:
            continue
        for cve_id in cve_ids:
            pairs.append((cve_id, path))
    pairs = sorted(set(pairs))
    if args.limit:
        pairs = pairs[: args.limit]
    log.info("Path-scoped -G search across %d (cve, file) pairs (workers=%d)",
             len(pairs), args.workers)

    ckpt = Path(args.checkpoint)
    ckpt.parent.mkdir(parents=True, exist_ok=True)
    per_cve: dict[str, dict] = {}
    if ckpt.exists():
        raw = json.loads(ckpt.read_text())
        for cve_id, payload in raw.items():
            payload["metasploit_first_seen"] = datetime.fromisoformat(
                payload["metasploit_first_seen"]
            )
            per_cve[cve_id] = payload
        log.info("Resuming with %d already-cached CVE results", len(per_cve))

    # Skip (cve, path) pairs whose CVE already has a result *unless* this pair could
    # produce an earlier date — but we don't know without querying. Cheaper to keep
    # the cache CVE-keyed and re-query only CVEs not yet seen at all.
    pending = [(c, p) for c, p in pairs if c not in per_cve]

    def _flush() -> None:
        serialisable = {
            cve_id: {**v, "metasploit_first_seen": v["metasploit_first_seen"].isoformat()}
            for cve_id, v in per_cve.items()
        }
        ckpt.write_text(json.dumps(serialisable))

    def _update(cve_id: str, path: str, hit: tuple[int, str]) -> None:
        ts, sha = hit
        prev = per_cve.get(cve_id)
        if prev is None or ts < int(prev["metasploit_first_seen"].timestamp()):
            per_cve[cve_id] = {
                "cve_id": cve_id,
                "metasploit_first_seen": datetime.fromtimestamp(ts, tz=timezone.utc),
                "metasploit_commit_sha": sha,
                "metasploit_commit_path": path,
            }

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(earliest_introduction_in_path, repo, c, p): (c, p)
            for c, p in pending
        }
        try:
            for i, fut in enumerate(tqdm(as_completed(futures), total=len(futures), unit="pair")):
                cve, path = futures[fut]
                try:
                    hit = fut.result()
                except Exception as exc:  # noqa: BLE001
                    log.warning("error on %s @ %s: %s", cve, path, exc)
                    continue
                if hit is None:
                    continue
                _update(cve, path, hit)
                if (i + 1) % 200 == 0:
                    _flush()
        finally:
            _flush()

    rows = list(per_cve.values())
    df = pd.DataFrame(rows, columns=[
        "cve_id", "metasploit_first_seen",
        "metasploit_commit_sha", "metasploit_commit_path",
    ])
    if not df.empty:
        df = df.sort_values("metasploit_first_seen")
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    log.info("Wrote %d rows → %s  (checkpoint: %s)", len(df), out_path, ckpt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
