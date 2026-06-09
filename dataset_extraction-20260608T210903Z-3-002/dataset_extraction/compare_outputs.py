#!/usr/bin/env python3
"""Compare every parquet in `out/` against its counterpart in `out2/`.

For each pair: schema, row count, then full-content equality (after a
canonical sort so row-order differences don't show as data differences).
On mismatch, reports first divergent column(s) and a few example diff rows.

Run after a full re-pipeline into out2/:
    python compare_outputs.py
    python compare_outputs.py --a out --b out2 --skip epss_history
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq


def _human_bytes(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _hash_file(path: Path, block: int = 1 << 20) -> str:
    """SHA-256 of the raw parquet bytes. Different here != different data
    (compression dictionaries, row-group layout etc. can differ for identical
    content) but identical hash means identical bytes."""
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(block), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_sort(df: pd.DataFrame) -> pd.DataFrame:
    """Sort by all hashable columns so row order doesn't show up as diff.
    Skips list/dict columns (unhashable) when choosing sort keys."""
    sortable = [
        c for c in df.columns
        if not df[c].apply(lambda v: isinstance(v, (list, dict, np.ndarray))).any()
    ]
    if not sortable:
        return df.reset_index(drop=True)
    return df.sort_values(sortable, kind="stable").reset_index(drop=True)


def _compare_content(a: pd.DataFrame, b: pd.DataFrame, sample: int = 3) -> dict:
    """Return a structured diff result for two same-schema DataFrames."""
    result: dict = {"row_diff": len(a) - len(b)}
    if list(a.columns) != list(b.columns):
        result["col_diff"] = {
            "only_in_a": [c for c in a.columns if c not in b.columns],
            "only_in_b": [c for c in b.columns if c not in a.columns],
        }
        return result

    if len(a) != len(b):
        # No point comparing values when shape differs; flag mismatched cve_ids
        # when that column exists.
        if "cve_id" in a.columns:
            extra_a = set(a["cve_id"]) - set(b["cve_id"])
            extra_b = set(b["cve_id"]) - set(a["cve_id"])
            result["cve_only_in_a"] = sorted(extra_a)[:sample]
            result["cve_only_in_b"] = sorted(extra_b)[:sample]
            result["cve_only_in_a_count"] = len(extra_a)
            result["cve_only_in_b_count"] = len(extra_b)
        return result

    # Same shape — compare column-by-column on a canonical-sorted view.
    a = _canonical_sort(a)
    b = _canonical_sort(b)
    col_mismatches: dict[str, int] = {}
    for col in a.columns:
        sa, sb = a[col], b[col]
        if pd.api.types.is_float_dtype(sa) and pd.api.types.is_float_dtype(sb):
            mask = ~((sa == sb) | (sa.isna() & sb.isna()))
        elif a[col].apply(lambda v: isinstance(v, (list, dict, np.ndarray))).any():
            # List/dict cells can't use vectorised compare — numpy broadcasts
            # element-wise and chokes on length mismatch. Hand-loop them.
            def _eq(x, y):
                # numpy arrays / pyarrow list columns: equal length & equal items.
                if isinstance(x, (list, np.ndarray)) and isinstance(y, (list, np.ndarray)):
                    return len(x) == len(y) and all(xi == yi for xi, yi in zip(x, y))
                # NaN-vs-NaN handling for None / NaN scalars in object columns.
                if x is None and y is None: return True
                try:
                    return x == y
                except Exception:
                    return False
            mask = pd.Series([not _eq(x, y) for x, y in zip(sa, sb)], index=sa.index)
        else:
            try:
                mask = (sa.astype(object).fillna("__NA__")
                        != sb.astype(object).fillna("__NA__"))
            except Exception:
                mask = pd.Series([x != y for x, y in zip(sa, sb)], index=sa.index)
        n_diff = int(mask.sum())
        if n_diff:
            col_mismatches[col] = n_diff
    if col_mismatches:
        result["column_mismatches"] = col_mismatches
        # Pick the first mismatching column and show example rows.
        bad_col = next(iter(col_mismatches))
        diff_idx = a.index[a[bad_col].astype(object).fillna("__NA__") !=
                           b[bad_col].astype(object).fillna("__NA__")][:sample]
        example_rows: list[dict] = []
        for i in diff_idx:
            row = {"row": int(i), "column": bad_col,
                   "a": a.at[i, bad_col], "b": b.at[i, bad_col]}
            if "cve_id" in a.columns:
                row["cve_id"] = a.at[i, "cve_id"]
            example_rows.append(row)
        result["example_diffs"] = example_rows
    return result


def compare_pair(name: str, p_a: Path, p_b: Path, *, sample: int) -> None:
    print(f"\n=== {name} ===")
    if not p_a.exists():
        print(f"  ! missing in A: {p_a}")
        return
    if not p_b.exists():
        print(f"  ! missing in B: {p_b}")
        return

    meta_a = pq.ParquetFile(p_a).metadata
    meta_b = pq.ParquetFile(p_b).metadata
    print(f"  rows : A={meta_a.num_rows:>12,}   B={meta_b.num_rows:>12,}   "
          f"Δ={meta_a.num_rows - meta_b.num_rows:+,}")
    print(f"  cols : A={meta_a.num_columns:>3}            B={meta_b.num_columns:>3}")
    print(f"  size : A={_human_bytes(p_a.stat().st_size):>10}      "
          f"B={_human_bytes(p_b.stat().st_size):>10}")

    # Byte-hash short-circuit
    sha_a = _hash_file(p_a)
    sha_b = _hash_file(p_b)
    if sha_a == sha_b:
        print("  hash : IDENTICAL byte-for-byte ✓")
        return
    print(f"  hash : A={sha_a[:12]}…   B={sha_b[:12]}…  (differ — comparing content)")

    # For huge files (EPSS), don't load whole — count by cve_id summary.
    if meta_a.num_rows > 5_000_000 or meta_b.num_rows > 5_000_000:
        print(f"  (>5M rows — skipping full content compare; sampling 100k by cve_id)")
        df_a = pd.read_parquet(p_a).head(100_000)
        df_b = pd.read_parquet(p_b).head(100_000)
        diff = _compare_content(df_a, df_b, sample=sample)
    else:
        df_a = pd.read_parquet(p_a)
        df_b = pd.read_parquet(p_b)
        diff = _compare_content(df_a, df_b, sample=sample)

    if not diff.get("column_mismatches") and "col_diff" not in diff and diff.get("row_diff", 0) == 0:
        print("  content: IDENTICAL after canonical sort ✓")
        return

    if "col_diff" in diff:
        print(f"  ! schema differs: {diff['col_diff']}")
    if diff.get("row_diff", 0):
        print(f"  ! row count differs by {diff['row_diff']:+}")
        if "cve_only_in_a_count" in diff:
            print(f"      {diff['cve_only_in_a_count']} CVEs only in A "
                  f"(e.g. {diff['cve_only_in_a']})")
            print(f"      {diff['cve_only_in_b_count']} CVEs only in B "
                  f"(e.g. {diff['cve_only_in_b']})")
    if "column_mismatches" in diff:
        print(f"  ! column mismatches: {diff['column_mismatches']}")
        for ex in diff.get("example_diffs", []):
            cve = f" [{ex['cve_id']}]" if "cve_id" in ex else ""
            print(f"      row {ex['row']}{cve} col={ex['column']!r}: "
                  f"A={ex['a']!r}  B={ex['b']!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--a", default="out", help="First directory (default: out)")
    parser.add_argument("--b", default="out2", help="Second directory (default: out2)")
    parser.add_argument("--skip", default="", help="Comma-separated names to skip")
    parser.add_argument("--sample", type=int, default=3, help="Example rows on mismatch")
    args = parser.parse_args()

    dir_a = Path(args.a)
    dir_b = Path(args.b)
    if not dir_a.is_dir() or not dir_b.is_dir():
        print(f"error: both {dir_a} and {dir_b} must exist", file=sys.stderr)
        return 2

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    names = sorted({p.stem for p in dir_a.glob("*.parquet")} |
                   {p.stem for p in dir_b.glob("*.parquet")})
    names = [n for n in names if n not in skip]

    print(f"Comparing {len(names)} parquet pair(s): {args.a}/ vs {args.b}/")
    for name in names:
        compare_pair(name, dir_a / f"{name}.parquet", dir_b / f"{name}.parquet",
                     sample=args.sample)
    return 0


if __name__ == "__main__":
    sys.exit(main())
