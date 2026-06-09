#!/usr/bin/env python3
"""Inspect a parquet file in `out/` (or any path) without loading the whole thing.

Designed to be safe on huge files like `epss_history.parquet` (375M rows / 3.7 GB):
schema and row counts come from parquet metadata (no data load), sample rows
are streamed from the first row group, and per-CVE filters use pyarrow's
predicate pushdown so only matching rows are deserialised.

Usage:
    python view_parquet.py                        # list available parquets
    python view_parquet.py cve_corpus             # schema + stats + head(5)
    python view_parquet.py kev_events --head 20
    python view_parquet.py epss_history --cve CVE-2021-44228
    python view_parquet.py cve_corpus --columns cve_id,published,description
    python view_parquet.py epss_history --schema-only
    python view_parquet.py --path .cache/epss/epss-2026-03-14.parquet
    python view_parquet.py cve_corpus --stats     # per-column null counts + summary
"""
import argparse
import sys
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq

DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "out"


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def list_parquets(out_dir: Path) -> int:
    files = sorted(out_dir.glob("*.parquet"))
    if not files:
        print(f"(no .parquet files in {out_dir})")
        return 1
    print(f"Parquet files in {out_dir}:\n")
    name_w = max(len(f.stem) for f in files)
    for f in files:
        meta = pq.ParquetFile(f).metadata
        print(f"  {f.stem:<{name_w}}  {_human_bytes(f.stat().st_size):>10}  "
              f"{meta.num_rows:>15,} rows  {meta.num_columns:>3} cols")
    return 0


def resolve_path(name_or_path: str, out_dir: Path) -> Path:
    """Resolve `cve_corpus` → out_dir/cve_corpus.parquet; treat `/` or `.parquet` as a path."""
    p = Path(name_or_path)
    if p.exists():
        return p
    candidate = out_dir / f"{name_or_path}.parquet"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(
        f"can't resolve '{name_or_path}'. Tried {p!s} and {candidate!s}. "
        "Use --list to see available parquets, or --path to specify a full path."
    )


def print_schema(path: Path) -> None:
    pf = pq.ParquetFile(path)
    meta = pf.metadata
    print(f"\n=== {path.name} ===")
    print(f"  size on disk : {_human_bytes(path.stat().st_size)}")
    print(f"  rows         : {meta.num_rows:,}")
    print(f"  row groups   : {meta.num_row_groups}")
    print(f"  columns      : {meta.num_columns}")
    print(f"\nSchema:")
    name_w = max(len(f.name) for f in pf.schema_arrow)
    for f in pf.schema_arrow:
        print(f"  {f.name:<{name_w}}  {str(f.type)}")


def print_head(df: pd.DataFrame, n: int) -> None:
    if df.empty:
        print("(no rows)")
        return
    print(f"\nFirst {min(n, len(df))} row(s):")
    with pd.option_context(
        "display.max_columns", None,
        "display.width", 240,
        "display.max_colwidth", 60,
    ):
        print(df.head(n).to_string(index=False))


def print_stats(df: pd.DataFrame) -> None:
    print("\nPer-column summary:")
    rows: list[tuple[str, str, str]] = []
    for col in df.columns:
        s = df[col]
        n_null = int(s.isna().sum())
        sample = s.dropna().iloc[0] if s.notna().any() else None
        if isinstance(sample, (list, tuple)) or hasattr(sample, "__len__") and not isinstance(sample, str):
            lens = s.dropna().apply(lambda v: len(v) if hasattr(v, "__len__") else 0)
            summary = (
                f"list  len min/median/max = "
                f"{int(lens.min()) if not lens.empty else 0}/"
                f"{int(lens.median()) if not lens.empty else 0}/"
                f"{int(lens.max()) if not lens.empty else 0}"
            )
        elif pd.api.types.is_numeric_dtype(s):
            d = s.dropna()
            if d.empty:
                summary = "numeric (all null)"
            else:
                summary = (
                    f"min={d.min():g}  median={d.median():g}  max={d.max():g}  mean={d.mean():.3g}"
                )
        elif pd.api.types.is_datetime64_any_dtype(s):
            d = s.dropna()
            summary = (
                f"{d.min()} → {d.max()}" if not d.empty else "datetime (all null)"
            )
        elif s.dtype == bool:
            summary = f"true={int(s.sum()):,} / {len(s):,} ({s.mean():.1%})"
        else:
            uniq = s.nunique(dropna=True)
            summary = f"object  unique={uniq:,}"
            if uniq <= 5 and uniq > 0:
                top = s.value_counts(dropna=True).head(5)
                summary += "  values=" + ", ".join(f"{k}={v}" for k, v in top.items())
        rows.append((col, f"{n_null:,} null ({n_null/len(s):.1%})", summary))

    col_w = max(len(r[0]) for r in rows)
    null_w = max(len(r[1]) for r in rows)
    for name, nulls, summary in rows:
        print(f"  {name:<{col_w}}  {nulls:<{null_w}}  {summary}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("name", nargs="?", default=None,
                        help="Parquet stem (e.g. 'survival') or empty to list")
    parser.add_argument("--path", default=None,
                        help="Absolute or relative path to a parquet file (overrides 'name')")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR),
                        help=f"Directory containing parquet files (default: {DEFAULT_OUT_DIR})")
    parser.add_argument("--list", action="store_true",
                        help="List all parquet files under --out-dir and exit")
    parser.add_argument("--head", type=int, default=5,
                        help="Number of sample rows to display (default 5)")
    parser.add_argument("--cve", default=None,
                        help="Filter to a single CVE by cve_id (uses pyarrow predicate pushdown)")
    parser.add_argument("--columns", default=None,
                        help="Comma-separated list of columns to project")
    parser.add_argument("--schema-only", action="store_true",
                        help="Show schema + row count, skip the head/stats data load")
    parser.add_argument("--stats", action="store_true",
                        help="Per-column null counts + summary (slow on huge files)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)

    if args.list or (not args.name and not args.path):
        return list_parquets(out_dir)

    try:
        path = Path(args.path) if args.path else resolve_path(args.name, out_dir)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print_schema(path)
    if args.schema_only:
        return 0

    columns = [c.strip() for c in args.columns.split(",")] if args.columns else None

    if args.cve:
        # Predicate pushdown via the pyarrow dataset API — only matching rows
        # are decoded, so this is safe on huge files.
        dataset = ds.dataset(str(path), format="parquet")
        table = dataset.to_table(
            columns=columns,
            filter=ds.field("cve_id") == args.cve,
        )
        df = table.to_pandas()
        print(f"\nFilter cve_id == {args.cve!r}: {len(df):,} row(s)")
    else:
        # Stream the first row group rather than read the whole file. Enough
        # for a head; sufficient for stats on the typical small parquets.
        pf = pq.ParquetFile(path)
        rg = pf.read_row_group(0, columns=columns)
        df = rg.to_pandas()
        if pf.metadata.num_row_groups > 1:
            print(f"\n(stats/head computed from first row group of {pf.metadata.num_row_groups})")

    print_head(df, args.head)
    if args.stats:
        print_stats(df)
    return 0


if __name__ == "__main__":
    sys.exit(main())
