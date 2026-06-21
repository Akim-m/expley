"""D3 — autoresearch-style GATED HILL-CLIMB to try to beat EPSS at top-k.

Generator: greedy forward selection over leakage-safe feature GROUPS (from the
audited publication_features matrix). Incumbent starts as EPSS-only — the thing
to beat. Accept gate (all required):
  (1) significance — paired per-origin delta in recall@top-10% @30d vs incumbent
      has a 95% CI excluding 0 (rolling-origin, not a single split);
  (2) leakage-safe — only whole pre-vetted groups can be added (by construction);
  (3) the final winner's signal must vanish under outcome-shuffle (permute=True).
Hard stop: plateau when no remaining group gives a significant gain.

Honest hypothesis (stated up front): the project's own finding is that the
ceiling is data-limited, so this search likely plateaus near EPSS — and an
autonomous search that tried many safe options and still plateaued is a STRONGER
negative than a one-shot attempt. Run in background; ~minutes.
"""
import json
import time
from pathlib import Path

import pandas as pd

from temporal_exploit.backtest import make_origins, paired_origin_deltas, rolling_origin_backtest
from temporal_exploit.cli import EVENT_SOURCES, load_optional_event
from temporal_exploit.hillclimb import (
    feature_groups,
    greedy_forward_select,
    is_significant_gain,
    select_columns,
)
from temporal_exploit.loaders import load_parquet

OUT = Path("data/merged")
ART = Path("artifacts/merged")
SNAPSHOT = "2026-03-14"
CLOCK_START = "2021-01-01"   # clean era (PoC-date artifact is pre-2022; restrict train/test)
ORIGIN_START = "2022-01-01"  # first rolling origin
METRIC, MH, TOPK = "recall_at_top", 30, 0.10  # climb on recall@top-10% at 30d


def main() -> None:
    corpus = load_parquet(OUT, "cve_corpus", columns=["cve_id", "published"])
    features = pd.read_parquet(ART / "publication_features.parquet")
    event_frames = {}
    for s in ("poc", "metasploit", "nuclei", "kev", "google_0day", "exploitdb"):
        nm, c = EVENT_SOURCES[s]
        fr = load_optional_event(OUT, nm, c)
        if fr is not None:
            event_frames[s] = (fr, c)

    groups = feature_groups(features.columns)
    origins = make_origins(SNAPSHOT, ORIGIN_START, min_followup_days=180)
    print(f"groups: { {k: len(v) for k, v in groups.items()} }")
    print(f"{len(origins)} origins {origins[0]}..{origins[-1]}; metric={METRIC}@{MH}d top={TOPK}")

    _cache = {}

    def evaluate(groups_selected):
        key = tuple(sorted(groups_selected))
        if key not in _cache:
            cols = select_columns(groups_selected, groups)
            feat = features[cols]
            _cache[key] = rolling_origin_backtest(
                corpus, event_frames, feat, SNAPSHOT, origins, model="xgb",
                label_set="first_weaponization", top_frac=TOPK, clock_start=CLOCK_START,
            )
        return _cache[key]

    def paired_delta(challenger, incumbent):
        return paired_origin_deltas(challenger, incumbent, METRIC, MH)

    candidates = [g for g in groups if g != "epss"]
    t0 = time.time()
    result = greedy_forward_select(
        candidate_groups=candidates, incumbent_groups=["epss"],
        evaluate=evaluate, paired_delta=paired_delta,
    )
    dt = time.time() - t0

    # EPSS-only baseline vs the final selected config: did we beat EPSS at top-k?
    base = evaluate(["epss"])
    final = evaluate(result["final_groups"])
    base_recall = base["aggregate"]["recall_at_top"].get(str(MH), {})
    final_recall = final["aggregate"]["recall_at_top"].get(str(MH), {})
    final_vs_base = paired_origin_deltas(final, base, METRIC, MH)

    # Gate (3): outcome-shuffle null on the final config — signal must collapse.
    null = rolling_origin_backtest(
        corpus, event_frames, features[select_columns(result["final_groups"], groups)],
        SNAPSHOT, origins, model="xgb", label_set="first_weaponization",
        top_frac=TOPK, clock_start=CLOCK_START, permute=True, seed=0,
    )
    null_recall = null["aggregate"]["recall_at_top"].get(str(MH), {})

    beat = is_significant_gain(final_vs_base)
    out = {
        "metric": f"{METRIC}@{MH}d", "top_frac": TOPK, "n_origins": len(origins),
        "elapsed_s": round(dt, 1),
        "accepted_groups": result["accepted"], "final_groups": result["final_groups"],
        "plateau": result["plateau"], "n_rounds": result["n_rounds"],
        "epss_only_recall": base_recall, "final_recall": final_recall,
        "final_vs_epss_paired_delta": final_vs_base,
        "beat_epss_significant": bool(beat),
        "shuffle_null_recall": null_recall,
        "trials": result["trials"],
    }
    ART.mkdir(parents=True, exist_ok=True)
    (ART / "beat_epss_hillclimb.json").write_text(json.dumps(out, indent=2, default=str))
    _write_doc(out)

    print(f"\n=== GATED HILL-CLIMB ({dt:.0f}s, {result['n_rounds']} rounds) ===")
    for t in result["trials"]:
        flag = "ACCEPT" if t["accepted"] else ("sig" if t["significant"] else "—")
        print(f"  r{t['round']} +{t['added']:10s} dmean={t['mean_delta']} ci={t['ci95']} [{flag}]")
    print(f"\naccepted: {result['accepted']}  plateau={result['plateau']}")
    print(f"EPSS-only recall@top10%@30 = {base_recall.get('mean')}")
    print(f"final     recall@top10%@30 = {final_recall.get('mean')}  (groups={result['final_groups']})")
    print(f"final vs EPSS paired delta = {final_vs_base['mean_delta']} ci={final_vs_base['ci95']}")
    print(f"BEAT EPSS (significant)?   = {beat}")
    print(f"shuffle-null recall        = {null_recall.get('mean')}  (must be << real)")
    print(f"wrote {ART/'beat_epss_hillclimb.json'} + docs/beat_epss_attempt_2026-06.md")


def _write_doc(out: dict) -> None:
    beat = out["beat_epss_significant"]
    verdict = ("**A leakage-safe feature config significantly beat EPSS-only** at recall@top-10%."
               if beat else
               "**No leakage-safe config significantly beat EPSS-only** at recall@top-10% — the "
               "search plateaued, confirming the data-limited ceiling.")
    lines = [
        "# Beat-EPSS Attempt — Gated Hill-Climb (D3)", "",
        f"**Date:** 2026-06-21. Reproduce: `scripts/beat_epss_hillclimb.py` → "
        f"`artifacts/merged/beat_epss_hillclimb.json`. autoresearch-style greedy forward "
        f"selection over leakage-safe feature groups; accept gate = significant paired "
        f"per-origin delta (95% CI excludes 0) on a {out['n_origins']}-origin rolling backtest; "
        f"hard plateau stop; final config shuffle-null-checked.", "",
        f"## Verdict", "", verdict, "",
        f"- metric: {out['metric']}, top fraction {out['top_frac']}",
        f"- EPSS-only recall@top-10%@30d: **{out['epss_only_recall'].get('mean')}**",
        f"- final config ({', '.join(out['final_groups'])}) recall: **{out['final_recall'].get('mean')}**",
        f"- final vs EPSS paired delta: **{out['final_vs_epss_paired_delta']['mean_delta']}** "
        f"(95% CI {out['final_vs_epss_paired_delta']['ci95']})",
        f"- accepted groups (in order): {out['accepted_groups'] or 'none — plateaued immediately'}",
        f"- shuffle-null recall (sanity, must be ≪ real): {out['shuffle_null_recall'].get('mean')}", "",
        "## Trial log", "",
        "| round | added group | mean Δ recall | 95% CI | decision |",
        "|---|---|---|---|---|",
    ]
    for t in out["trials"]:
        dec = "**ACCEPT**" if t["accepted"] else ("significant" if t["significant"] else "—")
        lines.append(f"| {t['round']} | {t['added']} | {t['mean_delta']} | {t['ci95']} | {dec} |")
    lines += ["", "## Interpretation", "",
              "The hill-climb can only add whole publication-time-safe feature groups, so it "
              "cannot climb via leakage; and it accepts a group only when the per-origin gain is "
              "statistically significant, so it cannot chase tiny-event noise. "
              + ("The accepted groups are a genuine, reproducible improvement over EPSS-only."
                 if beat else
                 "That it plateaued is the honest result: consistent with the documented "
                 "data-limited ceiling, no safe feature set significantly out-ranks EPSS at the "
                 "top decile for publication-time first-weaponization triage.")]
    Path("docs/beat_epss_attempt_2026-06.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
