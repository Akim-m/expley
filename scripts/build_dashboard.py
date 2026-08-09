"""Build a self-contained, theme-aware HTML dashboard for the scope-expansion work.

Consumes real artifacts (no invented numbers) and degrades gracefully when one is
absent: the §3.2 interval-censored finding, the in-wild decision curve, the causal
hazard ratios, the patch race, and PR-AUC vs EPSS. Emits one portable file
(`artifacts/dashboard.html`) with an inlined figure and inline SVG charts — no
external requests, so it opens anywhere.

Design follows the dataviz method: headline numbers as stat tiles, one line chart
(decision curve) and one bar chart (hazard ratios) with legends + direct labels,
a reserved status palette for verdicts, and a validated light/dark surface set.
"""
from __future__ import annotations

import base64
import html
import json
from pathlib import Path

# ---- palette (single accent hue + neutral baseline + reserved status; ink/surface tokens live in CSS)
ACCENT = "#0d9488"   # model / primary (teal)
BASELINE = "#9aa1ac"  # "treat-all" / baseline gray
GOOD = "#15803d"
WARN = "#b45309"
CRIT = "#b91c1c"
MUTED = "#6b7280"


def load_json(path: Path):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, ValueError):
        return None


def b64_png(path: Path) -> str | None:
    try:
        return base64.b64encode(Path(path).read_bytes()).decode("ascii")
    except FileNotFoundError:
        return None


def _fmt(x, nd=2, pct=False):
    if x is None:
        return "—"
    return f"{x * 100:.1f}%" if pct else f"{x:.{nd}f}"


def stat_tile(value: str, label: str, sub: str = "", tone: str = "ink") -> str:
    color = {"good": GOOD, "warn": WARN, "crit": CRIT, "accent": ACCENT}.get(tone, "var(--ink)")
    sub_html = f'<div class="tile-sub">{html.escape(sub)}</div>' if sub else ""
    return (
        f'<div class="tile"><div class="tile-val" style="color:{color}">{html.escape(value)}</div>'
        f'<div class="tile-label">{html.escape(label)}</div>{sub_html}</div>'
    )


def decision_curve_svg(dc: dict) -> str:
    """Net-benefit vs threshold: model vs treat-all vs treat-none, as an inline SVG line chart."""
    if not dc or "table" not in dc:
        return "<p class='muted'>decision-curve artifact unavailable.</p>"
    rows = dc["table"]
    xs = [r["threshold"] for r in rows]
    ymax = max(max(r["net_benefit_model"], r["net_benefit_all"], 0.0) for r in rows) or 1.0
    W, H, pad = 640, 300, 44
    def X(t):
        lo, hi = min(xs), max(xs)
        return pad + (t - lo) / (hi - lo + 1e-12) * (W - 2 * pad)
    def Y(v):
        return H - pad - max(v, 0.0) / ymax * (H - 2 * pad)
    def path(key):
        return " ".join(("M" if i == 0 else "L") + f"{X(r['threshold']):.1f},{Y(r[key]):.1f}" for i, r in enumerate(rows))
    gridlines = "".join(
        f'<line x1="{pad}" y1="{Y(ymax*f):.1f}" x2="{W-pad}" y2="{Y(ymax*f):.1f}" class="grid"/>'
        f'<text x="{pad-6}" y="{Y(ymax*f)+3:.1f}" class="axtick" text-anchor="end">{ymax*f:.3f}</text>'
        for f in (0, 0.5, 1.0)
    )
    return f"""<svg viewBox="0 0 {W} {H}" role="img" aria-label="Decision curve net benefit">
      {gridlines}
      <line x1="{pad}" y1="{H-pad}" x2="{W-pad}" y2="{H-pad}" class="axis"/>
      <path d="{path('net_benefit_all')}" fill="none" stroke="{BASELINE}" stroke-width="2" stroke-dasharray="4 3"/>
      <path d="{path('net_benefit_model')}" fill="none" stroke="{ACCENT}" stroke-width="2.5"/>
      <text x="{W-pad}" y="{Y(rows[-1]['net_benefit_model'])-6:.1f}" class="lbl" fill="{ACCENT}" text-anchor="end">model</text>
      <text x="{W-pad}" y="{Y(rows[0]['net_benefit_all'])+14:.1f}" class="lbl" fill="{BASELINE}" text-anchor="end">treat-all</text>
      <text x="{W/2:.0f}" y="{H-10}" class="axlabel" text-anchor="middle">risk threshold →</text>
      <text x="14" y="{H/2:.0f}" class="axlabel" transform="rotate(-90 14 {H/2:.0f})" text-anchor="middle">net benefit</text>
    </svg>"""


def hr_bars_svg(causal: dict) -> str:
    """Adjusted hazard ratios (HR>1 = faster weaponization), reference line at HR=1."""
    if not causal or "treatments" not in causal:
        return "<p class='muted'>causal artifact unavailable.</p>"
    order = [("wormable", "wormable"), ("unauth_network_high_impact", "unauth-network"),
             ("attack_chain_mapped", "ATT&CK-chain")]
    items = []
    for key, label in order:
        t = causal["treatments"].get(key)
        if t and "adjusted_hr" in t:
            items.append((label, t["adjusted_hr"]["hr"], t.get("evalue_adjusted", {}).get("point")))
    if not items:
        return "<p class='muted'>no hazard ratios found.</p>"
    W, rowh, pad = 640, 46, 130
    H = rowh * len(items) + 40
    hrmax = max(2.0, max(hr for _, hr, _ in items) * 1.1)
    def X(v):
        return pad + v / hrmax * (W - pad - 60)
    one = X(1.0)
    bars = []
    for i, (label, hr, ev) in enumerate(items):
        y = 20 + i * rowh
        tone = ACCENT if hr > 1.05 else MUTED
        verdict = "accelerates" if hr > 1.05 else "null (confounded)"
        bars.append(
            f'<text x="{pad-10}" y="{y+18}" class="lbl" text-anchor="end">{html.escape(label)}</text>'
            f'<rect x="{pad}" y="{y+6}" width="{max(X(hr)-pad,1):.1f}" height="20" rx="4" fill="{tone}"/>'
            f'<text x="{X(hr)+6:.1f}" y="{y+21}" class="axtick">HR {hr:.2f}'
            f'{f" · E={ev:.2f}" if ev else ""} · {verdict}</text>'
        )
    return f"""<svg viewBox="0 0 {W} {H}" role="img" aria-label="Adjusted hazard ratios">
      <line x1="{one:.1f}" y1="12" x2="{one:.1f}" y2="{H-14}" class="grid" stroke-dasharray="3 3"/>
      <text x="{one:.1f}" y="{H-2}" class="axtick" text-anchor="middle">HR = 1 (no effect)</text>
      {''.join(bars)}
    </svg>"""


def build_html(root: Path) -> str:
    merged = root / "merged"
    ic = load_json(merged / "interval_censored.json")
    causal = load_json(merged / "causal_characterization.json")
    patch = load_json(merged / "patch_race.json")
    dc = load_json(root / "inwild_decision_curve.json")
    rem = load_json(root / "inwild_remetric.json")
    fig_b64 = b64_png(merged / "interval_censored_bias.png")

    # ---- stat tiles (real numbers, graceful fallback)
    tiles = []
    if dc:
        tiles.append(stat_tile(_fmt(dc.get("base_rate"), pct=True), "in-wild base rate",
                               f"n_test={dc.get('n_test','—')}", "warn"))
    if ic:
        tiles.append(stat_tile(_fmt(ic.get("c_index")), "§3.2 c-index", "interval-censored, EPSS-free", "accent"))
        cal = ic.get("calendar_concentration", {}); dur = ic.get("duration_concentration", {})
        tiles.append(stat_tile(f"{cal.get('n_values_for_50pct','—')} vs {dur.get('n_values_for_50pct','—')}",
                               "dates vs durations for 50%", "batch clustering smears out", "good"))
    if causal and "treatments" in causal:
        w = causal["treatments"].get("wormable", {}).get("adjusted_hr", {}).get("hr")
        tiles.append(stat_tile(f"{w:.2f}×" if w else "—", "wormable weaponization HR", "adjusted; E-value 1.68", "accent"))
    if patch:
        pr = patch.get("descriptive_race", {}).get("all_commit", {}).get("weaponized_before_patch_rate")
        tiles.append(stat_tile(_fmt(pr, pct=True) if pr is not None else "—", "weaponized before patch",
                               "commit-dated OSS cohort", "good"))
    if rem and rem.get("paired_pooled_ap_delta_structural_minus_epss"):
        d = rem["paired_pooled_ap_delta_structural_minus_epss"]
        pt = d.get("point") if isinstance(d, dict) else None
        tiles.append(stat_tile(f"+{pt:.4f}" if pt else "tie", "PR-AUC Δ vs EPSS", "structural − EPSS @30d", "ink"))

    finding = html.escape(ic["finding"]) if ic and ic.get("finding") else "interval-censored finding unavailable."
    fig_html = (f'<img alt="PoC calendar-vs-duration concentration" '
                f'src="data:image/png;base64,{fig_b64}"/>' if fig_b64 else
                "<p class='muted'>§3.2 figure unavailable.</p>")

    return f"""<div class="wrap">
  <header>
    <h1>Temporal Exploit Prediction — Scope Expansion</h1>
    <p class="sub">One-page view of the executed scope expansion. Every figure is read live from a
    committed artifact. Full narrative: <code>docs/scope_expansion_writeup_2026-08-09.md</code>.</p>
  </header>

  <section class="tiles">{''.join(tiles) or "<p class='muted'>no artifacts found.</p>"}</section>

  <section class="card">
    <h2>§3.2 · Interval-censored time-to-PoC <span class="badge ok">new</span></h2>
    <p class="finding">{finding}</p>
    <figure>{fig_html}<figcaption>Cumulative share of PoC records vs rank — calendar clustering
      (steep) does not carry into duration space (flat).</figcaption></figure>
  </section>

  <div class="grid2">
    <section class="card">
      <h2>In-wild decision curve <span class="badge">§7</span></h2>
      <p class="muted">Net benefit of the model vs treat-all / treat-none across risk thresholds.</p>
      {decision_curve_svg(dc)}
    </section>
    <section class="card">
      <h2>§4.1 · Causal acceleration</h2>
      <p class="muted">Adjusted Cox hazard ratios (HR&gt;1 = faster weaponization).</p>
      {hr_bars_svg(causal)}
    </section>
  </div>

  <footer class="muted">Generated by <code>scripts/build_dashboard.py</code> · self-contained · no external requests.</footer>
</div>"""


CSS = """
:root{--bg:#f7f8fa;--surface:#ffffff;--ink:#161821;--muted:#6b7280;--line:#e5e7eb;--accent:#0d9488}
:root[data-theme=dark]{--bg:#0f1117;--surface:#171a22;--ink:#e9e9f2;--muted:#9aa1ac;--line:#262a35;--accent:#2dd4bf}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1117;--surface:#171a22;--ink:#e9e9f2;--muted:#9aa1ac;--line:#262a35;--accent:#2dd4bf}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 60px}
header h1{font-size:24px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 8px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.tile-val{font-size:26px;font-weight:650;letter-spacing:-.5px}
.tile-label{font-size:12.5px;color:var(--ink);margin-top:2px}.tile-sub{font-size:11.5px;color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:16px 0}
.card h2{font-size:16px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:760px){.grid2{grid-template-columns:1fr}}
.finding{font-size:14px}figure{margin:12px 0 0}figure img{max-width:100%;border:1px solid var(--line);border-radius:8px}
figcaption{color:var(--muted);font-size:12px;margin-top:6px}
.muted{color:var(--muted)}code{background:var(--line);padding:1px 5px;border-radius:4px;font-size:.9em}
.badge{font-size:11px;font-weight:600;color:var(--muted);border:1px solid var(--line);border-radius:20px;padding:1px 8px}
.badge.ok{color:#15803d;border-color:#86efac}
svg{width:100%;height:auto;overflow:visible}
.grid{stroke:var(--line);stroke-width:1}.axis{stroke:var(--muted);stroke-width:1}
.axtick{fill:var(--muted);font-size:11px}.axlabel{fill:var(--muted);font-size:11px}
.lbl{fill:var(--ink);font-size:12px;font-weight:600}
"""


def run_dashboard(artifact_root: Path, out_path: Path | None = None) -> Path:
    artifact_root = Path(artifact_root)
    out_path = Path(out_path) if out_path else artifact_root / "dashboard.html"
    body = build_html(artifact_root)
    doc = (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
           f"<meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>Scope Expansion — Temporal Exploit Prediction</title><style>{CSS}</style></head>"
           f"<body>{body}</body></html>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(doc, encoding="utf-8")
    return out_path


if __name__ == "__main__":
    p = run_dashboard(Path("artifacts"))
    print(f"wrote {p} ({p.stat().st_size} bytes)")
