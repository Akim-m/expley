# Architecture & Data Flow — `temporal_exploit`

Visual map of the full pipeline. Every box names the **actual function/class** that
does the work and the **module** it lives in (`module.py :: function`). Diagrams are
[Mermaid](https://mermaid.js.org/) — they render in GitHub, VS Code (with the Mermaid
extension), and most markdown viewers.

The spine is `cli.py`. Five CLI subcommands drive everything:
`fetch` / `refresh` → `merge` → `build-dataset` → `train` / `train-competing` / `backtest`.

---

## 0. Top-level command map

```mermaid
flowchart TB
    classDef cmd fill:#1f6feb,color:#fff,stroke:#1f6feb;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    subgraph CLI["cli.py :: main() — argparse subcommands"]
        F["fetch<br/><i>fetch_command()</i>"]:::cmd
        R["refresh<br/><i>refresh_command()</i>"]:::cmd
        M["merge<br/><i>merge.merge_live()</i>"]:::cmd
        B["build-dataset<br/><i>build_dataset_command()</i>"]:::cmd
        T["train<br/><i>train_command()</i>"]:::cmd
        TC["train-competing<br/><i>train_competing_command()</i>"]:::cmd
        BT["backtest<br/><i>backtest_command()</i>"]:::cmd
    end

    NET([External sources:<br/>NVD, CISA-KEV, EPSS, ExploitDB,<br/>git repos, VulnCheck, Shadowserver]):::data
    LIVE[(live_dir/<br/>*.parquet deltas)]:::data
    HAND[(handover out/<br/>9 source parquets)]:::data
    OUT[(out_dir/<br/>merged parquets)]:::data
    ART[(artifacts/<br/>labels + features<br/>+ manifest)]:::data
    REP[(report_dir/<br/>metrics.json + PNGs)]:::data

    NET --> F --> LIVE
    NET --> R --> LIVE
    LIVE --> M
    HAND --> M --> OUT
    OUT --> B --> ART
    ART --> T --> REP
    ART --> TC --> REP
    OUT --> BT --> REP
    ART --> BT
```

---

## 1. Fetch / Refresh — pulling live data (`fetch/` package)

All connectors subclass `fetch/base.py :: Connector` (abstract `fetch()` + shared
`save()`). HTTP sources go through `fetch/cache.py :: conditional_get()` (ETag /
Last-Modified, serves stale on outage). Git-mined sources use `fetch/gitmine.py`
helpers (`shallow_clone`, `earliest_introduction`, `first_add_dates`).

```mermaid
flowchart LR
    classDef conn fill:#347d39,color:#fff,stroke:#347d39;
    classDef util fill:#9e6a03,color:#fff,stroke:#9e6a03;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    subgraph HTTP["HTTP connectors → cache.conditional_get()"]
        KEV["KevConnector.fetch()<br/><i>fetch/kev.py</i><br/>CISA KEV"]:::conn
        EPSS["EpssConnector.fetch(date)<br/><i>fetch/epss.py</i><br/>EPSS daily"]:::conn
        EDB["ExploitDbConnector.fetch()<br/><i>fetch/exploitdb.py</i>"]:::conn
        ZD["ZerodayConnector.fetch()<br/><i>fetch/zeroday.py</i><br/>Google 0-day sheet"]:::conn
        NVD["NvdConnector.fetch(start,end)<br/><i>fetch/nvd.py</i><br/>CVE corpus"]:::conn
    end

    subgraph GIT["Git-mined connectors → gitmine.py"]
        POC["PocConnector.fetch(repo)<br/><i>fetch/poc.py</i><br/>Trickest + Nomi-sec"]:::conn
        NUC["NucleiConnector.fetch(repo)<br/><i>fetch/nuclei.py</i>"]:::conn
        MSF["MetasploitConnector.fetch(repo)<br/><i>fetch/metasploit.py</i>"]:::conn
    end

    subgraph TOKEN["Token / credential gated"]
        VC["VulncheckKevConnector.fetch(token)<br/><i>fetch/vulncheck.py</i><br/>VULNCHECK_API_TOKEN"]:::conn
        SS["ShadowserverConnector.fetch(key,secret)<br/><i>fetch/shadowserver.py</i><br/>honeypot in-wild"]:::conn
    end

    CACHE["cache.conditional_get()<br/><i>ETag/Last-Modified, stale-on-outage</i>"]:::util
    GMINE["gitmine.shallow_clone /<br/>earliest_introduction /<br/>first_add_dates"]:::util

    HTTP --> CACHE
    GIT --> GMINE
    SAVE["Connector.save(frame, live_dir)<br/>+ base.write_fetch_manifest()"]:::util
    HTTP --> SAVE
    GIT --> SAVE
    TOKEN --> SAVE
    LIVE[(live_dir/<br/>per-source parquet + manifest)]:::data
    SAVE --> LIVE
```

**`refresh_command()`** runs all keyless HTTP + git sources in one shot (errors per
source are caught, not fatal), then conditionally adds VulnCheck (if
`VULNCHECK_API_TOKEN`) and Shadowserver (if credentials) — otherwise records them as
`skipped`. **`fetch_command()`** runs one named source on demand.

---

## 2. Merge — live deltas onto handover parquets (`merge.py`)

```mermaid
flowchart LR
    classDef fn fill:#8957e5,color:#fff,stroke:#8957e5;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    HAND[(handover_dir/<br/>source parquets)]:::data
    LIVE[(live_dir/<br/>fetch deltas)]:::data
    ML["merge_live(handover, live, out)<br/><i>iterates MERGE_SPECS</i>"]:::fn
    MS["merge_source(handover, live,<br/>key, order_col, keep)<br/><i>dedup earliest/latest per source</i>"]:::fn
    OUT[(out_dir/<br/>merged parquets)]:::data

    HAND --> ML
    LIVE --> ML
    ML --> MS --> OUT
```

`MERGE_SPECS` holds the per-source dedup key + ordering (e.g. keep *earliest*
`first_seen`, keep *latest* EPSS reading).

---

## 3. build-dataset — labels + features (`build_dataset_command`)

This is the integration hub. Loads the corpus + every optional event parquet, builds
**four label sets** and the **feature matrix**, then writes artifacts + a manifest.

```mermaid
flowchart TB
    classDef load fill:#1f6feb,color:#fff,stroke:#1f6feb;
    classDef label fill:#cf222e,color:#fff,stroke:#cf222e;
    classDef feat fill:#347d39,color:#fff,stroke:#347d39;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    OUT[(out_dir parquets)]:::data

    subgraph LOAD["Load + validate"]
        LP["loaders.load_parquet(cve_corpus,<br/>CORPUS_BUILD_COLUMNS)"]:::load
        VC["schema.validate_columns()<br/><i>REQUIRED_COLUMNS</i>"]:::load
        LOE["load_optional_event() ×<br/>EVENT_SOURCES<br/><i>poc, metasploit, nuclei, kev,<br/>google_0day, exploitdb,<br/>vulncheck_kev, shadowserver</i>"]:::load
    end
    OUT --> LP --> VC --> LOE

    subgraph LABELS["labels.py — published = clock origin"]
        L1["build_first_weaponization_labels()<br/><i>→ modeling_labels.parquet</i>"]:::label
        L2["build_per_signal_labels()<br/><i>→ per_signal_labels.parquet</i>"]:::label
        L3["build_competing_risks_labels()<br/><i>→ competing_risks_labels.parquet</i>"]:::label
        L4["build_in_wild_labels()<br/><i>→ in_wild_labels.parquet</i>"]:::label
        DOM["evaluate.event_source_dominance()<br/><i>warns if one source &gt;50%</i>"]:::label
    end
    LOE --> L1 --> DOM
    LOE --> L2
    LOE --> L3
    LOE --> L4

    subgraph FEATS["features — publication-time-safe only"]
        F1["features.build_publication_features()<br/><i>CVSS, CWE, vendor/product counts</i>"]:::feat
        F2["attack_features.build_attack_features()<br/><i>opt: --technique-chain</i>"]:::feat
        F3["epss_features.build_epss_at_publication()<br/><i>opt: --epss-path, streams 375M rows</i>"]:::feat
        F4["nlp_features.build_description_features()<br/><i>opt: --description-text, masked+fresh</i>"]:::feat
        F5["landmark.build_landmark_features()<br/><i>opt: --landmarks L</i>"]:::feat
        F6["poc_features.build_poc_features()<br/><i>PoC→tooling transition-safe</i>"]:::feat
        F7["presence_features.build_presence_features()<br/><i>snapshot, leakage-flagged</i>"]:::feat
    end
    LP --> F1 --> F2 --> F3 --> F4

    PROV["features.feature_provenance() + per-family<br/>*_feature_provenance() → feature_provenance.csv<br/><i>leakage audit trail</i>"]:::feat
    F1 --> PROV

    SPLIT["splits.make_time_split() +<br/>write_time_split()<br/><i>opt: --cutoff-date</i>"]:::load
    MAN["artifacts.write_manifest() +<br/>artifact_hashes()<br/><i>→ manifest.json (sha256)</i>"]:::load

    ART[(artifacts/<br/>4 label parquets,<br/>publication_features.parquet,<br/>provenance.csv, manifest.json)]:::data

    L1 --> ART
    F4 --> ART
    PROV --> ART
    L1 --> SPLIT --> ART
    ART --> MAN --> ART
```

**Leakage safety** (non-negotiable): default features exclude post-event description
text, snapshot presence flags, and snapshot EPSS. `text_safety.mask_leakage_terms()` +
`description_is_fresh()` guard the opt-in NLP path.

---

## 4. train — survival models + evaluation (`train_command`)

```mermaid
flowchart TB
    classDef prep fill:#1f6feb,color:#fff,stroke:#1f6feb;
    classDef model fill:#bf3989,color:#fff,stroke:#bf3989;
    classDef eval fill:#9e6a03,color:#fff,stroke:#9e6a03;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    ART[(artifacts/<br/>labels + features)]:::data

    subgraph PREP["Prepare"]
        RD["read_parquet(LABEL_SETS[label_set])<br/><i>first_weaponization | in_wild</i>"]:::prep
        CF["in_wild_clock_start() filter<br/><i>CATALOG_START backfill guard</i>"]:::prep
        LM["landmark.restart_clock()<br/><i>opt: --landmark L</i>"]:::prep
        PM["modeling.prepare_modeling_frame()"]:::prep
        TS["modeling.time_split_frame(cutoff)<br/><i>→ train / test</i>"]:::prep
    end
    ART --> RD --> CF --> LM --> PM --> TS

    subgraph MODELS["Fit (--models cox,rsf,xgb,cure)"]
        CX["modeling.fit_cox()<br/><i>penalizer escalation</i>"]:::model
        RSF["modeling.fit_rsf(max_samples)"]:::model
        XGB["xgb.fit_xgb_aft()<br/><i>GPU AFT</i>"]:::model
        CURE["cure.fit_cure() [+ .recalibrate()]<br/><i>mixture-cure, AIC latency</i>"]:::model
        KM["baselines.fit_kaplan_meier()<br/><i>reference</i>"]:::model
    end
    TS --> CX
    TS --> RSF
    TS --> XGB
    TS --> CURE
    TS --> KM

    subgraph EVAL["Evaluate (per model)"]
        SA["modeling.survival_at(horizons)<br/>+ _risk_scores()"]:::eval
        ES["modeling.evaluate_survival()<br/><i>IPCW C-index, Brier, IPA, AUC</i>"]:::eval
        CT["modeling.calibration_table()<br/>+ plot_calibration() → PNG"]:::eval
        BC["modeling.bootstrap_cindex_report()<br/><i>paired Δ vs cox, 500 boots</i>"]:::eval
        PHA["modeling.cox_ph_assumptions()"]:::eval
        NV["evaluate.event_rate_by_horizon()<br/><i>naive baseline</i>"]:::eval
        DS["deep.fit_deepsurv() +<br/>evaluate_deepsurv()<br/><i>opt: --deep</i>"]:::eval
    end
    CX --> SA --> ES --> CT
    SA --> BC
    CX --> PHA
    TS --> NV
    TS --> DS

    REP[(report_dir/<br/>metrics.json,<br/>calibration_*.png)]:::data
    ES --> REP
    CT --> REP
    BC --> REP
```

---

## 5. train-competing — competing risks & transitions (`train_competing_command`)

```mermaid
flowchart TB
    classDef prep fill:#1f6feb,color:#fff,stroke:#1f6feb;
    classDef model fill:#bf3989,color:#fff,stroke:#bf3989;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    ART[(competing_risks_labels.parquet<br/>+ publication_features)]:::data
    PC["competing.prepare_competing_frame()<br/>+ modeling.time_split_frame()"]:::prep
    AJ["competing.fit_aalen_johansen()<br/><i>unbiased CIF per cause</i>"]:::model
    CIF["competing.cif_table() / cif_vs_independent()<br/><i>AJ vs inflated naive-KM</i>"]:::model
    CSC["competing.fit_cause_specific_cox()<br/>+ cause_specific_cindex()"]:::model
    SB["survboost.fit_survival_boost()<br/>+ cif_calibration_table()<br/><i>opt: --boost</i>"]:::model
    DH["deephit.fit_deephit() + evaluate_deephit()<br/><i>opt: --deep-hit</i>"]:::model
    TR["competing.transition_frame() +<br/>CoxPHFitter per PoC→{msf,nuclei,kev}<br/><i>opt: --snapshot-date, clock restart</i>"]:::model
    REP[(report_dir/<br/>competing_metrics.json,<br/>calibration_boost_*.png)]:::data

    ART --> PC --> AJ --> CIF
    PC --> CSC
    PC --> SB
    PC --> DH
    PC --> TR
    AJ --> REP
    CSC --> REP
    SB --> REP
    TR --> REP
```

---

## 6. backtest — rolling-origin walk-forward (`backtest_command` → `backtest.py`)

```mermaid
flowchart LR
    classDef prep fill:#1f6feb,color:#fff,stroke:#1f6feb;
    classDef run fill:#bf3989,color:#fff,stroke:#bf3989;
    classDef data fill:#2d333b,color:#adbac7,stroke:#444c56;

    OUT[(corpus + event parquets)]:::data
    FEAT[(publication_features.parquet)]:::data
    MO["backtest.make_origins(start,<br/>min_followup_days)<br/><i>quarter-start origins</i>"]:::prep
    ROB["backtest.rolling_origin_backtest()<br/><i>per origin: rebuild labels as-of,<br/>fit cox|xgb|cure, score next period,<br/>permutation null + recalibrate</i>"]:::run
    OM["backtest.operational_metrics()<br/><i>recall@top, lead-time-days</i>"]:::run
    REP[(report_dir/<br/>backtest_metrics.json)]:::data

    OUT --> MO --> ROB
    FEAT --> ROB
    ROB --> OM --> REP
```

Each origin only trains on what was knowable then (`label_set`, `clock_start` from
`in_wild_clock_start()`); honest walk-forward, no peeking.

---

## Module quick-reference

| Layer | Module | Role |
|---|---|---|
| **Spine** | `cli.py` | argparse + 7 `*_command()` orchestrators |
| **Fetch** | `fetch/base.py` | `Connector` ABC, `save()`, `write_fetch_manifest()` |
| | `fetch/cache.py` | `conditional_get()` ETag cache |
| | `fetch/gitmine.py` | git-history CVE mining helpers |
| | `fetch/{kev,epss,nvd,exploitdb,zeroday}.py` | HTTP connectors |
| | `fetch/{poc,nuclei,metasploit}.py` | git-mined connectors |
| | `fetch/{vulncheck,shadowserver}.py` | token/cred-gated in-wild |
| **Merge** | `merge.py` | `merge_live()` / `merge_source()` + `MERGE_SPECS` |
| **Load** | `loaders.py`, `schema.py` | parquet load + column validation |
| **Labels** | `labels.py` | 4 label builders, `published` = origin |
| **Features** | `features.py` | publication-time CVSS/CWE/CPE |
| | `attack_features.py`, `epss_features.py` | ATT&CK + EPSS-at-publication |
| | `nlp_features.py`, `text_safety.py` | masked, freshness-gated text |
| | `landmark.py`, `poc_features.py`, `presence_features.py` | post-pub / transition / snapshot |
| **Split** | `splits.py` | time-based `make_time_split()` |
| **Models** | `modeling.py` | Cox / RSF / GBM + evaluate + calibration + bootstrap |
| | `baselines.py` | Kaplan-Meier, Cox baseline |
| | `cure.py`, `xgb.py`, `deep.py`, `deephit.py`, `survboost.py` | cure / AFT / neural / competing-risk models |
| | `competing.py` | Aalen-Johansen, cause-specific Cox, transitions |
| | `calibration.py` | temperature recalibration |
| **Eval** | `evaluate.py`, `backtest.py`, `simulate.py` | descriptive stats, walk-forward, synthetic DGP |
| **Artifacts** | `artifacts.py`, `config.py` | manifest + hashes, paths |
```
