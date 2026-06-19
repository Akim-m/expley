"""Live health-check: attempt every source connector and report ok/fail/blocked."""
import os
import time
from datetime import date, timedelta
from pathlib import Path

from temporal_exploit.fetch.epss import EpssConnector
from temporal_exploit.fetch.exploitdb import ExploitDbConnector
from temporal_exploit.fetch.kev import KevConnector
from temporal_exploit.fetch.nuclei import NucleiConnector
from temporal_exploit.fetch.nvd import NvdConnector
from temporal_exploit.fetch.poc import PocConnector
from temporal_exploit.fetch.shadowserver import ShadowserverConnector
from temporal_exploit.fetch.vulncheck import VulncheckKevConnector
from temporal_exploit.fetch.zeroday import ZerodayConnector


def check(name, fn):
    t = time.time()
    try:
        df = fn()
        n = len(df)
        cols = list(df.columns)
        print(f"  OK    {name:14} rows={n:>7}  {time.time()-t:5.1f}s  cols={cols}", flush=True)
    except Exception as exc:
        print(f"  FAIL  {name:14} {type(exc).__name__}: {str(exc)[:90]}  {time.time()-t:5.1f}s",
              flush=True)


y = (date.today() - timedelta(days=1)).isoformat()
yy = (date.today() - timedelta(days=2)).isoformat()

print("== HTTP keyless ==", flush=True)
check("kev", lambda: KevConnector().fetch())
check("google_0day", lambda: ZerodayConnector().fetch())
check("exploitdb", lambda: ExploitDbConnector().fetch())


def _epss():
    try:
        return EpssConnector().fetch(y)
    except Exception:
        return EpssConnector().fetch(yy)


check("epss", _epss)
check("nvd", lambda: NvdConnector().fetch(y, date.today().isoformat()))

print("== git-mined (incremental on existing clone) ==", flush=True)
check("nuclei", lambda: NucleiConnector().fetch(Path("nuclei")))
check("poc", lambda: PocConnector().fetch(Path("poc")))

print("== credential-gated ==", flush=True)
check("vulncheck_kev", lambda: VulncheckKevConnector().fetch(os.environ.get("VULNCHECK_API_TOKEN", "")))
check("shadowserver", lambda: ShadowserverConnector().fetch())
print("done", flush=True)
