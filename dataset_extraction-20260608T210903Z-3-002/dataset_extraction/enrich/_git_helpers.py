"""Shared helpers for git-history mining scripts.

Approach: clone the upstream repo with `--filter=blob:none --no-checkout` for
speed, then drive the walking via `git log` rather than checking files out.

Authentication: GITHUB_TOKEN is read from dataset_extraction/.env (loaded
automatically on import) or the shell environment, and passed to `git clone`
as a bearer token via `-c http.extraheader`. Unauthenticated clones work but
hit GitHub's anonymous rate limits on the bigger repos (Nomi-sec PoC in
particular).
"""
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv

# Load dataset_extraction/.env once at import time. override=False means an
# already-exported GITHUB_TOKEN wins over the file (useful for CI).
load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)


def _authenticated_url(url: str) -> tuple[str, bool]:
    """Inject GITHUB_TOKEN as the password in github.com HTTPS URLs.

    Returns (url_to_use, was_authenticated). The caller is expected to reset
    the remote after cloning so the token does not persist in .git/config.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token or not url.startswith("https://github.com/"):
        return url, False
    return url.replace(
        "https://github.com/",
        f"https://x-access-token:{token}@github.com/",
        1,
    ), True


def normalise_cve(text: str) -> str | None:
    m = CVE_RE.search(text)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def shallow_clone(
    repo_url: str,
    dest: Path,
    *,
    depth: int | None = None,
    with_blobs: bool = False,
) -> None:
    """Clone (or refresh) a repo.

    Always uses `--no-checkout`: blobs needed for `git log` / `git grep` live in
    `.git/objects/pack/` and don't need to be extracted to the working tree.
    Critically, this prevents corporate AV from quarantining files in repos
    that ship exploit payloads (e.g. rapid7/metasploit-framework's
    `data/SqlClrPayload/`, `data/evasion/`, `data/exploits/`, `data/eicar.com`).
    Those payloads are real malware artefacts that any AV will detect; they
    only become visible to AV scanners if they get extracted to disk.

    `with_blobs=False` (default) additionally uses `--filter=blob:none` so
    blobs aren't even downloaded — fine for consumers that only need filenames
    + commit timestamps (Nuclei, Trickest, Nomi-sec).

    `with_blobs=True` downloads all blobs locally (kept in packfiles, not
    extracted) so `git grep` and `git log -G` can read file contents from the
    object store. Used by the Metasploit miner.
    """
    authed_url, was_authed = _authenticated_url(repo_url)
    if was_authed:
        log.info("using GITHUB_TOKEN from env for authenticated git access")
    if dest.exists() and (dest / ".git").exists():
        log.info("repo exists at %s — fetching latest", dest)
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--all"],
            check=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        return
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--no-checkout"]
    if not with_blobs:
        cmd += ["--filter=blob:none"]
    if depth is not None:
        cmd += ["--depth", str(depth)]
    cmd += [authed_url, str(dest)]
    log.info("cloning %s → %s (with_blobs=%s, no-checkout)", repo_url, dest, with_blobs)
    subprocess.run(cmd, check=True, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if was_authed:
        subprocess.run(
            ["git", "-C", str(dest), "remote", "set-url", "origin", repo_url],
            check=True,
        )


def first_add_dates(repo: Path, paths: Iterable[str] | None = None) -> dict[str, int]:
    """Return {path: first_add_unix_timestamp} via a single `git log --diff-filter=A` walk.

    If `paths` is provided, restrict to that subtree (e.g. "modules/exploits/").
    """
    cmd = [
        "git", "-C", str(repo), "log", "--all", "--diff-filter=A", "--no-renames",
        "--name-only", "--format=COMMIT %at",
    ]
    if paths:
        cmd += ["--"] + list(paths)
    log.info("walking git history: %s", " ".join(cmd[:8]) + " …")
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    earliest: dict[str, int] = {}
    current_ts: int | None = None
    for line in result.stdout.splitlines():
        if line.startswith("COMMIT "):
            current_ts = int(line.split(" ", 1)[1])
            continue
        if not line or current_ts is None:
            continue
        prev = earliest.get(line)
        if prev is None or current_ts < prev:
            earliest[line] = current_ts
    log.info("walked %d unique paths", len(earliest))
    return earliest


def file_content_at_head(repo: Path, path: str) -> str | None:
    """Read file content at HEAD without a working-tree checkout. Returns None if missing.

    Note: spawns a git process per call. For bulk scans of many files, prefer
    `grep_cve_refs` below, which runs a single git grep across the whole subtree.
    """
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"HEAD:{path}"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def cves_in_text(text: str) -> set[str]:
    return {f"CVE-{m.group(1)}-{m.group(2)}" for m in CVE_RE.finditer(text or "")}


def grep_cve_refs(repo: Path, paths: Iterable[str]) -> dict[str, set[str]]:
    """Bulk-extract CVE references from HEAD via a single `git grep`.

    Returns {path: {CVE-YYYY-NNNNN, …}}. Vastly faster than per-file
    `git show` for repos with thousands of source files (single git process,
    streams matches from the packed index).
    """
    cmd = [
        "git", "-C", str(repo), "grep",
        "--no-color", "--full-name", "-h", "-I",
        "-E", r"CVE-[0-9]{4}-[0-9]{4,7}",
        "HEAD", "--", *paths,
    ]
    # -h suppresses filename prefixes, but we need them — drop -h and parse below.
    cmd.remove("-h")
    log.info("running git grep across %s", list(paths))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):  # 1 = no matches; fine
        log.warning("git grep exited %s: %s", result.returncode, result.stderr.strip())
        return {}

    per_path: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        # Format: HEAD:<path>:<matched line>
        if not line.startswith("HEAD:"):
            continue
        _, rest = line.split(":", 1)
        if ":" not in rest:
            continue
        path, content = rest.split(":", 1)
        for cve in cves_in_text(content):
            per_path.setdefault(path, set()).add(cve)
    log.info("git grep matched %d files containing CVE refs", len(per_path))
    return per_path
