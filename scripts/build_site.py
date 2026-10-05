#!/usr/bin/env python3
"""Assemble the static Casebench website (browser-only mode) for GitHub Pages or any static host.

    python3 scripts/build_site.py                 # writes _site/
    python3 -m http.server 8000 --bind 127.0.0.1 --directory _site

The site has no backend: keys and events go from the visitor's browser straight to TypeSafe and
OpenRouter (see site/index.html for the connection policy that enforces it).
"""

import argparse
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = "https://github.com/tsale/jev-incident-timeline"


def repository_url():
    """The repository the site is built from: GitHub Actions' own repo, else the git remote."""
    if os.environ.get("GITHUB_REPOSITORY"):
        return f'{os.environ.get("GITHUB_SERVER_URL", "https://github.com")}/{os.environ["GITHUB_REPOSITORY"]}'
    try:
        remote = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return DEFAULT_REPO
    remote = re.sub(r"^git@([^:]+):", r"https://\1/", remote)
    remote = re.sub(r"^https://[^@/]+@", "https://", remote)  # Never publish credentials embedded in a remote URL.
    return remote[:-4] if remote.endswith(".git") else remote


def build(out, repo_url):
    if out.exists():
        shutil.rmtree(out)
    (out / "examples").mkdir(parents=True)
    page = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    (out / "index.html").write_text(page.replace("{{REPO_URL}}", html.escape(repo_url, quote=True)), encoding="utf-8")
    for name in ("app.js", "engine.js", "styles.css"):
        shutil.copyfile(ROOT / "ui" / name, out / name)
    # Loaded as a script, so the page's connection policy needs no access to its own host.
    example = json.loads((ROOT / "examples" / "malicious_events.json").read_text(encoding="utf-8"))
    (out / "examples" / "malicious_events.js").write_text(
        "window.CASEBENCH_EXAMPLE = " + json.dumps(example, ensure_ascii=False, separators=(",", ":")) + ";\n", encoding="utf-8")
    return sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "_site", help="output directory (replaced; default: _site)")
    parser.add_argument("--repo-url", help="link to the source code shown on the page (default: this repository)")
    args = parser.parse_args()
    url = args.repo_url or repository_url()
    if not re.fullmatch(r"https://[^\s\"'<>]+", url):
        parser.error(f"--repo-url must be an https URL, got {url!r}")
    files = build(args.out.resolve(), url)
    print(f"Built {len(files)} files into {args.out} (source link: {url}): {', '.join(files)}")


if __name__ == "__main__":
    main()
