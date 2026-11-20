"""S-CORE Verified TCK: shared helpers."""

import hashlib
import json
import pathlib
import re
import subprocess

__version__ = "0.1.0"

MANIFEST = "manifest.sha256"
SIG_NAMESPACE = "score-tck"


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def tool_sha256():
    """Hash of the TCK sources, so a report names the exact tool that produced it."""
    h = hashlib.sha256()
    for f in sorted(pathlib.Path(__file__).parent.glob("*.py")):
        h.update(f.name.encode() + b"\0" + f.read_bytes())
    return h.hexdigest()


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def load_baseline(baseline_path, sbom_path):
    """Load baselines/vX.Y.json and the S-CORE product SBOM it pins.

    The SBOM is the only source of module versions and commits; it must match
    the pinned sha256.
    """
    baseline = json.loads(pathlib.Path(baseline_path).read_text())
    pin = baseline["sbom"]["sha256"]
    if not pin:
        raise SystemExit(
            f"S-CORE {baseline['score_release']}: no product SBOM pinned in {baseline_path} "
            "(upstream has not published one yet); no verdict can be issued."
        )
    if sha256(sbom_path) != pin:
        raise SystemExit(f"{sbom_path} does not match the sha256 pinned in {baseline_path}")
    modules = {}
    for pkg in json.loads(pathlib.Path(sbom_path).read_text())["packages"]:
        # SPDX VCS location: git+<repo url>@<commit>
        m = re.fullmatch(r"git\+(.+)@([0-9a-f]{40})", pkg.get("downloadLocation", ""))
        if m:
            modules[pkg["name"]] = {"version": pkg["versionInfo"], "repo": m[1], "commit": m[2]}
    missing = sorted(set(baseline["mandatory"]) - set(modules))
    if missing:
        raise SystemExit(f"baseline SBOM has no commit for mandatory module(s): {', '.join(missing)}")
    baseline["modules"] = modules
    baseline["sbom_sha256"] = pin
    return baseline
