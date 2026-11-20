"""Is a vendor module based on exactly the S-CORE release commit, and nothing later?"""

import subprocess

from . import git


def check(path, base, upstream):
    """Return (facts, errors) for the module checkout at `path`.

    base: commit of the module in the S-CORE release. upstream: its public repo.
    Vendor commits on top of `base` are fine (cherry-picks of later upstream fixes
    included, they are new commits); merging upstream past `base` is not.
    """
    errors = []
    dirty = bool(git(path, "status", "--porcelain"))
    if dirty:
        errors.append("working tree is not clean; commit or remove local changes")
    # ponytail: assumes release tags sit on upstream main (true for all v0.10.0
    # modules); add a per-module branch to the baseline if a release is ever cut
    # from a release branch.
    git(path, "fetch", "--quiet", upstream, "main")
    # exit code 1 and no output: no common history with upstream at all
    bases = subprocess.run(
        ["git", "-C", str(path), "merge-base", "--all", "HEAD", "FETCH_HEAD"],
        capture_output=True, text=True,
    ).stdout.split()
    if bases != [base]:
        later = bases and all(
            subprocess.run(
                ["git", "-C", str(path), "merge-base", "--is-ancestor", base, b]
            ).returncode == 0
            for b in bases
        )
        errors.append(
            f"contains upstream commits later than the release ({base[:12]})"
            if later
            else f"not based on the release commit {base[:12]} (common ancestor with upstream: "
            f"{', '.join(b[:12] for b in bases) or 'none'})"
        )
    # The facts are what was found, not what was expected: the verdict is derived from them.
    facts = {
        "base_commit": " ".join(bases) or "none",
        "head_commit": git(path, "rev-parse", "HEAD") + ("-dirty" if dirty else ""),
        "commits_ahead": int(git(path, "rev-list", "--count", f"{base}..HEAD")),
    }
    return facts, errors
