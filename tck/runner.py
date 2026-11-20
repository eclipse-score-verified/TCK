"""Run the release's platform integration tests on the vendor modules."""

import json
import pathlib
import shutil
import subprocess

from . import git
from .sbom import tck_refs


def run(baseline, ref_int, module_paths, out_dir):
    """Run the pinned Bazel test targets in a reference_integration checkout.

    Writes <out_dir>/tests.json and <out_dir>/junit/. Raises SystemExit if the
    checkout or the modules are not the ones the SBOM step saw.
    """
    out = pathlib.Path(out_dir)
    pinned = baseline["reference_integration"]["commit"]
    head = git(ref_int, "rev-parse", "HEAD")
    if head != pinned or git(ref_int, "status", "--porcelain"):
        raise SystemExit(
            f"{ref_int} must be an unmodified reference_integration checkout at {pinned[:12]} "
            f"(S-CORE {baseline['score_release']}); found {head[:12]} or local changes"
        )
    sbom = json.loads((out / "sbom.spdx.json").read_text())
    recorded = {p["name"]: tck_refs(p).get("head_commit") for p in sbom["packages"]}
    modules = {}
    for name, path in module_paths.items():
        modules[name] = git(path, "rev-parse", "HEAD")
        if name in baseline["mandatory"] and (
            modules[name] != recorded.get(name) or git(path, "status", "--porcelain")
        ):
            raise SystemExit(f"{name}: checkout differs from the one in the SBOM; run 'tck sbom' again")

    tests = baseline["tests"]
    # --lockfile_mode=off: the overrides change the module graph; bazel must not rewrite
    # MODULE.bazel.lock in the checkout that has to stay unmodified.
    cmd = ["bazel", "test", "--lockfile_mode=off", *tests["bazel_args"], *tests["targets"]] + [
        f"--override_module={name}={pathlib.Path(path).resolve()}" for name, path in module_paths.items()
    ]
    print("+", " ".join(cmd))
    exit_code = subprocess.run(cmd, cwd=ref_int).returncode

    junit = out / "junit"
    shutil.rmtree(junit, ignore_errors=True)
    logs = pathlib.Path(ref_int) / "bazel-testlogs"
    # 0 = all passed, 3 = some tests failed. Otherwise bazel did not get to the tests and
    # bazel-testlogs may still hold the results of an earlier run on other modules.
    for prefix in tests["modules"].values() if exit_code in (0, 3) else ():
        for xml in (logs / prefix).rglob("test.xml"):
            dest = junit / xml.relative_to(logs)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(xml, dest)
    (out / "tests.json").write_text(
        json.dumps(
            {"reference_integration_commit": head, "modules": modules, "bazel_exit_code": exit_code},
            indent=2,
        )
        + "\n"
    )
    return exit_code
