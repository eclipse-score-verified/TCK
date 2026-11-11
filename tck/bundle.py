"""Evaluate the collected evidence, sign it (vendor), check it (S-CORE Verified)."""

import json
import pathlib
import subprocess
import xml.etree.ElementTree as ET

from . import MANIFEST, SIG_NAMESPACE, __version__, sha256, tool_sha256
from .sbom import tck_refs

SIG = MANIFEST + ".sig"


def _junit(junit_dir, prefix):
    """(number of test cases, number failed) below junit/<prefix>."""
    total = failed = 0
    for xml in (junit_dir / prefix).rglob("test.xml"):
        for case in ET.parse(xml).getroot().iter("testcase"):
            total += 1
            failed += case.find("failure") is not None or case.find("error") is not None
    return total, failed


def evaluate(out_dir, baseline):
    """Re-derive the verdict from sbom.spdx.json, tests.json and junit/ against the baseline."""
    out = pathlib.Path(out_dir)
    packages = {p["name"]: p for p in json.loads((out / "sbom.spdx.json").read_text())["packages"]}
    tests = json.loads((out / "tests.json").read_text())
    errors = []
    if tests["reference_integration_commit"] != baseline["reference_integration"]["commit"]:
        errors.append("tests were not run from the pinned reference_integration release commit")
    # 0 = all passed, 3 = some tests failed (junit says which); anything else: no trustworthy results
    if tests["bazel_exit_code"] not in (0, 3):
        errors.append(f"bazel test did not complete (exit code {tests['bazel_exit_code']})")

    modules = {}
    for name, ref in baseline["modules"].items():
        mandatory = name in baseline["mandatory"]
        facts = tck_refs(packages.get(name, {}))
        if not facts:
            if mandatory:
                errors.append(f"{name}: mandatory module missing from the SBOM")
            continue
        entry = {"mandatory": mandatory, "version": packages[name].get("versionInfo"), **facts}
        problems = []
        if entry["version"] != ref["version"] or facts.get("base_commit") != ref["commit"]:
            problems.append(
                f"not based on the release commit {ref['commit'][:12]} "
                f"(common ancestor with upstream: {facts.get('base_commit')})"
            )
        if str(facts.get("head_commit")).endswith("-dirty"):
            problems.append("working tree was not clean")
        if tests["modules"].get(name) != facts.get("head_commit"):
            problems.append("tested commit differs from the SBOM")
        prefix = baseline["tests"]["modules"].get(name)
        if name in baseline["gaps"]:
            entry["test"] = "gap: " + baseline["gaps"][name]
        elif prefix:
            total, failed = _junit(out / "junit", prefix)
            entry["test"] = f"{total - failed}/{total} passed"
            if total == 0 or failed:
                problems.append("platform integration tests failed or did not run")
        else:
            entry["test"] = "none defined"
        entry["status"] = "fail" if problems else "pass"
        if problems and mandatory:
            errors += [f"{name}: {p}" for p in problems]
        elif problems:
            entry["status"] = "not verified: " + "; ".join(problems)
        modules[name] = entry

    return {
        "tck_version": __version__,
        "tck_sha256": tool_sha256(),
        "score_release": baseline["score_release"],
        "baseline_sbom_sha256": baseline["sbom_sha256"],
        "reference_integration_commit": tests["reference_integration_commit"],
        "verdict": "NON-CONFORMANT" if errors else "CONFORMANT",
        "errors": errors,
        "modules": modules,
    }


def _summary(report):
    lines = [
        f"# S-CORE {report['score_release']} verification report",
        "",
        f"**Verdict: {report['verdict']}** (TCK {report['tck_version']})",
        "",
        "| Module | Mandatory | Version | Commits on top | SBOM + binding | Platform tests |",
        "|---|---|---|---|---|---|",
    ]
    for name, m in report["modules"].items():
        lines.append(
            f"| {name} | {'yes' if m['mandatory'] else 'no'} | {m['version']} | "
            f"{m.get('commits_ahead', '?')} | {m['status']} | {m['test']} |"
        )
    lines += ["", *[f"- {e}" for e in report["errors"]]]
    return "\n".join(lines) + "\n"


def _files(out):
    return sorted(
        p.relative_to(out).as_posix()
        for p in out.rglob("*")
        if p.is_file() and p.name not in (MANIFEST, SIG)
    )


def bundle(out_dir, baseline, key):
    """Write report.json, summary.md and a signed manifest into out_dir. Returns the report."""
    out = pathlib.Path(out_dir)
    report = evaluate(out, baseline)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / "summary.md").write_text(_summary(report))
    (out / MANIFEST).write_text("".join(f"{sha256(out / f)}  {f}\n" for f in _files(out)))
    (out / SIG).unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", SIG_NAMESPACE, str(out / MANIFEST)],
        check=True,
    )
    return report


def verify(bundle_dir, baseline, allowed_signers, identity):
    """Check a vendor bundle. Returns (report, errors); CONFORMANT only if errors is empty."""
    out = pathlib.Path(bundle_dir)
    errors = []
    signature = subprocess.run(
        ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", identity,
         "-n", SIG_NAMESPACE, "-s", str(out / SIG)],
        input=(out / MANIFEST).read_bytes(),
        capture_output=True,
    )
    if signature.returncode != 0:
        errors.append(f"signature is not valid for '{identity}'")
    listed = dict(line.split("  ", 1)[::-1] for line in (out / MANIFEST).read_text().splitlines())
    if set(listed) != set(_files(out)):
        errors.append("bundle content differs from the signed manifest")
    errors += [f"{f}: content differs from the signed manifest" for f in listed
               if (out / f).is_file() and sha256(out / f) != listed[f]]

    try:
        report = evaluate(out, baseline)  # never trust the vendor's own report.json
        claimed = json.loads((out / "report.json").read_text())
    except (OSError, ValueError, KeyError) as e:
        return {"verdict": "NON-CONFORMANT", "errors": errors}, errors + [f"evidence is unreadable: {e}"]
    if claimed.get("tck_sha256") != report["tck_sha256"]:
        errors.append("bundle was produced with a different TCK version than the one verifying it")
    errors += report["errors"]
    report["errors"] = errors
    report["verdict"] = "NON-CONFORMANT" if errors else "CONFORMANT"
    return report, errors
