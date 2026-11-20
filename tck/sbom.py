"""Generate the vendor SBOM (SPDX 2.3) with the git facts of each S-CORE module."""

import datetime
import json
import pathlib
import uuid

from . import __version__, gitcheck

REF_PREFIX = "score-tck-"


def tck_refs(pkg):
    """The facts this tool recorded on an SPDX package, e.g. {'base_commit': ...}."""
    return {
        r["referenceType"][len(REF_PREFIX):].replace("-", "_"): r["referenceLocator"]
        for r in pkg.get("externalRefs", [])
        if r["referenceType"].startswith(REF_PREFIX)
    }


def generate(baseline, module_paths, out_dir, product_sbom=None):
    """Check every module, write <out_dir>/sbom.spdx.json. Returns a list of errors.

    The SBOM is written also when a module fails: it records what was found, so
    the later steps still run and the report shows the failure.

    product_sbom: SPDX file built by the vendor with S-CORE's own generator
    (`bazel build //:sbom`); its S-CORE module packages get annotated. Without it
    the SBOM lists the S-CORE modules only.
    """
    if product_sbom:
        doc = json.loads(pathlib.Path(product_sbom).read_text())
    else:
        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "SBOM for S-CORE verification",
            "documentNamespace": f"https://eclipse.dev/score/spdx/tck-{uuid.uuid4()}",
            "packages": [],
            "relationships": [],
        }
    doc["creationInfo"] = {
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creators": doc.get("creationInfo", {}).get("creators", []) + [f"Tool: score-tck-{__version__}"],
    }

    errors = [f"{m}: mandatory module not provided" for m in baseline["mandatory"] if m not in module_paths]
    for name, path in module_paths.items():
        ref = baseline["modules"].get(name)
        if not ref:
            errors.append(f"{name}: not a module of S-CORE {baseline['score_release']}")
            continue
        facts, problems = gitcheck.check(path, ref["commit"], ref["repo"])
        if problems:
            if name in baseline["mandatory"]:
                errors += [f"{name}: {p}" for p in problems]
            else:
                print(f"warning: optional module {name} not verified: {'; '.join(problems)}")
        pkg = next((p for p in doc["packages"] if p["name"] == name), None)
        if pkg is None:
            pkg = {
                "SPDXID": f"SPDXRef-{name.replace('_', '-')}",
                "name": name,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:generic/{name}@{ref['version']}",
                    }
                ],
            }
            doc["packages"].append(pkg)
        if not problems:
            pkg["versionInfo"] = ref["version"]
        pkg.setdefault("versionInfo", "NOASSERTION")
        pkg["externalRefs"] = [
            r for r in pkg.get("externalRefs", []) if not r["referenceType"].startswith(REF_PREFIX)
        ] + [
            {
                "referenceCategory": "OTHER",
                "referenceType": REF_PREFIX + key.replace("_", "-"),
                "referenceLocator": str(value),
            }
            for key, value in facts.items()
        ]

    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "sbom.spdx.json").write_text(json.dumps(doc, indent=2) + "\n")
    return errors
