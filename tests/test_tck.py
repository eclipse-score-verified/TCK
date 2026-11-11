"""End-to-end checks on throwaway git repos: python3 -m unittest discover tests"""

import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
import unittest.mock

from tck import bundle, git, gitcheck, load_baseline, runner, sbom, sha256

MODULES = ["score_a", "score_b"]  # both mandatory in the test baseline
JUNIT_OK = '<testsuites><testsuite><testcase name="t"/></testsuite></testsuites>'
JUNIT_FAIL = '<testsuites><testsuite><testcase name="t"><failure/></testcase></testsuite></testsuites>'
FAKE_BAZEL = """#!/bin/sh
for m in a b; do
  mkdir -p bazel-testlogs/pit/$m/test && echo '%s' > bazel-testlogs/pit/$m/test/test.xml
done
"""


def commit(repo, name):
    (pathlib.Path(repo) / name).write_text(name)
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


class TckTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        packages = []
        self.upstream, self.vendor, self.commits = {}, {}, {}
        for name in MODULES:
            up = self.tmp / "upstream" / name
            up.mkdir(parents=True)
            git(up, "init", "-q", "-b", "main")
            older, release, later = commit(up, "older"), commit(up, "release"), commit(up, "later")
            self.commits[name] = {"older": older, "release": release, "later": later}
            vendor = self.tmp / "vendor" / name
            subprocess.run(["git", "clone", "-q", str(up), str(vendor)], check=True)
            git(vendor, "checkout", "-q", release)
            self.upstream[name], self.vendor[name] = up, vendor
            packages.append({"name": name, "versionInfo": "1.0.0", "downloadLocation": f"git+{up}@{release}"})

        self.ref_int = self.tmp / "ref_int"
        self.ref_int.mkdir()
        git(self.ref_int, "init", "-q", "-b", "main")
        (self.ref_int / ".gitignore").write_text("bazel-testlogs\n")
        ref_int_commit = commit(self.ref_int, "tests")

        self.baseline_sbom = self.tmp / "baseline.spdx.json"
        self.baseline_sbom.write_text(json.dumps({"packages": packages}))
        self.baseline_file = self.tmp / "baseline.json"
        self.baseline_file.write_text(json.dumps({
            "score_release": "vTEST",
            "reference_integration": {"commit": ref_int_commit},
            "sbom": {"sha256": sha256(self.baseline_sbom)},
            "mandatory": MODULES,
            "tests": {"bazel_args": [], "targets": ["//pit"], "modules": {"score_a": "pit/a"}},
            "gaps": {"score_b": "no test"},
        }))
        self.baseline = load_baseline(self.baseline_file, self.baseline_sbom)
        self.out = self.tmp / "out"

        self.key = self.tmp / "key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        self.signers = self.tmp / "allowed_signers"
        self.signers.write_text("vendor@example.com " + self.key.with_suffix(".pub").read_text())

    def check(self, name="score_a"):
        return gitcheck.check(self.vendor[name], self.commits[name]["release"], self.upstream[name])[1]

    def fake_bazel(self, junit=JUNIT_OK):
        bindir = self.tmp / "bin"
        bindir.mkdir(exist_ok=True)
        script = bindir / "bazel"
        script.write_text(FAKE_BAZEL % junit)
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        patch = unittest.mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}"})
        patch.start()
        self.addCleanup(patch.stop)

    def make_bundle(self, junit=JUNIT_OK):
        self.assertEqual(sbom.generate(self.baseline, self.vendor, self.out), [])
        self.fake_bazel(junit)
        runner.run(self.baseline, self.ref_int, self.vendor, self.out)
        return bundle.bundle(self.out, self.baseline, self.key)

    def verify(self, signers=None):
        return bundle.verify(self.out, self.baseline, signers or self.signers, "vendor@example.com")[1]

    # --- "same version, not later" ---

    def test_release_commit_and_vendor_commits_on_top_pass(self):
        self.assertEqual(self.check(), [])
        commit(self.vendor["score_a"], "vendor-change")
        facts, errors = gitcheck.check(
            self.vendor["score_a"], self.commits["score_a"]["release"], self.upstream["score_a"])
        self.assertEqual((errors, facts["commits_ahead"]), ([], 1))

    def test_cherry_pick_of_later_upstream_fix_passes(self):
        commit(self.vendor["score_a"], "vendor-change")
        git(self.vendor["score_a"], "-c", "user.name=t", "-c", "user.email=t@t",
            "cherry-pick", self.commits["score_a"]["later"])
        self.assertEqual(self.check(), [])

    def test_later_upstream_merged_fails(self):
        git(self.vendor["score_a"], "checkout", "-q", self.commits["score_a"]["later"])
        self.assertIn("later than the release", self.check()[0])

    def test_older_base_fails(self):
        git(self.vendor["score_a"], "checkout", "-q", self.commits["score_a"]["older"])
        self.assertIn("not based on the release commit", self.check()[0])

    def test_dirty_tree_fails(self):
        (self.vendor["score_a"] / "uncommitted").write_text("x")
        self.assertIn("not clean", self.check()[0])

    # --- SBOM ---

    def test_missing_mandatory_module_fails(self):
        errors = sbom.generate(self.baseline, {"score_a": self.vendor["score_a"]}, self.out)
        self.assertEqual(errors, ["score_b: mandatory module not provided"])

    def test_wrong_base_still_runs_every_step_and_is_non_conformant(self):
        git(self.vendor["score_a"], "checkout", "-q", self.commits["score_a"]["older"])
        self.assertTrue(sbom.generate(self.baseline, self.vendor, self.out))
        self.fake_bazel()
        runner.run(self.baseline, self.ref_int, self.vendor, self.out)
        report = bundle.bundle(self.out, self.baseline, self.key)
        self.assertEqual(report["verdict"], "NON-CONFORMANT")
        self.assertIn("score_a: not based on the release commit", self.verify()[0])

    def test_unrelated_history_is_reported_not_a_crash(self):
        git(self.vendor["score_a"], "checkout", "-q", "--orphan", "own")
        commit(self.vendor["score_a"], "own")
        self.assertIn("common ancestor with upstream: none", self.check()[0])

    def test_product_sbom_is_annotated_not_replaced(self):
        product = self.tmp / "product.spdx.json"
        product.write_text(json.dumps({"packages": [
            {"name": "serde", "versionInfo": "1.0"}, {"name": "score_a", "versionInfo": "unknown"}]}))
        self.assertEqual(sbom.generate(self.baseline, self.vendor, self.out, product), [])
        packages = {p["name"]: p for p in json.loads((self.out / "sbom.spdx.json").read_text())["packages"]}
        self.assertEqual(set(packages), {"serde", "score_a", "score_b"})
        self.assertEqual(packages["score_a"]["versionInfo"], "1.0.0")
        self.assertEqual(sbom.tck_refs(packages["score_a"])["base_commit"], self.commits["score_a"]["release"])

    def test_unpinned_or_wrong_baseline_sbom_is_refused(self):
        with self.assertRaises(SystemExit):  # the shipped v0.10.0 baseline has no SBOM pinned yet
            load_baseline("baselines/v0.10.0.json", "tests/fixtures/v0.10.0-baseline.spdx.json")
        self.baseline_sbom.write_text(json.dumps({"packages": []}))
        with self.assertRaises(SystemExit):
            load_baseline(self.baseline_file, self.baseline_sbom)

    # --- tests + bundle + verify ---

    def test_full_flow_is_conformant(self):
        report = self.make_bundle()
        self.assertEqual((report["verdict"], report["errors"]), ("CONFORMANT", []))
        self.assertEqual(report["modules"]["score_a"]["test"], "1/1 passed")
        self.assertEqual(report["modules"]["score_b"]["test"], "gap: no test")
        self.assertEqual(self.verify(), [])

    def test_failing_platform_test_is_non_conformant(self):
        self.assertEqual(self.make_bundle(JUNIT_FAIL)["verdict"], "NON-CONFORMANT")
        self.assertTrue(self.verify())

    def test_results_of_an_earlier_run_are_not_collected_when_the_build_fails(self):
        self.make_bundle()
        (self.tmp / "bin" / "bazel").write_text("#!/bin/sh\nexit 1\n")
        runner.run(self.baseline, self.ref_int, self.vendor, self.out)
        report = bundle.bundle(self.out, self.baseline, self.key)
        self.assertIn("score_a: platform integration tests failed or did not run", report["errors"])

    def test_modified_reference_integration_is_refused(self):
        sbom.generate(self.baseline, self.vendor, self.out)
        (self.ref_int / "tests").write_text("edited")
        with self.assertRaises(SystemExit):
            runner.run(self.baseline, self.ref_int, self.vendor, self.out)

    def test_module_changed_after_sbom_is_refused(self):
        sbom.generate(self.baseline, self.vendor, self.out)
        commit(self.vendor["score_a"], "sneaky")
        with self.assertRaises(SystemExit):
            runner.run(self.baseline, self.ref_int, self.vendor, self.out)

    def test_tampered_bundle_fails(self):
        self.make_bundle()
        (self.out / "junit/pit/a/test/test.xml").write_text(JUNIT_OK + " ")
        self.assertIn("junit/pit/a/test/test.xml: content differs from the signed manifest", self.verify())
        (self.out / "junit/pit/a/extra.xml").write_text(JUNIT_OK)
        self.assertIn("bundle content differs from the signed manifest", self.verify())
        (self.out / "sbom.spdx.json").write_text("not json")
        self.assertIn("evidence is unreadable", self.verify()[-1])

    def test_unregistered_key_fails(self):
        self.make_bundle()
        other = self.tmp / "other"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True)
        signers = self.tmp / "other_signers"
        signers.write_text("vendor@example.com " + other.with_suffix(".pub").read_text())
        self.assertIn("signature is not valid for 'vendor@example.com'", self.verify(signers))

    def test_tested_commit_must_match_sbom(self):
        self.make_bundle()
        tests = json.loads((self.out / "tests.json").read_text())
        tests["modules"]["score_a"] = "0" * 40
        (self.out / "tests.json").write_text(json.dumps(tests))
        self.assertIn("score_a: tested commit differs from the SBOM", self.verify())


if __name__ == "__main__":
    unittest.main()
