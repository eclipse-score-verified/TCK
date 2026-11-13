# S-CORE verification process

A verification is always for one S-CORE release, for example "verified for
S-CORE v0.10.0". Diagram: [process.drawio](process.drawio).

## Who does what

| Party | Does | Sees vendor source |
|---|---|---|
| S-CORE upstream | Publishes the `reference_integration` release and its product SBOM | no |
| TCK (this repo) | Pins the release in `baselines/vX.Y.json`, ships the `tck` tool | no |
| Vendor | Runs `tck sbom`, `tck test`, `tck bundle` on their stack, sends the bundle | yes |
| S-CORE Verified | Runs `tck verify` on the bundle | no |

## What is checked

**Based on the release version, not later.** For each module, the release SBOM
gives a commit `B` in the public upstream repository. The vendor checkout passes
when the only common ancestor of its `HEAD` and upstream `main` is `B`, and the
working tree is clean. So:

- own commits on top of `B`: allowed
- cherry-picks of later upstream fixes: allowed (they are new commits)
- upstream merged in past `B`, or a base older than `B`: rejected

Mandatory modules must pass. Other S-CORE modules are checked if given and only reported.

**Platform integration tests.** The test targets listed in the baseline are run
with Bazel from an unmodified `reference_integration` checkout at the release
commit, with the vendor modules passed as `--override_module`. A mandatory module
with no platform test in that release is reported as a gap, not as passed.

The release tags alone do not build these tests: `reference_integration` applies
its own patches (`patches/<module>/`) to every module. A vendor module must carry
them as commits on top of the release commit.

Every step writes its evidence also when it fails, so a failed run still ends in
a signed NON-CONFORMANT report.

**Binding.** The test step refuses to run if a module differs from the commit
recorded in the SBOM. The bundle lists the sha256 of every file and is signed.

## Vendor steps

Needed: the module git repositories (with upstream history), a
`reference_integration` checkout at the release tag, Bazel, and network access
to the public upstream repositories (the tool fetches upstream `main` to compare).

```sh
python3 -m tck sbom --baseline baselines/v0.10.0.json --baseline-sbom score-v0.10.0.spdx.json \
    --module score_baselibs=../baselibs --module score_communication=../communication \
    --module score_logging=../logging --module score_lifecycle=../lifecycle \
    --module score_persistency=../persistency --module score_time=../time

python3 -m tck test --baseline baselines/v0.10.0.json --baseline-sbom score-v0.10.0.spdx.json \
    --ref-int ../reference_integration   # plus the same --module options

python3 -m tck bundle --baseline baselines/v0.10.0.json --baseline-sbom score-v0.10.0.spdx.json \
    --key ~/.ssh/id_ed25519
```

With Bazel, `bazel run //:cli --` replaces `python3 -m tck` in every command here.

`score-v0.10.0.spdx.json` is the product SBOM of the S-CORE release. `tck sbom
--product-sbom <file>` annotates an existing full SBOM instead of writing one
that lists the S-CORE modules only.

Send the `tck-out/` directory. It contains:

| File | Content |
|---|---|
| `sbom.spdx.json` | SPDX 2.3. Each S-CORE module package has `versionInfo` = release version and `externalRefs` `score-tck-base-commit`, `score-tck-head-commit`, `score-tck-commits-ahead` |
| `junit/` | Bazel `test.xml` files of the platform integration tests |
| `tests.json` | `reference_integration` commit, tested module commits, Bazel exit code |
| `report.json`, `summary.md` | Verdict per module, TCK version and hash, baseline SBOM hash |
| `manifest.sha256`, `manifest.sha256.sig` | Hash of every file above, signed with the vendor's SSH key |

Commit hashes are the only thing in the bundle that comes from the private repositories.

## Verifier steps

The vendor's public key is registered in an OpenSSH `allowed_signers` file
(`<identity> <public key>`).

```sh
python3 -m tck verify --baseline baselines/v0.10.0.json --baseline-sbom score-v0.10.0.spdx.json \
    --out <bundle dir> --allowed-signers allowed_signers --identity vendor@example.com
```

`verify` checks the signature and the manifest, then recomputes the verdict from
the SBOM and JUnit files; the vendor's own `report.json` is not trusted. It must
be run with the same TCK version that produced the bundle.

## Adding an S-CORE release

Add `baselines/vX.Y.json`: release tag commit, URL and sha256 of the product SBOM
release asset, mandatory modules, test targets, the `bazel-testlogs` directory of
each module's tests, and known gaps. Module versions and commits are read from the
SBOM, where each S-CORE module package must have
`downloadLocation: git+<repo url>@<commit>`.

## Trust model

Reports are self-attested: the vendor runs the tools and signs the result. The
signature and hashes make the claim attributable and tamper-evident; they do not
prove the run happened as described.
