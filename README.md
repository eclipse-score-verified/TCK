# TCK

Eclipse S-CORE Verified - Technology Compatibility Kit (TCK)

Tools a company runs on its own S-CORE based stack to become **S-CORE verified**
for one S-CORE release. Source code never leaves the company; only a signed
report bundle is sent.

Two checks, both bound to one `reference_integration` release:

1. **SBOM** - the mandatory modules (`score_baselibs`, `score_communication`,
   `score_logging`, `score_lifecycle`, `score_persistency`, `score_time`) are
   based on exactly the version in the S-CORE release. Own commits on top are
   allowed; anything later from upstream is not.
2. **Tests** - the release's platform integration tests pass on those modules.

```
python3 -m tck sbom   ...   # vendor: check module ancestry, write the SBOM
python3 -m tck test   ...   # vendor: run the platform integration tests
python3 -m tck bundle ...   # vendor: write and sign the report bundle
python3 -m tck verify ...   # S-CORE Verified: check a received bundle
```

Process, commands and the report format: [docs/process.md](docs/process.md).
Diagram: [docs/process.drawio](docs/process.drawio).

Requires Python 3.9+, git and OpenSSH 8.1+ (`ssh-keygen -Y`); no other dependencies.

## Bazel

| | Bazel | Plain Python |
|---|---|---|
| Build | `bazel build //...` | - |
| Test | `bazel test //...` | `python3 -m unittest discover tests` |
| Run | `bazel run //:cli -- sbom ...` | `python3 -m tck sbom ...` |

Both forms are the same tool and accept each other's bundles. Under `bazel run`,
paths are relative to the directory the command is called from. Another Bazel
module can use `@score_tck//:cli` and `@score_tck//:baselines`.

## Status

`baselines/v0.10.0.json` has no product SBOM pinned, because S-CORE v0.10.0 does
not publish one with module commits. Until it does, the tool refuses to issue a
verdict for v0.10.0. For development only, `tests/fixtures/v0.10.0-dev-baseline.json`
pins the hand-made stand-in `tests/fixtures/v0.10.0-baseline.spdx.json`.

Run against the real `reference_integration` v0.10.0 with the dev baseline: the
upstream release tags plus the `reference_integration` patches come out CONFORMANT
(5 of 5 platform integration tests pass).
