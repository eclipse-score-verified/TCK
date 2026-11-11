"""S-CORE Verified TCK command line: python3 -m tck {sbom,test,bundle,verify}."""

import argparse
import sys

from . import bundle, load_baseline, runner, sbom


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--baseline", required=True, help="baselines/vX.Y.json from this repo")
    common.add_argument("--baseline-sbom", required=True, help="product SBOM of the S-CORE release")
    common.add_argument("--out", default="tck-out", help="evidence directory (default: tck-out)")
    modules = argparse.ArgumentParser(add_help=False)
    modules.add_argument("--module", action="append", default=[], metavar="NAME=PATH",
                         help="git checkout of a module, e.g. score_baselibs=../baselibs (repeat)")

    parser = argparse.ArgumentParser(prog="tck", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("sbom", parents=[common, modules], help="check module ancestry, write the SBOM")
    p.add_argument("--product-sbom", help="SPDX file from 'bazel build //:sbom' to annotate")
    p = sub.add_parser("test", parents=[common, modules], help="run the platform integration tests")
    p.add_argument("--ref-int", required=True, help="reference_integration checkout at the release tag")
    p = sub.add_parser("bundle", parents=[common], help="write and sign the report bundle")
    p.add_argument("--key", required=True, help="SSH private key to sign with")
    p = sub.add_parser("verify", parents=[common], help="check a vendor bundle (--out is the bundle)")
    p.add_argument("--allowed-signers", required=True, help="ssh allowed_signers file of registered vendors")
    p.add_argument("--identity", required=True, help="vendor identity in the allowed_signers file")
    args = parser.parse_args(argv)

    baseline = load_baseline(args.baseline, args.baseline_sbom)
    paths = dict(m.split("=", 1) for m in getattr(args, "module", []))

    if args.command == "sbom":
        errors = sbom.generate(baseline, paths, args.out, args.product_sbom)
    elif args.command == "test":
        runner.run(baseline, args.ref_int, paths, args.out)
        return 0  # results are judged by 'bundle' / 'verify'
    elif args.command == "bundle":
        errors = bundle.bundle(args.out, baseline, args.key)["errors"]
    else:
        errors = bundle.verify(args.out, baseline, args.allowed_signers, args.identity)[1]

    for e in errors:
        print("FAIL:", e, file=sys.stderr)
    print(f"{args.command}: {'NON-CONFORMANT' if errors else 'OK'} (S-CORE {baseline['score_release']})")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
