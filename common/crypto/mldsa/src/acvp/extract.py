#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
#
# Regenerates the trimmed ACVP known-answer-test vectors used by `mod.rs` from
# the upstream NIST ACVP-Server vector set:
#
#     https://github.com/usnistgov/ACVP-Server
#         gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json
#         gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
#
# We keep only the ML-DSA-87 cases that the pure-software `caliptra-mldsa`
# implementation can actually drive:
#
#   * keyGen: all 25 cases (deterministic public key from a 32-byte seed).
#   * sigVer: only the `external` signature interface with `pure` preHash and
#     internal mu (externalMu=false). That is the single combination our
#     `verify_internal` implements (it prepends the 0x00||len(ctx)||ctx domain
#     separator and computes mu itself). The `internal`, `externalMu`, and
#     `preHash` (HashML-DSA) groups are intentionally excluded -- they use
#     message processing the library does not implement.
#
# The vectors are derived from NIST's ACVP-Server project and are subject to
# its license: https://github.com/usnistgov/ACVP-Server#license
#
# Usage:
#     python3 extract.py /path/to/ACVP-Server/gen-val/json-files
#
# Run from this directory; it overwrites key_gen.json and sig_ver.json.

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Embedded in every generated file so the provenance and license travel with the
# data (JSON has no comment syntax). The Rust harness ignores these keys.
ACVP_SOURCE = "https://github.com/usnistgov/ACVP-Server"
ACVP_LICENSE = "https://github.com/usnistgov/ACVP-Server#license"


def load(root, name):
    with open(os.path.join(root, name, "internalProjection.json")) as f:
        return json.load(f)


def mldsa87_groups(doc, **selectors):
    for g in doc["testGroups"]:
        if g.get("parameterSet") != "ML-DSA-87":
            continue
        if all(g.get(k) == v for k, v in selectors.items()):
            yield g


def write(name, test_groups):
    obj = {
        "_source": ACVP_SOURCE,
        "_license": ACVP_LICENSE,
        "testGroups": test_groups,
    }
    path = os.path.join(HERE, name)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    print(f"wrote {name}: {sum(len(g['tests']) for g in test_groups)} cases")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "/work/ACVP-Server/gen-val/json-files"

    # keyGen: seed -> pk
    kg = load(root, "ML-DSA-keyGen-FIPS204")
    kg_groups = []
    for g in mldsa87_groups(kg, testType="AFT"):
        tests = [{k: t[k] for k in ("tcId", "seed", "pk")} for t in g["tests"]]
        kg_groups.append({"tgId": g["tgId"], "parameterSet": g["parameterSet"], "tests": tests})
    write("key_gen.json", kg_groups)

    # sigVer: external / pure / internal-mu -> verify(pk, sig, msg, ctx) == testPassed
    sv = load(root, "ML-DSA-sigVer-FIPS204")
    sv_groups = []
    fields = ("tcId", "pk", "message", "context", "signature", "testPassed", "reason")
    for g in mldsa87_groups(sv, signatureInterface="external", preHash="pure", externalMu=False):
        tests = [{k: t.get(k, "") for k in fields} for t in g["tests"]]
        sv_groups.append({"tgId": g["tgId"], "parameterSet": g["parameterSet"], "tests": tests})
    write("sig_ver.json", sv_groups)


if __name__ == "__main__":
    main()
