# Licensed under the Apache-2.0 license

"""Drives an ACVP campaign against the caliptra-drivers ACVP test firmware.

For each test case in a vector file this script writes the vector to
`stimulus/current.txt`, rebuilds and runs the corresponding firmware test,
captures the UART output to a per-test-case log, and finally scrapes those logs
into a response file next to the vector file.

The firmware reads `stimulus/current.txt` at compile time via `include_str!`, so
cargo recompiles on every iteration. That is inherent to the design.

Usage:

    python3 run_acvp.py --alg SHA384ACC --vectors /path/to/SHA2-384-605645.txt
    python3 run_acvp.py --alg MLDSA_SIGGEN --vectors /path/to/vectors.txt --verilator

Run with --list to see the supported algorithms.
"""

import argparse
import os
import re
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Rewritten before every firmware build; read by the test binaries via
# include_str!("../../stimulus/current.txt").
CURRENT_VECTOR_FILE = os.path.join(SCRIPT_DIR, "stimulus", "current.txt")

# Per-algorithm configuration.
#
#   hash_size    bytes per response value; used to chunk MCT digests apart
#   cargo_filter the #[test] name in drivers/tests/drivers_integration_tests
#   resp_dir     directory for the per-test-case logs
#   resp_pattern overrides the default "<ALG>:(..)" scrape pattern
#   vector_fmt   layout of a vector-file line, for --list
ALGORITHMS = {
    "SHA1": {
        "hash_size": 20,
        "cargo_filter": "test_acvp_sha1",
        "resp_dir": "sha1_resp",
        "vector_fmt": "(AFT|MCT) tgId tcId len_bits hex_msg",
    },
    "SHA384ACC": {
        "hash_size": 48,
        "cargo_filter": "test_acvp_sha2_512_384acc",
        "resp_dir": "sha384acc_resp",
        "resp_pattern": r"SHA384ACC:([0-9A-F]+)",
        "vector_fmt": "(AFT|MCT) tgId tcId len_bits hex_msg",
    },
    "SHA512ACC": {
        "hash_size": 64,
        "cargo_filter": "test_acvp_sha2_512_384acc",
        "resp_dir": "sha512acc_resp",
        "resp_pattern": r"SHA512ACC:([0-9A-F]+)",
        "vector_fmt": "(AFT|MCT) tgId tcId len_bits hex_msg",
    },
    "HMAC384KDF": {
        "hash_size": 48,
        "cargo_filter": "test_acvp_hmac",
        "resp_dir": "hmac384kdf_resp",
        "vector_fmt": "AFT tcId hex_key",
    },
    "LMS_SIGVER": {
        "hash_size": 1,  # 1 byte response: 01=pass, 00=fail
        "cargo_filter": "test_acvp_lms_24",
        "resp_dir": "lms_sigver_resp",
        "vector_fmt": "AFT tgId tcId hex_msg hex_pubkey(96) hex_sig(3240)",
    },
    "MLDSA_KEYGEN": {
        "hash_size": 2592,  # public key; private key is captured separately
        "cargo_filter": "test_acvp_mldsa87",
        "resp_dir": "mldsa87_keygen_resp",
        "resp_pattern": r"MLDSA_PUBKEY:([0-9A-F]+)",
        "vector_fmt": "AFT keyGen tgId tcId parameterSet hex_seed(64)",
    },
    "MLDSA_SIGGEN": {
        "hash_size": 4628,
        "cargo_filter": "test_acvp_mldsa87",
        "resp_dir": "mldsa87_siggen_resp",
        "resp_pattern": r"MLDSA_SIGGEN:([0-9A-F]+)",
        "vector_fmt": "AFT sigGen tgId tcId parameterSet hex_sk(9792) hex_msg [hex_ctx]",
    },
    "MLDSA_SIGVER": {
        "hash_size": 1,
        "cargo_filter": "test_acvp_mldsa87",
        "resp_dir": "mldsa87_sigver_resp",
        "vector_fmt": "AFT sigVer tgId tcId parameterSet hex_pk(5184) hex_msg hex_sig(9254) [hex_ctx]",
    },
    "MLKEM_KEYGEN": {
        "hash_size": 4736,  # 1568 (ek) + 3168 (dk)
        "cargo_filter": "test_acvp_ml_kem",
        "resp_dir": "mlkem1024_keygen_resp",
        "resp_pattern": r"MLKEM_KEYGEN:([0-9A-F]+) ([0-9A-F]+)",
        "vector_fmt": "AFT tgId tcId hex_d(64) hex_z(64)",
    },
    "MLKEM_ENCAPDECAP": {
        "hash_size": 1,  # unused; each sub-test carries its own output
        "cargo_filter": "test_acvp_ml_kem",
        "resp_dir": "mlkem1024_encapdecap_resp",
        "resp_pattern": r"MLKEM_(?:ENCAPS|DECAPS):([0-9A-F]+)(?: ([0-9A-F]+))?",
        "vector_fmt": "AFT (encapsulation|decapsulation) tgId tcId hex_field1 hex_field2",
    },
}

# Populated by main() from the selected algorithm.
ALG_NAME = None
HASH_SIZE_BYTES = None
CARGO_COMMAND = None
RESP_DIR = None
RESP_PATTERN = None
OUTPUT_FILE_TEMPLATE = None


def run_cargo_test(tcId, alg):
    """Executes the cargo test command and writes iteration output to a file."""
    output_file = OUTPUT_FILE_TEMPLATE.format(tcId)

    with open(output_file, "w") as outfile:
        outfile.write("--- {} tcId {} ---\n".format(alg, tcId))
        subprocess.call(CARGO_COMMAND, stdout=outfile, stderr=outfile)

    print("tcId {} output saved to {}".format(tcId, output_file))


def gen_resp_file(input_dir, output_file, resp_pattern=None, kdf_labels=None):
    concatenated = ""
    concatenated2 = ""
    current_tcId = None
    current_alg = None

    if os.path.exists(output_file):
        os.remove(output_file)
        print("Existing output file '{}' removed.".format(output_file))

    files = [f for f in os.listdir(input_dir) if f.endswith(".log")]
    files.sort(key=lambda f: os.path.getmtime(os.path.join(input_dir, f)))

    pattern = re.compile(r"{}".format(resp_pattern or RESP_PATTERN))
    privkey_pattern = (
        re.compile(r"MLDSA_PRIVKEY:([0-9A-F]+)") if ALG_NAME == "MLDSA_KEYGEN" else None
    )
    header_pattern = re.compile(
        r"--- (AFT|MCT|LMS_SIGVER|KDF|MLDSA_KEYGEN|MLDSA_SIGGEN|MLDSA_SIGVER"
        r"|MLKEM_KEYGEN|MLKEM_ENCAPS|MLKEM_DECAPS) tcId (\d+) ---"
    )

    for filename in files:
        if filename.endswith(".log"):
            file_path = os.path.join(input_dir, filename)
            with open(file_path, "r", encoding="utf-8") as file:
                for line in file:
                    match = pattern.search(line)
                    if match:
                        concatenated += match.group(1)
                        if match.lastindex >= 2:
                            concatenated2 += match.group(2)
                    if privkey_pattern:
                        pk_match = privkey_pattern.search(line)
                        if pk_match:
                            concatenated2 += pk_match.group(1)
                    header_match = header_pattern.search(line)
                    if header_match:
                        current_alg = header_match.group(1)
                        current_tcId = int(header_match.group(2))

            with open(output_file, "a", encoding="utf-8") as file1:
                if current_alg == "MCT":
                    chunk = HASH_SIZE_BYTES * 2  # hex chars per digest
                    for i in range(0, len(concatenated), chunk):
                        digest = concatenated[i : i + chunk]
                        file1.write("MCT {} {}\n".format(current_tcId, digest))
                elif current_alg == "KDF" and kdf_labels and current_tcId in kdf_labels:
                    label = kdf_labels[current_tcId]
                    file1.write(
                        "AFT {} {} {}\n".format(current_tcId, label, concatenated)
                    )
                elif current_alg == "LMS_SIGVER":
                    passed = "true" if concatenated == "01" else "false"
                    file1.write("AFT {} {}\n".format(current_tcId, passed))
                elif current_alg == "MLKEM_KEYGEN":
                    # group(1) = ek, group(2) = dk (space-separated on one line)
                    file1.write(
                        "AFT {} {} {}\n".format(
                            current_tcId, concatenated, concatenated2
                        )
                    )
                elif current_alg == "MLKEM_ENCAPS":
                    # group(1) = ciphertext, group(2) = shared_key
                    file1.write(
                        "AFT {} {} {}\n".format(
                            current_tcId, concatenated, concatenated2
                        )
                    )
                elif current_alg == "MLKEM_DECAPS":
                    # Entire blob is k (shared secret)
                    file1.write("AFT {} {}\n".format(current_tcId, concatenated))
                elif current_alg == "MLDSA_KEYGEN":
                    file1.write(
                        "AFT keyGen {} {} {}\n".format(
                            current_tcId, concatenated, concatenated2
                        )
                    )
                elif current_alg == "MLDSA_SIGGEN":
                    file1.write("AFT sigGen {} {}\n".format(current_tcId, concatenated))
                elif current_alg == "MLDSA_SIGVER":
                    passed = "true" if concatenated == "01" else "false"
                    file1.write("AFT sigVer {} {}\n".format(current_tcId, passed))
                else:
                    file1.write(
                        "{} {} {}\n".format(current_alg, current_tcId, concatenated)
                    )

            concatenated = ""
            concatenated2 = ""
            current_tcId = None
            current_alg = None

    print("Extraction complete. Output saved to {}".format(output_file))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run an ACVP campaign against the caliptra-drivers ACVP test firmware."
    )
    parser.add_argument(
        "--alg", choices=sorted(ALGORITHMS), help="algorithm / vector set to run"
    )
    parser.add_argument("--vectors", help="path to the ACVP request vector file")
    parser.add_argument(
        "--resp-dir",
        help="directory for per-test-case logs (default: ./<alg>_resp)",
    )
    parser.add_argument(
        "--verilator",
        action="store_true",
        help="build the firmware against Verilator instead of the emulator",
    )
    parser.add_argument(
        "--list", action="store_true", help="list supported algorithms and exit"
    )
    args = parser.parse_args()

    if args.list:
        for name in sorted(ALGORITHMS):
            print("{:<18} {}".format(name, ALGORITHMS[name]["vector_fmt"]))
        raise SystemExit(0)

    if not args.alg or not args.vectors:
        parser.error("--alg and --vectors are required (use --list to see algorithms)")
    if not os.path.isfile(args.vectors):
        parser.error("vector file not found: {}".format(args.vectors))
    return args


def main():
    global ALG_NAME, HASH_SIZE_BYTES, CARGO_COMMAND, RESP_DIR
    global RESP_PATTERN, OUTPUT_FILE_TEMPLATE

    args = parse_args()
    cfg = ALGORITHMS[args.alg]

    ALG_NAME = args.alg
    HASH_SIZE_BYTES = cfg["hash_size"]
    RESP_DIR = args.resp_dir or os.path.join(".", cfg["resp_dir"])
    OUTPUT_FILE_TEMPLATE = os.path.join(RESP_DIR, "test_output_{}.log")
    RESP_PATTERN = cfg.get("resp_pattern", r"{}:(..)".format(ALG_NAME))

    # The ACVP integration tests are #[ignore]d unless `acvp-tests` is enabled.
    features = "acvp-tests,verilator" if args.verilator else "acvp-tests"
    CARGO_COMMAND = [
        "cargo",
        "test",
        "-p",
        "caliptra-drivers",
        "--features",
        features,
        cfg["cargo_filter"],
    ]

    vect_file = args.vectors
    _vect_base, _vect_ext = os.path.splitext(vect_file)
    resp_file = _vect_base + "_resp" + _vect_ext

    print("Algorithm : {}".format(ALG_NAME))
    print("Vectors   : {}".format(vect_file))
    print("Stimulus  : {}".format(CURRENT_VECTOR_FILE))
    print("Logs      : {}".format(RESP_DIR))
    print("Response  : {}".format(resp_file))
    print("Cargo     : {}".format(" ".join(CARGO_COMMAND)))

    os.makedirs(os.path.dirname(CURRENT_VECTOR_FILE), exist_ok=True)
    os.makedirs(RESP_DIR, exist_ok=True)

    # Remove any leftover log files from a previous run
    for f in os.listdir(RESP_DIR):
        if f.endswith(".log"):
            os.remove(os.path.join(RESP_DIR, f))

    kdf_labels = {}

    with open(vect_file, "r") as vectfile:
        for line in vectfile:
            parts = line.strip().split()

            if ALG_NAME.endswith("KDF"):
                if len(parts) != 3:
                    continue
                alg, tcId, hex_key = parts
                # Generate a fresh random 16-byte label each test
                label_bytes = os.urandom(16)
                hex_label = label_bytes.hex().upper()
                kdf_labels[int(tcId)] = hex_label
                print("Running KDF test for tcId {}".format(tcId))
                with open(CURRENT_VECTOR_FILE, "w") as f:
                    f.write("{}\n{}".format(hex_key, hex_label))
                run_cargo_test(tcId, "KDF")
            elif ALG_NAME == "LMS_SIGVER":
                # Format: AFT tgId tcId hex_msg hex_pubkey(96) hex_sig(3240)
                if len(parts) != 6:
                    continue
                alg, tgId, tcId, hex_msg, hex_pubkey, hex_sig = parts
                if alg == "AFT":
                    print("Running LMS_SIGVER test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write(
                            "LMS_SIGVER\n{}\n{}\n{}".format(
                                hex_msg, hex_pubkey, hex_sig
                            )
                        )
                    run_cargo_test(tcId, "LMS_SIGVER")
            elif ALG_NAME == "MLDSA_KEYGEN":
                # Format: AFT keyGen tgId tcId parameterSet hex_seed(64 hex chars)
                if len(parts) != 6:
                    continue
                alg, mode, tgId, tcId, parameterSet, hex_seed = parts
                if alg == "AFT" and mode == "keyGen":
                    print("Running MLDSA_KEYGEN test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write("MLDSA_KEYGEN\n{}".format(hex_seed))
                    run_cargo_test(tcId, "MLDSA_KEYGEN")
            elif ALG_NAME == "MLDSA_SIGGEN":
                # Format: AFT sigGen tgId tcId parameterSet hex_sk(9792) hex_msg [hex_ctx]
                if len(parts) not in (7, 8):
                    continue
                alg, mode, tgId, tcId, parameterSet, hex_sk, hex_msg = parts[:7]
                hex_ctx = parts[7] if len(parts) == 8 else None
                if alg == "AFT" and mode == "sigGen":
                    print("Running MLDSA_SIGGEN test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        content = "MLDSA_SIGGEN\n{}\n{}".format(hex_sk, hex_msg)
                        if hex_ctx is not None:
                            content += "\n{}".format(hex_ctx)
                        f.write(content)
                    run_cargo_test(tcId, "MLDSA_SIGGEN")
            elif ALG_NAME == "MLDSA_SIGVER":
                # Format: AFT sigVer tgId tcId parameterSet hex_pk(5184) hex_msg hex_sig(9254) [hex_ctx]
                if len(parts) not in (8, 9):
                    continue
                (
                    alg,
                    mode,
                    tgId,
                    tcId,
                    parameterSet,
                    hex_pubkey,
                    hex_msg,
                    hex_sig,
                ) = parts[:8]
                hex_ctx = parts[8] if len(parts) == 9 else None
                if alg == "AFT" and mode == "sigVer":
                    print("Running MLDSA_SIGVER test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        content = "MLDSA_SIGVER\n{}\n{}\n{}".format(
                            hex_pubkey, hex_msg, hex_sig
                        )
                        if hex_ctx is not None:
                            content += "\n{}".format(hex_ctx)
                        f.write(content)
                    run_cargo_test(tcId, "MLDSA_SIGVER")
            elif ALG_NAME == "MLKEM_KEYGEN":
                # Format: AFT tgId tcId hex_d(64) hex_z(64)
                if len(parts) != 5:
                    continue
                alg, tgId, tcId, hex_d, hex_z = parts
                if alg == "AFT":
                    print("Running MLKEM_KEYGEN test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write("MLKEM_KEYGEN\n{}\n{}".format(hex_d, hex_z))
                    run_cargo_test(tcId, "MLKEM_KEYGEN")
            elif ALG_NAME == "MLKEM_ENCAPDECAP":
                # Format: AFT encapsulation tgId tcId hex_ek(3136) hex_msg(64)
                #         AFT decapsulation tgId tcId hex_dk(6336) hex_ct(3136)
                if len(parts) != 6:
                    continue
                alg, function, tgId, tcId, hex_field1, hex_field2 = parts
                if alg == "AFT" and function == "encapsulation":
                    print("Running MLKEM_ENCAPS test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write("MLKEM_ENCAPS\n{}\n{}".format(hex_field1, hex_field2))
                    run_cargo_test(tcId, "MLKEM_ENCAPS")
                elif alg == "AFT" and function == "decapsulation":
                    print("Running MLKEM_DECAPS test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write("MLKEM_DECAPS\n{}\n{}".format(hex_field1, hex_field2))
                    run_cargo_test(tcId, "MLKEM_DECAPS")
            elif ALG_NAME in ("SHA384ACC", "SHA512ACC"):
                # Format: AFT tgId tcId len_bits hex_msg   (AFT)
                #         MCT tgId tcId len_bits hex_seed  (MCT)
                # current.txt: SHA384ACC or SHA512ACC / test type / hex data
                if len(parts) != 5:
                    continue
                alg, tgId, tcId, len_bits, hex_str = parts
                if alg in ("AFT", "MCT"):
                    print("Running {} test for tcId {}".format(ALG_NAME, tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write("{}\n{}\n{}".format(ALG_NAME, alg, hex_str))
                    run_cargo_test(tcId, alg)
            else:
                if len(parts) != 5:
                    continue
                alg, tgId, tcId, len_bits, hex_str = parts
                if alg in ("AFT", "MCT"):
                    print("Running test for tcId {}".format(tcId))
                    with open(CURRENT_VECTOR_FILE, "w") as f:
                        f.write("{}\n{}".format(alg, hex_str))
                    run_cargo_test(tcId, alg)

    gen_resp_file(RESP_DIR, resp_file, kdf_labels=kdf_labels)


if __name__ == "__main__":
    main()
