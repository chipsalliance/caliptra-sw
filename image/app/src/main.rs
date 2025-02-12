/*++

Licensed under the Apache-2.0 license.

File Name:

   main.rs

Abstract:

    Main entry point Caliptra Imaging application

--*/
use std::path::PathBuf;

use clap::{arg, value_parser, Command};

mod create;

/// Entry point
fn main() {
    let sub_cmds = vec![Command::new("create")
        .about("Create a new firmware image bundle")
        .arg(
            arg!(--"pqc-key-type" <U32> "Type of PQC key validation: 1: MLDSA; 3: LMS")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"key-config" <FILE> "Key Configuration file")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"ecc-pk-idx" <U32> "Vendor ECC Public Key Index")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"pqc-pk-idx" <U32> "Vendor PQC (LMS or MLDSA) Public Key Index")
                .required(false)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"fmc" <FILE> "FMC ELF binary")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"fmc-rev" <SHA256HASH> "FMC GIT Revision")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"fmc-version" <U32> "FMC Firmware Version Number")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"rt" <FILE> "Runtime ELF binary")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"rt-rev" <SHA256HASH> "Runtime GIT Revision")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"rt-version" <U32> "Runtime Firmware Version Number")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"fw-svn" <U32> "Firmware Security Version Number")
                .required(true)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"out" <FILE> "Output file")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"own-from-date" <String> "Certificate Validity Start Date By Owner [YYYYMMDDHHMMSS - Zulu Time]")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"own-to-date" <String> "Certificate Validity End Date By Owner [YYYYMMDDHHMMSS - Zulu Time]")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"mfg-from-date" <String> "Certificate Validity Start Date By Manufacturer [YYYYMMDDHHMMSS - Zulu Time]")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"mfg-to-date" <String> "Certificate Validity End Date By Manufacturer [YYYYMMDDHHMMSS - Zulu Time]")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!(--"print-hashes" "Print vendor and owner hashes").action(clap::ArgAction::SetTrue),
        )
        ];

    let cmd = Command::new("caliptra-image-app")
        .arg_required_else_help(true)
        .subcommands(sub_cmds)
        .about("Caliptra firmware imaging tools")
        .get_matches();

    let result = match cmd.subcommand().unwrap() {
        ("create", args) => create::run_cmd(args),
        (_, _) => unreachable!(),
    };

    result.unwrap();
}
