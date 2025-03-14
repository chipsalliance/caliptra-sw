// Licensed under the Apache-2.0 license

use caliptra_builder::ImageOptions;
use caliptra_builder::firmware;
use caliptra_builder::version;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_image_types::ImageHeader;
use caliptra_image_types::ImageManifest;
use caliptra_image_types::ImageSignatures;
use clap::{Command, arg, value_parser};
use memoffset::{offset_of, span_of};
use serde_json::{json, to_string_pretty};
use sha2::{Digest, Sha384};
use std::collections::HashSet;
use std::path::PathBuf;
use zerocopy::FromBytes;

fn main() {
    let args = Command::new("image-gen")
        .about("Caliptra firmware image builder")
        .arg(
            arg!(--"rom-no-log" [FILE] "ROM binary image (prod)")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(--"rom-with-log" [FILE] "ROM binary image (with logging)")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(--"fw" [FILE] "FW bundle image").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(--"fw-svn" [VALUE] "Security Version Number of firmware image")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(--"all_elfs" [DIR] "Build all firmware elf files")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(--"fake-rom" [FILE] "Fake ROM").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--"fake-fw" [FILE] "Fake FW bundle image").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(--"hashes" [FILE] "File path for output JSON file containing image bundle header hashes for external signing tools")
                .value_parser(value_parser!(PathBuf))
        )
        .arg(arg!(--"zeros" "Build an image bundle with zero'd FMC and RT. This will NMI immediately."))
        .arg(arg!(--"owner-sig-override" [FILE] "Manually overwrite the owner_sigs of the FW bundle image with the contents of binary [FILE]. The signature should be an ECC signature concatenated with an LMS signature").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--"vendor-sig-override" [FILE] "Manually overwrite the vendor_sigs of the FW bundle image with the contents of binary [FILE]. The signature should be an ECC signature concatenated with an LMS signature").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(--"pqc-key-type" [integer] "PQC key type to use (MLDSA: 1, LMS: 3)")
                .value_parser(value_parser!(i32)),
        )
        .get_matches();

    if let Some(path) = args.get_one::<PathBuf>("rom-no-log") {
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM).unwrap();
        std::fs::write(path, rom).unwrap();
    }

    if let Some(path) = args.get_one::<PathBuf>("rom-with-log") {
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();
        std::fs::write(path, rom).unwrap();
    }
    if let Some(path) = args.get_one::<PathBuf>("fake-rom") {
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_FAKE_WITH_UART).unwrap();
        std::fs::write(path, rom).unwrap();
    }

    let fw_svn = match args.get_one::<u32>("fw-svn") {
        Some(fw_svn) => *fw_svn,
        _ => 0,
    };

    let pqc_key_type = match args.get_one("pqc-key-type") {
        Some(1) | None => FwVerificationPqcKeyType::MLDSA,
        Some(3) => FwVerificationPqcKeyType::LMS,
        _ => panic!("--pqc-key-type must be 1 or 3"),
    };

    if let Some(path) = args.get_one::<PathBuf>("fw") {
        // Generate Image Bundle
        let image = if args.contains_id("zeros") {
            caliptra_builder::build_and_sign_image(
                &firmware::FMC_ZEROS,
                &firmware::APP_ZEROS,
                ImageOptions::default(),
            )
            .unwrap()
        } else {
            let mut image = caliptra_builder::build_and_sign_image(
                &firmware::FMC_WITH_UART,
                &firmware::APP_WITH_UART,
                ImageOptions {
                    fmc_version: version::get_fmc_version(),
                    app_version: version::get_runtime_version(),
                    fw_svn,
                    pqc_key_type,
                    ..Default::default()
                },
            )
            .unwrap();

            if let Some(path) = args.get_one::<PathBuf>("owner-sig-override") {
                let sig_override = std::fs::read(path).unwrap();
                image.manifest.preamble.owner_sigs =
                    ImageSignatures::read_from_bytes(&sig_override).unwrap();
            }

            if let Some(path) = args.get_one::<PathBuf>("vendor-sig-override") {
                let sig_override = std::fs::read(path).unwrap();
                image.manifest.preamble.vendor_sigs =
                    ImageSignatures::read_from_bytes(&sig_override).unwrap();
            }

            image
        };

        let contents = image.to_bytes().unwrap();
        std::fs::write(path, contents.clone()).unwrap();

        if let Some(path) = args.get_one::<PathBuf>("hashes") {
            let header_range = span_of!(ImageManifest, header);

            // Get the vendor digest which is taken from a subset of the header
            let vendor_header_len = offset_of!(ImageHeader, owner_data);
            let vendor_range = header_range.start..header_range.start + vendor_header_len;
            let vendor_digest = Sha384::digest(&contents[vendor_range]);

            // Get the owner digest which is the full header
            let owner_digest = Sha384::digest(&contents[header_range]);

            let json = json!({
                "vendor": format!("{vendor_digest:02x}"),
                "owner": format!("{owner_digest:02x}"),
            });
            std::fs::write(path, to_string_pretty(&json).unwrap()).unwrap();
        }
    }

    if let Some(path) = args.get_one::<PathBuf>("fake-fw") {
        // Generate Image Bundle
        let image = caliptra_builder::build_and_sign_image(
            &firmware::FMC_FAKE_WITH_UART,
            &firmware::APP_WITH_UART,
            ImageOptions {
                fmc_version: version::get_fmc_version(),
                app_version: version::get_runtime_version(),
                pqc_key_type,
                ..Default::default()
            },
        )
        .unwrap();
        std::fs::write(path, image.to_bytes().unwrap()).unwrap();
    }

    let mut used_filenames = HashSet::new();
    if let Some(all_dir) = args.get_one::<PathBuf>("all_elfs") {
        for (fwid, elf_bytes) in
            caliptra_builder::build_firmware_elfs_uncached(None, firmware::REGISTERED_FW).unwrap()
        {
            let elf_filename = fwid.elf_filename();
            if !used_filenames.insert(elf_filename.clone()) {
                panic!("Multiple fwids with filename {elf_filename}")
            }
            std::fs::write(all_dir.join(elf_filename), elf_bytes).unwrap();
        }
    }
}

#[test]
#[cfg_attr(not(feature = "slow_tests"), ignore)]
fn test_binaries_are_identical() {
    for (fwid, elf_bytes1) in
        caliptra_builder::build_firmware_elfs_uncached(None, firmware::REGISTERED_FW).unwrap()
    {
        let elf_bytes2 = caliptra_builder::build_firmware_elf_uncached(None, fwid).unwrap();

        assert!(
            elf_bytes1 == elf_bytes2,
            "binaries are not consistent in {fwid:?}"
        );
    }
}
