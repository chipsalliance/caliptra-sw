// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_builder::version;
use caliptra_builder::ImageOptions;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_image_types::ImageHeader;
use caliptra_image_types::ImageManifest;
use caliptra_image_types::ImageSignatures;
use clap::{arg, value_parser, Command};
use memoffset::{offset_of, span_of};
use serde_json::{json, to_string_pretty};
use sha2::{Digest, Sha384};
use std::collections::HashSet;
use std::path::PathBuf;
use zerocopy::FromBytes;

fn main() {
    let mut cmd = Command::new("image-gen")
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
        .arg(arg!(--"image-options" [FILE] "Override the `ImageOptions` struct for the image bundle with the given TOML file").value_parser(value_parser!(PathBuf)));
    let args = cmd.get_matches_mut();

    // Print help if the provided args did not create anything.
    let mut valid_cmd = false;

    if let Some(path) = args.get_one::<PathBuf>("rom-no-log") {
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM).unwrap();
        valid_cmd = true;
        std::fs::write(path, rom).unwrap();
    }

    if let Some(path) = args.get_one::<PathBuf>("rom-with-log") {
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();
        valid_cmd = true;
        std::fs::write(path, rom).unwrap();
    }
    if let Some(path) = args.get_one::<PathBuf>("fake-rom") {
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_FAKE_WITH_UART).unwrap();
        valid_cmd = true;
        std::fs::write(path, rom).unwrap();
    }

    let fw_svn = if let Some(fw_svn) = args.get_one::<u32>("fw-svn") {
        *fw_svn
    } else {
        0
    };

    let pqc_key_type = match args.get_one("pqc-key-type") {
        Some(1) | None => FwVerificationPqcKeyType::MLDSA,
        Some(3) => FwVerificationPqcKeyType::LMS,
        _ => panic!("--pqc-key-type must be 1 or 3"),
    };

    if let Some(path) = args.get_one::<PathBuf>("fw") {
        // Get image options
        let image_options = if let Some(path) = args.get_one::<PathBuf>("image-options") {
            toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        } else if args.contains_id("zeros") {
            ImageOptions::default()
        } else {
            ImageOptions {
                fmc_version: version::get_fmc_version(),
                app_version: version::get_runtime_version(),
                fw_svn,
                pqc_key_type,
                ..Default::default()
            }
        };

        // Get image types (zeros or actual firmware)
        let (fmc_type, app_type) = if args.contains_id("zeros") {
            (firmware::FMC_ZEROS, firmware::APP_ZEROS)
        } else {
            (firmware::FMC_WITH_UART, firmware::APP_WITH_UART)
        };

        // Generate Image Bundle
        let mut image =
            caliptra_builder::build_and_sign_image(&fmc_type, &app_type, image_options).unwrap();

        // Override signatures if provided
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

        let contents = image.to_bytes().unwrap();
        valid_cmd = true;
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
            valid_cmd = true;
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
        valid_cmd = true;
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
            valid_cmd = true;
            std::fs::write(all_dir.join(elf_filename), elf_bytes).unwrap();
        }
    }

    if !valid_cmd {
        let _ = cmd.print_long_help();
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

#[test]
fn test_image_options_imports_correctly() {
    // Use a thread with a larger stack to avoid stack overflow
    const STACK_SIZE: usize = 16 * 1024 * 1024; // 16MB stack

    let thread_result = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| {
            // Toml options
            let t: ImageOptions = toml::from_str(
                &std::fs::read_to_string("test_data/default_image_options.toml").unwrap(),
            )
            .unwrap();

            // Default options
            let d = ImageOptions {
                fmc_version: version::get_fmc_version(),
                app_version: version::get_runtime_version(),
                ..Default::default()
            };

            // Check top level fields
            assert_eq!(t.fmc_version, d.fmc_version);
            assert_eq!(t.fw_svn, d.fw_svn);
            assert_eq!(t.app_version, d.app_version);
            assert_eq!(t.pqc_key_type, d.pqc_key_type);

            // Check vendor config fields. Only the first key is populated in the toml file.
            let t_v = &t.vendor_config;
            let d_v = &d.vendor_config;
            assert_eq!(t_v.ecc_key_idx, d_v.ecc_key_idx);
            assert_eq!(t_v.pqc_key_idx, d_v.pqc_key_idx);
            assert_eq!(t_v.ecc_key_count, d_v.ecc_key_count);
            assert_eq!(t_v.lms_key_count, d_v.lms_key_count);
            assert_eq!(t_v.mldsa_key_count, d_v.mldsa_key_count);
            assert_eq!(t_v.not_before, d_v.not_before);
            assert_eq!(t_v.not_after, d_v.not_after);
            assert_eq!(t_v.pl0_pauser, d_v.pl0_pauser);

            // Check vendor public keys
            assert_eq!(t_v.pub_keys.ecc_pub_keys[0], d_v.pub_keys.ecc_pub_keys[0]);
            assert_eq!(t_v.pub_keys.lms_pub_keys[0], d_v.pub_keys.lms_pub_keys[0]);
            assert_eq!(
                t_v.pub_keys.mldsa_pub_keys[0],
                d_v.pub_keys.mldsa_pub_keys[0]
            );

            // Check vendor private keys
            assert_eq!(
                t_v.priv_keys.unwrap().ecc_priv_keys[0],
                d_v.priv_keys.unwrap().ecc_priv_keys[0]
            );
            assert_eq!(
                t_v.priv_keys.unwrap().lms_priv_keys[0],
                d_v.priv_keys.unwrap().lms_priv_keys[0]
            );
            assert_eq!(
                t_v.priv_keys.unwrap().mldsa_priv_keys[0],
                d_v.priv_keys.unwrap().mldsa_priv_keys[0]
            );

            // Check owner config fields
            let t_o = &t.owner_config.unwrap();
            let d_o = &d.owner_config.unwrap();
            assert_eq!(t_o.not_before, d_o.not_before);
            assert_eq!(t_o.not_after, d_o.not_after);

            // Check owner public keys
            assert_eq!(t_o.pub_keys.ecc_pub_key, d_o.pub_keys.ecc_pub_key);
            assert_eq!(t_o.pub_keys.lms_pub_key, d_o.pub_keys.lms_pub_key);
            assert_eq!(t_o.pub_keys.mldsa_pub_key, d_o.pub_keys.mldsa_pub_key);

            // Check owner private keys
            assert_eq!(
                t_o.priv_keys.unwrap().ecc_priv_key,
                d_o.priv_keys.unwrap().ecc_priv_key
            );
            assert_eq!(
                t_o.priv_keys.unwrap().lms_priv_key,
                d_o.priv_keys.unwrap().lms_priv_key
            );
            assert_eq!(
                t_o.priv_keys.unwrap().mldsa_priv_key,
                d_o.priv_keys.unwrap().mldsa_priv_key
            );
        })
        .unwrap();

    // Wait for the thread to complete and propagate any panics
    thread_result.join().unwrap();
}
