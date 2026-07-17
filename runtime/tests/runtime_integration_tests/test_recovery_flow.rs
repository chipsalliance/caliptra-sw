// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPreamble, AuthManifestPrivKeysConfig,
    AuthManifestPubKeysConfig, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, QuotePcrsEcc384Req, QuotePcrsEcc384Resp,
    SetAuthManifestReq,
};
#[cfg(not(feature = "fpga_subsystem"))]
use caliptra_emu_bus::{Device, EventData};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, InitParams};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_image_gen::from_hw_format;
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_image_types::FwVerificationPqcKeyType;
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

const RT_READY_FOR_COMMANDS: u32 = 0x600;
const PCR_ID_STASH_MEASUREMENT: usize = 31;

#[derive(asn1::Asn1Read)]
struct Fwid<'a> {
    _hash_alg: asn1::ObjectIdentifier,
    digest: &'a [u8],
}

#[derive(asn1::Asn1Read)]
struct IntegrityRegister<'a> {
    #[implicit(0)]
    _register_name: Option<asn1::IA5String<'a>>,
    #[implicit(1)]
    _register_num: Option<u64>,
    #[implicit(2)]
    _register_digests: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
}

#[derive(asn1::Asn1Read)]
struct TcbInfo<'a> {
    #[implicit(0)]
    _vendor: Option<asn1::Utf8String<'a>>,
    #[implicit(1)]
    _model: Option<asn1::Utf8String<'a>>,
    #[implicit(2)]
    _version: Option<asn1::Utf8String<'a>>,
    #[implicit(3)]
    svn: Option<u64>,
    #[implicit(4)]
    _layer: Option<u64>,
    #[implicit(5)]
    _index: Option<u64>,
    #[implicit(6)]
    fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
    #[implicit(7)]
    _flags: Option<asn1::BitString<'a>>,
    #[implicit(8)]
    _vendor_info: Option<&'a [u8]>,
    #[implicit(9)]
    tci_type: Option<&'a [u8]>,
    #[implicit(10)]
    _operational_flags_mask: Option<asn1::BitString<'a>>,
    #[implicit(11)]
    _integrity_registers: Option<asn1::SequenceOf<'a, IntegrityRegister<'a>>>,
}

struct TcbSnapshot {
    tci_type: [u8; 4],
    svn: Option<u64>,
    digest: Option<[u8; 48]>,
}

fn sha384_digest(data: &[u8]) -> [u8; 48] {
    Sha384::digest(data).into()
}

fn preamble_range_digest(
    preamble: &AuthManifestPreamble,
    range: core::ops::Range<u32>,
) -> [u8; 48] {
    let preamble_bytes = preamble.as_bytes();
    sha384_digest(&preamble_bytes[range.start as usize..range.end as usize])
}

fn somv_measurement(manifest: &AuthorizationManifest) -> [u8; 48] {
    preamble_range_digest(
        &manifest.preamble,
        AuthManifestPreamble::vendor_signed_data_range(),
    )
}

fn somo_measurement(manifest: &AuthorizationManifest) -> [u8; 48] {
    preamble_range_digest(
        &manifest.preamble,
        AuthManifestPreamble::owner_pub_keys_range(),
    )
}

fn create_auth_manifest_with_alt_owner_keys(
    image_metadata_list: Vec<AuthManifestImageMetadata>,
    svn: u32,
) -> AuthorizationManifest {
    let vendor_fw_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
            mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
            mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
        }),
    });
    let vendor_man_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
            mldsa_pub_key: VENDOR_MLDSA_KEY_1_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
            mldsa_priv_key: VENDOR_MLDSA_KEY_1_PRIVATE,
        }),
    });
    let owner_fw_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
            lms_pub_key: OWNER_LMS_KEY_PUBLIC,
            mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
            lms_priv_key: OWNER_LMS_KEY_PRIVATE,
            mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
        }),
    });
    let owner_man_key_info = Some(AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: VENDOR_ECC_KEY_2_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_2_PUBLIC,
            mldsa_pub_key: VENDOR_MLDSA_KEY_2_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: VENDOR_ECC_KEY_2_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_2_PRIVATE,
            mldsa_priv_key: VENDOR_MLDSA_KEY_2_PRIVATE,
        }),
    });

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&AuthManifestGeneratorConfig {
        vendor_fw_key_info,
        vendor_man_key_info,
        owner_fw_key_info,
        owner_man_key_info,
        image_metadata_list,
        version: 1,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        svn,
    })
    .unwrap()
}

fn set_auth_manifest(model: &mut DefaultHwModel, manifest: &AuthorizationManifest) {
    let buf = manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            set_auth_manifest_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
}

fn quote_pcr31(model: &mut DefaultHwModel) -> [u8; 48] {
    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0xf5; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
    let resp = QuotePcrsEcc384Resp::read_from_bytes(resp.as_slice()).unwrap();
    resp.pcrs[PCR_ID_STASH_MEASUREMENT]
}

fn dpe_tcb_snapshots(model: &mut DefaultHwModel) -> Vec<TcbSnapshot> {
    use crate::common::{certify_key, CertifyKeyCommandNoRef, CreateCertifyKeyCmdArgs};
    use caliptra_dpe::{commands::CertifyKeyCommand, response::CertifyKeyResp};
    use x509_parser::{nom::Parser, prelude::*};

    let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        format: CertifyKeyCommand::FORMAT_X509,
        ..Default::default()
    });
    let CertifyKeyResp::P384(certify_key_resp) = certify_key(model, certify_key_cmd).unwrap()
    else {
        panic!("Wrong response type!");
    };
    let cert_bytes = &certify_key_resp.cert[..certify_key_resp.header.cert_size as usize];
    let (_, cert) = X509CertificateParser::new()
        .with_deep_parse_extensions(true)
        .parse(cert_bytes)
        .unwrap();
    let multi_tcb_info_oid = x509_parser::oid_registry::asn1_rs::oid!(2.23.133 .5 .4 .5);
    let ext = cert
        .get_extension_unique(&multi_tcb_info_oid)
        .unwrap()
        .expect("MultiTcbInfo extension missing");
    let parsed_tcb_infos = asn1::parse_single::<asn1::SequenceOf<TcbInfo>>(ext.value).unwrap();
    parsed_tcb_infos
        .filter_map(|mut tcb_info| {
            let tci_type: [u8; 4] = tcb_info.tci_type?.try_into().ok()?;
            let digest = tcb_info
                .fwids
                .as_mut()
                .and_then(|fwids| fwids.next().and_then(|fwid| fwid.digest.try_into().ok()));
            Some(TcbSnapshot {
                tci_type,
                svn: tcb_info.svn,
                digest,
            })
        })
        .collect()
}

fn find_tcb_snapshot<'a>(snapshots: &'a [TcbSnapshot], tci_type: &[u8; 4]) -> &'a TcbSnapshot {
    let tci_type = u32::from_be_bytes(*tci_type);
    snapshots
        .iter()
        .find(|snapshot| snapshot.tci_type == tci_type.as_bytes())
        .unwrap_or_else(|| {
            panic!(
                "{} TCB info missing",
                core::str::from_utf8(tci_type.as_bytes()).unwrap()
            )
        })
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_loads_mcu_fw() {
    // Test that the recovery flow runs and loads MCU's firmware

    let mcu_fw = vec![0x37u8; 256];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();
    let mut args = RuntimeTestArgs::default();
    let rom = crate::common::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest);
    args.mcu_fw_image = Some(&mcu_fw);
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    #[cfg(not(feature = "fpga_subsystem"))]
    {
        // check that we got an MCU write
        let events = model.events_from_caliptra();
        let mut found = false;
        for event in events {
            if event.dest == Device::MCU && matches!(event.event, EventData::MemoryWrite { .. }) {
                found = true;
                break;
            }
        }
        assert!(found);
    }
}

#[cfg_attr(
    any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    ),
    ignore
)]
#[test]
fn test_mcu_fw_bad_signature() {
    // Test that the recovery flow runs and loads MCU's firmware

    let mcu_fw = vec![0x37u8; 256];
    let bad_mcu_fw = vec![5, 6, 7, 8];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    // add a different digest to the to the SoC manifest
    let digest = from_hw_format(&crypto.sha384_digest(&bad_mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata(metadata);
    let soc_manifest = soc_manifest.as_bytes();
    let mut args = RuntimeTestArgs::default();
    let rom = crate::common::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest);
    args.mcu_fw_image = Some(&mcu_fw);
    args.successful_reach_rt = false;
    let mut model = run_rt_test(args);
    model.step_until_fatal_error(
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH.into(),
        30_000_000,
    );
}

#[cfg_attr(any(feature = "verilator", feature = "fpga_realtime"), ignore)]
#[test]
fn test_recovery_flow_with_svn() {
    // Test that recovery boot passes the SoC manifest SVN to the MCU RT DPE context.
    // The manifest is created with SVN=5, and fuses are configured to allow it.
    use crate::test_set_auth_manifest::create_auth_manifest_with_metadata_with_svn;

    let mcu_fw = vec![0x37u8; 256];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest = create_auth_manifest_with_metadata_with_svn(
        metadata,
        FwVerificationPqcKeyType::LMS,
        5, // SVN = 5
    );
    let soc_manifest_bytes = soc_manifest.as_bytes();
    let mut args = RuntimeTestArgs::default();
    let rom = crate::common::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest_bytes);
    args.mcu_fw_image = Some(&mcu_fw);
    args.soc_manifest_svn = Some(5);
    args.soc_manifest_max_svn = Some(127);
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    let snapshots = dpe_tcb_snapshots(&mut model);
    let somv_tcb_info = find_tcb_snapshot(&snapshots, b"SOMV");
    assert_eq!(somv_tcb_info.svn, Some(5));
    assert_eq!(somv_tcb_info.digest, Some(somv_measurement(&soc_manifest)));
    let somo_tcb_info = find_tcb_snapshot(&snapshots, b"SOMO");
    assert_eq!(somo_tcb_info.svn, Some(0));
    assert_eq!(somo_tcb_info.digest, Some(somo_measurement(&soc_manifest)));
    let mcfw_tcb_info = find_tcb_snapshot(&snapshots, b"MCFW");
    assert_eq!(mcfw_tcb_info.svn, Some(5));
}

#[cfg_attr(
    any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    ),
    ignore
)]
#[test]
fn test_set_auth_manifest_updates_soc_manifest_dpe_contexts() {
    use crate::test_set_auth_manifest::create_auth_manifest_with_metadata_with_svn;

    let mcu_fw = vec![0x37u8; 256];
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    let soc_manifest_v5 = create_auth_manifest_with_metadata_with_svn(
        metadata.clone(),
        FwVerificationPqcKeyType::LMS,
        5,
    );
    let soc_manifest_v5_bytes = soc_manifest_v5.as_bytes();
    let mut args = RuntimeTestArgs::default();
    let rom = crate::common::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        subsystem_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(soc_manifest_v5_bytes);
    args.mcu_fw_image = Some(&mcu_fw);
    args.soc_manifest_svn = Some(5);
    args.soc_manifest_max_svn = Some(127);
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    let initial_snapshots = dpe_tcb_snapshots(&mut model);
    let initial_somv = find_tcb_snapshot(&initial_snapshots, b"SOMV");
    assert_eq!(initial_somv.svn, Some(5));
    assert_eq!(
        initial_somv.digest,
        Some(somv_measurement(&soc_manifest_v5))
    );
    let initial_somo = find_tcb_snapshot(&initial_snapshots, b"SOMO");
    assert_eq!(initial_somo.svn, Some(0));
    assert_eq!(
        initial_somo.digest,
        Some(somo_measurement(&soc_manifest_v5))
    );
    let initial_pcr31 = quote_pcr31(&mut model);

    set_auth_manifest(&mut model, &soc_manifest_v5);
    let same_manifest_snapshots = dpe_tcb_snapshots(&mut model);
    let same_somv = find_tcb_snapshot(&same_manifest_snapshots, b"SOMV");
    assert_eq!(same_somv.svn, Some(5));
    assert_eq!(same_somv.digest, initial_somv.digest);
    let same_somo = find_tcb_snapshot(&same_manifest_snapshots, b"SOMO");
    assert_eq!(same_somo.svn, Some(0));
    assert_eq!(same_somo.digest, initial_somo.digest);
    assert_eq!(quote_pcr31(&mut model), initial_pcr31);

    let soc_manifest_v6 =
        create_auth_manifest_with_metadata_with_svn(metadata, FwVerificationPqcKeyType::LMS, 6);
    set_auth_manifest(&mut model, &soc_manifest_v6);
    let updated_snapshots = dpe_tcb_snapshots(&mut model);
    let updated_somv = find_tcb_snapshot(&updated_snapshots, b"SOMV");
    assert_eq!(updated_somv.svn, Some(5));
    assert_eq!(
        updated_somv.digest,
        Some(somv_measurement(&soc_manifest_v6))
    );
    assert_ne!(updated_somv.digest, initial_somv.digest);
    let updated_somo = find_tcb_snapshot(&updated_snapshots, b"SOMO");
    assert_eq!(updated_somo.svn, Some(0));
    assert_eq!(updated_somo.digest, initial_somo.digest);
    assert_ne!(quote_pcr31(&mut model), initial_pcr31);

    let pcr31_after_somv_update = quote_pcr31(&mut model);
    let soc_manifest_alt_owner = create_auth_manifest_with_alt_owner_keys(
        vec![AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags.0,
            digest,
            ..Default::default()
        }],
        6,
    );
    set_auth_manifest(&mut model, &soc_manifest_alt_owner);
    let owner_updated_snapshots = dpe_tcb_snapshots(&mut model);
    let owner_updated_somv = find_tcb_snapshot(&owner_updated_snapshots, b"SOMV");
    assert_eq!(owner_updated_somv.svn, Some(5));
    assert_eq!(owner_updated_somv.digest, updated_somv.digest);
    let owner_updated_somo = find_tcb_snapshot(&owner_updated_snapshots, b"SOMO");
    assert_eq!(owner_updated_somo.svn, Some(0));
    assert_eq!(
        owner_updated_somo.digest,
        Some(somo_measurement(&soc_manifest_alt_owner))
    );
    assert_ne!(owner_updated_somo.digest, initial_somo.digest);
    assert_ne!(quote_pcr31(&mut model), pcr31_after_somv_update);
}
