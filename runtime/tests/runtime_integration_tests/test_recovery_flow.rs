// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_auth_man_types::{AuthManifestImageMetadata, ImageMetadataFlags};
#[cfg(not(feature = "fpga_subsystem"))]
use caliptra_emu_bus::{Device, EventData};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, InitParams};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::from_hw_format;
use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::IntoBytes;

const RT_READY_FOR_COMMANDS: u32 = 0x600;

#[derive(asn1::Asn1Read)]
struct Fwid<'a> {
    _hash_alg: asn1::ObjectIdentifier,
    _digest: &'a [u8],
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
    _fwids: Option<asn1::SequenceOf<'a, Fwid<'a>>>,
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
    use caliptra_image_types::FwVerificationPqcKeyType;

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
    args.soc_manifest_svn = Some(5);
    args.soc_manifest_max_svn = Some(127);
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);

    use crate::common::{certify_key, CertifyKeyCommandNoRef, CreateCertifyKeyCmdArgs};
    use caliptra_dpe::{commands::CertifyKeyCommand, response::CertifyKeyResp};
    use x509_parser::{nom::Parser, prelude::*};

    let certify_key_cmd = &mut CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        format: CertifyKeyCommand::FORMAT_X509,
        ..Default::default()
    });
    let CertifyKeyResp::P384(certify_key_resp) = certify_key(&mut model, certify_key_cmd).unwrap()
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
    let mut parsed_tcb_infos = asn1::parse_single::<asn1::SequenceOf<TcbInfo>>(ext.value).unwrap();
    let mcu_tci_type = u32::from_be_bytes(*b"MCFW");
    let mcfw_tcb_info = parsed_tcb_infos
        .find(|tcb_info| tcb_info.tci_type == Some(mcu_tci_type.as_bytes()))
        .expect("MCFW TCB info missing");
    assert_eq!(mcfw_tcb_info.svn, Some(5));
}
