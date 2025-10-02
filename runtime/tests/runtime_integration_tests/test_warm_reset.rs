// Licensed under the Apache-2.0 license

use crate::common::generate_test_x509_cert;
use caliptra_api::soc_mgr::SocManager;
use caliptra_builder::{
    build_and_sign_image, build_firmware_rom,
    firmware::{self, runtime_tests::MBOX, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_common::{
    capabilities::Capabilities,
    checksum::{calc_checksum, verify_checksum},
    mailbox_api::{
        CapabilitiesResp, CommandId, GetIdevCertResp, GetIdevEcc384CertReq, MailboxReq,
        MailboxReqHeader, MailboxRespHeader,
    },
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::ImageGenerator;
use caliptra_image_types::RomInfo;
use caliptra_test::image_pk_desc_hash;
use dpe::DPE_PROFILE;
use zerocopy::{FromBytes, IntoBytes};

use caliptra_common::x509::get_tbs;

use openssl::asn1::Asn1TimeRef;
use openssl::ecdsa::EcdsaSig;

use openssl::x509::X509;

use std::cmp::Ordering;

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{PKey, Private},
    sha::sha384,
};

#[test]
fn test_rt_journey_pcr_validation() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let _ = model
        .mailbox_execute(0xD000_0000, &[0u8; DPE_PROFILE.get_tci_size()])
        .unwrap()
        .unwrap();

    // Perform warm reset
    model.warm_reset_flow(&boot_params).unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED)
    });

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

// TODO: https://github.com/chipsalliance/caliptra-sw/issues/2225
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_mbox_busy_during_warm_reset() {
    // This test uses the mailbox responder binary to set the mailbox_flow_done register to
    // false.
    // A warm reset is then performed, since the mailbox responder binary never sets mailbox_flow_done
    // to true, we verify that the mailbox_flow_done register remains false through the warm reset.
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MBOX,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // 0xE000_0000 == OPCODE_HOLD_COMMAND_BUSY
    model.mailbox_execute(0xE000_0000, &[]).unwrap();

    assert!(!model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .mailbox_flow_done());

    // Perform warm reset
    model.warm_reset_flow(&boot_params).unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}

// TODO: https://github.com/chipsalliance/caliptra-sw/issues/2225
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_mbox_idle_during_warm_reset() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let binding = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            fw_svn: [0b1111111, 0, 0, 0],
            ..Default::default()
        },
        fw_image: Some(&binding),
        ..Default::default()
    };

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    // Perform warm reset
    model.warm_reset_flow(&boot_params).unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    assert_ne!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET)
    );
}

fn get_capabilities(model: &mut DefaultHwModel) -> (CapabilitiesResp, Vec<u8>) {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .expect("mailbox_execute failed")
        .expect("CAPABILITIES returned no data");

    assert!(!resp.is_empty(), "CAPABILITIES returned empty payload");

    let capabilities_resp =
        CapabilitiesResp::read_from_bytes(resp.as_slice()).expect("parse CapabilitiesResp failed");

    // Verify response checksum (exclude the checksum field itself).
    assert!(
        verify_checksum(
            capabilities_resp.hdr.chksum,
            0x0,
            &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
        ),
        "CAPABILITIES response checksum invalid"
    );
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CAPABILITIES FIPS not APPROVED"
    );

    (capabilities_resp, resp)
}

pub struct BuildArgs {
    pub security_state: SecurityState,
    pub fmc_version: u32,
    pub app_version: u32,
    pub fw_svn: u32,
}

impl Default for BuildArgs {
    fn default() -> Self {
        let security_state = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production);
        Self {
            security_state,
            fmc_version: 3,
            app_version: 5,
            fw_svn: 9,
        }
    }
}

pub fn build_ready_runtime_model(args: BuildArgs) -> (DefaultHwModel, Vec<u8>) {
    // Security state & versions from args
    let security_state = args.security_state;
    let fmc_version = args.fmc_version;
    let app_version = args.app_version;

    // ROM & image
    let rom = build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_version: fmc_version.try_into().unwrap(),
            app_version,
            fw_svn: args.fw_svn,
            ..Default::default()
        },
    )
    .unwrap();

    // compute rom_info + owner_pub_key_hash
    let _rom_info = find_rom_info(&rom).unwrap();
    let _owner_pub_key_hash = ImageGenerator::new(Crypto::default())
        .owner_pubkey_digest(&image.manifest.preamble)
        .unwrap();

    // Fuses / boot params
    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);
    let image_bytes = image.to_bytes().unwrap();
    let boot_params = BootParams {
        fuses: Fuses {
            vendor_pk_hash: vendor_pk_desc_hash,
            owner_pk_hash,
            fw_svn: [0x7F, 0, 0, 0],
            ..Default::default()
        },
        fw_image: Some(&image_bytes),
        ..Default::default()
    };

    // Model
    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        boot_params.clone(),
    )
    .unwrap();

    // Wait until runtime ready
    wait_runtime_ready(&mut model);
    (model, image_bytes)
}

fn find_rom_info(rom: &[u8]) -> Option<RomInfo> {
    // RomInfo is 64-byte aligned and the last data in the ROM bin
    // Iterate backwards by 64-byte increments (assumes rom size will always be 64 byte aligned)
    for i in (0..rom.len() - 63).rev().step_by(64) {
        let chunk = &rom[i..i + 64];

        // Check if the chunk contains non-zero data
        if chunk.iter().any(|&byte| byte != 0) {
            // Found non-zero data, return RomInfo constructed from the data
            if let Ok(rom_info) = RomInfo::read_from_bytes(&rom[i..i + size_of::<RomInfo>()]) {
                return Some(rom_info);
            }
        }
    }

    // No non-zero data found
    None
}

pub fn wait_runtime_ready(model: &mut DefaultHwModel) {
    while !model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_runtime()
    {
        model.step();
    }
}

#[test]
fn test_capabilities_after_warm_reset() {
    let (mut model, _image_bytes) = build_ready_runtime_model(BuildArgs::default());

    // --- Before warm reset ---
    let (cap_resp_before, raw_resp_before) = get_capabilities(&mut model);
    let capabilities_before =
        Capabilities::try_from(&cap_resp_before.capabilities[..]).expect("decode caps");
    assert!(capabilities_before.contains(Capabilities::RT_BASE));

    // --- Warm reset ---
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // --- After warm reset ---
    let (cap_resp_after, raw_resp_after) = get_capabilities(&mut model);
    let capabilities_after =
        Capabilities::try_from(&cap_resp_after.capabilities[..]).expect("decode caps");
    assert!(capabilities_after.contains(Capabilities::RT_BASE));

    assert_eq!(
        raw_resp_before, raw_resp_after,
        "Raw CAPABILITIES changed across warm reset"
    );
    assert_eq!(
        cap_resp_before.as_bytes(),
        cap_resp_after.as_bytes(),
        "Typed CAPABILITIES bytes changed across warm reset"
    );
    assert_eq!(
        capabilities_before.to_bytes(),
        capabilities_after.to_bytes(),
        "Capability bitflags changed across warm reset"
    ); //
}

/// Compare two X509 certs by semantic fields rather than raw bytes.
fn assert_x509_semantic_eq(a: &X509, b: &X509) {
    // Issuer / Subject
    assert_eq!(
        a.issuer_name().entries().count(),
        b.issuer_name().entries().count(),
        "issuer entry count mismatch"
    );
    assert_eq!(
        a.issuer_name().to_der().unwrap(),
        b.issuer_name().to_der().unwrap(),
        "issuer differs"
    );

    assert_eq!(
        a.subject_name().entries().count(),
        b.subject_name().entries().count(),
        "subject entry count mismatch"
    );
    assert_eq!(
        a.subject_name().to_der().unwrap(),
        b.subject_name().to_der().unwrap(),
        "subject differs"
    );

    // Serial number
    let a_sn = a.serial_number().to_bn().unwrap().to_vec();
    let b_sn = b.serial_number().to_bn().unwrap().to_vec();
    assert_eq!(a_sn, b_sn, "serial number differs");

    // Public key
    let a_pk = a.public_key().unwrap().public_key_to_der().unwrap();
    let b_pk = b.public_key().unwrap().public_key_to_der().unwrap();
    assert_eq!(a_pk, b_pk, "public key differs");

    // Signature algorithm OID (not the signature value)
    let a_sig_oid = a.signature_algorithm().object().nid();
    let b_sig_oid = b.signature_algorithm().object().nid();
    assert_eq!(a_sig_oid, b_sig_oid, "signature algorithm differs");

    //check validity
    assert_same_time(a.not_before(), b.not_before(), "notBefore");
    assert_same_time(a.not_after(), b.not_after(), "notAfter");
}

fn assert_same_time(a: &Asn1TimeRef, b: &Asn1TimeRef, label: &str) {
    let d = a.diff(b).expect("ASN.1 time diff failed");
    // Equal iff  day delta is 0 and second deltas is less than 10

    // Must be the same day
    assert_eq!(
        d.days, 0,
        "{label} differs by {} days, {} secs",
        d.days, d.secs
    );

    // Seconds delta allowed up to 10
    assert!(
        d.secs.abs() <= 10,
        "{label} differs by {} secs (allowed ≤ 10)",
        d.secs
    );
}

/// Deterministically derive a P-384 EC key from `seed`.
/// Same seed => same key.
pub fn deterministic_p384_key_from_seed(seed: &[u8]) -> PKey<Private> {
    // Curve group and order n
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut n = BigNum::new().unwrap();
    group
        .order(&mut n, &mut BigNumContext::new().unwrap())
        .unwrap();

    // Helper: portable zero check
    fn is_zero_bn(bn: &BigNum) -> bool {
        bn.num_bits() == 0
    }

    // Find d in [1, n-1] by hashing (seed || counter) until d < n and d != 0
    let mut ctr: u32 = 0;
    let d = loop {
        let mut buf = Vec::with_capacity(seed.len() + 4);
        buf.extend_from_slice(seed);
        buf.extend_from_slice(&ctr.to_be_bytes());
        let h = sha384(&buf);

        let cand = BigNum::from_slice(&h).unwrap();
        if !is_zero_bn(&cand) && cand.ucmp(&n) == Ordering::Less {
            break cand;
        }
        ctr = ctr.wrapping_add(1);
    };

    // Q = d·G
    let ctx = BigNumContext::new().unwrap();
    let mut q = EcPoint::new(&group).unwrap();
    q.mul_generator(&group, &d, &ctx).unwrap();

    // EcKey(d, Q) -> PKey
    let ec_key = EcKey::from_private_components(&group, &d, &q).unwrap();
    PKey::from_ec_key(ec_key).unwrap()
}

/// Issue GET_IDEV_ECC384_CERT once and return the parsed X509.
fn get_idev_cert(model: &mut DefaultHwModel) -> X509 {
    // Build deterministic ec_Key so pub key will be the same

    const TEST_SEED: &[u8] = b"idev-cert-seed-v1";
    let ec_key = deterministic_p384_key_from_seed(TEST_SEED);

    let cert = generate_test_x509_cert(&ec_key);
    assert!(
        cert.verify(&ec_key).unwrap(),
        "self-check: test cert must verify"
    );

    let sig_bytes = cert.signature().as_slice();
    let signature = EcdsaSig::from_der(sig_bytes).unwrap();
    let signature_r: [u8; 48] = signature.r().to_vec_padded(48).unwrap().try_into().unwrap();
    let signature_s: [u8; 48] = signature.s().to_vec_padded(48).unwrap().try_into().unwrap();

    let tbs = get_tbs(cert.to_der().unwrap());
    let tbs_len = tbs.len();

    let mut req = GetIdevEcc384CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0; GetIdevEcc384CertReq::DATA_MAX_SIZE],
        signature_r,
        signature_s,
        tbs_size: tbs_len as u32,
    };
    req.tbs[..tbs_len].copy_from_slice(&tbs);

    let mut cmd = MailboxReq::GetIdevEcc384Cert(req);
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_ECC384_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("expected response");

    assert!(
        resp.len() <= core::mem::size_of::<GetIdevCertResp>(),
        "unexpected payload size"
    );
    let mut cert_resp = GetIdevCertResp::default();
    cert_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    // Verify checksum on variable-sized payload (everything after chksum)
    assert!(
        verify_checksum(
            cert_resp.hdr.chksum,
            0x0,
            &resp[core::mem::size_of_val(&cert_resp.hdr.chksum)..],
        ),
        "response checksum invalid"
    );

    assert_eq!(
        cert_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CERT FIPS not APPROVED"
    );
    assert!(
        (cert_resp.data_size as usize) <= cert_resp.data.len(),
        "data_size exceeds buffer"
    );
    let der = &cert_resp.data[..(cert_resp.data_size as usize)];

    X509::from_der(der).unwrap()
}

#[test]
fn test_get_idev_ecc384_cert_after_warm_reset() {
    // Build runtime using your helper
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _image_bytes) = build_ready_runtime_model(args);

    // Before warm reset
    let cert_before = get_idev_cert(&mut model);

    // Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // After warm reset
    let cert_after = get_idev_cert(&mut model);

    // Compare semantically
    assert_x509_semantic_eq(&cert_before, &cert_after);
}
