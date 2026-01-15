// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{
        CapabilitiesResp, CommandId, EndorsementAlgorithms, HpkeAlgorithms, MailboxReq,
        MailboxReqHeader, MailboxRespHeader, OcpLockEndorseHpkePubKeyReq,
        OcpLockEndorseHpkePubKeyResp, OcpLockEnumerateHpkeHandlesReq,
        OcpLockEnumerateHpkeHandlesResp, OcpLockInitializeMekSecretReq,
        OcpLockReportHekMetadataReq, OcpLockReportHekMetadataResp,
        OcpLockReportHekMetadataRespFlags,
    },
    Capabilities,
};
use caliptra_builder::{firmware::runtime_tests, FwId};
use caliptra_drivers::HekSeedState;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    DefaultHwModel, HwModel, ModelCallback, ModelError, OcpLockState, SecurityState,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::U8Bool;
use zerocopy::{FromBytes, IntoBytes};

use openssl::x509::X509;
use x509_parser::nom::Parser;
use x509_parser::prelude::*;

use crate::common::{get_rt_alias_ecc384_cert, run_rt_test, RuntimeTestArgs};

mod test_derive_mek;
mod test_endorse_hpke_pubkey;
mod test_enumerate_hpke_handles;
mod test_generate_mek;
mod test_get_algorithms;
mod test_initialize_mek_secret;
mod test_rotate_hpke_key;

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_hek_metadata_never_reported() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        // This test assumes OCP LOCK is always enabled.
        force_ocp_lock_en: true,
        rt_fw_id: Some(&runtime_tests::MBOX_FPGA),
        ..Default::default()
    });

    // HEK can NEVER be valid if MCU ROM never reported the HEK metadata.
    let expected_val = U8Bool::new(false);
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_hek_available() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        rt_fw_id: Some(&runtime_tests::MBOX_FPGA),
        ..Default::default()
    });

    // We reported HEK metadata so it should be available.
    let expected_val = U8Bool::new(true);
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}

struct InitializeMekSecretParams {
    sek: [u8; 32],
    dpk: [u8; 32],
}

#[derive(Default)]
struct OcpLockBootParams {
    hek_available: bool,
    init_mek_secret_params: Option<InitializeMekSecretParams>,
    force_ocp_lock_en: bool,
    rt_fw_id: Option<&'static FwId<'static>>,
    security_state: Option<SecurityState>,
    // The linter doesn't like using Default when all params are set.
    _private: (),
}

fn boot_ocp_lock_runtime(params: OcpLockBootParams) -> DefaultHwModel {
    let mut cmd = MailboxReq::OcpLockReportHekMetadata(OcpLockReportHekMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed_state: HekSeedState::Programmed.into(),
        ..Default::default()
    });

    cmd.populate_chksum().unwrap();

    // A common operation is to report the HEK metadata.
    // The HEK is not available without this step.
    let cb = move |model: &mut DefaultHwModel| {
        let response = model
            .mailbox_execute(
                CommandId::OCP_LOCK_REPORT_HEK_METADATA.into(),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();

        let response = OcpLockReportHekMetadataResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert!(response
            .flags
            .contains(OcpLockReportHekMetadataRespFlags::HEK_AVAILABLE));
    };

    let rom_callback: Option<ModelCallback> = if params.hek_available {
        Some(Box::new(cb))
    } else {
        None
    };

    let security_state = params.security_state.unwrap_or(
        *SecurityState::default()
            .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
            .set_debug_locked(true),
    );

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: params.rt_fw_id,
        ocp_lock_en: params.force_ocp_lock_en,
        key_type: Some(FwVerificationPqcKeyType::MLDSA),
        rom_callback,
        security_state: Some(security_state),
        ..Default::default()
    });

    // Another common operation is to seed the MEK secret.
    // Many commands, e.g. `DERIVE_MEK` will not work until this happens.
    if let Some(params) = params.init_mek_secret_params {
        // Initialize MEK Secret Seed
        let mut cmd = MailboxReq::OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq {
            hdr: MailboxReqHeader { chksum: 0 },
            reserved: 0,
            sek: params.sek,
            dpk: params.dpk,
        });
        cmd.populate_chksum().unwrap();
        let response = model.mailbox_execute(
            CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET.into(),
            cmd.as_bytes().unwrap(),
        );
        validate_ocp_lock_response(&mut model, response, |response, _| {
            response.unwrap().unwrap();
        });
    }
    model
}

fn ocp_lock_supported(model: &mut DefaultHwModel) -> bool {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let response = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .unwrap()
        .unwrap();

    let capabilities_resp = CapabilitiesResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        capabilities_resp.hdr.chksum,
        0x0,
        &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
    ));
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let caps = Capabilities::try_from(capabilities_resp.capabilities.as_bytes()).unwrap();
    assert!(caps.contains(Capabilities::RT_BASE));

    caps.contains(Capabilities::RT_OCP_LOCK)
}

fn validate_ocp_lock_response<T>(
    model: &mut DefaultHwModel,
    response: std::result::Result<Option<Vec<u8>>, ModelError>,
    check_callback: impl FnOnce(std::result::Result<Option<Vec<u8>>, ModelError>, OcpLockState) -> T,
) -> Option<T> {
    if ocp_lock_supported(model) {
        let state = model.ocp_lock_state().unwrap();
        return Some(check_callback(response, state));
    } else {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into(),
            )
        );
    }
    None
}

#[derive(Debug, PartialEq)]
struct ValidatedHpkeHandle {
    hpke_handle: u32,
    pub_key: Vec<u8>,
}

fn get_hpke_handle(model: &mut DefaultHwModel, suite: HpkeAlgorithms) -> Option<u32> {
    let mut cmd =
        MailboxReq::OcpLockEnumerateHpkeHandles(OcpLockEnumerateHpkeHandlesReq::default());
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES.into(),
        cmd.as_bytes().unwrap(),
    );

    let hpke_handle = validate_ocp_lock_response(model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let enumerate_resp =
            OcpLockEnumerateHpkeHandlesResp::ref_from_bytes(response.as_bytes()).unwrap();
        let hpke_handle = enumerate_resp
            .hpke_handles
            .iter()
            .find(|entry| entry.hpke_algorithm == suite)
            .unwrap()
            .clone();
        hpke_handle
    })?;

    Some(hpke_handle.handle)
}

fn get_validated_hpke_handle(
    model: &mut DefaultHwModel,
    suite: HpkeAlgorithms,
) -> Option<ValidatedHpkeHandle> {
    let hpke_handle = get_hpke_handle(model, suite)?;
    verify_hpke_pub_key(model, hpke_handle)
}

fn verify_hpke_pub_key(
    model: &mut DefaultHwModel,
    hpke_handle: u32,
) -> Option<ValidatedHpkeHandle> {
    // TODO(clundin): Update for ML-DSA endorsement after https://github.com/chipsalliance/caliptra-sw/issues/3106.
    let mut cmd = MailboxReq::OcpLockEndorseHpkePubKey(OcpLockEndorseHpkePubKeyReq {
        hpke_handle,
        endorsement_algorithm: EndorsementAlgorithms::ECDSA_P384_SHA384,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENDORSE_HPKE_PUB_KEY.into(),
        cmd.as_bytes().unwrap(),
    );

    let endorse_resp = validate_ocp_lock_response(model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let endorse_resp =
            OcpLockEndorseHpkePubKeyResp::read_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(caliptra_common::checksum::verify_checksum(
            endorse_resp.hdr.chksum,
            0x0,
            &endorse_resp.as_bytes()[core::mem::size_of_val(&endorse_resp.hdr.chksum)..],
        ));
        // Verify FIPS status
        assert_eq!(
            endorse_resp.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        endorse_resp
    })?;
    verify_endorsement_certificate(model, &endorse_resp);
    Some(ValidatedHpkeHandle {
        hpke_handle,
        pub_key: endorse_resp.pub_key[..endorse_resp.pub_key_len as usize].to_vec(),
    })
}

fn verify_endorsement_certificate(
    model: &mut DefaultHwModel,
    endorse_resp: &OcpLockEndorseHpkePubKeyResp,
) {
    // Get RT Alias Cert
    let rt_alias_cert_resp = get_rt_alias_ecc384_cert(model);
    let rt_alias_cert =
        X509::from_der(&rt_alias_cert_resp.data[..rt_alias_cert_resp.data_size as usize]).unwrap();

    // Verify Endorsement Certificate Signature
    let endorsement_cert_der = &endorse_resp.endorsement[..endorse_resp.endorsement_len as usize];
    let endorsement_cert = X509::from_der(endorsement_cert_der).unwrap();
    assert!(endorsement_cert
        .verify(&rt_alias_cert.public_key().unwrap())
        .unwrap());

    // Verify Subject Public Key in Certificate matches Response Public Key
    let pub_key_resp = &endorse_resp.pub_key[..endorse_resp.pub_key_len as usize];

    // Parse with x509_parser to extract Subject Public Key bytes
    let (_, cert_parsed) = X509CertificateParser::new()
        .parse(endorsement_cert_der)
        .unwrap();
    let spki = cert_parsed.tbs_certificate.subject_pki;

    // Ensure the public key in response is contained in the certificate's SPKI
    assert_eq!(spki.subject_public_key.data, pub_key_resp);
}
