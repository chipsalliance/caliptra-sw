// Licensed under the Apache-2.0 license.

//! Shared infrastructure for per-command measurement tests.
//!
//! `CommandSampler` captures a "before" snapshot, lets the command run, then
//! produces a scalar result from the "after" snapshot. `run_command_suite`
//! drives the full ordered set of runtime commands through a given sampler and
//! returns the (name, measurement) pairs.
//!
//! Callers (test_stack_usage, test_command_timing) implement `CommandSampler`
//! and hand their impl to `run_command_suite` to get the table.
#![cfg(not(any(feature = "verilator", feature = "fpga_realtime")))]

use crate::common::{execute_dpe_cmd, generate_test_x509_cert, DpeResult, TEST_DIGEST, TEST_LABEL};
use crate::test_authorize_and_stash::{FW_ID_1, IMAGE_DIGEST1};
use crate::test_lms::representative_lms_verify_req;
use crate::test_set_auth_manifest::create_auth_manifest;
use caliptra_auth_man_types::AuthManifestFlags;
use caliptra_common::mailbox_api::{
    AddSubjectAltNameReq, AuthorizeAndStashReq, CertifyKeyExtendedFlags, CertifyKeyExtendedReq,
    CommandId, EcdsaVerifyReq, ExtendPcrReq, GetIdevCertReq, ImageHashSource,
    IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader, PopulateIdevCertReq, QuotePcrsReq,
    RevokeExportedCdiHandleReq, SetAuthManifestReq, SignWithExportedEcdsaReq, StashMeasurementReq,
    TagTciReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError, ShaAccMode};
use caliptra_runtime::CaliptraDpeProfile;
use dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyP384Cmd, Command, DeriveContextCmd,
        DeriveContextFlags, GetProfileCmd,
    },
    context::ContextHandle,
    response::Response,
    tci::TciMeasurement,
    TCI_SIZE,
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};
use zerocopy::IntoBytes;

const PROFILE: CaliptraDpeProfile = CaliptraDpeProfile::Ecc384;

/// Abstracts how a single command execution is measured.
///
/// `before` is called immediately before the mailbox round-trip; `after` is
/// called immediately after and returns the scalar measurement value (bytes,
/// cycles, etc.).
pub trait CommandSampler {
    fn before(&mut self, model: &mut DefaultHwModel);
    fn after(&mut self, model: &mut DefaultHwModel) -> u64;
}

fn measure_raw(
    sampler: &mut dyn CommandSampler,
    model: &mut DefaultHwModel,
    cmd_id: u32,
    req: &[u8],
) -> u64 {
    sampler.before(model);
    let _ = model.mailbox_execute(cmd_id, req);
    sampler.after(model)
}

fn measure_hdr(
    sampler: &mut dyn CommandSampler,
    model: &mut DefaultHwModel,
    cmd_id: CommandId,
) -> u64 {
    let id_u32 = u32::from(cmd_id);
    let req = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(id_u32, &[]),
    };
    measure_raw(sampler, model, id_u32, req.as_bytes())
}

fn measure_req(
    sampler: &mut dyn CommandSampler,
    model: &mut DefaultHwModel,
    cmd_id: CommandId,
    mut req: MailboxReq,
) -> u64 {
    req.populate_chksum().unwrap();
    let bytes = req.as_bytes().unwrap().to_vec();
    measure_raw(sampler, model, u32::from(cmd_id), &bytes)
}

fn measure_dpe(
    sampler: &mut dyn CommandSampler,
    model: &mut DefaultHwModel,
    cmd: &mut Command,
) -> u64 {
    sampler.before(model);
    let _ = execute_dpe_cmd(PROFILE, model, cmd, DpeResult::Success);
    sampler.after(model)
}

/// Drive every runtime command through `sampler` in state-dependency order and
/// return `(name, measurement)` pairs unsorted.
pub fn run_command_suite(
    model: &mut DefaultHwModel,
    sampler: &mut dyn CommandSampler,
) -> Vec<(&'static str, u64)> {
    let mut results: Vec<(&'static str, u64)> = Vec::new();

    // --- Header-only commands ---
    for (name, cmd_id) in [
        ("VERSION", CommandId::VERSION),
        ("CAPABILITIES", CommandId::CAPABILITIES),
        ("FW_INFO", CommandId::FW_INFO),
        ("GET_IDEV_INFO", CommandId::GET_IDEV_INFO),
        ("GET_LDEV_CERT", CommandId::GET_LDEV_CERT),
        ("GET_FMC_ALIAS_CERT", CommandId::GET_FMC_ALIAS_CERT),
        ("GET_RT_ALIAS_CERT", CommandId::GET_RT_ALIAS_CERT),
        ("GET_IDEV_CSR", CommandId::GET_IDEV_CSR),
        ("GET_FMC_ALIAS_CSR", CommandId::GET_FMC_ALIAS_CSR),
    ] {
        results.push((name, measure_hdr(sampler, model, cmd_id)));
    }

    // --- GET_PCR_LOG ---
    results.push((
        "GET_PCR_LOG",
        measure_req(
            sampler,
            model,
            CommandId::GET_PCR_LOG,
            MailboxReq::GetPcrLog(MailboxReqHeader::default()),
        ),
    ));

    // --- GET_IDEV_CERT ---
    {
        const TBS_SIZE: usize = 223;
        results.push((
            "GET_IDEV_CERT",
            measure_req(
                sampler,
                model,
                CommandId::GET_IDEV_CERT,
                MailboxReq::GetIdevCert(GetIdevCertReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    tbs: [0u8; GetIdevCertReq::DATA_MAX_SIZE],
                    signature_r: [0u8; 48],
                    signature_s: [0u8; 48],
                    tbs_size: TBS_SIZE as u32,
                }),
            ),
        ));
    }

    // --- PCR commands ---
    results.push((
        "INCREMENT_PCR_RESET_COUNTER",
        measure_req(
            sampler,
            model,
            CommandId::INCREMENT_PCR_RESET_COUNTER,
            MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
                hdr: MailboxReqHeader { chksum: 0 },
                index: 7,
            }),
        ),
    ));
    results.push((
        "EXTEND_PCR",
        measure_req(
            sampler,
            model,
            CommandId::EXTEND_PCR,
            MailboxReq::ExtendPcr(ExtendPcrReq {
                hdr: MailboxReqHeader { chksum: 0 },
                pcr_idx: 4,
                data: TEST_DIGEST,
            }),
        ),
    ));
    results.push((
        "QUOTE_PCRS",
        measure_req(
            sampler,
            model,
            CommandId::QUOTE_PCRS,
            MailboxReq::QuotePcrs(QuotePcrsReq {
                hdr: MailboxReqHeader { chksum: 0 },
                nonce: [0u8; 32],
            }),
        ),
    ));

    // --- STASH_MEASUREMENT ---
    results.push((
        "STASH_MEASUREMENT",
        measure_req(
            sampler,
            model,
            CommandId::STASH_MEASUREMENT,
            MailboxReq::StashMeasurement(StashMeasurementReq {
                measurement: TEST_DIGEST,
                ..Default::default()
            }),
        ),
    ));

    // --- INVOKE_DPE: light (GetProfile) and heavy (CertifyKey/X509) ---
    results.push((
        "INVOKE_DPE(GetProfile)",
        measure_dpe(sampler, model, &mut Command::GetProfile(&GetProfileCmd)),
    ));
    results.push((
        "INVOKE_DPE(CertifyKey/X509)",
        measure_dpe(
            sampler,
            model,
            &mut Command::CertifyKey(CertifyKeyCommand::P384(&CertifyKeyP384Cmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: CertifyKeyFlags::empty(),
                format: CertifyKeyCommand::FORMAT_X509,
            })),
        ),
    ));

    // --- DPE context tagging ---
    const TAG: u32 = 1;
    results.push((
        "DPE_TAG_TCI",
        measure_req(
            sampler,
            model,
            CommandId::DPE_TAG_TCI,
            MailboxReq::TagTci(TagTciReq {
                hdr: MailboxReqHeader { chksum: 0 },
                handle: [0u8; 16],
                tag: TAG,
            }),
        ),
    ));
    results.push((
        "DPE_GET_TAGGED_TCI",
        measure_req(
            sampler,
            model,
            CommandId::DPE_GET_TAGGED_TCI,
            MailboxReq::GetTaggedTci(caliptra_common::mailbox_api::GetTaggedTciReq {
                hdr: MailboxReqHeader { chksum: 0 },
                tag: TAG,
            }),
        ),
    ));

    // --- REALLOCATE_DPE_CONTEXT_LIMITS ---
    results.push((
        "REALLOCATE_DPE_CONTEXT_LIMITS",
        measure_req(
            sampler,
            model,
            CommandId::REALLOCATE_DPE_CONTEXT_LIMITS,
            MailboxReq::ReallocateDpeContextLimits(
                caliptra_common::mailbox_api::ReallocateDpeContextLimitsReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    pl0_context_limit: 8,
                },
            ),
        ),
    ));

    // --- Exported CDI: derive, sign, revoke ---
    {
        let export_cdi_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement([0; TCI_SIZE]),
            flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
            tci_type: 0,
            target_locality: 0,
            svn: 0,
        };
        let exported_cdi = match execute_dpe_cmd(
            PROFILE,
            model,
            &mut Command::DeriveContext(&export_cdi_cmd),
            DpeResult::Success,
        ) {
            Some(Response::DeriveContextExportedCdi(resp)) => resp.header.exported_cdi,
            _ => panic!("expected an exported-CDI derive-context response"),
        };

        results.push((
            "SIGN_WITH_EXPORTED_ECDSA",
            measure_req(
                sampler,
                model,
                CommandId::SIGN_WITH_EXPORTED_ECDSA,
                MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    exported_cdi_handle: exported_cdi,
                    tbs: TEST_DIGEST,
                }),
            ),
        ));
        results.push((
            "REVOKE_EXPORTED_CDI_HANDLE",
            measure_req(
                sampler,
                model,
                CommandId::REVOKE_EXPORTED_CDI_HANDLE,
                MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    exported_cdi_handle: exported_cdi,
                }),
            ),
        ));
    }

    // --- ECDSA384_VERIFY (digest primed in SHA accelerator) ---
    {
        model
            .compute_sha512_acc_digest(&TEST_DIGEST, ShaAccMode::Sha384Stream)
            .unwrap();
        results.push((
            "ECDSA384_VERIFY",
            measure_req(
                sampler,
                model,
                CommandId::ECDSA384_VERIFY,
                MailboxReq::EcdsaVerify(EcdsaVerifyReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    pub_key_x: [0u8; 48],
                    pub_key_y: [0u8; 48],
                    signature_r: [0u8; 48],
                    signature_s: [0u8; 48],
                }),
            ),
        ));
    }

    // --- LMS_VERIFY ---
    {
        let (lms_req, msg) = representative_lms_verify_req();
        model
            .compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
            .unwrap();
        results.push((
            "LMS_VERIFY",
            measure_req(sampler, model, CommandId::LMS_VERIFY, lms_req),
        ));
    }

    // --- ADD_SUBJECT_ALT_NAME, then CERTIFY_KEY_EXTENDED ---
    {
        let dmtf_device_info_bytes = b"ChipsAlliance:Caliptra:0123456789";
        let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
        dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
        results.push((
            "ADD_SUBJECT_ALT_NAME",
            measure_req(
                sampler,
                model,
                CommandId::ADD_SUBJECT_ALT_NAME,
                MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
                    dmtf_device_info,
                }),
            ),
        ));

        let certify_key_cmd = CertifyKeyCommand::P384(&CertifyKeyP384Cmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCommand::FORMAT_X509,
        });
        results.push((
            "CERTIFY_KEY_EXTENDED",
            measure_req(
                sampler,
                model,
                CommandId::CERTIFY_KEY_EXTENDED,
                MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
                    flags: CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
                }),
            ),
        ));
    }

    // --- POPULATE_IDEV_CERT ---
    {
        let ec_key = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap();
        let cert: X509 = generate_test_x509_cert(PKey::from_ec_key(ec_key).unwrap());
        let cert_der = cert.to_der().unwrap();
        let mut cert_slice = [0u8; PopulateIdevCertReq::MAX_CERT_SIZE];
        cert_slice[..cert_der.len()].copy_from_slice(&cert_der);
        results.push((
            "POPULATE_IDEV_CERT",
            measure_req(
                sampler,
                model,
                CommandId::POPULATE_IDEV_CERT,
                MailboxReq::PopulateIdevCert(PopulateIdevCertReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    cert_size: cert_der.len() as u32,
                    cert: cert_slice,
                }),
            ),
        ));
    }

    // --- SET_AUTH_MANIFEST, then AUTHORIZE_AND_STASH ---
    {
        let manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
        let buf = manifest.as_bytes();
        let mut manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
        manifest_slice[..buf.len()].copy_from_slice(buf);
        results.push((
            "SET_AUTH_MANIFEST",
            measure_req(
                sampler,
                model,
                CommandId::SET_AUTH_MANIFEST,
                MailboxReq::SetAuthManifest(SetAuthManifestReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    manifest_size: buf.len() as u32,
                    manifest: manifest_slice,
                }),
            ),
        ));
        results.push((
            "AUTHORIZE_AND_STASH",
            measure_req(
                sampler,
                model,
                CommandId::AUTHORIZE_AND_STASH,
                MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    measurement: IMAGE_DIGEST1,
                    source: ImageHashSource::InRequest as u32,
                    flags: 0,
                    fw_id: FW_ID_1,
                    ..Default::default()
                }),
            ),
        ));
    }

    // --- FIPS self-test: kick off, then poll until async KATs complete.
    // The measurement window spans the entire KAT execution so it captures
    // the true cost rather than just the final GET_RESULTS round-trip. ---
    results.push((
        "SELF_TEST_START",
        measure_hdr(sampler, model, CommandId::SELF_TEST_START),
    ));
    {
        let cmd_id = u32::from(CommandId::SELF_TEST_GET_RESULTS);
        let req = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(cmd_id, &[]),
        };
        sampler.before(model);
        loop {
            match model.mailbox_execute(cmd_id, req.as_bytes()) {
                Ok(_) => break,
                Err(ModelError::MailboxCmdFailed(code))
                    if code == u32::from(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED) => {}
                Err(ModelError::UnableToLockMailbox) => {}
                Err(e) => panic!("unexpected SELF_TEST_GET_RESULTS error: {e}"),
            }
            let mut cycles = 10_000;
            model.step_until(|_| {
                cycles -= 1;
                cycles == 0
            });
        }
        results.push(("SELF_TEST_GET_RESULTS(+KATs)", sampler.after(model)));
    }

    // --- Side-effecting commands, run last ---
    results.push((
        "DISABLE_ATTESTATION",
        measure_hdr(sampler, model, CommandId::DISABLE_ATTESTATION),
    ));
    results.push(("SHUTDOWN", measure_hdr(sampler, model, CommandId::SHUTDOWN)));

    results
}
