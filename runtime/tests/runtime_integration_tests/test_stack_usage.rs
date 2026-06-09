// Licensed under the Apache-2.0 license.

//! Measures the peak runtime stack usage of each Runtime Command.
//!
//! This walks every command dispatched by `handle_command()` and, for each,
//! drives it with a simple representative parameter set while the emulator
//! tracks the lowest stack pointer reached. Peak usage is the distance from the
//! top of the runtime stack down to that high-water mark, i.e. the absolute
//! deepest the stack gets while servicing the command (including the dispatch
//! frames already on the stack).
//!
//! Commands are issued in an order that respects state dependencies: state
//! builders (auth manifest, exported CDI, tagged contexts) run before their
//! consumers, and the side-effecting `DISABLE_ATTESTATION` / `SHUTDOWN` run
//! last.
//!
//! The mechanism relies on the emulator's stack-pointer tracking, so this test
//! only runs against the software emulator (not verilator/FPGA).
#![cfg(not(any(feature = "verilator", feature = "fpga_realtime")))]

use crate::common::{
    execute_dpe_cmd, generate_test_x509_cert, run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST,
    TEST_LABEL,
};
use crate::test_authorize_and_stash::{FW_ID_1, IMAGE_DIGEST1};
use crate::test_lms::representative_lms_verify_req;
use crate::test_set_auth_manifest::create_auth_manifest;
use caliptra_api::SocManager;
use caliptra_auth_man_types::AuthManifestFlags;
use caliptra_common::{
    mailbox_api::{
        AddSubjectAltNameReq, AuthorizeAndStashReq, CertifyKeyExtendedFlags, CertifyKeyExtendedReq,
        CommandId, EcdsaVerifyReq, ExtendPcrReq, GetIdevCertReq, ImageHashSource,
        IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader, PopulateIdevCertReq,
        QuotePcrsReq, RevokeExportedCdiHandleReq, SetAuthManifestReq, SignWithExportedEcdsaReq,
        StashMeasurementReq, TagTciReq,
    },
    memory_layout::{STACK_ORG, STACK_SIZE},
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError, ShaAccMode};
use caliptra_runtime::RtBootStatus;
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

/// Top of the runtime stack. The stack grows downward from here, so peak usage
/// is `STACK_TOP - min_sp`.
const STACK_TOP: u32 = STACK_ORG + STACK_SIZE;

/// A single command's measurement result.
type Measurement = (&'static str, u32);

/// Peak stack usage (in bytes) observed since the last reset, or `None` if no
/// stack activity occurred within a tracked image (e.g. the firmware never ran
/// because the mailbox could not be locked).
fn peak_stack_usage(model: &DefaultHwModel) -> Option<u32> {
    model.stack_min_sp().map(|min_sp| STACK_TOP - min_sp)
}

/// Reset the high-water mark, run a raw mailbox command, and return its peak
/// stack usage in bytes. The response is ignored: some commands legitimately
/// fail (e.g. a zero-signature verify) while still exercising their stack.
fn measure_raw(model: &mut DefaultHwModel, cmd_id: u32, req: &[u8]) -> u32 {
    model.reset_stack_high_water();
    let _ = model.mailbox_execute(cmd_id, req);
    peak_stack_usage(model)
        .expect("no stack activity observed; was the model built with stack_info?")
}

/// Measure a header-only command (no payload).
fn measure_header(model: &mut DefaultHwModel, cmd_id: CommandId) -> u32 {
    let cmd_id = u32::from(cmd_id);
    let req = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(cmd_id, &[]),
    };
    measure_raw(model, cmd_id, req.as_bytes())
}

/// Measure a command built from a `MailboxReq` (populates the checksum first).
fn measure_req(model: &mut DefaultHwModel, cmd_id: CommandId, mut req: MailboxReq) -> u32 {
    req.populate_chksum().unwrap();
    let bytes = req.as_bytes().unwrap().to_vec();
    measure_raw(model, u32::from(cmd_id), &bytes)
}

/// Measure a DPE command issued via `INVOKE_DPE`.
fn measure_dpe(model: &mut DefaultHwModel, cmd: &mut Command) -> u32 {
    model.reset_stack_high_water();
    let _ = execute_dpe_cmd(model, cmd, DpeResult::Success);
    peak_stack_usage(model).expect("no stack activity observed during DPE command")
}

#[test]
fn measure_runtime_command_stack_usage() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut results: Vec<Measurement> = Vec::new();

    // --- Header-only commands (no payload) ---
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
        results.push((name, measure_header(&mut model, cmd_id)));
    }

    // --- GET_PCR_LOG (header-only payload) ---
    results.push((
        "GET_PCR_LOG",
        measure_req(
            &mut model,
            CommandId::GET_PCR_LOG,
            MailboxReq::GetPcrLog(MailboxReqHeader::default()),
        ),
    ));

    // --- GET_IDEV_CERT: reassembles a cert from a TBS blob + signature ---
    {
        const TBS_SIZE: usize = 223;
        results.push((
            "GET_IDEV_CERT",
            measure_req(
                &mut model,
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
            &mut model,
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
            &mut model,
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
            &mut model,
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
            &mut model,
            CommandId::STASH_MEASUREMENT,
            MailboxReq::StashMeasurement(StashMeasurementReq {
                measurement: TEST_DIGEST,
                ..Default::default()
            }),
        ),
    ));

    // --- INVOKE_DPE: a light path (GetProfile) and a heavy one (CertifyKey) ---
    results.push((
        "INVOKE_DPE(GetProfile)",
        measure_dpe(&mut model, &mut Command::GetProfile(&GetProfileCmd)),
    ));
    results.push((
        "INVOKE_DPE(CertifyKey/X509)",
        measure_dpe(
            &mut model,
            &mut Command::CertifyKey(CertifyKeyCommand::P384(&CertifyKeyP384Cmd {
                handle: ContextHandle::default(),
                label: TEST_LABEL,
                flags: CertifyKeyFlags::empty(),
                format: CertifyKeyCommand::FORMAT_X509,
            })),
        ),
    ));

    // --- DPE context tagging (tag, then read the tag back) ---
    const TAG: u32 = 1;
    results.push((
        "DPE_TAG_TCI",
        measure_req(
            &mut model,
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
            &mut model,
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
            &mut model,
            CommandId::REALLOCATE_DPE_CONTEXT_LIMITS,
            MailboxReq::ReallocateDpeContextLimits(
                caliptra_common::mailbox_api::ReallocateDpeContextLimitsReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    pl0_context_limit: 8,
                },
            ),
        ),
    ));

    // --- Exported CDI: derive one, sign with it, then revoke it ---
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
            &mut model,
            &mut Command::DeriveContext(&export_cdi_cmd),
            DpeResult::Success,
        ) {
            Some(Response::DeriveContextExportedCdi(resp)) => resp.exported_cdi,
            _ => panic!("expected an exported-CDI derive-context response"),
        };

        results.push((
            "SIGN_WITH_EXPORTED_ECDSA",
            measure_req(
                &mut model,
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
                &mut model,
                CommandId::REVOKE_EXPORTED_CDI_HANDLE,
                MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    exported_cdi_handle: exported_cdi,
                }),
            ),
        ));
    }

    // --- ECDSA384_VERIFY (digest must be primed in the SHA accelerator) ---
    {
        model
            .compute_sha512_acc_digest(&TEST_DIGEST, ShaAccMode::Sha384Stream)
            .unwrap();
        results.push((
            "ECDSA384_VERIFY",
            measure_req(
                &mut model,
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

    // --- LMS_VERIFY (valid vector; message primed in the SHA accelerator) ---
    {
        let (req, msg) = representative_lms_verify_req();
        model
            .compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
            .unwrap();
        results.push((
            "LMS_VERIFY",
            measure_req(&mut model, CommandId::LMS_VERIFY, req),
        ));
    }

    // --- ADD_SUBJECT_ALT_NAME, then CERTIFY_KEY_EXTENDED using it ---
    {
        let dmtf_device_info_bytes = b"ChipsAlliance:Caliptra:0123456789";
        let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
        dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
        results.push((
            "ADD_SUBJECT_ALT_NAME",
            measure_req(
                &mut model,
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
                &mut model,
                CommandId::CERTIFY_KEY_EXTENDED,
                MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    certify_key_req: certify_key_cmd.as_bytes().try_into().unwrap(),
                    flags: CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
                }),
            ),
        ));
    }

    // --- POPULATE_IDEV_CERT (store a generated X509 cert in the chain) ---
    {
        let ec_key = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap();
        let cert: X509 = generate_test_x509_cert(PKey::from_ec_key(ec_key).unwrap());
        let cert_der = cert.to_der().unwrap();
        let mut cert_slice = [0u8; PopulateIdevCertReq::MAX_CERT_SIZE];
        cert_slice[..cert_der.len()].copy_from_slice(&cert_der);
        results.push((
            "POPULATE_IDEV_CERT",
            measure_req(
                &mut model,
                CommandId::POPULATE_IDEV_CERT,
                MailboxReq::PopulateIdevCert(PopulateIdevCertReq {
                    hdr: MailboxReqHeader { chksum: 0 },
                    cert_size: cert_der.len() as u32,
                    cert: cert_slice,
                }),
            ),
        ));
    }

    // --- SET_AUTH_MANIFEST, then AUTHORIZE_AND_STASH against it ---
    {
        let manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
        let buf = manifest.as_bytes();
        let mut manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
        manifest_slice[..buf.len()].copy_from_slice(buf);
        results.push((
            "SET_AUTH_MANIFEST",
            measure_req(
                &mut model,
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
                &mut model,
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

    // --- FIPS self test: kick it off, then poll for results. The asynchronous
    // KATs run in the idle loop, so the GET_RESULTS polling window captures the
    // self-test's stack usage. Run this near the end so the KATs do not
    // contaminate the measurements of other commands. ---
    results.push((
        "SELF_TEST_START",
        measure_header(&mut model, CommandId::SELF_TEST_START),
    ));
    {
        let cmd_id = u32::from(CommandId::SELF_TEST_GET_RESULTS);
        let req = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(cmd_id, &[]),
        };
        // Reset once and leave the high-water mark running for the whole poll:
        // the asynchronous KATs execute while we step (both inside
        // `mailbox_execute` and `step_until`), so this window captures the
        // self-test's stack usage rather than just the GET_RESULTS floor.
        model.reset_stack_high_water();
        loop {
            match model.mailbox_execute(cmd_id, req.as_bytes()) {
                Ok(_) => break,
                Err(ModelError::MailboxCmdFailed(code))
                    if code == u32::from(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED) => {}
                Err(ModelError::UnableToLockMailbox) => {}
                Err(e) => panic!("unexpected SELF_TEST_GET_RESULTS error: {e}"),
            }
            // Give the firmware time to make progress on the KATs.
            let mut cycles = 10_000;
            model.step_until(|_| {
                cycles -= 1;
                cycles == 0
            });
        }
        let usage = peak_stack_usage(&model).expect("no stack activity observed during self test");
        results.push(("SELF_TEST_GET_RESULTS(+KATs)", usage));
    }

    // --- Side-effecting commands, run last ---
    // DISABLE_ATTESTATION must come after all attestation-dependent commands.
    results.push((
        "DISABLE_ATTESTATION",
        measure_header(&mut model, CommandId::DISABLE_ATTESTATION),
    ));
    // SHUTDOWN rejects all subsequent commands, so it must be the very last.
    results.push(("SHUTDOWN", measure_header(&mut model, CommandId::SHUTDOWN)));

    // Report, highest stack usage first.
    results.sort_by_key(|b| std::cmp::Reverse(b.1));
    println!("\nRuntime command peak stack usage (runtime stack = {STACK_SIZE} bytes):");
    println!("{:<32} {:>10} {:>8}", "command", "bytes", "% stack");
    println!("{}", "-".repeat(52));
    for (name, bytes) in &results {
        let pct = (*bytes as f64) * 100.0 / (STACK_SIZE as f64);
        println!("{name:<32} {bytes:>10} {pct:>7.1}%");
    }

    // Sanity: every command must consume some stack and stay within the budget.
    for (name, bytes) in &results {
        assert!(*bytes > 0, "{name} reported zero stack usage");
        assert!(
            *bytes < STACK_SIZE,
            "{name} stack usage {bytes} exceeds runtime stack size {STACK_SIZE}"
        );
    }
}
