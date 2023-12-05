// Licensed under the Apache-2.0 license.

use crate::common::{execute_dpe_cmd, run_rt_test};
use caliptra_common::mailbox_api::{CommandId, InvokeDpeReq, MailboxReq, MailboxReqHeader};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::{InvokeDpeCmd, RtBootStatus, DPE_SUPPORT, VENDOR_ID, VENDOR_SKU};
use dpe::{
    commands::{
        CertifyKeyCmd, CertifyKeyFlags, Command, CommandHdr, DeriveChildCmd, DeriveChildFlags,
        GetCertificateChainCmd, RotateCtxCmd, RotateCtxFlags, SignCmd, SignFlags,
    },
    context::ContextHandle,
    response::Response,
    DPE_PROFILE,
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
};
use zerocopy::AsBytes;

const TEST_LABEL: [u8; 48] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];
const TEST_DIGEST: [u8; 48] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
];

#[test]
fn test_invoke_dpe_get_profile_cmd() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let resp = execute_dpe_cmd(&mut model, &mut Command::GetProfile);
    let Response::GetProfile(profile) = resp else {
        panic!("Wrong response type!");
    };
    assert_eq!(profile.resp_hdr.profile, DPE_PROFILE as u32);
    assert_eq!(profile.vendor_id, VENDOR_ID);
    assert_eq!(profile.vendor_sku, VENDOR_SKU);
    assert_eq!(profile.flags, DPE_SUPPORT.bits());
}

#[test]
fn test_invoke_dpe_size_too_big() {
    // Test with data_size too big.
    let mut cmd = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data_size: InvokeDpeReq::DATA_MAX_SIZE as u32 + 1,
        data: [0u8; InvokeDpeReq::DATA_MAX_SIZE],
    });
    assert_eq!(
        cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}

#[test]
fn test_invoke_dpe_get_certificate_chain_cmd() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::GetCertificateChain(get_cert_chain_cmd),
    );
    let Response::GetCertificateChain(cert_chain) = resp else {
        panic!("Wrong response type!");
    };

    assert_eq!(cert_chain.certificate_size, 2048);
    assert_ne!([0u8; 2048], cert_chain.certificate_chain);
}

#[test]
fn test_pauser_privilege_level_dpe_context_thresholds() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // First rotate the default context so that we don't run into an error
    // when trying to retain the default context in derive child.
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };
    let resp = execute_dpe_cmd(&mut model, &mut Command::RotateCtx(rotate_ctx_cmd));
    let Response::RotateCtx(rotate_ctx_resp) = resp else {
        panic!("Wrong response type!");
    };
    let mut handle = rotate_ctx_resp.handle;

    // Call DeriveChild with PL0 enough times to breach the threshold on the last iteration.
    // Note that this loop runs exactly PL0_DPE_ACTIVE_CONTEXT_THRESHOLD times. When we initialize
    // DPE, we measure mailbox valid pausers in pl0_pauser's locality. Thus, we can call derive child
    // from PL0 exactly 7 times, and the last iteration of this loop, is expected to throw a threshold breached error.
    let num_iterations = InvokeDpeCmd::PL0_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let derive_child_cmd = DeriveChildCmd {
            handle,
            data: [0u8; DPE_PROFILE.get_hash_size()],
            flags: DeriveChildFlags::RETAIN_PARENT,
            tci_type: 0,
            target_locality: 0,
        };

        // If we are on the last call to DeriveChild, expect that we get a PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let mut cmd_data: [u8; 512] = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
            let derive_child_cmd_hdr = CommandHdr::new_for_test(Command::DERIVE_CHILD);
            let derive_child_cmd_hdr_buf = derive_child_cmd_hdr.as_bytes();
            cmd_data[..derive_child_cmd_hdr_buf.len()].copy_from_slice(derive_child_cmd_hdr_buf);
            let derive_child_cmd_buf = derive_child_cmd.as_bytes();
            cmd_data[derive_child_cmd_hdr_buf.len()
                ..derive_child_cmd_hdr_buf.len() + derive_child_cmd_buf.len()]
                .copy_from_slice(derive_child_cmd_buf);
            let mut derive_child_mbox_cmd = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
                hdr: MailboxReqHeader { chksum: 0 },
                data: cmd_data,
                data_size: (derive_child_cmd_hdr_buf.len() + derive_child_cmd_buf.len()) as u32,
            });
            derive_child_mbox_cmd.populate_chksum().unwrap();

            let resp = model
                .mailbox_execute(
                    u32::from(CommandId::INVOKE_DPE),
                    derive_child_mbox_cmd.as_bytes().unwrap(),
                )
                .unwrap_err();
            if let ModelError::MailboxCmdFailed(code) = resp {
                assert_eq!(
                    code,
                    u32::from(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED)
                );
            } else {
                panic!("This DeriveChild call should have failed since it would have breached the PL0 non-inactive dpe context threshold.")
            }
            break;
        }

        let resp = execute_dpe_cmd(&mut model, &mut Command::DeriveChild(derive_child_cmd));
        let Response::DeriveChild(derive_child_resp) = resp else {
            panic!("Wrong response type!");
        };
        handle = derive_child_resp.handle;
    }
}

#[test]
fn test_invoke_dpe_sign_and_certify_key_cmds() {
    let mut model = run_rt_test(None, None, None);

    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(&mut model, &mut Command::Sign(sign_cmd));
    let Response::Sign(sign_resp) = resp else {
        panic!("Wrong response type!");
    };

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(&mut model, &mut Command::CertifyKey(certify_key_cmd));
    let Response::CertifyKey(certify_key_resp) = resp else {
        panic!("Wrong response type!");
    };

    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sign_resp.sig_r_or_hmac).unwrap(),
        BigNum::from_slice(&sign_resp.sig_s).unwrap(),
    )
    .unwrap();

    let ecc_pub_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &BigNum::from_slice(&certify_key_resp.derived_pubkey_x).unwrap(),
        &BigNum::from_slice(&certify_key_resp.derived_pubkey_y).unwrap(),
    )
    .unwrap();
    assert!(sig.verify(&TEST_DIGEST, &ecc_pub_key).unwrap());
}

#[test]
fn test_invoke_dpe_symmetric_sign() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let sign_cmd = SignCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::IS_SYMMETRIC,
        digest: TEST_DIGEST,
    };
    let resp = execute_dpe_cmd(&mut model, &mut Command::Sign(sign_cmd));
    let Response::Sign(sign_resp) = resp else {
        panic!("Wrong response type!");
    };

    // r contains the hmac so it should not be all 0s
    assert_ne!(sign_resp.sig_r_or_hmac, [0u8; 48]);
    // s must be all 0s for hmac sign
    assert_eq!(sign_resp.sig_s, [0u8; 48]);
}
