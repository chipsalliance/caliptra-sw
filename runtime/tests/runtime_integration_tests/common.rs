// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, GetFmcAliasCertResp, GetRtAliasCertResp, InvokeDpeReq, InvokeDpeResp, MailboxReq,
    MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams, ModelError};
use dpe::{
    commands::{Command, CommandHdr},
    response::{
        CertifyKeyResp, DeriveContextResp, GetCertificateChainResp, GetProfileResp, NewHandleResp,
        Response, ResponseHdr, SignResp,
    },
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
    x509::{X509Name, X509NameBuilder},
};
use zerocopy::{AsBytes, FromBytes};

pub const TEST_LABEL: [u8; 48] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];
pub const TEST_DIGEST: [u8; 48] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
];

pub const DEFAULT_FMC_VERSION: u16 = 0xaaaa;
pub const DEFAULT_APP_VERSION: u32 = 0xbbbbbbbb;

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(
    test_fwid: Option<&'static FwId>,
    test_image_options: Option<ImageOptions>,
    init_params: Option<InitParams>,
) -> DefaultHwModel {
    let default_rt_fwid = if cfg!(feature = "fpga_realtime") {
        &APP_WITH_UART_FPGA
    } else {
        &APP_WITH_UART
    };
    let runtime_fwid = test_fwid.unwrap_or(default_rt_fwid);

    let image_options = test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = DEFAULT_FMC_VERSION;
        opts.app_version = DEFAULT_APP_VERSION;
        opts
    });

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let init_params = match init_params {
        Some(init_params) => init_params,
        None => InitParams {
            rom: &rom,
            ..Default::default()
        },
    };

    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, runtime_fwid, image_options)
        .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params,
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}

pub fn generate_test_x509_cert(ec_key: PKey<Private>) -> X509 {
    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    let mut subj_name_builder = X509Name::builder().unwrap();
    subj_name_builder
        .append_entry_by_text("CN", "example.com")
        .unwrap();
    let subject_name = X509NameBuilder::build(subj_name_builder);
    cert_builder.set_subject_name(&subject_name).unwrap();
    cert_builder.set_issuer_name(&subject_name).unwrap();
    cert_builder.set_pubkey(&ec_key).unwrap();
    cert_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    cert_builder.sign(&ec_key, MessageDigest::sha384()).unwrap();
    cert_builder.build()
}

fn get_cmd_id(dpe_cmd: &mut Command) -> u32 {
    match dpe_cmd {
        Command::GetProfile => Command::GET_PROFILE,
        Command::InitCtx(_) => Command::INITIALIZE_CONTEXT,
        Command::DeriveContext(_) => Command::DERIVE_CONTEXT,
        Command::CertifyKey(_) => Command::CERTIFY_KEY,
        Command::Sign(_) => Command::SIGN,
        Command::RotateCtx(_) => Command::ROTATE_CONTEXT_HANDLE,
        Command::DestroyCtx(_) => Command::DESTROY_CONTEXT,
        Command::GetCertificateChain(_) => Command::GET_CERTIFICATE_CHAIN,
    }
}

fn as_bytes(dpe_cmd: &mut Command) -> &[u8] {
    match dpe_cmd {
        Command::CertifyKey(cmd) => cmd.as_bytes(),
        Command::DeriveContext(cmd) => cmd.as_bytes(),
        Command::GetCertificateChain(cmd) => cmd.as_bytes(),
        Command::DestroyCtx(cmd) => cmd.as_bytes(),
        Command::GetProfile => &[],
        Command::InitCtx(cmd) => cmd.as_bytes(),
        Command::RotateCtx(cmd) => cmd.as_bytes(),
        Command::Sign(cmd) => cmd.as_bytes(),
    }
}

fn parse_dpe_response(dpe_cmd: &mut Command, resp_bytes: &[u8]) -> Response {
    match dpe_cmd {
        Command::CertifyKey(_) => {
            Response::CertifyKey(CertifyKeyResp::read_from(resp_bytes).unwrap())
        }
        Command::DeriveContext(_) => {
            Response::DeriveContext(DeriveContextResp::read_from(resp_bytes).unwrap())
        }
        Command::GetCertificateChain(_) => {
            Response::GetCertificateChain(GetCertificateChainResp::read_from(resp_bytes).unwrap())
        }
        Command::DestroyCtx(_) => Response::DestroyCtx(ResponseHdr::read_from(resp_bytes).unwrap()),
        Command::GetProfile => Response::GetProfile(GetProfileResp::read_from(resp_bytes).unwrap()),
        Command::InitCtx(_) => Response::InitCtx(NewHandleResp::read_from(resp_bytes).unwrap()),
        Command::RotateCtx(_) => Response::RotateCtx(NewHandleResp::read_from(resp_bytes).unwrap()),
        Command::Sign(_) => Response::Sign(SignResp::read_from(resp_bytes).unwrap()),
    }
}

pub enum DpeResult {
    Success,
    DpeCmdFailure,
    MboxCmdFailure(CaliptraError),
}

pub fn execute_dpe_cmd(
    model: &mut DefaultHwModel,
    dpe_cmd: &mut Command,
    expected_result: DpeResult,
) -> Option<Response> {
    let mut cmd_data: [u8; 512] = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let dpe_cmd_id = get_cmd_id(dpe_cmd);
    let cmd_hdr = CommandHdr::new_for_test(dpe_cmd_id);
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let dpe_cmd_buf = as_bytes(dpe_cmd);
    cmd_data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + dpe_cmd_buf.len()].copy_from_slice(dpe_cmd_buf);
    let mut mbox_cmd = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data: cmd_data,
        data_size: (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32,
    });
    mbox_cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(
        u32::from(CommandId::INVOKE_DPE),
        mbox_cmd.as_bytes().unwrap(),
    );
    if let DpeResult::MboxCmdFailure(expected_err) = expected_result {
        assert_error(model, expected_err, resp.unwrap_err());
        return None;
    }
    let resp = resp.unwrap().expect("We should have received a response");

    assert!(resp.len() <= std::mem::size_of::<InvokeDpeResp>());
    let mut resp_hdr = InvokeDpeResp::default();
    resp_hdr.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);

    assert!(caliptra_common::checksum::verify_checksum(
        resp_hdr.hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&resp_hdr.hdr.chksum)..],
    ));

    let resp_bytes = &resp_hdr.data[..resp_hdr.data_size as usize];
    Some(match expected_result {
        DpeResult::Success => parse_dpe_response(dpe_cmd, resp_bytes),
        DpeResult::DpeCmdFailure => Response::Error(ResponseHdr::read_from(resp_bytes).unwrap()),
        DpeResult::MboxCmdFailure(_) => unreachable!("If MboxCmdFailure is the expected DPE result, the function would have returned None earlier."),
    })
}

pub fn assert_error(
    model: &mut DefaultHwModel,
    expected_err: CaliptraError,
    actual_err: ModelError,
) {
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(expected_err)
    );
    if let ModelError::MailboxCmdFailed(code) = actual_err {
        assert_eq!(code, u32::from(expected_err));
    } else {
        panic!("Mailbox command should have failed with MailboxCmdFailed error, instead failed with {} error", actual_err)
    }
}

pub fn get_fmc_alias_cert(model: &mut DefaultHwModel) -> GetFmcAliasCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_FMC_ALIAS_CERT), payload.as_bytes())
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetFmcAliasCertResp>());
    let mut fmc_resp = GetFmcAliasCertResp::default();
    fmc_resp.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);
    fmc_resp
}

pub fn get_rt_alias_cert(model: &mut DefaultHwModel) -> GetRtAliasCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_RT_ALIAS_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_RT_ALIAS_CERT), payload.as_bytes())
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetRtAliasCertResp>());
    let mut rt_resp = GetRtAliasCertResp::default();
    rt_resp.as_bytes_mut()[..resp.len()].copy_from_slice(&resp);
    rt_resp
}
