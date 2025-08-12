// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{GetFmcAliasMlDsa87CertResp, Request},
    SocManager,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_common::{
    mailbox_api::{
        CommandId, GetFmcAliasEcc384CertResp, GetLdevCertResp, GetRtAliasCertResp, InvokeDpeReq,
        InvokeDpeResp, MailboxReq, MailboxReqHeader,
    },
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_drivers::MfgFlags;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, CodeRange, DefaultHwModel, Fuses, HwModel, ImageInfo, InitParams, ModelError,
    StackInfo, StackRange,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_test::image_pk_desc_hash;
use dpe::{
    commands::{Command, CommandHdr, DeriveContextCmd, DeriveContextFlags},
    response::{
        CertifyKeyResp, DeriveContextExportedCdiResp, DeriveContextResp, DpeErrorCode,
        GetCertificateChainResp, GetProfileResp, NewHandleResp, Response, ResponseHdr, SignResp,
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
use zerocopy::{FromBytes, FromZeros, IntoBytes};

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

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];

#[derive(Default)]
pub struct RuntimeTestArgs<'a> {
    pub test_fwid: Option<&'static FwId<'static>>,
    pub test_fmc_fwid: Option<&'static FwId<'static>>,
    pub test_image_options: Option<ImageOptions>,
    pub init_params: Option<InitParams<'a>>,
    pub test_mfg_flags: Option<MfgFlags>,
    // SoC manifest passed via the recovery interface
    pub soc_manifest: Option<&'a [u8]>,
    // MCU firmware image passed via the recovery interface
    pub mcu_fw_image: Option<&'a [u8]>,
    /// Initial content of the test SRAM
    pub test_sram: Option<&'a [u8]>,
    pub stop_at_rom: bool,
}

pub fn run_rt_test_pqc(
    args: RuntimeTestArgs,
    pqc_key_type: FwVerificationPqcKeyType,
) -> DefaultHwModel {
    let mut model = start_rt_test_pqc_model(args, pqc_key_type).0;
    model.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });
    model
}

pub fn start_rt_test_pqc_model(
    args: RuntimeTestArgs,
    pqc_key_type: FwVerificationPqcKeyType,
) -> (DefaultHwModel, Vec<u8>) {
    let default_rt_fwid = if cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem")) {
        &APP_WITH_UART_FPGA
    } else {
        &APP_WITH_UART
    };
    let runtime_fwid = args.test_fwid.unwrap_or(default_rt_fwid);
    let fmc_fwid = args.test_fmc_fwid.unwrap_or(&FMC_WITH_UART);

    let image_options = args.test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = DEFAULT_FMC_VERSION;
        opts.app_version = DEFAULT_APP_VERSION;
        opts.pqc_key_type = pqc_key_type;
        opts
    });

    let image_info = vec![
        ImageInfo::new(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
        ),
        ImageInfo::new(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
        ),
    ];
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let init_params = match args.init_params {
        Some(init_params) => init_params,
        None => InitParams {
            rom: &rom,
            stack_info: Some(StackInfo::new(image_info)),
            test_sram: args.test_sram,
            ..Default::default()
        },
    };

    let image =
        caliptra_builder::build_and_sign_image(fmc_fwid, runtime_fwid, image_options).unwrap();

    let (vendor_pk_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let boot_flags = if let Some(flags) = args.test_mfg_flags {
        flags.bits()
    } else {
        0
    };

    let image = image.to_bytes().unwrap();

    let model = caliptra_hw_model::new(
        init_params,
        BootParams {
            fw_image: if args.stop_at_rom { None } else { Some(&image) },
            fuses: Fuses {
                fuse_pqc_key_type: pqc_key_type as u32,
                vendor_pk_hash,
                owner_pk_hash,
                ..Default::default()
            },
            initial_dbg_manuf_service_reg: boot_flags,
            soc_manifest: args.soc_manifest,
            mcu_fw_image: args.mcu_fw_image,
            ..Default::default()
        },
    )
    .unwrap();

    (model, image)
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(args: RuntimeTestArgs) -> DefaultHwModel {
    run_rt_test_pqc(args, FwVerificationPqcKeyType::LMS)
}

pub fn generate_test_x509_cert(private_key: &PKey<Private>) -> X509 {
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
    cert_builder.set_pubkey(private_key).unwrap();
    cert_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    // Use appropriate message digest based on key type
    let digest = match private_key.id() {
        openssl::pkey::Id::EC => MessageDigest::sha384(),
        _ => MessageDigest::null(), // For MLDSA and other key types
    };

    cert_builder.sign(private_key, digest).unwrap();
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

fn as_bytes<'a>(dpe_cmd: &'a mut Command) -> &'a [u8] {
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

fn check_dpe_status(resp_bytes: &[u8], expected_status: DpeErrorCode) {
    if let Ok(&ResponseHdr { status, .. }) =
        ResponseHdr::ref_from_bytes(&resp_bytes[..core::mem::size_of::<ResponseHdr>()])
    {
        if status != expected_status.get_error_code() {
            panic!("Unexpected DPE Status: 0x{:X}", status);
        }
    }
}

fn parse_dpe_response(dpe_cmd: &mut Command, resp_bytes: &[u8]) -> Response {
    // Peek response header so we can panic with an error code in case the command failed.
    check_dpe_status(resp_bytes, DpeErrorCode::NoError);

    match dpe_cmd {
        Command::CertifyKey(_) => {
            Response::CertifyKey(CertifyKeyResp::read_from_bytes(resp_bytes).unwrap())
        }
        Command::DeriveContext(DeriveContextCmd { flags, .. })
            if flags.contains(DeriveContextFlags::EXPORT_CDI) =>
        {
            Response::DeriveContextExportedCdi(
                DeriveContextExportedCdiResp::read_from_bytes(resp_bytes).unwrap(),
            )
        }
        Command::DeriveContext(_) => {
            Response::DeriveContext(DeriveContextResp::read_from_bytes(resp_bytes).unwrap())
        }
        Command::GetCertificateChain(_) => Response::GetCertificateChain(
            GetCertificateChainResp::read_from_bytes(resp_bytes).unwrap(),
        ),
        Command::DestroyCtx(_) => {
            Response::DestroyCtx(ResponseHdr::read_from_bytes(resp_bytes).unwrap())
        }
        Command::GetProfile => {
            Response::GetProfile(GetProfileResp::read_from_bytes(resp_bytes).unwrap())
        }
        Command::InitCtx(_) => {
            Response::InitCtx(NewHandleResp::read_from_bytes(resp_bytes).unwrap())
        }
        Command::RotateCtx(_) => {
            Response::RotateCtx(NewHandleResp::read_from_bytes(resp_bytes).unwrap())
        }
        Command::Sign(_) => Response::Sign(SignResp::read_from_bytes(resp_bytes).unwrap()),
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
    resp_hdr.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    assert!(caliptra_common::checksum::verify_checksum(
        resp_hdr.hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&resp_hdr.hdr.chksum)..],
    ));

    let resp_bytes = &resp_hdr.data[..resp_hdr.data_size as usize];
    Some(match expected_result {
        DpeResult::Success => parse_dpe_response(dpe_cmd, resp_bytes),
        DpeResult::DpeCmdFailure => Response::Error(ResponseHdr::read_from_bytes(resp_bytes).unwrap()),
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

pub fn get_certs<R: Request>(model: &mut DefaultHwModel) -> R::Resp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(R::ID), &[]),
    };
    let resp_data = model
        .mailbox_execute(u32::from(R::ID), payload.as_bytes())
        .unwrap()
        .unwrap();
    assert!(resp_data.len() <= std::mem::size_of::<<R as Request>::Resp>());
    let mut resp = R::Resp::new_zeroed();
    resp.as_mut_bytes()[..resp_data.len()].copy_from_slice(&resp_data);
    resp
}

pub fn get_ecc_fmc_alias_cert(model: &mut DefaultHwModel) -> GetFmcAliasEcc384CertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_ECC384_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_FMC_ALIAS_ECC384_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetFmcAliasEcc384CertResp>());
    let mut fmc_resp = GetFmcAliasEcc384CertResp::default();
    fmc_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    fmc_resp
}

pub fn get_mldsa_fmc_alias_cert(model: &mut DefaultHwModel) -> GetFmcAliasMlDsa87CertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_MLDSA87_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_FMC_ALIAS_MLDSA87_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetFmcAliasMlDsa87CertResp>());
    let mut fmc_resp = GetFmcAliasMlDsa87CertResp::default();
    fmc_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    fmc_resp
}

pub fn get_rt_alias_ecc384_cert(model: &mut DefaultHwModel) -> GetRtAliasCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_RT_ALIAS_ECC384_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_RT_ALIAS_ECC384_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetRtAliasCertResp>());
    let mut rt_resp = GetRtAliasCertResp::default();
    rt_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    rt_resp
}

pub fn get_rt_alias_mldsa87_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_RT_ALIAS_MLDSA87_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_RT_ALIAS_MLDSA87_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut rt_resp = GetLdevCertResp::default();
    rt_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    rt_resp
}
