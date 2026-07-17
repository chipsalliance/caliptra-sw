// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::Request;
use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_common::{
    mailbox_api::{
        CommandId, GetFmcAliasCertResp, GetRtAliasCertResp, InvokeDpeReq, InvokeDpeResp,
        MailboxReq, MailboxReqHeader,
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
use caliptra_image_types::ImageBundle;
use dpe::{
    commands::{Command, CommandHdr},
    error::DpeErrorCode,
    response::{Response, ResponseHdr},
    DpeProfile,
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
    x509::{X509Name, X509NameBuilder},
};
use zerocopy::{FromZeros, IntoBytes, TryFromBytes};

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

#[derive(Default)]
pub struct RuntimeTestArgs<'a> {
    pub test_fwid: Option<&'static FwId<'static>>,
    pub test_image_options: Option<ImageOptions>,
    pub init_params: Option<InitParams<'a>>,
    pub test_mfg_flags: Option<MfgFlags>,
}

pub fn run_rt_test_lms(args: RuntimeTestArgs, lms_verify: bool) -> DefaultHwModel {
    let (model, _image) = run_rt_test_base(args, lms_verify);
    model
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(args: RuntimeTestArgs) -> DefaultHwModel {
    let (model, _image) = run_rt_test_base(args, false);
    model
}

pub fn run_rt_test_return_fw(args: RuntimeTestArgs) -> (DefaultHwModel, ImageBundle) {
    run_rt_test_base(args, false)
}

// Boot the ML-DSA attestation runtime image and wait until it is ready for
// commands. Shared by the per-command PQC DPE integration tests.
#[cfg(feature = "mldsa_attestation")]
pub fn run_pqc_rt_test() -> DefaultHwModel {
    use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
    use caliptra_runtime::RtBootStatus;

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    model
}

// Boot the ML-DSA attestation runtime image **debug-locked** (Production
// lifecycle) so the firmware actually arms the per-command watchdog. The
// runtime's `start_wdt` (runtime/src/lib.rs) is a no-op unless the device is
// debug-locked, so the default (unlocked) test boots never enforce the WDT.
// This helper enables realistic WDT-constrained tests for the PQC commands.
//
// WDT budget: `WdtTimeout::default()` = 20M cycles (WDT1), cascading to WDT2
// (1 cycle) -> NMI -> `RUNTIME_GLOBAL_WDT_EXPIRED` fatal error.
#[cfg(feature = "mldsa_attestation")]
pub fn run_pqc_rt_test_wdt() -> DefaultHwModel {
    use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
    use caliptra_hw_model::{DeviceLifecycle, SecurityState};
    use openssl::sha::sha384;

    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let mut image_options = ImageOptions::default();
    image_options.vendor_config.pl0_pauser = Some(0x1);
    image_options.fmc_version = DEFAULT_FMC_VERSION;
    image_options.app_version = DEFAULT_APP_VERSION;

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_MLDSA_ATTESTATION,
        image_options,
    )
    .unwrap();

    // Debug-locked (Production) boot verifies the image signature, so the fuses
    // must carry the vendor/owner public-key hashes of the signed image.
    let vendor_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.vendor_pub_keys.as_bytes()));
    let owner_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.owner_pub_keys.as_bytes()));

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

    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            stack_info: Some(StackInfo::new(image_info)),
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image.to_bytes().unwrap()),
            fuses: Fuses {
                key_manifest_pk_hash: vendor_pk_hash,
                owner_pk_hash,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    model
}

pub fn run_rt_test_base(args: RuntimeTestArgs, lms_verify: bool) -> (DefaultHwModel, ImageBundle) {
    let default_rt_fwid = if cfg!(feature = "fpga_realtime") {
        &APP_WITH_UART_FPGA
    } else {
        &APP_WITH_UART
    };
    let runtime_fwid = args.test_fwid.unwrap_or(default_rt_fwid);

    let image_options = args.test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = DEFAULT_FMC_VERSION;
        opts.app_version = DEFAULT_APP_VERSION;
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
            ..Default::default()
        },
    };

    let image = caliptra_builder::build_and_sign_image(&FMC_WITH_UART, runtime_fwid, image_options)
        .unwrap();

    let boot_flags = if let Some(flags) = args.test_mfg_flags {
        flags.bits()
    } else {
        0
    };

    let mut model = caliptra_hw_model::new(
        init_params,
        BootParams {
            fw_image: Some(&image.to_bytes().unwrap()),
            fuses: Fuses {
                lms_verify,
                ..Default::default()
            },
            initial_dbg_manuf_service_reg: boot_flags,
            ..Default::default()
        },
    )
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    (model, image)
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

fn check_dpe_status(resp_bytes: &[u8], expected_status: DpeErrorCode) {
    if let Ok(ResponseHdr { status, .. }) =
        ResponseHdr::try_read_from_bytes(&resp_bytes[..core::mem::size_of::<ResponseHdr>()])
    {
        if status != expected_status.get_error_code() {
            panic!("Unexpected DPE Status: 0x{:X}", status);
        }
    }
}

fn parse_dpe_response(dpe_cmd: &mut Command, resp_bytes: &[u8]) -> Response {
    // Peek response header so we can panic with an error code in case the command failed.
    check_dpe_status(resp_bytes, DpeErrorCode::NoError);

    Response::try_read_from_bytes(dpe_cmd, resp_bytes).unwrap()
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
    let dpe_cmd_id = dpe_cmd.id();
    let cmd_hdr = CommandHdr::new(DpeProfile::P384Sha384, dpe_cmd_id);
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let dpe_cmd_buf = dpe_cmd.as_bytes();
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
        DpeResult::Success => parse_dpe_response(dpe_cmd, &resp_hdr.data),
        DpeResult::DpeCmdFailure => Response::Error(ResponseHdr::try_read_from_bytes(resp_bytes).unwrap()),
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
    fmc_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
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
    rt_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    rt_resp
}

fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

pub fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

pub fn calculate_cptra_config_init_vals_hash<T: HwModel>(
    model: &mut T,
    image_bundle: &ImageBundle,
) -> [u8; 48] {
    use sha2::{Digest, Sha384};

    const PAUSER_COUNT: usize = 5;

    let mut hasher = Sha384::new();

    // Hash locked pausers
    for i in 0..PAUSER_COUNT {
        if model.soc_ifc().cptra_mbox_pauser_lock().at(i).read().lock() {
            hasher.update(
                model
                    .soc_ifc()
                    .cptra_mbox_valid_pauser()
                    .at(i)
                    .read()
                    .as_bytes(),
            );
        }
    }

    // Hash manifest fields
    let manifest = &image_bundle.manifest;
    hasher.update(manifest.header.pl0_pauser.as_bytes());
    hasher.update(manifest.header.flags.as_bytes());
    hasher.update(manifest.fmc.load_addr.as_bytes());
    hasher.update(manifest.fmc.entry_point.as_bytes());
    hasher.update(manifest.runtime.load_addr.as_bytes());
    hasher.update(manifest.runtime.entry_point.as_bytes());

    hasher.finalize().into()
}
