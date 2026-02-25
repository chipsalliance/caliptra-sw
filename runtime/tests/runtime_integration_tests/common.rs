// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{
        AxiResponseInfo, GetFmcAliasMlDsa87CertResp, InvokeDpeMldsa87Flags, InvokeDpeMldsa87Req,
        Request,
    },
    SocManager,
};
use caliptra_builder::{
    firmware::{
        APP_WITH_UART, APP_WITH_UART_FPGA, APP_WITH_UART_OCP_LOCK, APP_WITH_UART_OCP_LOCK_FPGA,
        FMC_WITH_UART,
    },
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
use caliptra_image_types::FwVerificationPqcKeyType;

use caliptra_drivers::MfgFlags;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, CodeRange, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, ImageInfo, InitParams,
    ModelCallback, ModelError, SecurityState, StackInfo, StackRange, SubsystemInitParams,
};

use caliptra_runtime::CaliptraDpeProfile;
pub use caliptra_test::{
    default_soc_manifest_bytes, image_pk_desc_hash, test_upload_firmware, DEFAULT_MCU_FW,
};
use crypto::{Digest, Mu, PrecomputedSignData, Sha384};
use dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyMldsa87Cmd, CertifyKeyP384Cmd, Command,
        CommandHdr, DeriveContextCmd, SignFlags, SignMldsa87Cmd, SignP384Cmd,
    },
    context::ContextHandle,
    response::{DpeErrorCode, Response, ResponseHdr},
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time, Asn1TimeRef},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
    x509::{X509Name, X509NameBuilder},
};
use std::borrow::Cow;
use std::io;
use zerocopy::{FromZeros, IntoBytes, TryFromBytes};

pub const TEST_LABEL: [u8; 48] = [
    48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
];

pub const TEST_DIGEST: [u8; 48] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
];
pub const TEST_MU: [u8; 64] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
];
pub const TEST_SD_SHA384: PrecomputedSignData =
    PrecomputedSignData::Digest(Digest::Sha384(Sha384(TEST_DIGEST)));
pub const TEST_SD_MU: PrecomputedSignData = PrecomputedSignData::Mu(Mu(TEST_MU));

pub const DEFAULT_FMC_VERSION: u16 = 0xaaaa;
pub const DEFAULT_APP_VERSION: u32 = 0xbbbbbbbb;

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];

#[derive(Default)]
pub struct RuntimeProductionArgs {
    pub fmc_version: u16,
    pub app_version: u32,
    pub fw_svn: u32,
}

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
    pub security_state: Option<SecurityState>,
    pub production_state: Option<RuntimeProductionArgs>,
    pub soc_manifest_svn: Option<u32>,
    pub soc_manifest_max_svn: Option<u32>,
    pub hek_seed: Option<[u32; 8]>,
    pub subsystem_mode: bool,
    pub successful_reach_rt: bool,
    pub ocp_lock_en: bool,
    pub key_type: Option<FwVerificationPqcKeyType>,
    pub rom_callback: Option<ModelCallback>,
}

impl RuntimeTestArgs<'_> {
    // A handy shortcut for testing production
    pub fn test_productions_args() -> RuntimeTestArgs<'static> {
        let mut sec_state = SecurityState::default();
        sec_state.set_debug_locked(true);
        sec_state.set_device_lifecycle(DeviceLifecycle::Production);

        RuntimeTestArgs {
            security_state: Some(sec_state),
            production_state: Some(RuntimeProductionArgs {
                fmc_version: 3,
                app_version: 5,
                fw_svn: 9,
            }),
            ..Default::default()
        }
    }
}

// clippy gets confused about cfg(feature = "...")
#[allow(clippy::derivable_impls)]
impl Default for RuntimeTestArgs<'_> {
    fn default() -> Self {
        Self {
            test_fwid: None,
            test_fmc_fwid: None,
            test_image_options: None,
            init_params: None,
            test_mfg_flags: None,
            soc_manifest: None,
            mcu_fw_image: None,
            test_sram: None,
            stop_at_rom: false,
            security_state: None,
            production_state: None,
            soc_manifest_svn: None,
            soc_manifest_max_svn: None,
            hek_seed: None,
            subsystem_mode: cfg!(feature = "fpga_subsystem"),
            successful_reach_rt: true,
            ocp_lock_en: cfg!(feature = "ocp-lock"),
            key_type: None,
            rom_callback: None,
        }
    }
}

pub fn run_rt_test_pqc(
    args: RuntimeTestArgs,
    pqc_key_type: FwVerificationPqcKeyType,
) -> DefaultHwModel {
    let successful_reach_rt = args.successful_reach_rt;
    let mut model = start_rt_test_pqc_model(args, pqc_key_type).0;
    if successful_reach_rt {
        model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
    } else {
        model.step_until(|m| {
            m.soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_mb_processing()
        });
    }

    model
}

pub const fn svn_to_bitmap(svn: u32) -> [u32; 4] {
    let n = if svn > 128 { 128 } else { svn };

    // Build a 128-bit value with the lowest `n` bits set.
    // Shifting by 128 is invalid, so handle that case explicitly.
    let val: u128 = if n == 0 {
        0
    } else if n == 128 {
        u128::MAX
    } else {
        (1u128 << n) - 1
    };

    [
        (val & 0xffff_ffff) as u32,
        ((val >> 32) & 0xffff_ffff) as u32,
        ((val >> 64) & 0xffff_ffff) as u32,
        ((val >> 96) & 0xffff_ffff) as u32,
    ]
}

pub fn rom_for_fw_integration_tests() -> io::Result<Cow<'static, [u8]>> {
    caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
}

pub fn start_rt_test_pqc_model(
    args: RuntimeTestArgs,
    pqc_key_type: FwVerificationPqcKeyType,
) -> (DefaultHwModel, Vec<u8>) {
    let fpga = cfg!(any(feature = "fpga_realtime", feature = "fpga_subsystem"));
    let ocp_lock = args.ocp_lock_en || cfg!(feature = "ocp-lock");
    let default_rt_fwid = match (fpga, ocp_lock) {
        (false, false) => &APP_WITH_UART,
        (true, false) => &APP_WITH_UART_FPGA,
        (false, true) => &APP_WITH_UART_OCP_LOCK,
        (true, true) => &APP_WITH_UART_OCP_LOCK_FPGA,
    };

    let runtime_fwid = args.test_fwid.unwrap_or(default_rt_fwid);
    let fmc_fwid = args.test_fmc_fwid.unwrap_or(&FMC_WITH_UART);

    let production_state = args.production_state.unwrap_or(RuntimeProductionArgs {
        fmc_version: DEFAULT_FMC_VERSION,
        app_version: DEFAULT_APP_VERSION,
        fw_svn: Default::default(),
    });

    let image_options = args.test_image_options.unwrap_or_else(|| {
        let mut opts = ImageOptions::default();
        opts.vendor_config.pl0_pauser = Some(0x1);
        opts.fmc_version = production_state.fmc_version;
        opts.app_version = production_state.app_version;
        opts.fw_svn = production_state.fw_svn;
        opts.pqc_key_type = pqc_key_type;
        opts
    });

    let image_info = vec![
        ImageInfo::with_name(
            StackRange::new(ROM_STACK_ORG + ROM_STACK_SIZE, ROM_STACK_ORG),
            CodeRange::new(ROM_ORG, ROM_ORG + ROM_SIZE),
            "caliptra-rom".to_owned(),
        ),
        ImageInfo::with_name(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(FMC_ORG, FMC_ORG + FMC_SIZE),
            "caliptra-fmc".to_owned(),
        ),
        ImageInfo::with_name(
            StackRange::new(STACK_ORG + STACK_SIZE, STACK_ORG),
            CodeRange::new(RUNTIME_ORG, RUNTIME_ORG + RUNTIME_SIZE),
            "caliptra-runtime".to_owned(),
        ),
    ];

    let rom = rom_for_fw_integration_tests().unwrap();

    let image =
        caliptra_builder::build_and_sign_image(fmc_fwid, runtime_fwid, image_options).unwrap();
    let (vendor_pk_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut init_params = args.init_params.unwrap_or_else(|| InitParams {
        rom: &rom,
        stack_info: Some(StackInfo::new(image_info)),
        test_sram: args.test_sram,
        security_state: args.security_state.unwrap_or_default(),
        subsystem_mode: args.subsystem_mode,
        ocp_lock_en: ocp_lock,
        ss_init_params: SubsystemInitParams {
            enable_mcu_uart_log: args.subsystem_mode,
            ..Default::default()
        },
        rom_callback: args.rom_callback,
        ..Default::default()
    });
    init_params.fuses = Fuses {
        fuse_pqc_key_type: pqc_key_type as u32,
        vendor_pk_hash,
        owner_pk_hash,
        soc_manifest_svn: svn_to_bitmap(args.soc_manifest_svn.unwrap_or(0)),
        soc_manifest_max_svn: args.soc_manifest_max_svn.unwrap_or(127) as u8,
        fw_svn: svn_to_bitmap(production_state.fw_svn),
        hek_seed: args.hek_seed.unwrap_or([0xABDEu32; 8]),
        ..Default::default()
    };

    let boot_flags = if let Some(flags) = args.test_mfg_flags {
        flags.bits()
    } else {
        0
    };

    let image = image.to_bytes().unwrap();

    let default_manifest_bytes;
    let (soc_manifest, mcu_fw_image) = if args.subsystem_mode && args.soc_manifest.is_none() {
        default_manifest_bytes =
            default_soc_manifest_bytes(pqc_key_type, args.soc_manifest_svn.unwrap_or(0));
        (Some(&default_manifest_bytes[..]), Some(&DEFAULT_MCU_FW[..]))
    } else {
        (args.soc_manifest, args.mcu_fw_image)
    };

    let model = caliptra_hw_model::new(
        init_params,
        BootParams {
            fw_image: if args.stop_at_rom { None } else { Some(&image) },
            initial_dbg_manuf_service_reg: boot_flags,
            soc_manifest,
            mcu_fw_image,
            ..Default::default()
        },
    )
    .unwrap();

    (model, image)
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(args: RuntimeTestArgs) -> DefaultHwModel {
    // TODO(clundin): Do we want to use MLDSA by default in 2.1?
    let key_type = args.key_type.unwrap_or(FwVerificationPqcKeyType::LMS);
    run_rt_test_pqc(args, key_type)
}

pub fn generate_test_x509_cert(private_key: &PKey<Private>) -> X509 {
    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder
        .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
        .unwrap();
    let mut subj_name_builder: X509NameBuilder = X509Name::builder().unwrap();
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

fn check_dpe_status(resp_bytes: &[u8], expected_status: DpeErrorCode) {
    if let Ok(&ResponseHdr { status, .. }) =
        ResponseHdr::try_ref_from_bytes(&resp_bytes[..core::mem::size_of::<ResponseHdr>()])
    {
        if status != expected_status.get_error_code() {
            panic!("Unexpected DPE Status: 0x{:X}", status);
        }
    }
}

pub enum DpeResult {
    Success,
    DpeCmdFailure,
    MboxCmdFailure(CaliptraError),
}

pub fn check_header_checksum(resp: &[u8]) -> anyhow::Result<()> {
    let resp_hdr =
        MailboxReqHeader::try_read_from_bytes(&resp[..core::mem::size_of::<MailboxReqHeader>()])
            .map_err(|e| anyhow::anyhow!("Failed to get the header from the response: {e}"))?;
    if !caliptra_common::checksum::verify_checksum(
        resp_hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&resp_hdr.chksum)..],
    ) {
        anyhow::bail!("Invalid checksum in response header");
    }
    Ok(())
}

pub fn execute_dpe_cmd(
    model: &mut DefaultHwModel,
    profile: CaliptraDpeProfile,
    dpe_cmd: &mut Command,
    expected_result: DpeResult,
) -> Option<Response> {
    // For certain commands, the DPE response is returned via an AXI write to external MCU SRAM
    // instead of the mailbox response because the response is too large for the mailbox. In those
    // cases, we need to set up the staging area and indicate to Caliptra that we want the response
    // to be written there.
    let external_response = match (model.subsystem_mode(), profile, &dpe_cmd) {
        (true, CaliptraDpeProfile::Mldsa87, Command::CertifyKey(_)) => true,
        (
            true,
            CaliptraDpeProfile::Mldsa87,
            Command::DeriveContext(DeriveContextCmd { flags, .. }),
        ) => flags.exports_cdi(),
        _ => false,
    };
    let (flags, addr_lo, addr_hi) = if external_response {
        let addr = model.staging_physical_address().unwrap();
        (
            InvokeDpeMldsa87Flags::EXTERNAL_AXI_RESPONSE,
            addr as u32,
            (addr >> 32) as u32,
        )
    } else {
        (InvokeDpeMldsa87Flags::empty(), 0, 0)
    };

    // Fill the request buffer with the correct info
    let mut cmd_data: [u8; 512] = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let cmd_hdr = CommandHdr::new(profile.into(), dpe_cmd.id());
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let dpe_cmd_buf = dpe_cmd.as_bytes();
    cmd_data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + dpe_cmd_buf.len()].copy_from_slice(dpe_cmd_buf);

    // Get the profile specific mailbox command
    let (cmd_id, mut mbox_cmd) = match profile {
        CaliptraDpeProfile::Ecc384 => (
            CommandId::INVOKE_DPE_ECC384,
            MailboxReq::InvokeDpeEcc384Command(InvokeDpeReq {
                hdr: MailboxReqHeader { chksum: 0 },
                data: cmd_data,
                data_size: (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32,
            }),
        ),
        CaliptraDpeProfile::Mldsa87 => (
            CommandId::INVOKE_DPE_MLDSA87,
            MailboxReq::InvokeDpeMldsa87Command(InvokeDpeMldsa87Req {
                hdr: MailboxReqHeader { chksum: 0 },
                flags,
                axi_response: AxiResponseInfo {
                    addr_lo,
                    addr_hi,
                    max_size: size_of::<InvokeDpeResp>() as u32,
                },
                data: cmd_data,
                data_size: (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32,
            }),
        ),
    };
    mbox_cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(u32::from(cmd_id), mbox_cmd.as_bytes().unwrap());
    if let DpeResult::MboxCmdFailure(expected_err) = expected_result {
        assert_error(model, expected_err, resp.unwrap_err());
        return None;
    }
    // The external mailbox command also sends the mailbox header so we always expect something.
    let resp = resp.unwrap().expect("We should have received a response");
    check_header_checksum(&resp).unwrap();

    let mut resp_hdr = InvokeDpeResp::default();
    if !external_response {
        assert!(resp.len() <= std::mem::size_of::<InvokeDpeResp>());
        resp_hdr.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    } else {
        let resp = model
            .read_payload_from_ss_staging_area(size_of::<InvokeDpeResp>())
            .unwrap();
        resp_hdr.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
        check_header_checksum(resp_hdr.as_bytes_partial().unwrap()).unwrap();
    };

    let resp_bytes = &resp_hdr.data[..resp_hdr.data_size as usize];
    Some(match expected_result {
        DpeResult::Success => {
            // Peek response header so we can panic with an error code in case the command failed.
            check_dpe_status(resp_bytes, DpeErrorCode::NoError);
            Response::try_read_from_bytes(dpe_cmd, resp_bytes).unwrap()
        },
        DpeResult::DpeCmdFailure => Response::Error(ResponseHdr::try_read_from_bytes(resp_bytes).unwrap()),
        DpeResult::MboxCmdFailure(_) => unreachable!("If MboxCmdFailure is the expected DPE result, the function would have returned None earlier."),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertifyKeyCommandNoRef {
    P384(CertifyKeyP384Cmd),
    Mldsa(CertifyKeyMldsa87Cmd),
}

impl CertifyKeyCommandNoRef {
    pub fn new(args: CreateCertifyKeyCmdArgs) -> Self {
        match args.profile {
            CaliptraDpeProfile::Ecc384 => CertifyKeyCommandNoRef::P384(CertifyKeyP384Cmd {
                handle: args.handle,
                label: args.label,
                flags: args.flags,
                format: args.format,
            }),
            CaliptraDpeProfile::Mldsa87 => CertifyKeyCommandNoRef::Mldsa(CertifyKeyMldsa87Cmd {
                handle: args.handle,
                label: args.label,
                flags: args.flags,
                format: args.format,
            }),
        }
    }
}

impl<'a> From<&'a CertifyKeyCommandNoRef> for Command<'a> {
    fn from(cmd: &'a CertifyKeyCommandNoRef) -> Command<'a> {
        match cmd {
            CertifyKeyCommandNoRef::P384(cmd) => cmd.into(),
            CertifyKeyCommandNoRef::Mldsa(cmd) => cmd.into(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignCommandNoRef {
    P384(SignP384Cmd),
    Mldsa(SignMldsa87Cmd),
}

impl SignCommandNoRef {
    pub fn new(args: CreateSignCmdArgs) -> Self {
        let CreateSignCmdArgs { profile, data, .. } = args;
        match (profile, data) {
            (CaliptraDpeProfile::Ecc384, PrecomputedSignData::Digest(Digest::Sha384(digest))) => {
                Self::P384(SignP384Cmd {
                    handle: args.handle,
                    label: args.label,
                    flags: args.flags,
                    digest: digest.0,
                })
            }
            (CaliptraDpeProfile::Mldsa87, PrecomputedSignData::Mu(mu)) => {
                Self::Mldsa(SignMldsa87Cmd {
                    handle: args.handle,
                    label: args.label,
                    flags: args.flags,
                    digest: mu.0,
                })
            }
            _ => panic!("Invalid combination of profile and precomputed sign data"),
        }
    }
}

impl<'a> From<&'a SignCommandNoRef> for Command<'a> {
    fn from(cmd: &'a SignCommandNoRef) -> Command<'a> {
        match cmd {
            SignCommandNoRef::P384(cmd) => cmd.into(),
            SignCommandNoRef::Mldsa(cmd) => cmd.into(),
        }
    }
}

pub struct CreateSignCmdArgs {
    pub profile: CaliptraDpeProfile,
    pub handle: ContextHandle,
    pub label: [u8; 48],
    pub flags: SignFlags,
    pub data: PrecomputedSignData,
}

impl Default for CreateSignCmdArgs {
    fn default() -> Self {
        Self {
            profile: CaliptraDpeProfile::Ecc384,
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: SignFlags::empty(),
            data: PrecomputedSignData::Digest([0u8; 48].into()),
        }
    }
}

#[derive(Debug)]
pub struct CreateCertifyKeyCmdArgs {
    pub profile: CaliptraDpeProfile,
    pub handle: ContextHandle,
    pub label: [u8; 48],
    pub flags: CertifyKeyFlags,
    pub format: u32,
}

impl Default for CreateCertifyKeyCmdArgs {
    fn default() -> Self {
        Self {
            profile: CaliptraDpeProfile::Ecc384,
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCommand::FORMAT_X509,
        }
    }
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

#[allow(dead_code)]
/// Compare two X509 certs by semantic fields rather than raw bytes.
pub fn assert_x509_semantic_eq(a: &X509, b: &X509) {
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

#[allow(dead_code)]
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
