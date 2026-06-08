// Licensed under the Apache-2.0 license

use crate::test_set_auth_manifest::create_auth_manifest_with_metadata_with_svn;
use anyhow::Context;
use caliptra_api::{
    mailbox::{GetFmcAliasMlDsa87CertResp, Request},
    SocManager,
};
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, APP_WITH_UART_FPGA, FMC_WITH_UART},
    FwId, ImageOptions,
};
use caliptra_common::{
    mailbox_api::{
        AxiResponseInfo, CertifyKeyChunksFlags, CertifyKeyChunksReq, CertifyKeyChunksResp,
        CommandId, GetFmcAliasEcc384CertResp, GetLdevCertResp, GetRtAliasCertResp,
        InvokeDpeMldsa87Flags, InvokeDpeMldsa87Req, InvokeDpeReq, InvokeDpeResp, MailboxReq,
        MailboxReqHeader, MailboxRespHeader,
    },
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyMldsa87Cmd, CertifyKeyP384Cmd, Command,
        CommandHdr, DeriveContextCmd, SignFlags, SignMldsa87Cmd, SignP384Cmd,
    },
    context::ContextHandle,
    response::{CertifyKeyResp, DpeErrorCode, Response, ResponseHdr, SignResp},
    DpeProfile,
};
use caliptra_dpe_crypto::{Digest, Mu, PrecomputedSignData, Sha384};
use caliptra_drivers::MfgFlags;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, CodeRange, DefaultHwModel, Fuses, HwModel, ImageInfo, InitParams, ModelError,
    SecurityState, StackInfo, StackRange, SubsystemInitParams,
};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageBundle};
use caliptra_runtime::CaliptraDpeProfile;
use caliptra_test::image_pk_desc_hash;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509Builder, X509},
    x509::{X509Name, X509NameBuilder},
};
use std::borrow::Cow;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
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
static NEXT_TEST_TCI_TYPE: AtomicU32 = AtomicU32::new(u32::from_be_bytes(*b"TST0"));

pub const DEFAULT_MCU_FW: &[u8] = &[0x6f; 256];

fn default_soc_manifest(pqc_key_type: FwVerificationPqcKeyType, svn: u32) -> AuthorizationManifest {
    // generate a default SoC manifest if one is not provided in subsystem mode
    const IMAGE_SOURCE_IN_REQUEST: u32 = 1;
    let mut flags = ImageMetadataFlags(0);
    flags.set_image_source(IMAGE_SOURCE_IN_REQUEST);
    let crypto = Crypto::default();
    let digest = from_hw_format(&crypto.sha384_digest(DEFAULT_MCU_FW).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: flags.0,
        digest,
        ..Default::default()
    }];
    create_auth_manifest_with_metadata_with_svn(metadata, pqc_key_type, svn)
}

pub fn default_soc_manifest_bytes(pqc_key_type: FwVerificationPqcKeyType, svn: u32) -> Vec<u8> {
    let manifest = default_soc_manifest(pqc_key_type, svn);
    manifest.as_bytes().to_vec()
}

pub fn test_upload_firmware<T: HwModel>(
    model: &mut T,
    fw_image: &[u8],
    pqc_key_type: FwVerificationPqcKeyType,
) {
    if model.subsystem_mode() {
        model
            .upload_firmware_rri(
                fw_image,
                Some(&default_soc_manifest_bytes(pqc_key_type, 1)),
                Some(DEFAULT_MCU_FW),
            )
            .unwrap();
    } else {
        model.upload_firmware(fw_image).unwrap();
    }
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
    pub soc_manifest_svn: Option<u32>,
    pub soc_manifest_max_svn: Option<u32>,
    pub subsystem_mode: bool,
    pub successful_reach_rt: bool,
    pub key_type: Option<FwVerificationPqcKeyType>,
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
            soc_manifest_svn: None,
            soc_manifest_max_svn: None,
            subsystem_mode: cfg!(feature = "fpga_subsystem"),
            successful_reach_rt: true,
            key_type: None,
        }
    }
}

pub fn run_rt_test_pqc_return_fw(
    args: RuntimeTestArgs,
    pqc_key_type: FwVerificationPqcKeyType,
) -> (DefaultHwModel, ImageBundle) {
    let successful_reach_rt = args.successful_reach_rt;
    let (mut model, image_bundle) = start_rt_test_pqc_model(args, pqc_key_type);
    if successful_reach_rt {
        model.step_until_ready_for_runtime();
    } else {
        model.step_until(|m| {
            m.soc_ifc()
                .cptra_flow_status()
                .read()
                .ready_for_mb_processing()
        });
    }

    (model, image_bundle)
}

pub fn run_rt_test_pqc(
    args: RuntimeTestArgs,
    pqc_key_type: FwVerificationPqcKeyType,
) -> DefaultHwModel {
    let (model, _bundle) = run_rt_test_pqc_return_fw(args, pqc_key_type);
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
) -> (DefaultHwModel, ImageBundle) {
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

    let rom = rom_for_fw_integration_tests().unwrap();

    let image_bundle =
        caliptra_builder::build_and_sign_image(fmc_fwid, runtime_fwid, image_options).unwrap();
    let (vendor_pk_hash, owner_pk_hash) = image_pk_desc_hash(&image_bundle.manifest);

    let mut init_params = args.init_params.unwrap_or_else(|| InitParams {
        rom: &rom,
        stack_info: Some(StackInfo::new(image_info)),
        test_sram: args.test_sram,
        security_state: args.security_state.unwrap_or_default(),
        subsystem_mode: args.subsystem_mode,
        ss_init_params: SubsystemInitParams {
            enable_mcu_uart_log: args.subsystem_mode,
            ..Default::default()
        },
        ..Default::default()
    });
    init_params.fuses = Fuses {
        fuse_pqc_key_type: pqc_key_type as u32,
        vendor_pk_hash,
        owner_pk_hash,
        soc_manifest_svn: svn_to_bitmap(args.soc_manifest_svn.unwrap_or(0)),
        soc_manifest_max_svn: args.soc_manifest_max_svn.unwrap_or(127) as u8,
        ..Default::default()
    };

    let boot_flags = if let Some(flags) = args.test_mfg_flags {
        flags.bits()
    } else {
        0
    };

    let image = image_bundle.to_bytes().unwrap();

    let default_manifest_bytes;
    let (soc_manifest, mcu_fw_image) = if args.subsystem_mode && args.soc_manifest.is_none() {
        default_manifest_bytes =
            default_soc_manifest_bytes(pqc_key_type, args.soc_manifest_svn.unwrap_or(0));
        (Some(&default_manifest_bytes[..]), Some(DEFAULT_MCU_FW))
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

    (model, image_bundle)
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(args: RuntimeTestArgs) -> DefaultHwModel {
    let (model, _bundle) = run_rt_test_return_fw(args);
    model
}

pub fn run_rt_test_return_fw(args: RuntimeTestArgs) -> (DefaultHwModel, ImageBundle) {
    // TODO(clundin): Do we want to use MLDSA by default?
    let key_type = args.key_type.unwrap_or(FwVerificationPqcKeyType::LMS);
    run_rt_test_pqc_return_fw(args, key_type)
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

pub fn check_dpe_status(resp_bytes: &[u8], expected_status: DpeErrorCode) {
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

pub fn execute_dpe_cmd(
    model: &mut DefaultHwModel,
    dpe_cmd: &mut Command,
    expected_result: DpeResult,
) -> Option<Response> {
    let mut cmd_data: [u8; 512] = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let cmd_hdr = CommandHdr::new(DpeProfile::P384Sha384, dpe_cmd.id());
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let modified_derive_context_cmd;
    let modified_dpe_cmd;
    let dpe_cmd_buf = if let Command::DeriveContext(cmd) = dpe_cmd {
        if cmd.tci_type == 0 && !cmd.flags.is_recursive() {
            modified_derive_context_cmd = DeriveContextCmd {
                tci_type: NEXT_TEST_TCI_TYPE.fetch_add(1, Ordering::Relaxed),
                ..**cmd
            };
            modified_dpe_cmd = Command::from(&modified_derive_context_cmd);
            modified_dpe_cmd.as_bytes()
        } else {
            dpe_cmd.as_bytes()
        }
    } else {
        dpe_cmd.as_bytes()
    };
    cmd_data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + dpe_cmd_buf.len()].copy_from_slice(dpe_cmd_buf);
    let mut mbox_cmd = MailboxReq::InvokeDpeEcc384Command(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data: cmd_data,
        data_size: (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32,
    });
    mbox_cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(
        u32::from(CommandId::INVOKE_DPE_ECC384),
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
        DpeResult::Success => {
            // Peek response header so we can panic with an error code in case the command failed.
            check_dpe_status(resp_bytes, DpeErrorCode::NoError);
            Response::try_read_from_bytes(dpe_cmd, resp_bytes).unwrap()
        },
        DpeResult::DpeCmdFailure => Response::Error(ResponseHdr::try_read_from_bytes(resp_bytes).unwrap()),
        DpeResult::MboxCmdFailure(_) => unreachable!("If MboxCmdFailure is the expected DPE result, the function would have returned None earlier."),
    })
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

/// Response from `execute_dpe_cmd_raw` that can hold responses larger than
/// `InvokeDpeResp::DATA_MAX_SIZE` (needed for MLDSA87 certify-key responses).
pub struct DpeRawResp {
    pub data_size: u32,
    pub data: Vec<u8>,
}

pub fn execute_dpe_cmd_raw(
    model: &mut DefaultHwModel,
    profile: CaliptraDpeProfile,
    dpe_cmd: &mut Command,
) -> Result<DpeRawResp, ModelError> {
    // Fill the request buffer with the correct info
    let mut cmd_data: [u8; 512] = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let cmd_hdr = CommandHdr::new(profile.into(), dpe_cmd.id());
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let dpe_cmd_buf = dpe_cmd.as_bytes();
    cmd_data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + dpe_cmd_buf.len()].copy_from_slice(dpe_cmd_buf);

    let data_size = (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32;

    // Get the profile specific mailbox command
    let resp = match profile {
        CaliptraDpeProfile::Ecc384 => {
            let mut mbox_cmd = MailboxReq::InvokeDpeEcc384Command(InvokeDpeReq {
                hdr: MailboxReqHeader { chksum: 0 },
                data: cmd_data,
                data_size,
            });
            mbox_cmd.populate_chksum().unwrap();
            model.mailbox_execute(
                u32::from(CommandId::INVOKE_DPE_ECC384),
                mbox_cmd.as_bytes().unwrap(),
            )?
        }
        CaliptraDpeProfile::Mldsa87 => {
            let mut mbox_cmd = MailboxReq::InvokeDpeMldsa87Command(InvokeDpeMldsa87Req {
                hdr: MailboxReqHeader { chksum: 0 },
                flags: InvokeDpeMldsa87Flags::empty(),
                axi_response: AxiResponseInfo::default(),
                data: cmd_data,
                data_size,
            });
            mbox_cmd.populate_chksum().unwrap();
            model.mailbox_execute(
                u32::from(CommandId::INVOKE_DPE_MLDSA87),
                mbox_cmd.as_bytes().unwrap(),
            )?
        }
    };

    let resp = resp.expect("We should have received a response");
    check_header_checksum(&resp).unwrap();

    // Parse data_size and data from raw response bytes
    // Layout: MailboxRespHeader (8 bytes) | data_size (4 bytes) | data (variable)
    let hdr_size = core::mem::size_of::<MailboxRespHeader>();
    let data_size_offset = hdr_size;
    let data_offset = data_size_offset + core::mem::size_of::<u32>();
    let data_size = u32::from_le_bytes(
        resp[data_size_offset..data_offset]
            .try_into()
            .expect("data_size field"),
    );
    let data = resp[data_offset..].to_vec();

    Ok(DpeRawResp { data_size, data })
}

pub fn certify_key(
    model: &mut DefaultHwModel,
    cmd: &mut CertifyKeyCommandNoRef,
) -> anyhow::Result<CertifyKeyResp> {
    if model.subsystem_mode() {
        certify_key_chunks(model, cmd, None)
    } else {
        let resp = match cmd {
            CertifyKeyCommandNoRef::P384(ref cmd) => {
                let resp = execute_dpe_cmd_raw(
                    model,
                    CaliptraDpeProfile::Ecc384,
                    &mut Command::from(cmd),
                )?;
                let resp = resp.data[..resp.data_size as usize].to_vec();
                check_dpe_status(&resp, DpeErrorCode::NoError);
                resp
            }
            CertifyKeyCommandNoRef::Mldsa(ref cmd) => {
                let resp = execute_dpe_cmd_raw(
                    model,
                    CaliptraDpeProfile::Mldsa87,
                    &mut Command::from(cmd),
                )?;
                let resp = resp.data[..resp.data_size as usize].to_vec();
                check_dpe_status(&resp, DpeErrorCode::NoError);
                resp
            }
        };
        let resp = Response::try_read_from_bytes(&Command::from(&*cmd), &resp).map_err(|e| {
            anyhow::anyhow!("Failed to convert response into DPE response. {:?}", e)
        })?;
        let Response::CertifyKey(resp) = resp else {
            anyhow::bail!("Unexpected response type for CertifyKey command");
        };
        Ok(resp)
    }
}

pub fn certify_key_chunks(
    model: &mut DefaultHwModel,
    cmd: &mut CertifyKeyCommandNoRef,
    max_chunk_size: Option<usize>,
) -> anyhow::Result<CertifyKeyResp> {
    let mut full_resp = Vec::<u8>::new();
    let mut offset = 0;

    let use_mldsa = match cmd {
        CertifyKeyCommandNoRef::P384(_) => false,
        CertifyKeyCommandNoRef::Mldsa(_) => true,
    };

    let cmd_bytes = match cmd {
        CertifyKeyCommandNoRef::P384(ref c) => c.as_bytes().to_vec(),
        CertifyKeyCommandNoRef::Mldsa(ref c) => c.as_bytes().to_vec(),
    };

    let flags = if use_mldsa {
        CertifyKeyChunksFlags::USE_MLDSA
    } else {
        CertifyKeyChunksFlags(0)
    };

    loop {
        let mut certify_key_req = [0u8; 72];
        certify_key_req[..cmd_bytes.len()].copy_from_slice(&cmd_bytes);
        let req = CertifyKeyChunksReq {
            hdr: MailboxReqHeader { chksum: 0 },
            flags,
            reserved: 0,
            max_size: max_chunk_size.unwrap_or(0) as u32,
            offset: offset as u32,
            certify_key_req,
        };
        let mut mbox_cmd = MailboxReq::CertifyKeyChunks(req);
        mbox_cmd.populate_chksum().unwrap();

        let resp_data = model
            .mailbox_execute(
                u32::from(CommandId::CERTIFY_KEY_CHUNKS),
                mbox_cmd.as_bytes().unwrap(),
            )
            .context("Failed to get chunked certify key response")?;
        let resp_data = resp_data.expect("We should have received a response");
        check_header_checksum(&resp_data).unwrap();

        let mut resp = CertifyKeyChunksResp::default();
        assert!(resp_data.len() <= size_of::<CertifyKeyChunksResp>());
        resp.as_mut_bytes()[..resp_data.len()].copy_from_slice(&resp_data);

        let chunk_len = resp.info.chunk_len as usize;
        let remaining = resp.info.remaining as usize;

        full_resp.extend_from_slice(&resp.certify_key_resp[..chunk_len]);

        match cmd {
            CertifyKeyCommandNoRef::P384(ref mut c) => c.handle.0 = resp.info.context_handle,
            CertifyKeyCommandNoRef::Mldsa(ref mut c) => c.handle.0 = resp.info.context_handle,
        }

        if remaining == 0 {
            break;
        }
        offset += chunk_len;
    }

    let resp = Response::try_read_from_bytes(&Command::from(&*cmd), &full_resp)
        .map_err(|e| anyhow::anyhow!("Failed to convert response into DPE response. {:?}", e))?;
    let Response::CertifyKey(resp) = resp else {
        anyhow::bail!("Unexpected response type for CertifyKey command");
    };
    Ok(resp)
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

impl CertifyKeyCommandNoRef {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CertifyKeyCommandNoRef::P384(cmd) => cmd.as_bytes(),
            CertifyKeyCommandNoRef::Mldsa(cmd) => cmd.as_bytes(),
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

pub fn calculate_cptra_config_init_vals_hash<T: HwModel>(
    model: &mut T,
    image_bundle: &ImageBundle,
) -> [u8; 48] {
    use sha2::{Digest, Sha384};

    const PAUSER_COUNT: usize = 5;

    let mut hasher = Sha384::new();

    // Hash locked pausers
    for i in 0..PAUSER_COUNT {
        if model
            .soc_ifc()
            .cptra_mbox_axi_user_lock()
            .at(i)
            .read()
            .lock()
        {
            hasher.update(
                model
                    .soc_ifc()
                    .cptra_mbox_valid_axi_user()
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

pub fn verify_sign_and_certify_key(
    model: &mut DefaultHwModel,
    profile: CaliptraDpeProfile,
    sign_resp: &Response,
    certify_key_resp: &CertifyKeyResp,
    data: &[u8],
) {
    match (profile, sign_resp, certify_key_resp) {
        (
            CaliptraDpeProfile::Ecc384,
            Response::Sign(SignResp::P384(sign_resp)),
            CertifyKeyResp::P384(certify_key_resp),
        ) => {
            let sig = EcdsaSig::from_private_components(
                BigNum::from_slice(&sign_resp.sig_r).unwrap(),
                BigNum::from_slice(&sign_resp.sig_s).unwrap(),
            )
            .unwrap();

            let ecc_pub_key = EcKey::from_public_key_affine_coordinates(
                &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
                &BigNum::from_slice(&certify_key_resp.derived_pubkey_x).unwrap(),
                &BigNum::from_slice(&certify_key_resp.derived_pubkey_y).unwrap(),
            )
            .unwrap();
            assert!(sig.verify(data, &ecc_pub_key).unwrap());

            // Verify the certificate
            let alias_cert_resp = get_rt_alias_ecc384_cert(model);
            let alias_cert_bytes = alias_cert_resp.data().unwrap();
            let alias_x509 = X509::from_der(alias_cert_bytes).unwrap();
            let alias_pubkey = alias_x509.public_key().unwrap();

            let leaf_cert_bytes = &certify_key_resp.cert[..certify_key_resp.cert_size as usize];
            let leaf_x509 = X509::from_der(leaf_cert_bytes).unwrap();
            assert!(leaf_x509.verify(&alias_pubkey).unwrap());
        }
        (
            CaliptraDpeProfile::Mldsa87,
            Response::Sign(SignResp::Mldsa87(_sign_resp)),
            CertifyKeyResp::Mldsa87(certify_key_resp),
        ) => {
            // Skip raw MLDSA signature verification (ml-dsa v0.1.0-rc.0 has upstream compile issues)
            // Verify the certificate instead
            let alias_cert_resp = get_rt_alias_mldsa87_cert(model);
            let alias_cert_bytes = alias_cert_resp.data().unwrap();
            let alias_x509 = X509::from_der(alias_cert_bytes).unwrap();
            let alias_pubkey = alias_x509.public_key().unwrap();

            let leaf_cert_bytes = &certify_key_resp.cert[..certify_key_resp.cert_size as usize];
            let leaf_x509 = X509::from_der(leaf_cert_bytes).unwrap();
            assert!(leaf_x509.verify(&alias_pubkey).unwrap());
        }
        _ => panic!("Wrong response type!"),
    }
}
