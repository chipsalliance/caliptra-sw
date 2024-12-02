// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::{APP_WITH_UART, FMC_WITH_UART};
use caliptra_builder::{version, ImageOptions};
use caliptra_common::mailbox_api::*;
use caliptra_drivers::FipsTestHook;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams, ModelError, ShaAccMode};
use dpe::{
    commands::*,
    response::{
        CertifyKeyResp, DeriveContextResp, GetCertificateChainResp, GetProfileResp, NewHandleResp,
        Response, ResponseHdr, SignResp,
    },
};
use zerocopy::{AsBytes, FromBytes};

pub const HOOK_CODE_MASK: u32 = 0x00FF0000;
pub const HOOK_CODE_OFFSET: u32 = 16;

// =================================
//       EXPECTED CONSTANTS
// =================================

// Constants are grouped into RTL, ROM, and Runtime
// Values can be specified for specific release versions (i.e. 1.0.1)
// The user can specify which release (or default to current) to use when executing tests
// Subsequent versions should "inherit" the previous version and override any changed values
// The "current" struct must always match the behavior of components built from the same commit ID

// ===  RTL  ===
pub struct HwExpVals {
    pub hw_revision: u32,
}

const HW_EXP_1_0_0: HwExpVals = HwExpVals { hw_revision: 0x1 };

const HW_EXP_CURRENT: HwExpVals = HwExpVals { hw_revision: 0x11 };

// ===  ROM  ===
pub struct RomExpVals {
    pub rom_version: u16,
    pub capabilities: [u8; 16],
}

const ROM_EXP_1_0_1: RomExpVals = RomExpVals {
    rom_version: 0x801, // 1.0.1
    capabilities: [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
    ],
};

const ROM_EXP_1_0_3: RomExpVals = RomExpVals {
    rom_version: 0x803, // 1.0.3
    ..ROM_EXP_1_0_1
};

const ROM_EXP_1_1_0: RomExpVals = RomExpVals {
    rom_version: 0x840, // 1.1.0
    ..ROM_EXP_1_0_3
};

const ROM_EXP_1_2_0: RomExpVals = RomExpVals {
    rom_version: 0x880, // 1.2.0
    ..ROM_EXP_1_1_0
};

const ROM_EXP_CURRENT: RomExpVals = RomExpVals { ..ROM_EXP_1_2_0 };

// ===  RUNTIME  ===
pub struct RtExpVals {
    pub fmc_version: u16,
    pub fw_version: u32,
}

const RT_EXP_1_0_0: RtExpVals = RtExpVals {
    fmc_version: 0x800,      // 1.0.0
    fw_version: 0x0100_0000, // 1.0.0
};

const RT_EXP_1_1_0: RtExpVals = RtExpVals {
    fmc_version: 0x840,      // 1.1.0
    fw_version: 0x0101_0000, // 1.1.0
};

const RT_EXP_CURRENT: RtExpVals = RtExpVals { ..RT_EXP_1_1_0 };

// === Getter implementations ===
// TODO: These could be improved
//       Can we generate a var name from a str in rust and check if it exists?
//       Or we can just do a macro to generate a list of the valid versions and const names to use here
impl HwExpVals {
    pub fn get() -> HwExpVals {
        if let Ok(version) = std::env::var("FIPS_TEST_HW_EXP_VERSION") {
            match version.as_str() {
                // Add more versions here
                "1_0_0" => HW_EXP_1_0_0,
                _ => panic!(
                    "FIPS Test: Unknown version for expected HW values ({})",
                    version
                ),
            }
        } else {
            HW_EXP_CURRENT
        }
    }
}
impl RomExpVals {
    pub fn get() -> RomExpVals {
        if let Ok(version) = std::env::var("FIPS_TEST_ROM_EXP_VERSION") {
            match version.as_str() {
                // Add more versions here
                "1_0_1" => ROM_EXP_1_0_1,
                "1_0_3" => ROM_EXP_1_0_3,
                _ => panic!(
                    "FIPS Test: Unknown version for expected ROM values ({})",
                    version
                ),
            }
        } else {
            ROM_EXP_CURRENT
        }
    }
}
impl RtExpVals {
    pub fn get() -> RtExpVals {
        if let Ok(version) = std::env::var("FIPS_TEST_RT_EXP_VERSION") {
            match version.as_str() {
                // Add more versions here
                "1_0_0" => RT_EXP_1_0_0,
                _ => panic!(
                    "FIPS Test: Unknown version for expected Runtime values ({})",
                    version
                ),
            }
        } else {
            RT_EXP_CURRENT
        }
    }
}

// =================================
//       HELPER FUNCTIONS
// =================================

pub fn fips_test_init_model(init_params: Option<InitParams>) -> DefaultHwModel {
    // Create params if not provided
    let mut init_params = init_params.unwrap_or(InitParams::default());

    // Check that ROM was not provided if the immutable_rom feature is set
    #[cfg(feature = "test_env_immutable_rom")]
    if init_params.rom != <&[u8]>::default() {
        panic!("FIPS_TEST_SUITE ERROR: ROM cannot be provided/changed when immutable_ROM feature is set")
    }

    // If rom was not provided, build it or get it from the specified path
    let rom = match std::env::var("FIPS_TEST_ROM_BIN") {
        // Build default rom if not provided and no path is specified
        Err(_) => caliptra_builder::rom_for_fw_integration_tests().unwrap(),
        Ok(rom_path) => {
            // Read in the ROM file if a path was provided
            match std::fs::read(&rom_path) {
                Err(why) => panic!("couldn't open {}: {}", rom_path, why),
                Ok(rom) => rom.into(),
            }
        }
    };

    if init_params.rom == <&[u8]>::default() {
        init_params.rom = &rom;
    }

    // Create the model
    caliptra_hw_model::new_unbooted(init_params).unwrap()
}

fn fips_test_boot<T: HwModel>(hw: &mut T, boot_params: Option<BootParams>) {
    // Create params if not provided
    let boot_params = boot_params.unwrap_or(BootParams::default());

    // Boot
    hw.boot(boot_params).unwrap();
}

// Generic helper to boot to ROM or runtime
// Builds ROM, if not provided
// HW Model will boot to runtime if image is provided
fn fips_test_init_base(
    init_params: Option<InitParams>,
    boot_params: Option<BootParams>,
) -> DefaultHwModel {
    let mut hw = fips_test_init_model(init_params);

    fips_test_boot(&mut hw, boot_params);

    hw
}

// Initializes Caliptra
// Builds and uses default ROM if not provided
pub fn fips_test_init_to_boot_start(
    init_params: Option<InitParams>,
    boot_params: Option<BootParams>,
) -> DefaultHwModel {
    // Check that no fw_image is in boot params
    if let Some(ref params) = boot_params {
        if params.fw_image.is_some() {
            panic!("No FW image should be provided when calling fips_test_init_to_boot_start")
        }
    }

    fips_test_init_base(init_params, boot_params)
}

// Initializes caliptra to "ready_for_fw"
// Builds and uses default ROM if not provided
pub fn fips_test_init_to_rom(
    init_params: Option<InitParams>,
    boot_params: Option<BootParams>,
) -> DefaultHwModel {
    let mut model = fips_test_init_base(init_params, boot_params);

    // Step to ready for FW in ROM
    model.step_until(|m| {
        m.soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_mb_processing()
    });

    model
}

// Initializes Caliptra to runtime
// Builds and uses default ROM and FW if not provided
pub fn fips_test_init_to_rt(
    init_params: Option<InitParams>,
    boot_params: Option<BootParams>,
) -> DefaultHwModel {
    // Create params if not provided
    let mut boot_params = boot_params.unwrap_or(BootParams::default());

    if boot_params.fw_image.is_some() {
        fips_test_init_base(init_params, Some(boot_params))
    } else {
        let fw_image = fips_fw_image();
        boot_params.fw_image = Some(&fw_image);
        fips_test_init_base(init_params, Some(boot_params))
    }

    // HW model will complete FW upload cmd, nothing to wait for
}

pub fn mbx_send_and_check_resp_hdr<T: HwModel, U: FromBytes + AsBytes>(
    hw: &mut T,
    cmd: u32,
    req_payload: &[u8],
) -> std::result::Result<U, ModelError> {
    let resp_bytes = hw.mailbox_execute(cmd, req_payload)?.unwrap();

    // Check values against expected.
    let resp_hdr =
        MailboxRespHeader::read_from(&resp_bytes[..core::mem::size_of::<MailboxRespHeader>()])
            .unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        resp_hdr.chksum,
        0x0,
        &resp_bytes[core::mem::size_of_val(&resp_hdr.chksum)..],
    ));
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Handle variable-sized responses
    assert!(resp_bytes.len() <= std::mem::size_of::<U>());
    let mut typed_resp = U::new_zeroed();
    typed_resp.as_bytes_mut()[..resp_bytes.len()].copy_from_slice(&resp_bytes);
    Ok(typed_resp)

    // TODO: Add option for fixed-length enforcement
    //Ok(U::read_from(resp_bytes.as_bytes()).unwrap())
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
pub fn as_bytes(dpe_cmd: &mut Command) -> &[u8] {
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

pub fn parse_dpe_response(dpe_cmd: &mut Command, resp_bytes: &[u8]) -> Response {
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

pub fn execute_dpe_cmd<T: HwModel>(hw: &mut T, dpe_cmd: &mut Command) -> Response {
    let mut cmd_data: [u8; 512] = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let dpe_cmd_id = get_cmd_id(dpe_cmd);
    let cmd_hdr = CommandHdr::new_for_test(dpe_cmd_id);
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    cmd_data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let dpe_cmd_buf = as_bytes(dpe_cmd);
    cmd_data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + dpe_cmd_buf.len()].copy_from_slice(dpe_cmd_buf);

    let mut payload = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data: cmd_data,
        data_size: (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32,
    });
    payload.populate_chksum().unwrap();

    let resp = mbx_send_and_check_resp_hdr::<_, InvokeDpeResp>(
        hw,
        u32::from(CommandId::INVOKE_DPE),
        payload.as_bytes().unwrap(),
    )
    .unwrap();

    let resp_bytes = &resp.data[..resp.data_size as usize];
    parse_dpe_response(dpe_cmd, resp_bytes)
}

pub fn fips_fw_image() -> Vec<u8> {
    match std::env::var("FIPS_TEST_FW_BIN") {
        // Build default FW if not provided and no path is specified
        Err(_) => caliptra_builder::build_and_sign_image(
            &FMC_WITH_UART,
            &APP_WITH_UART,
            ImageOptions {
                fmc_version: version::get_fmc_version(),
                app_version: version::get_runtime_version(),
                ..Default::default()
            },
        )
        .unwrap()
        .to_bytes()
        .unwrap(),
        // Read in the ROM file if a path was provided
        Ok(fw_path) => match std::fs::read(&fw_path) {
            Err(why) => panic!("couldn't open {}: {}", fw_path, why),
            Ok(fw_image) => fw_image,
        },
    }
}

// Returns true if not all elements in array are the same
// (Mainly want to make sure data is not all 0s or all Fs)
pub fn contains_some_data<T: std::cmp::PartialEq>(data: &[T]) -> bool {
    for element in data {
        if *element != data[0] {
            return true;
        }
    }

    false
}

pub fn verify_mbox_cmds_fail<T: HwModel>(hw: &mut T, exp_error_code: u32) {
    // Send an arbitrary message
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };

    // Make sure we get the right failure
    match mbx_send_and_check_resp_hdr::<_, FwInfoResp>(
        hw,
        u32::from(CommandId::FW_INFO),
        payload.as_bytes(),
    ) {
        Ok(_) => panic!("MBX command should fail at this point"),
        Err(act_error) => {
            if act_error != ModelError::MailboxCmdFailed(exp_error_code) {
                panic!("MBX command received unexpected error {}", act_error)
            }
        }
    }
}

// Check mailbox output is inhibited
pub fn verify_mbox_output_inhibited<T: HwModel>(hw: &mut T) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };
    match hw.mailbox_execute(u32::from(CommandId::VERSION), payload.as_bytes()) {
        Ok(_) => panic!("Mailbox output is not inhibited"),
        Err(ModelError::MailboxTimeout) => (),
        Err(ModelError::UnableToLockMailbox) => (),
        Err(e) => panic!("Unexpected error from mailbox_execute {:?}", e),
    }
}

// Check sha engine output is inhibited (ensure sha engine is locked)
pub fn verify_sha_engine_output_inhibited<T: HwModel>(hw: &mut T) {
    let message: &[u8] = &[0x0, 0x1, 0x2, 0x3];
    match hw.compute_sha512_acc_digest(message, ShaAccMode::Sha384Stream) {
        Ok(_) => panic!("SHA engine is not locked, output is not inhibited"),
        Err(ModelError::UnableToLockSha512Acc) => (),
        Err(_) => panic!("Unexpected error from compute_sha512_acc_digest"),
    }
}

// Verify all output is inhibited
pub fn verify_output_inhibited<T: HwModel>(hw: &mut T) {
    verify_mbox_output_inhibited(hw);
    verify_sha_engine_output_inhibited(hw);
}

pub fn hook_code_read<T: HwModel>(hw: &mut T) -> u8 {
    ((hw.soc_ifc().cptra_dbg_manuf_service_reg().read() & HOOK_CODE_MASK) >> HOOK_CODE_OFFSET) as u8
}

pub fn hook_code_write<T: HwModel>(hw: &mut T, code: u8) {
    let val = (hw.soc_ifc().cptra_dbg_manuf_service_reg().read() & !(HOOK_CODE_MASK))
        | ((code as u32) << HOOK_CODE_OFFSET);
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| val);
}

pub fn hook_wait_for_complete<T: HwModel>(hw: &mut T) {
    while hook_code_read(hw) != FipsTestHook::COMPLETE {
        // Give FW time to run
        let mut cycle_count = 1000;
        hw.step_until(|_| -> bool {
            cycle_count -= 1;
            cycle_count == 0
        });
    }
}
