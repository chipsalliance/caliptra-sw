// Licensed under the Apache-2.0 license

use caliptra_builder::firmware::{APP_WITH_UART, FMC_WITH_UART};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::*;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, ModelError};
use dpe::{
    commands::*,
    response::{
        CertifyKeyResp, DeriveContextResp, GetCertificateChainResp, GetProfileResp, NewHandleResp,
        Response, ResponseHdr, SignResp,
    },
};
use zerocopy::{AsBytes, FromBytes};

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
const ROM_EXP_CURRENT: RomExpVals = RomExpVals { ..ROM_EXP_1_0_1 };

// ===  RUNTIME  ===
pub struct RtExpVals {
    pub fmc_version: u16,
    pub fw_version: u32,
}

const RT_EXP_1_0_0: RtExpVals = RtExpVals {
    fmc_version: 0x0,
    fw_version: 0x0100_0000,
};

const RT_EXP_CURRENT: RtExpVals = RtExpVals {
    fmc_version: 0x0,
    fw_version: 0x0,
};

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

// Generic helper to boot to ROM or runtime
// Builds ROM, if not provided
// HW Model will boot to runtime if image is provided
fn fips_test_init_base(
    boot_params: Option<BootParams>,
    fw_image_override: Option<&[u8]>,
) -> DefaultHwModel {
    // Create params if not provided
    let mut boot_params = boot_params.unwrap_or(BootParams::default());

    // Check that ROM was not provided if the immutable_rom feature is set
    #[cfg(feature = "test_env_immutable_rom")]
    if boot_params.init_params.rom != <&[u8]>::default() {
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

    if boot_params.init_params.rom == <&[u8]>::default() {
        boot_params.init_params.rom = &rom;
    }

    // Add fw image override to boot params if provided
    if fw_image_override.is_some() {
        // Sanity check that the caller functions are written correctly
        if boot_params.fw_image.is_some() {
            panic!("FIPS_TEST_SUITE BUG: Should never have a fw_image override and a fw_image in boot params")
        }
        boot_params.fw_image = fw_image_override;
    }

    // Create the model
    caliptra_hw_model::new(boot_params).unwrap()
}

// Initializes caliptra to "ready_for_fw"
// Builds and uses default ROM if not provided
pub fn fips_test_init_to_rom(boot_params: Option<BootParams>) -> DefaultHwModel {
    // Check that no fw_image is in boot params
    if let Some(ref params) = boot_params {
        if params.fw_image.is_some() {
            panic!("No FW image should be provided when calling fips_test_init_to_rom")
        }
    }

    let mut model = fips_test_init_base(boot_params, None);

    // Step to ready for FW in ROM
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}

// Initializes Caliptra to runtime
// Builds and uses default ROM and FW if not provided
pub fn fips_test_init_to_rt(boot_params: Option<BootParams>) -> DefaultHwModel {
    let mut build_fw = true;

    if let Some(ref params) = boot_params {
        if params.fw_image.is_some() {
            build_fw = false;
        }
    }

    if build_fw {
        // If FW was not provided, build it or get it from the specified path
        let fw_image = fips_fw_image();

        fips_test_init_base(boot_params, Some(&fw_image))
    } else {
        fips_test_init_base(boot_params, None)
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
            ImageOptions::default(),
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
