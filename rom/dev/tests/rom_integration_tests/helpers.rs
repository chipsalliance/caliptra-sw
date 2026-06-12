// Licensed under the Apache-2.0 license
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unexpected_cfgs)]

use std::mem;

use caliptra_api::SocManager;
use caliptra_builder::{firmware, FwId, ImageOptions};
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::{
    memory_layout::{ROM_ORG, ROM_SIZE, ROM_STACK_ORG, ROM_STACK_SIZE, STACK_ORG, STACK_SIZE},
    FMC_ORG, FMC_SIZE, RUNTIME_ORG, RUNTIME_SIZE,
};
use caliptra_drivers::{InitDevIdCsrEnvelope, MfgFlags};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, CodeRange, Fuses, HwModel, ImageInfo, InitParams, SecurityState, StackInfo,
    StackRange, SubsystemInitParams,
};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, ModelCallback, ModelError};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageBundle};
use zerocopy::TryFromBytes;

pub use caliptra_test::{default_soc_manifest_bytes, test_upload_firmware, DEFAULT_MCU_FW};

pub const PQC_KEY_TYPE: [FwVerificationPqcKeyType; 2] = [
    FwVerificationPqcKeyType::LMS,
    FwVerificationPqcKeyType::MLDSA,
];

pub const LIFECYCLES_PROVISIONED: [DeviceLifecycle; 2] =
    [DeviceLifecycle::Manufacturing, DeviceLifecycle::Production];

pub const LIFECYCLES_ALL: [DeviceLifecycle; 3] = [
    DeviceLifecycle::Unprovisioned,
    DeviceLifecycle::Manufacturing,
    DeviceLifecycle::Production,
];

pub fn wait_until_runtime(model: &mut DefaultHwModel) {
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());
}

pub fn assert_fatal_fw_load(
    hw: &mut DefaultHwModel,
    pqc_key_type: FwVerificationPqcKeyType,
    data: &[u8],
    err: CaliptraError,
) {
    if hw.subsystem_mode() {
        test_upload_firmware(hw, data, pqc_key_type);
        hw.step_until_fatal_error(err.into(), 1000000)
    } else {
        assert_eq!(
            ModelError::MailboxCmdFailed(err.into()),
            hw.upload_firmware(data).unwrap_err()
        );
    }
}

pub fn rom_from_env() -> &'static FwId<'static> {
    firmware::rom_from_env_fpga(cfg!(any(
        feature = "fpga_subsystem",
        feature = "fpga_realtime"
    )))
}

// Start a firmware load via mailbox (non-blocking), used in tests that
// need to observe intermediate boot statuses during FIRMWARE_LOAD.
pub fn test_start_firmware_load(model: &mut DefaultHwModel, fw_image: &[u8]) {
    model
        .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), fw_image)
        .unwrap();
}

pub fn build_hw_model_and_image_bundle(
    fuses: Fuses,
    image_options: ImageOptions,
) -> (DefaultHwModel, ImageBundle) {
    build_hw_model_and_image_bundle_with_mfg_flags(fuses, image_options, MfgFlags::empty())
}

/// Same as [`build_hw_model_and_image_bundle`], but latches `mfg_flags` into
/// `cptra_dbg_manuf_service_reg` via `BootParams` before Caliptra ROM runs.
///
/// Flags that ROM samples during the cold-reset flow (e.g.
/// `GENERATE_IDEVID_CSR`) must be set this way: on the FPGA subsystem `boot()`
/// runs ROM far enough that setting the register on the built model can race
/// ROM and be latched too late.
pub fn build_hw_model_and_image_bundle_with_mfg_flags(
    fuses: Fuses,
    image_options: ImageOptions,
    mfg_flags: MfgFlags,
) -> (DefaultHwModel, ImageBundle) {
    let image = build_image_bundle(image_options);
    (build_hw_model_with_mfg_flags(fuses, mfg_flags), image)
}

pub fn build_hw_model(fuses: Fuses) -> DefaultHwModel {
    build_hw_model_with_mfg_flags(fuses, MfgFlags::empty())
}

pub fn build_hw_model_with_mfg_flags(fuses: Fuses, mfg_flags: MfgFlags) -> DefaultHwModel {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
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
    let mut security_state = SecurityState::from(fuses.life_cycle as u32);
    security_state.set_debug_locked(fuses.debug_locked);
    caliptra_hw_model::new(
        InitParams {
            fuses,
            rom: &rom,
            security_state,
            stack_info: Some(StackInfo::new(image_info)),
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        BootParams {
            initial_dbg_manuf_service_reg: mfg_flags.bits(),
            ..Default::default()
        },
    )
    .unwrap()
}

pub fn build_image_bundle(image_options: ImageOptions) -> ImageBundle {
    caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        if cfg!(feature = "fpga_subsystem") {
            &firmware::APP_WITH_UART_FPGA
        } else {
            &firmware::APP_WITH_UART
        },
        image_options,
    )
    .unwrap()
}

/// This function matches the to_match string in the haystack string and returns the data
/// after the match until the next newline character.
///
/// # Arguments
///
/// * `to_match` - String to search for
/// * `haystack` - String to search in
pub fn get_data<'a>(to_match: &str, haystack: &'a str) -> &'a str {
    let index = haystack
        .find(to_match)
        .unwrap_or_else(|| panic!("unable to find substr {to_match:?}"));
    haystack[index + to_match.len()..]
        .split('\n')
        .next()
        .unwrap_or("")
}

/// Boot takes well under 30M cycles, so a longer wait means the device is hung.
const BOOT_MAX_WAIT_CYCLES: u32 = 30_000_000;

/// Step until `predicate` is true, failing fast (with a register dump) if the
/// ROM reports a fatal error or the wait exceeds [`BOOT_MAX_WAIT_CYCLES`]. `what`
/// names the awaited condition.
pub fn step_until_boot_or_diagnose(
    hw: &mut DefaultHwModel,
    what: &str,
    mut predicate: impl FnMut(&mut DefaultHwModel) -> bool,
) {
    let mut cycles = 0u32;
    loop {
        if predicate(hw) {
            return;
        }
        let fatal = hw.soc_ifc().cptra_fw_error_fatal().read();
        if fatal != 0 {
            panic!("{}", diagnose(hw, what, "ROM reported a FATAL error"));
        }
        if cycles >= BOOT_MAX_WAIT_CYCLES {
            panic!(
                "{}",
                diagnose(
                    hw,
                    what,
                    "timed out (no fatal error reported \u{2013} device hung)"
                )
            );
        }
        hw.step();
        cycles += 1;
    }
}

fn diagnose(hw: &mut DefaultHwModel, what: &str, summary: &str) -> String {
    // Read the mailbox FSM (not the lock, which acquires on read) to show whether
    // the ROM is still contending for the mailbox to send the CSR.
    let mbox_status = hw.soc_mbox().status().read();
    let mbox_fsm = mbox_status.mbox_fsm_ps();
    let soc_ifc = hw.soc_ifc();
    let flow = soc_ifc.cptra_flow_status().read();
    format!(
        "CSR-stress diagnose: {summary} while waiting for `{what}`.\n  \
         cptra_fw_error_fatal     = 0x{:08x}\n  \
         cptra_fw_error_non_fatal = 0x{:08x}\n  \
         cptra_boot_status        = 0x{:08x}\n  \
         cptra_flow_status        = 0x{:08x} (idevid_csr_ready={} ready_for_mb_processing={} ready_for_runtime={})\n  \
         mbox_fsm_ps              = idle={} exec_uc={} exec_soc={}",
        soc_ifc.cptra_fw_error_fatal().read(),
        soc_ifc.cptra_fw_error_non_fatal().read(),
        soc_ifc.cptra_boot_status().read(),
        u32::from(flow),
        flow.idevid_csr_ready(),
        flow.ready_for_mb_processing(),
        flow.ready_for_runtime(),
        mbox_fsm.mbox_idle(),
        mbox_fsm.mbox_execute_uc(),
        mbox_fsm.mbox_execute_soc(),
    )
}

pub fn get_csr_envelop(hw: &mut DefaultHwModel) -> Result<InitDevIdCsrEnvelope, ModelError> {
    step_until_boot_or_diagnose(hw, "idevid_csr_ready", |m| {
        m.soc_ifc().cptra_flow_status().read().idevid_csr_ready()
    });
    let mut txn = hw.wait_for_mailbox_receive()?;
    let result = mem::take(&mut txn.req.data);
    txn.respond_success();
    hw.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
    let (csr_envelop, _) = InitDevIdCsrEnvelope::try_read_from_prefix(&result).unwrap();
    Ok(csr_envelop)
}

/// Holds the IDevID CSR captured during boot for the test to retrieve.
pub type CapturedCsr = std::sync::Arc<std::sync::Mutex<Option<InitDevIdCsrEnvelope>>>;

/// Build a model that requests the IDevID CSR and drains it from the mailbox
/// during boot (via `rom_callback`, when `idevid_csr_ready` asserts), then boots
/// to runtime. The returned cell holds the captured CSR.
pub fn build_hw_model_capturing_idevid_csr(
    fuses: Fuses,
    image_options: ImageOptions,
    pqc_key_type: FwVerificationPqcKeyType,
) -> (DefaultHwModel, CapturedCsr) {
    let csr_cell: CapturedCsr = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cb_cell = csr_cell.clone();
    let rom_callback: ModelCallback = Box::new(move |hw: &mut DefaultHwModel| {
        let csr = get_csr_envelop(hw).expect("failed to read IDevID CSR in rom_callback");
        *cb_cell.lock().unwrap() = Some(csr);
    });

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let image_bytes = build_image_bundle(image_options).to_bytes().unwrap();
    let soc_manifest = default_soc_manifest_bytes(pqc_key_type, 1);

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
    let mut security_state = SecurityState::from(fuses.life_cycle as u32);
    security_state.set_debug_locked(fuses.debug_locked);

    let model = caliptra_hw_model::new(
        InitParams {
            fuses,
            rom: &rom,
            security_state,
            stack_info: Some(StackInfo::new(image_info)),
            rom_callback: Some(rom_callback),
            ss_init_params: SubsystemInitParams {
                enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                ..Default::default()
            },
            ..Default::default()
        },
        BootParams {
            initial_dbg_manuf_service_reg: MfgFlags::GENERATE_IDEVID_CSR.bits(),
            read_idevid_csr_in_callback: true,
            fw_image: Some(&image_bytes),
            soc_manifest: Some(&soc_manifest),
            mcu_fw_image: Some(&DEFAULT_MCU_FW),
            ..Default::default()
        },
    )
    .unwrap();

    (model, csr_cell)
}

pub fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "Foo bar baz \n\
                       [idev] ECC CSR = foo bar\n\
                       [idev] ECC CSR = wrong";

    #[test]
    fn test_get_data() {
        assert_eq!("foo bar", get_data("[idev] ECC CSR = ", LOG));

        assert_eq!("", get_data("CSR = wrong", LOG));
    }

    #[test]
    #[should_panic(expected = "unable to find substr \"[idev] FOO = \"")]
    fn test_get_data_not_found() {
        assert_eq!("", get_data("[idev] FOO = ", LOG));
    }
}
