// Licensed under the Apache-2.0 license
use crate::common::{run_rt_test, RuntimeTestArgs};
#[cfg(all(not(feature = "verilator"), not(feature = "fpga_realtime")))]
use caliptra_emu_bus::{Device, EventData};
use caliptra_hw_model::{HwModel, InitParams};

const RT_READY_FOR_COMMANDS: u32 = 0x600;

#[cfg(all(not(feature = "verilator"), not(feature = "fpga_realtime")))]
#[test]
fn test_loads_mcu_fw() {
    // Test that the recovery flow runs and loads MCU's firmware
    let soc_manifest = vec![0x12u8; 128];
    let mcu_fw = vec![0x34u8; 128];
    let mut args = RuntimeTestArgs::default();
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    args.init_params = Some(InitParams {
        rom: &rom,
        active_mode: true,
        ..Default::default()
    });
    args.soc_manifest = Some(&soc_manifest);
    args.mcu_fw_image = Some(&mcu_fw);
    let mut model = run_rt_test(args);
    model.step_until_boot_status(RT_READY_FOR_COMMANDS, true);
    // check that we got an MCU write
    let events = model.events_from_caliptra();
    let mut found = false;
    for event in events {
        if event.dest == Device::MCU && matches!(event.event, EventData::MemoryWrite { .. }) {
            found = true;
            break;
        }
    }
    assert!(found);
}
