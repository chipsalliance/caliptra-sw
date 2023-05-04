// Licensed under the Apache-2.0 license.

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};

// Run test_bin as a ROM image. The is used for faster tests that can run
// against verilator
fn run_rom_test(test_bin_name: &str) -> DefaultHwModel {
    let runtime_fwid = FwId {
        crate_name: "caliptra-runtime-test-bin",
        bin_name: test_bin_name,
        features: &["emu", "riscv"],
    };

    let rom = caliptra_builder::build_firmware_rom(&runtime_fwid).unwrap();

    caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap()
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
fn run_rt_test(test_bin_name: Option<&str>) -> DefaultHwModel {
    let runtime_fwid = match test_bin_name {
        Some(bin) => FwId {
            crate_name: "caliptra-runtime-test-bin",
            bin_name: bin,
            features: &["emu", "riscv", "runtime"],
        },
        None => APP_WITH_UART,
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &runtime_fwid,
        ImageOptions::default(),
    )
    .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}

fn send_mailbox_command(model: &mut DefaultHwModel, cmd_id: u32, arg_buf: &[u32]) -> Vec<u32> {
    model.soc_mbox().lock().read().lock();
    model.soc_mbox().cmd().write(|_| cmd_id);
    model
        .soc_mbox()
        .dlen()
        .write(|_| u32::try_from(arg_buf.len()).unwrap() * 4);

    for word in arg_buf {
        model.soc_mbox().datain().write(|_| *word);
    }
    model
        .soc_mbox()
        .execute()
        .write(|exec_reg| exec_reg.execute(true));

    model.step_until(|m| !m.soc_mbox().status().read().status().cmd_busy());

    let dlen_bytes = model.soc_mbox().dlen().read() as usize;
    let dlen_words = (dlen_bytes + 3) / 4;
    let mut resp = vec![0u32; dlen_words];

    for dest_word in resp.iter_mut() {
        *dest_word = model.soc_mbox().dataout().read();
    }

    model
        .soc_mbox()
        .execute()
        .write(|exec_reg| exec_reg.execute(false));
    model.step(); // Step once to get mailbox to idel state

    resp
}

#[test]
fn test_standard() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    let mut model = run_rt_test(None);

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();
}

#[test]
fn test_boot() {
    let mut model = run_rt_test(Some("boot"));

    model.step_until_exit_success().unwrap();
}

#[test]
fn test_mbox() {
    let mut model = run_rom_test("mbox");

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let cmd_buf = [0u32; 4];
    let resp = send_mailbox_command(&mut model, 0x0, &cmd_buf);

    assert_eq!(resp, vec![0xFFFFFFFFu32; 4]);

    assert!(model.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());
}
