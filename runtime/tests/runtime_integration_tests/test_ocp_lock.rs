// Licensed under the Apache-2.0 license

use caliptra_builder::firmware::runtime_tests;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use dpe::U8Bool;
use zerocopy::IntoBytes;

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_hek_metadata_never_reported() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&runtime_tests::MBOX_FPGA),
        ..Default::default()
    });

    model.step_until_boot_status(u32::from(RtBootStatus::RtReadyForCommands), true);

    let expected_val = U8Bool::new(false);
    // HEK can NEVER be valid if MCU ROM never reported the HEK metadata.
    let resp = model.mailbox_execute(0xF100_0000, &[]).unwrap().unwrap();
    assert_eq!(resp.as_bytes(), expected_val.as_bytes());
}
