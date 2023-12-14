// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use zerocopy::AsBytes;

use crate::common::{assert_error, run_rt_test};

#[test]
fn test_cpu_fault() {
    let mut model = run_rt_test(None, None, None);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::TEST_ONLY_TRIGGER_CPU_FAULT),
            &[],
        ),
    };

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::TEST_ONLY_TRIGGER_CPU_FAULT),
            payload.as_bytes(),
        )
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_GLOBAL_EXCEPTION, resp);

    let mcause = model.soc_ifc().cptra_fw_extended_error_info().at(0).read();
    let mscause = model.soc_ifc().cptra_fw_extended_error_info().at(1).read();
    let mepc = model.soc_ifc().cptra_fw_extended_error_info().at(2).read();
    let ra = model.soc_ifc().cptra_fw_extended_error_info().at(3).read();

    // mcause must be illegal instruction
    assert_eq!(mcause, 0x2);
    // no mscause
    assert_eq!(mscause, 0);
    // program counter won't be 0
    assert_ne!(mepc as usize, 0);
    // return address won't be 0
    assert_ne!(ra, 0);

    #[cfg(feature = "verilator")]
    assert!(model.v.output.cptra_error_fatal);
}
