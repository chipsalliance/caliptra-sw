// Licensed under the Apache-2.0 license

use crate::common::{build_ready_runtime_model, wait_runtime_ready, BuildArgs};
use caliptra_common::{
    capabilities::Capabilities,
    checksum::{calc_checksum, verify_checksum},
    mailbox_api::{CapabilitiesResp, CommandId, MailboxReqHeader, MailboxRespHeader},
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use zerocopy::{FromBytes, IntoBytes};

fn get_capabilities(model: &mut DefaultHwModel) -> (CapabilitiesResp, Vec<u8>) {
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::CAPABILITIES), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::CAPABILITIES), payload.as_bytes())
        .expect("mailbox_execute failed")
        .expect("CAPABILITIES returned no data");

    assert!(!resp.is_empty(), "CAPABILITIES returned empty payload");

    let capabilities_resp =
        CapabilitiesResp::read_from_bytes(resp.as_slice()).expect("parse CapabilitiesResp failed");

    // Verify response checksum (exclude the checksum field itself).
    assert!(
        verify_checksum(
            capabilities_resp.hdr.chksum,
            0x0,
            &capabilities_resp.as_bytes()[core::mem::size_of_val(&capabilities_resp.hdr.chksum)..],
        ),
        "CAPABILITIES response checksum invalid"
    );
    assert_eq!(
        capabilities_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CAPABILITIES FIPS not APPROVED"
    );

    (capabilities_resp, resp)
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]

fn test_capabilities_after_warm_reset() {
    let (mut model, _, _, _) = build_ready_runtime_model(BuildArgs::default());

    // --- Before warm reset ---

    let (cap_resp_before, raw_resp_before) = get_capabilities(&mut model);

    let capabilities_before =
        Capabilities::try_from(&cap_resp_before.capabilities[..]).expect("decode caps");
    assert!(capabilities_before.contains(Capabilities::RT_BASE));

    // --- Warm reset ---
    model.warm_reset();

    wait_runtime_ready(&mut model);

    // --- After warm reset ---
    let (cap_resp_after, raw_resp_after) = get_capabilities(&mut model);

    let capabilities_after =
        Capabilities::try_from(&cap_resp_after.capabilities[..]).expect("decode caps");

    assert!(capabilities_after.contains(Capabilities::RT_BASE));

    assert_eq!(
        raw_resp_before, raw_resp_after,
        "Raw CAPABILITIES changed across warm reset"
    );
    assert_eq!(
        cap_resp_before.as_bytes(),
        cap_resp_after.as_bytes(),
        "Typed CAPABILITIES bytes changed across warm reset"
    );
    assert_eq!(
        capabilities_before.to_bytes(),
        capabilities_after.to_bytes(),
        "Capability bitflags changed across warm reset"
    ); //
}
