// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{CommandId, GetIDevIDCSRResp, MailboxReqHeader};
use caliptra_drivers::{MfgFlags, MAX_CSR_SIZE};
use caliptra_hw_model::{Fuses, HwModel};
use zerocopy::{AsBytes, FromBytes};

use crate::helpers;

#[test]
fn test_get_csr() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let csr_bytes = {
        let flags = MfgFlags::GENERATE_IDEVID_CSR;
        hw.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| flags.bits());

        let downloaded = helpers::get_csr(&mut hw).unwrap();

        hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
        downloaded
    };

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDV_CSR), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::GET_IDV_CSR.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let get_idv_csr_resp = GetIDevIDCSRResp::read_from(response.as_bytes()).unwrap();

    assert!(caliptra_common::checksum::verify_checksum(
        get_idv_csr_resp.hdr.chksum,
        0x0,
        &get_idv_csr_resp.as_bytes()[core::mem::size_of_val(&get_idv_csr_resp.hdr.chksum)..],
    ));

    assert_eq!(csr_bytes.len() as u32, get_idv_csr_resp.data_size);
    assert_eq!(
        csr_bytes,
        get_idv_csr_resp.data[..get_idv_csr_resp.data_size as usize]
    );
}

#[test]
fn test_get_csr_generate_csr_flag_not_set() {
    let (mut hw, _) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDV_CSR), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::GET_IDV_CSR.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let get_idv_csr_resp = GetIDevIDCSRResp::read_from(response.as_bytes()).unwrap();

    assert!(caliptra_common::checksum::verify_checksum(
        get_idv_csr_resp.hdr.chksum,
        0x0,
        &get_idv_csr_resp.as_bytes()[core::mem::size_of_val(&get_idv_csr_resp.hdr.chksum)..],
    ));

    assert_eq!([0; MAX_CSR_SIZE as usize], get_idv_csr_resp.data);
    assert_eq!(0, get_idv_csr_resp.data_size);
}
