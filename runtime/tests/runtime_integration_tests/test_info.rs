// Licensed under the Apache-2.0 license.

use crate::common::run_rt_test;
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    CommandId, FwInfoResp, GetIdevInfoResp, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use zerocopy::{AsBytes, FromBytes};

#[test]
fn test_fw_info() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = Some(0x1);
    image_opts.fmc_version = 0xaaaaaaaa;
    image_opts.app_version = 0xbbbbbbbb;
    image_opts.fmc_svn = 5;

    let mut image_opts10 = image_opts.clone();
    image_opts10.app_svn = 10;

    let mut model = run_rt_test(None, Some(image_opts10), None);

    let get_fwinfo = |model: &mut DefaultHwModel| {
        let payload = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
        };

        let resp = model
            .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
            .unwrap()
            .unwrap();

        let info = FwInfoResp::read_from(resp.as_slice()).unwrap();

        // Verify checksum and FIPS status
        assert!(caliptra_common::checksum::verify_checksum(
            info.hdr.chksum,
            0x0,
            &info.as_bytes()[core::mem::size_of_val(&info.hdr.chksum)..],
        ));
        assert_eq!(
            info.hdr.fips_status,
            MailboxRespHeader::FIPS_STATUS_APPROVED
        );
        assert_eq!(info.attestation_disabled, 0);
        info
    };

    let update_to = |model: &mut DefaultHwModel, image: &[u8]| {
        model
            .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), image)
            .unwrap();

        model
            .step_until_output_contains("Caliptra RT listening for mailbox commands...")
            .unwrap();
    };

    let info = get_fwinfo(&mut model);
    // Verify FW info
    assert_eq!(info.pl0_pauser, 0x1);
    assert_eq!(info.fmc_manifest_svn, 5);
    assert_eq!(info.runtime_svn, 10);
    assert_eq!(info.min_runtime_svn, 10);

    // Make image with newer SVN.
    let mut image_opts20 = image_opts.clone();
    image_opts20.app_svn = 20;

    let image20 =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_opts20)
            .unwrap()
            .to_bytes()
            .unwrap();

    // Trigger an update reset.
    update_to(&mut model, &image20);

    let info = get_fwinfo(&mut model);
    assert_eq!(info.runtime_svn, 20);
    assert_eq!(info.min_runtime_svn, 10);

    // Make image with older SVN.
    let mut image_opts5 = image_opts;
    image_opts5.app_svn = 5;

    let image5 =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_opts5)
            .unwrap()
            .to_bytes()
            .unwrap();

    update_to(&mut model, &image5);
    let info = get_fwinfo(&mut model);
    assert_eq!(info.runtime_svn, 5);
    assert_eq!(info.min_runtime_svn, 5);

    // Go back to SVN 20
    update_to(&mut model, &image20);
    let info = get_fwinfo(&mut model);
    assert_eq!(info.runtime_svn, 20);
    assert_eq!(info.min_runtime_svn, 5);
}

#[test]
fn test_idev_id_info() {
    let mut model = run_rt_test(None, None, None);
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_INFO), &[]),
    };
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_IDEV_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    GetIdevInfoResp::read_from(resp.as_slice()).unwrap();
}
