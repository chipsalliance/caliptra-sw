/*++

Licensed under the Apache-2.0 license.

File Name:

    uds_programming.rs

Abstract:

    File contains the implementation of UDS programming flow test.
--*/

use caliptra_api::{
    mailbox::{MailboxReqHeader, ZeroizeUdsFeReq, ZeroizeUdsFeResp, ZEROIZE_UDS_FLAG},
    SocManager,
};
use caliptra_builder::firmware::{self};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DbgManufServiceRegReq, DeviceLifecycle, HwModel, SecurityState};
use zerocopy::{FromBytes, IntoBytes};

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_programming_no_active_mode() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_uds_program_req(true);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            subsystem_mode: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Verify fatal code is correct
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_UDS_PROG_IN_PASSIVE_MODE)
    );
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_programming_granularity_64bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_uds_program_req(true);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Wait for ROM to complete
    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_service_reg_rsp().read();
        resp.uds_program_success()
    });

    let config_val = hw.soc_ifc().cptra_generic_input_wires().read()[0];
    assert_eq!((config_val >> 31) & 1, 0);
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_programming_granularity_32bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let dbg_manuf_service = *DbgManufServiceRegReq::default().set_uds_program_req(true);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            dbg_manuf_service,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Wait for ROM to complete
    hw.step_until(|m| {
        let resp = m.soc_ifc().ss_dbg_service_reg_rsp().read();
        resp.uds_program_success()
    });

    let config_val = hw.soc_ifc().cptra_generic_input_wires().read()[0];
    assert_eq!((config_val >> 31) & 1, 1);
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_zeroization_64bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Prepare ZEROIZE_UDS_FE command to zeroize UDS partition (flag 0x01)
    let mut cmd = ZeroizeUdsFeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: ZEROIZE_UDS_FLAG,
    };

    // Calculate checksum
    let chksum_size = core::mem::size_of_val(&cmd.hdr.chksum);
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE),
        &cmd.as_mut_bytes()[chksum_size..],
    );

    // Execute mailbox command
    let response = hw
        .mailbox_execute(
            caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE.into(),
            cmd.as_bytes(),
        )
        .unwrap()
        .unwrap();

    // Parse response
    let resp = ZeroizeUdsFeResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        resp.hdr.chksum,
        0x0,
        &response.as_bytes()[core::mem::size_of_val(&resp.hdr.chksum)..],
    ));

    // Verify DPE result indicates success
    assert_eq!(resp.dpe_result, 0); // DPE_STATUS_SUCCESS
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_uds_zeroization_32bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Prepare ZEROIZE_UDS_FE command to zeroize UDS partition (flag 0x01)
    let mut cmd = ZeroizeUdsFeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: ZEROIZE_UDS_FLAG,
    };

    // Calculate checksum
    let chksum_size = core::mem::size_of_val(&cmd.hdr.chksum);
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE),
        &cmd.as_mut_bytes()[chksum_size..],
    );

    // Execute mailbox command
    let response = hw
        .mailbox_execute(
            caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE.into(),
            cmd.as_bytes(),
        )
        .unwrap()
        .unwrap();

    // Parse response
    let resp = ZeroizeUdsFeResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        resp.hdr.chksum,
        0x0,
        &response.as_bytes()[core::mem::size_of_val(&resp.hdr.chksum)..],
    ));

    // Verify DPE result indicates success
    assert_eq!(resp.dpe_result, 0); // DPE_STATUS_SUCCESS
}

#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_zeroize_fe_partitions_one_at_a_time_64bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // FE partition flags in order: FE0, FE1, FE2, FE3
    let fe_flags = [
        caliptra_api::mailbox::ZEROIZE_FE0_FLAG,
        caliptra_api::mailbox::ZEROIZE_FE1_FLAG,
        caliptra_api::mailbox::ZEROIZE_FE2_FLAG,
        caliptra_api::mailbox::ZEROIZE_FE3_FLAG,
    ];

    // Loop through and zeroize each FE partition one at a time
    for (partition_num, &flag) in fe_flags.iter().enumerate() {
        println!("Zeroizing FE partition {}", partition_num);

        // Prepare ZEROIZE_UDS_FE command for this partition
        let mut cmd = ZeroizeUdsFeReq {
            hdr: MailboxReqHeader { chksum: 0 },
            flags: flag,
        };

        // Calculate checksum
        let chksum_size = core::mem::size_of_val(&cmd.hdr.chksum);
        cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
            u32::from(caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE),
            &cmd.as_mut_bytes()[chksum_size..],
        );

        // Execute mailbox command
        let response = hw
            .mailbox_execute(
                caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE.into(),
                cmd.as_bytes(),
            )
            .unwrap()
            .unwrap();

        // Parse response
        let resp = ZeroizeUdsFeResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(
            caliptra_common::checksum::verify_checksum(
                resp.hdr.chksum,
                0x0,
                &response.as_bytes()[core::mem::size_of_val(&resp.hdr.chksum)..],
            ),
            "Checksum verification failed for FE partition {}",
            partition_num
        );

        // Verify DPE result indicates success
        assert_eq!(
            resp.dpe_result, 0,
            "DPE result failed for FE partition {}",
            partition_num
        );

        println!("Successfully zeroized FE partition {}", partition_num);
    }
}


#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_zeroize_fe_partitions_one_at_a_time_32bit() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: false,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // FE partition flags in order: FE0, FE1, FE2, FE3
    let fe_flags = [
        caliptra_api::mailbox::ZEROIZE_FE0_FLAG,
        caliptra_api::mailbox::ZEROIZE_FE1_FLAG,
        caliptra_api::mailbox::ZEROIZE_FE2_FLAG,
        caliptra_api::mailbox::ZEROIZE_FE3_FLAG,
    ];

    // Loop through and zeroize each FE partition one at a time
    for (partition_num, &flag) in fe_flags.iter().enumerate() {
        println!("Zeroizing FE partition {}", partition_num);

        // Prepare ZEROIZE_UDS_FE command for this partition
        let mut cmd = ZeroizeUdsFeReq {
            hdr: MailboxReqHeader { chksum: 0 },
            flags: flag,
        };

        // Calculate checksum
        let chksum_size = core::mem::size_of_val(&cmd.hdr.chksum);
        cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
            u32::from(caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE),
            &cmd.as_mut_bytes()[chksum_size..],
        );

        // Execute mailbox command
        let response = hw
            .mailbox_execute(
                caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE.into(),
                cmd.as_bytes(),
            )
            .unwrap()
            .unwrap();

        // Parse response
        let resp = ZeroizeUdsFeResp::ref_from_bytes(response.as_bytes()).unwrap();

        // Verify response checksum
        assert!(
            caliptra_common::checksum::verify_checksum(
                resp.hdr.chksum,
                0x0,
                &response.as_bytes()[core::mem::size_of_val(&resp.hdr.chksum)..],
            ),
            "Checksum verification failed for FE partition {}",
            partition_num
        );

        // Verify DPE result indicates success
        assert_eq!(
            resp.dpe_result, 0,
            "DPE result failed for FE partition {}",
            partition_num
        );

        println!("Successfully zeroized FE partition {}", partition_num);
    }
}


#[cfg_attr(feature = "fpga_realtime", ignore)] // No fuse controller in FPGA without MCI
#[test]
fn test_zeroize_all_partitions_single_shot() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing);
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env_fpga(cfg!(
        feature = "fpga_subsystem"
    )))
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        caliptra_hw_model::InitParams {
            rom: &rom,
            security_state,
            subsystem_mode: true,
            uds_fuse_row_granularity_64: true,
            ..Default::default()
        },
        caliptra_hw_model::BootParams::default(),
    )
    .unwrap();

    // Prepare ZEROIZE_UDS_FE command to zeroize all partitions in a single shot
    // UDS (0x01) + FE0 (0x02) + FE1 (0x04) + FE2 (0x08) + FE3 (0x10) = 0x1F
    let all_flags = caliptra_api::mailbox::ZEROIZE_UDS_FLAG
        | caliptra_api::mailbox::ZEROIZE_FE0_FLAG
        | caliptra_api::mailbox::ZEROIZE_FE1_FLAG
        | caliptra_api::mailbox::ZEROIZE_FE2_FLAG
        | caliptra_api::mailbox::ZEROIZE_FE3_FLAG;

    let mut cmd = ZeroizeUdsFeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        flags: all_flags,
    };

    // Calculate checksum
    let chksum_size = core::mem::size_of_val(&cmd.hdr.chksum);
    cmd.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE),
        &cmd.as_mut_bytes()[chksum_size..],
    );

    // Execute mailbox command to zeroize all partitions at once
    let response = hw
        .mailbox_execute(
            caliptra_common::mailbox_api::CommandId::ZEROIZE_UDS_FE.into(),
            cmd.as_bytes(),
        )
        .unwrap()
        .unwrap();

    // Parse response
    let resp = ZeroizeUdsFeResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        resp.hdr.chksum,
        0x0,
        &response.as_bytes()[core::mem::size_of_val(&resp.hdr.chksum)..],
    ));

    // Verify DPE result indicates success
    assert_eq!(resp.dpe_result, 0); // DPE_STATUS_SUCCESS
}

