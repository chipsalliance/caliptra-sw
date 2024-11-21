// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::{get_ci_rom_version, CiRomVersion};
use caliptra_common::mailbox_api::{CommandId, GetIdevCsrResp, MailboxReqHeader};
use caliptra_drivers::{Ecc384IdevIdCsr, MfgFlags};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use openssl::x509::X509Req;
use zerocopy::{AsBytes, FromBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_csr() {
    // `run_rt_test` is responsibly for clearing the CSR bit.
    // Caliptra will wait until the CSR bit is cleared during startup.
    let args = RuntimeTestArgs {
        test_mfg_flags: Some(MfgFlags::GENERATE_IDEVID_CSR),
        ..Default::default()
    };
    let mut model = run_rt_test(args);

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CSR), &[]),
    };

    let result = model.mailbox_execute(CommandId::GET_IDEV_CSR.into(), payload.as_bytes());

    match get_ci_rom_version() {
        CiRomVersion::Latest => {
            let response = result.unwrap().unwrap();

            let get_idv_csr_resp = GetIdevCsrResp::read_from(response.as_bytes()).unwrap();
            assert_ne!(
                Ecc384IdevIdCsr::UNPROVISIONED_CSR,
                get_idv_csr_resp.data_size
            );
            assert_ne!(0, get_idv_csr_resp.data_size);

            let csr_bytes = &get_idv_csr_resp.data[..get_idv_csr_resp.data_size as usize];
            assert_ne!([0; 512], csr_bytes);

            assert!(X509Req::from_der(csr_bytes).is_ok());
        }
    };
}

#[test]
fn test_missing_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CSR), &[]),
    };

    let response = model
        .mailbox_execute(CommandId::GET_IDEV_CSR.into(), payload.as_bytes())
        .unwrap_err();

    match get_ci_rom_version() {
        CiRomVersion::Latest => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED.into())
        ),
    };
}
