// Licensed under the Apache-2.0 license

use crate::common::{
    assert_error, check_header_checksum, run_rt_test, CertifyKeyCommandNoRef,
    CreateCertifyKeyCmdArgs, RuntimeTestArgs,
};
use anyhow::anyhow;
use caliptra_api::{
    mailbox::{AxiResponseInfo, CertifyKeyExtendedMldsa87Req},
    SocManager,
};
use caliptra_common::mailbox_api::{
    AddSubjectAltNameReq, CertifyKeyExtendedEcc384Req, CertifyKeyExtendedFlags,
    CertifyKeyExtendedResp, CommandId, MailboxReq, MailboxReqHeader,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_kat::CaliptraError;
use caliptra_runtime::{AddSubjectAltNameCmd, CaliptraDpeProfile, RtBootStatus};
use dpe::{
    commands::Command,
    response::{CertifyKeyResp, Response},
};
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, oid_registry::asn1_rs::FromDer,
};
use zerocopy::IntoBytes;

#[test]
fn test_dmtf_other_name_validation_fail() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let dmtf_device_info_utf8 = "abc:def:ghi:";
    let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
    let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
    let mut cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
        dmtf_device_info,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED,
        resp,
    );
}

fn execute_certify_key_extended_cmd_helper(
    model: &mut impl HwModel,
    profile: CaliptraDpeProfile,
    flags: CertifyKeyExtendedFlags,
    axi_info: Option<AxiResponseInfo>,
) -> anyhow::Result<CertifyKeyResp> {
    let axi_response = axi_info.unwrap_or_default();
    let certify_key_cmd = CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        profile,
        ..Default::default()
    });
    let certify_key_req: [u8; CertifyKeyExtendedEcc384Req::CERTIFY_KEY_REQ_SIZE] =
        certify_key_cmd.as_bytes().try_into().unwrap();
    let external_response = flags.external_axi_response();
    let (cmd_id, mut cmd) = match profile {
        CaliptraDpeProfile::Ecc384 => (
            CommandId::CERTIFY_KEY_EXTENDED_ECC384,
            MailboxReq::CertifyKeyExtendedEcc384(CertifyKeyExtendedEcc384Req {
                hdr: MailboxReqHeader { chksum: 0 },
                certify_key_req,
                flags,
            }),
        ),
        CaliptraDpeProfile::Mldsa87 => (
            CommandId::CERTIFY_KEY_EXTENDED_MLDSA87,
            MailboxReq::CertifyKeyExtendedMldsa87(CertifyKeyExtendedMldsa87Req {
                hdr: MailboxReqHeader { chksum: 0 },
                certify_key_req,
                flags,
                axi_response,
            }),
        ),
    };
    cmd.populate_chksum()
        .map_err(|e| anyhow!("Failed to populate checksum: {:?}", e))?;

    let resp = model
        .mailbox_execute(u32::from(cmd_id), cmd.as_bytes().unwrap())
        .map_err(|e| anyhow!("Failed to execute mailbox command: {:?}", e))?
        .ok_or(anyhow!("Did not receive a response from mailbox command"))?;
    check_header_checksum(&resp)?;

    let mut certify_key_extended_resp = CertifyKeyExtendedResp::default();
    if external_response {
        let resp = model
            .read_payload_from_ss_staging_area(size_of::<CertifyKeyExtendedResp>())
            .unwrap();
        certify_key_extended_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
        check_header_checksum(certify_key_extended_resp.as_bytes_partial().unwrap())?;
    } else {
        assert!(resp.len() <= size_of::<CertifyKeyExtendedResp>());
        certify_key_extended_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    }

    let resp = Response::try_read_from_bytes(
        &Command::from(&certify_key_cmd),
        &certify_key_extended_resp.certify_key_resp,
    )
    .map_err(|e| anyhow!("Failed to parse CertifyKeyP384Resp: {:?}", e))?;
    let Response::CertifyKey(resp) = resp else {
        anyhow::bail!("Wrong response type!");
    };
    Ok(resp)
}

fn execute_certify_key_extended_cmd(
    model: &mut impl HwModel,
    profile: CaliptraDpeProfile,
    flags: CertifyKeyExtendedFlags,
) -> anyhow::Result<CertifyKeyResp> {
    let (flags, axi_info) = if model.subsystem_mode() && profile == CaliptraDpeProfile::Mldsa87 {
        let addr = model.staging_physical_address().unwrap();
        (
            flags | CertifyKeyExtendedFlags::EXTERNAL_AXI_RESPONSE,
            Some(AxiResponseInfo {
                addr_lo: addr as u32,
                addr_hi: (addr >> 32) as u32,
                max_size: size_of::<CertifyKeyExtendedResp>() as u32,
            }),
        )
    } else {
        (flags, None)
    };
    execute_certify_key_extended_cmd_helper(model, profile, flags, axi_info)
}

fn test_dmtf_other_name_extension_present_helper(model: &mut DefaultHwModel) {
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let dmtf_device_info_utf8 = "ChipsAlliance:Caliptra:0123456789";
    let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
    let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
    dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
    let mut cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
        hdr: MailboxReqHeader { chksum: 0 },
        dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
        dmtf_device_info,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    for profile in [CaliptraDpeProfile::Ecc384, CaliptraDpeProfile::Mldsa87] {
        let certify_key_resp = execute_certify_key_extended_cmd(
            model,
            profile,
            CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
        )
        .unwrap();

        let (_, cert) = X509Certificate::from_der(certify_key_resp.cert().unwrap()).unwrap();
        let ext = cert.subject_alternative_name().unwrap().unwrap();
        assert!(!ext.critical);
        let san = ext.value;
        assert_eq!(san.general_names.len(), 1);
        let general_name = san.general_names.first().unwrap();
        match general_name {
            GeneralName::OtherName(oid, other_name_value) => {
                assert_eq!(oid.as_bytes(), AddSubjectAltNameCmd::DMTF_OID);
                // skip first 4 der encoding bytes
                assert_eq!(&other_name_value[4..], dmtf_device_info_bytes);
            }
            _ => panic!("Wrong SubjectAlternativeName"),
        };
    }
}

#[test]
// Same as test_dmtf_other_name_extension_present on subsystem FPGA
#[cfg_attr(feature = "fpga_subsystem", ignore)]
fn test_dmtf_other_name_extension_present() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    test_dmtf_other_name_extension_present_helper(&mut model);
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_dmtf_other_name_extension_present_subsystem() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });
    test_dmtf_other_name_extension_present_helper(&mut model);
}

#[test]
fn test_dmtf_other_name_extension_not_present() {
    for profile in [CaliptraDpeProfile::Ecc384, CaliptraDpeProfile::Mldsa87] {
        let mut model = run_rt_test(RuntimeTestArgs::default());

        model.step_until(|m| {
            m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
        });

        let certify_key_resp = execute_certify_key_extended_cmd(
            &mut model,
            profile,
            CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
        )
        .unwrap();
        let (_, cert) = X509Certificate::from_der(certify_key_resp.cert().unwrap()).unwrap();
        assert!(cert.subject_alternative_name().unwrap().is_none());

        // populate DMTF otherName
        let dmtf_device_info_utf8 = "ChipsAlliance:Caliptra:0123456789";
        let dmtf_device_info_bytes = dmtf_device_info_utf8.as_bytes();
        let mut dmtf_device_info = [0u8; AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN];
        dmtf_device_info[..dmtf_device_info_bytes.len()].copy_from_slice(dmtf_device_info_bytes);
        let mut cmd = MailboxReq::AddSubjectAltName(AddSubjectAltNameReq {
            hdr: MailboxReqHeader { chksum: 0 },
            dmtf_device_info_size: dmtf_device_info_bytes.len() as u32,
            dmtf_device_info,
        });
        cmd.populate_chksum().unwrap();

        let _ = model
            .mailbox_execute(
                u32::from(CommandId::ADD_SUBJECT_ALT_NAME),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");

        // Check that otherName extension is not present if not requested in input flags
        let certify_key_resp =
            execute_certify_key_extended_cmd(&mut model, profile, CertifyKeyExtendedFlags::empty())
                .unwrap();
        let (_, cert) = X509Certificate::from_der(certify_key_resp.cert().unwrap()).unwrap();
        assert!(cert.subject_alternative_name().unwrap().is_none());
    }
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_subsystem_response_buffer_limits() {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });

    // The ML-DSA command should fail because it can easily surpass the size of the mailbox
    let profile = CaliptraDpeProfile::Mldsa87;
    execute_certify_key_extended_cmd_helper(
        &mut model,
        profile,
        CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
        None,
    )
    .unwrap_err();

    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_INTERNAL),
    );

    // Set the AXI size too small to ensure there is an error there too
    let addr = model.staging_physical_address().unwrap();
    execute_certify_key_extended_cmd_helper(
        &mut model,
        profile,
        CertifyKeyExtendedFlags::DMTF_OTHER_NAME,
        Some(AxiResponseInfo {
            addr_lo: addr as u32,
            addr_hi: (addr >> 32) as u32,
            max_size: 16 * 1024,
        }),
    )
    .unwrap_err();

    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::RUNTIME_INTERNAL),
    );
}
