// Licensed under the Apache-2.0 license

use crate::common::PQC_KEY_TYPE;
use crate::common::{
    execute_dpe_cmd, generate_test_x509_cert, get_ecc_fmc_alias_cert, get_mldsa_fmc_alias_cert,
    get_rt_alias_ecc384_cert, get_rt_alias_mldsa87_cert, run_rt_test, run_rt_test_pqc, DpeResult,
    RuntimeTestArgs, TEST_LABEL,
};
use caliptra_builder::firmware::FMC_WITH_UART;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    CommandId, GetIdevCertResp, GetIdevEcc384CertReq, GetIdevEcc384InfoResp, GetIdevMldsa87CertReq,
    GetIdevMldsa87InfoResp, GetLdevCertResp, GetRtAliasCertResp, MailboxReq, MailboxReqHeader,
    StashMeasurementReq,
};
use caliptra_common::x509::get_tbs;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, Fuses, HwModel, InitParams, SubsystemInitParams,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use dpe::{
    commands::{CertifyKeyCmd, CertifyKeyFlags, Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::{CertifyKeyResp, Response},
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private, Public},
    pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant},
    stack::Stack,
    x509::{
        store::X509StoreBuilder, verify::X509VerifyFlags, X509StoreContext, X509VerifyResult, X509,
    },
};
use zerocopy::{FromBytes, IntoBytes};

#[test]
// Check if the owner and vendor cert validity dates are present in RT Alias cert
fn test_rt_cert_with_custom_dates() {
    const VENDOR_CONFIG: (&str, &str) = ("20250101000000Z", "20260101000000Z");
    const OWNER_CONFIG: (&str, &str) = ("20270101000000Z", "20280101000000Z");

    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut opts = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };

        opts.vendor_config
            .not_before
            .copy_from_slice(VENDOR_CONFIG.0.as_bytes());

        opts.vendor_config
            .not_after
            .copy_from_slice(VENDOR_CONFIG.1.as_bytes());

        let mut own_config = opts.owner_config.unwrap();

        own_config
            .not_before
            .copy_from_slice(OWNER_CONFIG.0.as_bytes());
        own_config
            .not_after
            .copy_from_slice(OWNER_CONFIG.1.as_bytes());

        opts.owner_config = Some(own_config);

        let args = RuntimeTestArgs {
            test_image_options: Some(opts),
            ..Default::default()
        };
        let mut model = run_rt_test_pqc(args, *pqc_key_type);

        let payload = MailboxReqHeader {
            chksum: caliptra_common::checksum::calc_checksum(
                u32::from(CommandId::GET_RT_ALIAS_ECC384_CERT),
                &[],
            ),
        };
        let resp = model
            .mailbox_execute(
                u32::from(CommandId::GET_RT_ALIAS_ECC384_CERT),
                payload.as_bytes(),
            )
            .unwrap()
            .unwrap();
        assert!(resp.len() <= std::mem::size_of::<GetRtAliasCertResp>());
        let mut rt_resp = GetRtAliasCertResp::default();
        rt_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

        let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

        let not_before: Asn1Time = Asn1Time::from_str(OWNER_CONFIG.0).unwrap();
        let not_after: Asn1Time = Asn1Time::from_str(OWNER_CONFIG.1).unwrap();

        assert!(rt_cert.not_before() == not_before);
        assert!(rt_cert.not_after() == not_after);
    }
}

#[test]
fn test_idev_id_ecc384_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // generate 48 byte ECDSA key pair
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = PKey::from_ec_key(EcKey::generate(&ec_group).unwrap()).unwrap();

    let cert = generate_test_x509_cert(&ec_key);
    assert!(cert.verify(&ec_key).unwrap());

    // Extract the r and s values of the signature
    let sig_bytes = cert.signature().as_slice();
    let signature = EcdsaSig::from_der(sig_bytes).unwrap();
    let signature_r: [u8; 48] = signature.r().to_vec_padded(48).unwrap().try_into().unwrap();
    let signature_s: [u8; 48] = signature.s().to_vec_padded(48).unwrap().try_into().unwrap();

    // Extract tbs from cert using the derived TBS size
    let tbs = get_tbs(cert.to_der().unwrap());
    let tbs_len = tbs.len();

    let mut req = GetIdevEcc384CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0; GetIdevEcc384CertReq::DATA_MAX_SIZE],
        signature_r,
        signature_s,
        tbs_size: tbs_len as u32,
    };
    req.tbs[..tbs_len].copy_from_slice(&tbs);
    let mut cmd = MailboxReq::GetIdevEcc384Cert(req);
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_ECC384_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We expected a response");

    assert!(resp.len() <= std::mem::size_of::<GetIdevCertResp>());
    let mut cert = GetIdevCertResp::default();
    cert.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    assert!(caliptra_common::checksum::verify_checksum(
        cert.hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&cert.hdr.chksum)..],
    ));

    assert!(tbs_len < cert.data_size as usize);
    let idev_cert = X509::from_der(&cert.data[..cert.data_size as usize]).unwrap();
    assert!(idev_cert.verify(&ec_key).unwrap());
}

#[test]
fn test_idev_id_mldsa87_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Generate MLDSA key pair
    let seed = [0x42u8; 32]; // Use a deterministic seed for testing
    let builder = PKeyMlDsaBuilder::<Private>::from_seed(Variant::MlDsa87, &seed).unwrap();
    let private_key = builder.build().unwrap();

    // Extract public key for verification
    let public_params = PKeyMlDsaParams::<Public>::from_pkey(&private_key).unwrap();
    let public_key = PKeyMlDsaBuilder::<Public>::new(
        Variant::MlDsa87,
        public_params.public_key().unwrap(),
        None,
    )
    .unwrap()
    .build()
    .unwrap();

    let cert = generate_test_x509_cert(&private_key);
    assert!(cert.verify(&public_key).unwrap());

    // Extract signature from cert
    let sig_bytes = cert.signature().as_slice();
    let mut signature = [0u8; 4628];
    signature[..sig_bytes.len()].copy_from_slice(sig_bytes);

    // Extract tbs from cert using the derived TBS size
    let cert_der_vec = cert.to_der().unwrap();
    let tbs_data = get_tbs(cert_der_vec);
    let actual_tbs_size = std::cmp::min(tbs_data.len(), GetIdevMldsa87CertReq::DATA_MAX_SIZE);

    let mut req = GetIdevMldsa87CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0u8; GetIdevMldsa87CertReq::DATA_MAX_SIZE],
        signature,
        tbs_size: actual_tbs_size as u32,
    };
    req.tbs[..actual_tbs_size].copy_from_slice(&tbs_data[..actual_tbs_size]);
    let mut cmd = MailboxReq::GetIdevMldsa87Cert(req);
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_MLDSA87_CERT),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We expected a response");

    assert!(resp.len() <= std::mem::size_of::<GetIdevCertResp>());
    let mut cert = GetIdevCertResp::default();
    cert.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    assert!(caliptra_common::checksum::verify_checksum(
        cert.hdr.chksum,
        0x0,
        &resp[core::mem::size_of_val(&cert.hdr.chksum)..],
    ));

    assert!(actual_tbs_size < cert.data_size as usize);
    let idev_cert = X509::from_der(&cert.data[..cert.data_size as usize]).unwrap();
    assert!(idev_cert.verify(&public_key).unwrap());
}

#[test]
fn test_idev_id_cert_size_too_big() {
    // Test with tbs_size too big.
    let mut cmd = MailboxReq::GetIdevEcc384Cert(GetIdevEcc384CertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: [0u8; GetIdevEcc384CertReq::DATA_MAX_SIZE],
        signature_r: [0u8; 48],
        signature_s: [0u8; 48],
        tbs_size: GetIdevEcc384CertReq::DATA_MAX_SIZE as u32 + 1,
    });
    assert_eq!(
        cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}

fn get_ldev_ecc_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_LDEV_ECC384_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_LDEV_ECC384_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    ldev_resp
}

fn get_ldev_mldsa_cert(model: &mut DefaultHwModel) -> GetLdevCertResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_LDEV_MLDSA87_CERT),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_LDEV_MLDSA87_CERT),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    assert!(resp.len() <= std::mem::size_of::<GetLdevCertResp>());
    let mut ldev_resp = GetLdevCertResp::default();
    ldev_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);
    ldev_resp
}

#[test]
fn test_ldev_ecc384_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let ldev_resp = get_ldev_ecc_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Get IDev public key
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC384_INFO),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_ECC384_INFO),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let idev_resp = GetIdevEcc384InfoResp::read_from_bytes(resp.as_slice()).unwrap();

    // Check the LDevID is signed by IDevID
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let idev_x = &BigNum::from_slice(&idev_resp.idev_pub_x).unwrap();
    let idev_y = &BigNum::from_slice(&idev_resp.idev_pub_y).unwrap();

    let idev_ec_key = EcKey::from_public_key_affine_coordinates(&group, idev_x, idev_y).unwrap();
    assert!(ldev_cert
        .verify(&PKey::from_ec_key(idev_ec_key).unwrap())
        .unwrap());
}

#[test]
fn test_get_ldev_mldsa_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let ldev_resp = get_ldev_mldsa_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    // Get IDev MLDSA public key
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_MLDSA87_INFO),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_MLDSA87_INFO),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let idev_resp = GetIdevMldsa87InfoResp::read_from_bytes(resp.as_slice()).unwrap();

    // Check the LDevID is signed by IDevID
    let idev_public_key =
        PKeyMlDsaBuilder::<Public>::new(Variant::MlDsa87, &idev_resp.idev_pub_key, None)
            .unwrap()
            .build()
            .unwrap();

    assert!(ldev_cert.verify(&idev_public_key).unwrap());
}

#[test]
fn test_fmc_alias_ecc384_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let ldev_resp = get_ldev_ecc_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    let fmc_resp = get_ecc_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    // Check the FMC is signed by LDevID and that subject/issuer names match
    assert!(fmc_cert.verify(&ldev_cert.public_key().unwrap()).unwrap());
    assert_eq!(
        fmc_cert
            .issuer_name()
            .try_cmp(ldev_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_fmc_alias_mldsa87_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let ldev_resp = get_ldev_mldsa_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    let fmc_resp = get_mldsa_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    // Check the FMC is signed by LDevID and that subject/issuer names match
    assert!(fmc_cert.verify(&ldev_cert.public_key().unwrap()).unwrap());
    assert_eq!(
        fmc_cert
            .issuer_name()
            .try_cmp(ldev_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_rt_alias_ecc384_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let fmc_resp = get_ecc_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    let rt_resp = get_rt_alias_ecc384_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // Check that RT Alias is signed by FMC and that subject/issuer names match
    assert!(rt_cert.verify(&fmc_cert.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_cert
            .issuer_name()
            .try_cmp(fmc_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_rt_alias_mldsa87_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let fmc_resp = get_mldsa_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    let rt_resp = get_rt_alias_mldsa87_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // Check that RT Alias is signed by FMC and that subject/issuer names match
    assert!(rt_cert.verify(&fmc_cert.public_key().unwrap()).unwrap());
    assert_eq!(
        rt_cert
            .issuer_name()
            .try_cmp(fmc_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_dpe_leaf_cert() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let rt_resp = get_rt_alias_ecc384_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let dpe_leaf_cert: X509 =
        X509::from_der(&certify_key_resp.cert[..certify_key_resp.cert_size as usize]).unwrap();

    // Check that DPE Leaf Cert is signed by RT alias pub key and that subject/issuer names match
    assert!(dpe_leaf_cert
        .verify(&rt_cert.public_key().unwrap())
        .unwrap());
    assert_eq!(
        dpe_leaf_cert
            .issuer_name()
            .try_cmp(rt_cert.subject_name())
            .unwrap(),
        core::cmp::Ordering::Equal
    );
}

#[test]
fn test_full_cert_chain_ecc384() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let ldev_resp = get_ldev_ecc_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    let fmc_resp = get_ecc_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    let rt_resp = get_rt_alias_ecc384_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // Verify full cert chain
    let mut roots_bldr = X509StoreBuilder::new().unwrap();
    roots_bldr.add_cert(ldev_cert).unwrap();
    roots_bldr
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::PARTIAL_CHAIN)
        .unwrap();
    let roots = roots_bldr.build();
    let mut cert_store = X509StoreContext::new().unwrap();
    let mut chain = Stack::new().unwrap();
    chain.push(fmc_cert).unwrap();
    cert_store
        .init(&roots, &rt_cert, &chain, |c| {
            let success = c.verify_cert().unwrap();
            assert_eq!(c.error(), X509VerifyResult::OK);
            assert!(success);

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_full_cert_chain_mldsa87() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let ldev_resp = get_ldev_mldsa_cert(&mut model);
    let ldev_cert: X509 = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();

    let fmc_resp = get_mldsa_fmc_alias_cert(&mut model);
    let fmc_cert: X509 = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();

    let rt_resp = get_rt_alias_mldsa87_cert(&mut model);
    let rt_cert: X509 = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();

    // Verify full cert chain
    let mut roots_bldr = X509StoreBuilder::new().unwrap();
    roots_bldr.add_cert(ldev_cert).unwrap();
    roots_bldr
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::PARTIAL_CHAIN)
        .unwrap();
    let roots = roots_bldr.build();
    let mut cert_store = X509StoreContext::new().unwrap();
    let mut chain = Stack::new().unwrap();
    chain.push(fmc_cert).unwrap();
    cert_store
        .init(&roots, &rt_cert, &chain, |c| {
            let success = c.verify_cert().unwrap();
            assert_eq!(c.error(), X509VerifyResult::OK);
            assert!(success);

            Ok(())
        })
        .unwrap();
}

fn get_dpe_leaf_cert(model: &mut DefaultHwModel) -> CertifyKeyResp {
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        model,
        &mut Command::CertifyKey(&certify_key_cmd),
        DpeResult::Success,
    );
    let Some(Response::CertifyKey(certify_key_resp)) = resp else {
        panic!("Wrong response type!");
    };
    certify_key_resp
}

// Helper for cold reset compatible with SW emulator
// NOTE: Assumes all other boot and init params are default except for ROM and FW image
fn cold_reset(
    mut hw: DefaultHwModel,
    rom: &[u8],
    fw_image: &[u8],
    pqc_key_type: FwVerificationPqcKeyType,
) -> DefaultHwModel {
    if cfg!(any(
        feature = "fpga_realtime",
        feature = "verilator",
        feature = "fpga_subsystem"
    )) {
        // Re-creating the model does not seem to work for FPGA (and SW emulator cannot cold reset)
        hw.cold_reset();
    } else {
        hw = caliptra_hw_model::new_unbooted(InitParams {
            rom,
            ..Default::default()
        })
        .unwrap();
    }
    let fuses = Fuses {
        fuse_pqc_key_type: pqc_key_type as u32,
        ..Default::default()
    };
    hw.boot(BootParams {
        fw_image: Some(fw_image),
        fuses,
        ..Default::default()
    })
    .unwrap();
    hw
}

// Provide a measurement to Caliptra using each of the 3 methods
//      1. Stash measurement at ROM
//      2. Stash measurement at runtime
//      3. DPE derive context (at runtime)
// Confirm the resulting DPE leaf cert is identical in all three cases
#[test]
#[allow(dead_code)]
pub fn test_all_measurement_apis() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        // Shared inputs for all 3 methods
        let measurement: [u8; 48] = core::array::from_fn(|i| (i + 1) as u8);
        let tci_type: [u8; 4] = [101, 102, 103, 104];
        let rom =
            caliptra_builder::rom_for_fw_integration_tests_fpga(cfg!(feature = "fpga_subsystem"))
                .unwrap();
        let rt_fwid = crate::common::default_rt_fwid();
        let fw_image =
            caliptra_builder::build_and_sign_image(&FMC_WITH_UART, rt_fwid, image_options)
                .unwrap()
                .to_bytes()
                .unwrap();

        //
        // 1. ROM STASH MEASUREMENT
        //      Stash a measurement, boot to runtime, then get the DPE cert
        //      Start with a fresh cold boot for each method
        //
        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };
        let mut hw = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ss_init_params: SubsystemInitParams {
                    enable_mcu_uart_log: cfg!(feature = "fpga_subsystem"),
                    ..Default::default()
                },
                ..Default::default()
            },
            BootParams {
                fuses,
                ..Default::default()
            },
        )
        .unwrap();

        // Send the stash measurement command
        let mut stash_measurement_payload = MailboxReq::StashMeasurement(StashMeasurementReq {
            hdr: MailboxReqHeader {
                chksum: caliptra_common::checksum::calc_checksum(
                    u32::from(CommandId::STASH_MEASUREMENT),
                    &[],
                ),
            },
            metadata: tci_type.as_bytes().try_into().unwrap(),
            measurement,
            ..Default::default()
        });
        stash_measurement_payload.populate_chksum().unwrap();
        let _resp = hw
            .mailbox_execute(
                u32::from(CommandId::STASH_MEASUREMENT),
                stash_measurement_payload.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();

        // Get to runtime
        crate::common::test_upload_firmware(&mut hw, &fw_image, *pqc_key_type);
        crate::common::wait_for_runtime(&mut hw);

        // Get DPE cert
        let dpe_cert_resp = get_dpe_leaf_cert(&mut hw);
        let rom_stash_dpe_cert = &dpe_cert_resp.cert[..dpe_cert_resp.cert_size as usize];

        //
        // 2. RUNTIME STASH MEASUREMENT
        //      Boot to runtime, stash a measurement, then get the DPE cert
        //      Start with a fresh cold boot for each method
        //
        hw = cold_reset(hw, &rom, &fw_image, *pqc_key_type);

        // Send the stash measurement command
        let _resp = hw
            .mailbox_execute(
                u32::from(CommandId::STASH_MEASUREMENT),
                stash_measurement_payload.as_bytes().unwrap(),
            )
            .unwrap()
            .unwrap();

        // Get DPE cert
        let dpe_cert_resp = get_dpe_leaf_cert(&mut hw);
        let rt_stash_dpe_cert = &dpe_cert_resp.cert[..dpe_cert_resp.cert_size as usize];

        //
        // 3. DPE DERIVE CONTEXT
        //      Boot to runtime, perform DPE derive context, then get the DPE cert
        //      Start with a fresh cold boot for each method
        //
        hw = cold_reset(hw, &rom, &fw_image, *pqc_key_type);

        // Send derive context call
        let derive_context_cmd = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: measurement,
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::INPUT_ALLOW_CA
                | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: u32::read_from_bytes(&tci_type[..]).unwrap(),
            target_locality: 0,
        };
        let resp = execute_dpe_cmd(
            &mut hw,
            &mut Command::DeriveContext(&derive_context_cmd),
            DpeResult::Success,
        );
        let Some(Response::DeriveContext(_derive_ctx_resp)) = resp else {
            panic!("Wrong response type!");
        };

        // Get DPE cert
        let dpe_cert_resp = get_dpe_leaf_cert(&mut hw);
        let derive_context_dpe_cert = &dpe_cert_resp.cert[..dpe_cert_resp.cert_size as usize];

        //
        // COMPARE CERTS
        // Certs should be exactly the same regardless of method
        //
        assert_eq!(rom_stash_dpe_cert, rt_stash_dpe_cert);
        assert_eq!(rom_stash_dpe_cert, derive_context_dpe_cert);
    }
}
