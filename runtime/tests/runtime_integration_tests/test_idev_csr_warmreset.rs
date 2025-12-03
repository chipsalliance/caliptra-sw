use crate::common::{run_rt_test_pqc, RuntimeTestArgs};

use caliptra_builder::{get_ci_rom_version, CiRomVersion};

use caliptra_common::mailbox_api::{
    CommandId, GetIdevCsrResp, MailboxReqHeader, MailboxRespHeader,
};

use caliptra_drivers::{Ecc384IdevIdCsr, MfgFlags, Mldsa87IdevIdCsr};

use caliptra_hw_model::{DefaultHwModel, HwModel};

use openssl::x509::X509Req;

use zerocopy::IntoBytes;

use caliptra_image_types::FwVerificationPqcKeyType;

pub fn build_model_ready_with_csrbit() -> DefaultHwModel {
    // Request IDEVID CSR generation via manufacturing flags.
    let args = RuntimeTestArgs {
        test_mfg_flags: Some(MfgFlags::GENERATE_IDEVID_CSR),
        // successful_reach_rt: true,
        // production_state: Some(RuntimeProductionArgs { ... }),
        ..Default::default()
    };

    run_rt_test_pqc(args, FwVerificationPqcKeyType::LMS)
}

// -------------------------------------------------------------
// Helper: fetch IDEVID CSR via mailbox, validate response header,
//          FIPS Approved, checksum, CSR structure
// -------------------------------------------------------------
fn get_idev_csr_bytes(model: &mut DefaultHwModel) -> Vec<u8> {
    // Build request header with checksum over empty payload
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_ECC384_CSR),
            &[],
        ),
    };

    // Execute GET_IDEV_ECC384_CSR
    let response_bytes = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_ECC384_CSR),
            payload.as_bytes(),
        )
        .unwrap()
        .expect("GET_IDEV_ECC384_CSR should return a response");

    // Copy raw bytes into typed response container
    let mut csr_resp = GetIdevCsrResp::default();
    csr_resp.as_mut_bytes()[..response_bytes.len()].copy_from_slice(&response_bytes);

    //  FIPS / checksum validation

    assert!(caliptra_common::checksum::verify_checksum(
        csr_resp.hdr.chksum,
        0x0,
        &response_bytes[core::mem::size_of_val(&csr_resp.hdr.chksum)..],
    ));
    assert_eq!(
        csr_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "FIPS status for GET_IDEV_ECC384_CSR was not Approved"
    );

    // CSR must be provisioned and non-empty
    assert_ne!(
        csr_resp.data_size,
        Ecc384IdevIdCsr::UNPROVISIONED_CSR,
        "IDEVID CSR is still marked unprovisioned"
    );
    assert_ne!(csr_resp.data_size, 0, "CSR data_size is 0");

    let csr_len = csr_resp.data_size as usize;
    let csr_bytes = &csr_resp.data[..csr_len];

    // CSR content shouldn't just be zero padding
    assert_ne!(
        csr_bytes,
        &[0u8; 512][..csr_len],
        "CSR buffer unexpectedly all zeros"
    );

    // CSR must parse as a valid PKCS#10 CSR (DER-encoded X.509 certificate request)
    X509Req::from_der(csr_bytes).expect("CSR bytes are not a valid DER-encoded X509Req");

    // Return the DER CSR bytes
    csr_bytes.to_vec()
}

// -------------------------------------------------------------
// Helper: fetch ML-DSA87 IDEVID CSR, validate header/FIPS/checksum,
// ensure CSR is valid and provisioned, and return CSR bytes.
// -------------------------------------------------------------
fn get_idev_mldsa87_csr_bytes(model: &mut DefaultHwModel) -> Vec<u8> {
    // Build request header with checksum over empty payload
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_IDEV_MLDSA87_CSR),
            &[],
        ),
    };

    // Execute GET_IDEV_MLDSA87_CSR
    let response_bytes = model
        .mailbox_execute(
            u32::from(CommandId::GET_IDEV_MLDSA87_CSR),
            payload.as_bytes(),
        )
        .unwrap()
        .expect("GET_IDEV_MLDSA87_CSR should return a response");

    // Copy raw bytes into typed response buffer
    let mut csr_resp = GetIdevCsrResp::default();
    csr_resp.as_mut_bytes()[..response_bytes.len()].copy_from_slice(&response_bytes);

    //  FIPS / checksum validation

    assert!(caliptra_common::checksum::verify_checksum(
        csr_resp.hdr.chksum,
        0x0,
        &response_bytes[core::mem::size_of_val(&csr_resp.hdr.chksum)..],
    ));
    assert_eq!(
        csr_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "FIPS status for GET_IDEV_MLDSA87_CSR was not Approved"
    );

    // CSR content validation

    assert_ne!(
        csr_resp.data_size,
        Mldsa87IdevIdCsr::UNPROVISIONED_CSR,
        "MLDSA87 IDEVID CSR is still marked unprovisioned"
    );
    assert_ne!(csr_resp.data_size, 0, "CSR data_size is 0");

    let csr_len = csr_resp.data_size as usize;
    let csr_bytes = &csr_resp.data[..csr_len];

    let all_zero = vec![0u8; csr_len];
    assert_ne!(
        csr_bytes,
        &all_zero[..],
        "CSR buffer unexpectedly all zeros"
    );

    // CSR must parse as DER-encoded PKCS#10 request
    X509Req::from_der(csr_bytes).expect("MLDSA87 CSR bytes are not a valid DER-encoded X509Req");

    csr_bytes.to_vec()
}

/// Fetch the FMC alias ECC384 CSR once from the running model.
/// Returns the CSR bytes as a Vec<u8>.
pub fn get_fmc_alias_ecc384_csr_once(model: &mut DefaultHwModel) -> Vec<u8> {
    // Build mailbox request header with checksum
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_ECC384_CSR),
            &[],
        ),
    };

    // Send mailbox command
    let raw_rsp = model
        .mailbox_execute(
            CommandId::GET_FMC_ALIAS_ECC384_CSR.into(),
            payload.as_bytes(),
        )
        .expect("mailbox_execute failed for GET_FMC_ALIAS_ECC384_CSR")
        .expect("GET_FMC_ALIAS_ECC384_CSR returned mailbox error");

    // Interpret response buffer
    let mut csr_resp = GetIdevCsrResp::default();
    assert!(
        raw_rsp.len() <= csr_resp.as_mut_bytes().len(),
        "firmware response too large ({} bytes) for CSR struct {} bytes",
        raw_rsp.len(),
        csr_resp.as_mut_bytes().len()
    );
    csr_resp.as_mut_bytes()[..raw_rsp.len()].copy_from_slice(&raw_rsp);

    // Basic sanity on length
    let csr_len = csr_resp.data_size as usize;
    assert_ne!(
        csr_len, 0,
        "FMC alias ECC384 CSR length was zero (unprovisioned?)"
    );
    assert!(
        csr_len <= csr_resp.data.len(),
        "CSR length {} exceeds buffer {}",
        csr_len,
        csr_resp.data.len()
    );

    // Slice out the real CSR payload
    let csr_bytes = &csr_resp.data[..csr_len];

    // Must not just be all zeros
    assert_ne!(
        csr_bytes,
        &[0u8; 512][..csr_len.min(512)],
        "FMC alias ECC384 CSR buffer unexpectedly all zeros"
    );

    // Parse as PKCS#10 CSR
    let _csr =
        X509Req::from_der(csr_bytes).expect("FMC alias ECC384 CSR is not valid DER / not a CSR");

    // Return owned Vec so caller can compare before/after warm reset
    csr_bytes.to_vec()
}

/// Fetch the FMC alias ML-DSA87 CSR once from the running model.
/// Returns the CSR bytes .
pub fn get_fmc_alias_mldsa87_csr_once(model: &mut DefaultHwModel) -> Vec<u8> {
    // Build mailbox request header with checksum
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_MLDSA87_CSR),
            &[],
        ),
    };

    // Send mailbox command
    let raw_rsp = model
        .mailbox_execute(
            CommandId::GET_FMC_ALIAS_MLDSA87_CSR.into(),
            payload.as_bytes(),
        )
        .expect("mailbox_execute failed for GET_FMC_ALIAS_MLDSA87_CSR")
        .expect("GET_FMC_ALIAS_MLDSA87_CSR returned mailbox error");

    // Interpret response buffer
    let mut csr_resp = GetIdevCsrResp::default();
    assert!(
        raw_rsp.len() <= csr_resp.as_mut_bytes().len(),
        "firmware response too large ({} bytes) for CSR struct {} bytes",
        raw_rsp.len(),
        csr_resp.as_mut_bytes().len()
    );
    csr_resp.as_mut_bytes()[..raw_rsp.len()].copy_from_slice(&raw_rsp);

    // Basic sanity on length
    let csr_len = csr_resp.data_size as usize;
    assert_ne!(
        csr_len, 0,
        "FMC alias MLDSA87 CSR length was zero (unprovisioned?)"
    );
    assert!(
        csr_len <= csr_resp.data.len(),
        "CSR length {} exceeds buffer {}",
        csr_len,
        csr_resp.data.len()
    );

    // Slice out the real CSR payload
    let csr_bytes = &csr_resp.data[..csr_len];

    // Must not just be all zeros
    assert_ne!(
        csr_bytes,
        &[0u8; 512][..csr_len.min(512)],
        "FMC alias MLDSA87 CSR buffer unexpectedly all zeros"
    );

    // Parse as PKCS#10 CSR
    let _csr =
        X509Req::from_der(csr_bytes).expect("FMC alias MLDSA87 CSR is not valid DER / not a CSR");

    csr_bytes.to_vec()
}

#[test]
fn test_get_idev_ecc384_csr_after_warm_reset() {
    // Boot runtime
    let mut model = build_model_ready_with_csrbit();

    // Read CSR before warm reset
    let csr_before = match get_ci_rom_version() {
        CiRomVersion::Latest => get_idev_csr_bytes(&mut model),
    };

    // Warm reset & wait ready
    model.warm_reset_flow().unwrap();

    // Read CSR after warm reset
    let csr_after = match get_ci_rom_version() {
        CiRomVersion::Latest => get_idev_csr_bytes(&mut model),
    };

    // CSR should not change across warm reset
    assert_eq!(
        csr_after, csr_before,
        "IDEVID CSR changed across warm reset"
    );
}

#[test]
fn test_get_idev_mldsa87_csr_after_warm_reset() {
    // Boot runtime
    let mut model = build_model_ready_with_csrbit();

    // Capture CSR before warm reset
    let csr_before = match get_ci_rom_version() {
        CiRomVersion::Latest => get_idev_mldsa87_csr_bytes(&mut model),
    };

    // Warm reset & wait ready again
    model.warm_reset_flow().unwrap();

    // Capture CSR after warm reset
    let csr_after = match get_ci_rom_version() {
        CiRomVersion::Latest => get_idev_mldsa87_csr_bytes(&mut model),
    };

    // CSR should remain unchanged across warm reset
    assert_eq!(
        csr_after, csr_before,
        "MLDSA87 IDEVID CSR changed across warm reset"
    );
}

/// Warm reset test for GET_FMC_ALIAS_ECC384_CSR.
#[test]
fn test_get_fmc_alias_ecc384_csr_after_warm_reset() {
    // Boot model
    let mut model = build_model_ready_with_csrbit();

    // Issue CSR request before warm reset
    let csr_before = get_fmc_alias_ecc384_csr_once(&mut model);
    // Warm reset & wait ready
    model.warm_reset_flow().unwrap();

    // Issue CSR request after warm reset
    let csr_after = get_fmc_alias_ecc384_csr_once(&mut model);

    // Both CSRs must be non-empty and parseable (already asserted in helper).
    assert!(
        !csr_before.is_empty(),
        "ECC384 FMC alias CSR before warm reset was empty"
    );
    assert!(
        !csr_after.is_empty(),
        "ECC384 FMC alias CSR after warm reset was empty"
    );

    assert_eq!(
        csr_after, csr_before,
        "ECC384 FMC alias CSR changed across warm reset"
    );
}

/// Warm reset test for GET_FMC_ALIAS_MLDSA87_CSR.
#[test]
fn test_get_fmc_alias_mldsa87_csr_after_warm_reset() {
    // Boot model
    let mut model = build_model_ready_with_csrbit();

    // Issue CSR request before warm reset
    let csr_before = get_fmc_alias_mldsa87_csr_once(&mut model);
    // Warm reset & wait ready
    model.warm_reset_flow().unwrap();

    // Issue CSR request after warm reset
    let csr_after = get_fmc_alias_mldsa87_csr_once(&mut model);

    assert!(
        !csr_before.is_empty(),
        "MLDSA87 FMC alias CSR before warm reset was empty"
    );
    assert!(
        !csr_after.is_empty(),
        "MLDSA87 FMC alias CSR after warm reset was empty"
    );

    assert_eq!(
        csr_after, csr_before,
        "MLDSA87 FMC alias CSR changed across warm reset"
    );
}
