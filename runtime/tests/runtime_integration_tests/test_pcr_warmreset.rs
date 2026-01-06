// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test_pqc, RuntimeTestArgs};
use caliptra_api::SocManager;
use caliptra_common::{
    checksum::verify_checksum,
    mailbox_api::{
        CommandId, ExtendPcrReq, IncrementPcrResetCounterReq, MailboxReq, MailboxReqHeader,
        MailboxRespHeader, QuotePcrsEcc384Req, QuotePcrsEcc384Resp, QuotePcrsMldsa87Req,
        QuotePcrsMldsa87Resp,
    },
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use openssl::hash::{Hasher, MessageDigest};
use zerocopy::{FromBytes, IntoBytes};

fn ensure_mailbox_idle(model: &mut DefaultHwModel) {
    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());
}

/// Recompute ECC quote digest: first 48 bytes of SHA-512(concat(pcrs) || nonce)
fn recompute_ecc_digest(pcrs: &[[u8; 48]; 32], nonce: &[u8; 32]) -> [u8; 48] {
    let mut h = Hasher::new(MessageDigest::sha512()).unwrap();
    pcrs.iter().for_each(|p| h.update(p).unwrap());
    h.update(nonce).unwrap();
    let res = h.finish().unwrap();
    let bytes = res.as_bytes();
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes[..48]);
    out
}

/// Recompute ML-DSA quote digest: reverse(SHA-512(concat(pcrs) || nonce))
fn recompute_mldsa_digest(pcrs: &[[u8; 48]; 32], nonce: &[u8; 32]) -> [u8; 64] {
    let mut h = Hasher::new(MessageDigest::sha512()).unwrap();
    pcrs.iter().for_each(|p| h.update(p).unwrap());
    h.update(nonce).unwrap();
    let res = h.finish().unwrap();
    let mut out: [u8; 64] = res.as_bytes().try_into().unwrap();
    out.reverse();
    out
}

/// Send QUOTE_PCRS_ECC384, verify FIPS + checksum
fn quote_pcrs_ecc(model: &mut DefaultHwModel) -> QuotePcrsEcc384Resp {
    const NONCE: [u8; 32] = [0xF5; 32];

    let mut req = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: NONCE,
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    // Verify FIPS + checksum (over everything AFTER the chksum field)
    let hdr_resp = QuotePcrsEcc384Resp::read_from_bytes(resp_bytes.as_slice()).unwrap();

    assert!(
        verify_checksum(
            hdr_resp.hdr.chksum,
            0x0,
            &resp_bytes[core::mem::size_of_val(&hdr_resp.hdr.chksum)..],
        ),
        "response checksum invalid"
    );

    assert_eq!(
        hdr_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CERT FIPS not APPROVED"
    );

    hdr_resp
}

/// Send QUOTE_PCRS_MLDSA87, verify FIPS + checksum
fn quote_pcrs_mldsa(model: &mut DefaultHwModel, nonce: [u8; 32]) -> QuotePcrsMldsa87Resp {
    let mut req = MailboxReq::QuotePcrsMldsa87(QuotePcrsMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce,
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_MLDSA87),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    // Verify FIPS + checksum
    let hdr_resp = QuotePcrsMldsa87Resp::read_from_bytes(resp_bytes.as_slice()).unwrap();
    assert!(
        verify_checksum(
            hdr_resp.hdr.chksum,
            0x0,
            &resp_bytes[core::mem::size_of_val(&hdr_resp.hdr.chksum)..],
        ),
        "response checksum invalid"
    );

    assert_eq!(
        hdr_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "CERT FIPS not APPROVED"
    );

    hdr_resp
}

/// Increment a PCR reset counter and verify FIPS + checksum
fn inc_pcr_reset_counter(model: &mut DefaultHwModel, pcr_index: u32) {
    let mut req = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: pcr_index,
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let hdr = MailboxRespHeader::read_from_bytes(resp_bytes.as_slice()).unwrap();

    // Verify FIPS status
    assert_eq!(
        hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "INCREMENT_PCR_RESET_COUNTER is not FIPS approved"
    );

    // Checksum over everything AFTER the chksum field
    let chksum_region = &resp_bytes[core::mem::size_of_val(&hdr.chksum)..];
    assert!(
        verify_checksum(hdr.chksum, 0x0, chksum_region),
        "GetIdevEcc384InfoResp checksum invalid"
    );
}

/// Quote via ECC384 and return the reset counter for `pcr_index`.
fn quote_ecc_get_reset_ctr(model: &mut DefaultHwModel, pcr_index: u32, nonce: [u8; 32]) -> u32 {
    let mut req = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce,
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let resp = QuotePcrsEcc384Resp::read_from_bytes(resp_bytes.as_slice()).unwrap();
    resp.reset_ctrs[pcr_index as usize]
}

/// Quote via ML-DSA-87 and return the reset counter for `pcr_index`.
fn quote_mldsa_get_reset_ctr(model: &mut DefaultHwModel, pcr_index: u32, nonce: [u8; 32]) -> u32 {
    let mut req = MailboxReq::QuotePcrsMldsa87(QuotePcrsMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce,
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_MLDSA87),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let resp = QuotePcrsMldsa87Resp::read_from_bytes(resp_bytes.as_slice()).unwrap();
    resp.reset_ctrs[pcr_index as usize]
}

/// Send EXTEND_PCR and verify FIPS + checksum
fn extend_pcr(model: &mut DefaultHwModel, idx: u32, data: [u8; 48]) {
    let mut req = MailboxReq::ExtendPcr(ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pcr_idx: idx,
        data,
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(u32::from(CommandId::EXTEND_PCR), req.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    // Parse header
    let hdr = MailboxRespHeader::read_from_bytes(resp_bytes.as_slice()).unwrap();

    // FIPS approved
    assert_eq!(
        hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED,
        "EXTEND_PCR not FIPS approved"
    );

    // Verify checksum
    let chksum_region = &resp_bytes[core::mem::size_of::<u32>()..];
    assert!(
        verify_checksum(hdr.chksum, 0x0, chksum_region),
        "EXTEND_PCR response checksum invalid"
    );
}

///  reproduction of a PCR extend: SHA384( current || data )
fn sw_extend(current: &[u8; 48], data: &[u8; 48]) -> [u8; 48] {
    let mut h = Hasher::new(MessageDigest::sha384()).unwrap();
    h.update(current).unwrap();
    h.update(data).unwrap();
    let res = h.finish().unwrap();
    res.as_bytes().try_into().unwrap()
}

#[test]
fn test_quote_pcrs_ecc384_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());
    ensure_mailbox_idle(&mut model);

    // Before warm reset
    let resp_before = quote_pcrs_ecc(&mut model);
    let digest_before = recompute_ecc_digest(&resp_before.pcrs, &resp_before.nonce);
    assert_eq!(resp_before.digest, digest_before);

    // Warm reset
    model.warm_reset_flow().unwrap();

    ensure_mailbox_idle(&mut model);

    // After warm reset
    let resp_after = quote_pcrs_ecc(&mut model);
    let digest_after = recompute_ecc_digest(&resp_after.pcrs, &resp_after.nonce);
    assert_eq!(resp_after.digest, digest_after);

    // Compare PCRs and digest across reset (should be identical if no state changed)
    assert_eq!(
        resp_after.pcrs, resp_before.pcrs,
        "PCRs changed across warm reset"
    );
    assert_eq!(
        digest_after, digest_before,
        "ECC digest changed across warm reset"
    );
}

#[test]
fn test_quote_pcrs_mldsa87_after_warm_reset() {
    const NONCE: [u8; 32] = [0xF5; 32];

    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());
    ensure_mailbox_idle(&mut model);

    // Before warm reset
    let resp_before = quote_pcrs_mldsa(&mut model, NONCE);
    let digest_before = recompute_mldsa_digest(&resp_before.pcrs, &resp_before.nonce);
    assert_eq!(resp_before.digest, digest_before);

    // Warm reset
    model.warm_reset_flow().unwrap();

    ensure_mailbox_idle(&mut model);

    // After warm reset
    let resp_after = quote_pcrs_mldsa(&mut model, NONCE);
    let digest_after = recompute_mldsa_digest(&resp_after.pcrs, &resp_after.nonce);
    assert_eq!(resp_after.digest, digest_after);

    // Compare PCRs and digest across reset (should be identical if no state changed)
    assert_eq!(
        resp_after.pcrs, resp_before.pcrs,
        "PCRs changed across warm reset"
    );
    assert_eq!(
        digest_after, digest_before,
        "ML-DSA digest changed across warm reset"
    );
}

#[test]
fn test_pcr_reset_counter_persists_after_warm_reset_ecc() {
    const RESET_PCR: u32 = 7;
    const NONCE: [u8; 32] = [0xF5; 32];

    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());
    ensure_mailbox_idle(&mut model);

    let base = quote_ecc_get_reset_ctr(&mut model, RESET_PCR, NONCE);

    inc_pcr_reset_counter(&mut model, RESET_PCR);
    let after_inc = quote_ecc_get_reset_ctr(&mut model, RESET_PCR, NONCE);
    assert_eq!(
        after_inc,
        base + 1,
        "counter should be base+1 before warm reset"
    );

    model.warm_reset_flow().unwrap();

    ensure_mailbox_idle(&mut model);

    inc_pcr_reset_counter(&mut model, RESET_PCR);
    let after_reset_inc = quote_ecc_get_reset_ctr(&mut model, RESET_PCR, NONCE);
    assert_eq!(
        after_reset_inc,
        base + 2,
        "counter should persist across warm reset and reach base+2"
    );
}

#[test]
fn test_pcr_reset_counter_persists_after_warm_reset_mldsa() {
    const RESET_PCR: u32 = 7;
    const NONCE: [u8; 32] = [0xF5; 32];

    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());
    ensure_mailbox_idle(&mut model);

    let base = quote_mldsa_get_reset_ctr(&mut model, RESET_PCR, NONCE);

    inc_pcr_reset_counter(&mut model, RESET_PCR);
    let after_inc = quote_mldsa_get_reset_ctr(&mut model, RESET_PCR, NONCE);
    assert_eq!(
        after_inc,
        base + 1,
        "counter should be base+1 before warm reset"
    );

    model.warm_reset_flow().unwrap();

    ensure_mailbox_idle(&mut model);

    inc_pcr_reset_counter(&mut model, RESET_PCR);
    let after_reset_inc = quote_mldsa_get_reset_ctr(&mut model, RESET_PCR, NONCE);
    assert_eq!(
        after_reset_inc,
        base + 2,
        "counter should persist across warm reset and reach base+2"
    );
}

#[test]
fn test_extend_pcr_after_warm_reset() {
    const PCR_INDEX: u32 = 4;
    let extension_data: [u8; 48] = [0u8; 48];

    // Boot and idle
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());
    ensure_mailbox_idle(&mut model);

    // Baseline PCRs (expect zero for a fresh PCR[4])
    let pcrs_before = quote_pcrs_ecc(&mut model).pcrs;
    assert_eq!(
        pcrs_before[PCR_INDEX as usize], [0u8; 48],
        "PCR[4] not zero at baseline"
    );

    // extension
    extend_pcr(&mut model, PCR_INDEX, extension_data);

    // Read back and check against software-extended value
    let pcrs_ext_before = quote_pcrs_ecc(&mut model).pcrs;
    let expected = sw_extend(&[0u8; 48], &extension_data);
    assert_eq!(
        pcrs_ext_before[PCR_INDEX as usize], expected,
        "PCR[4] after extension mismatch"
    );

    // Warm reset + wait ready
    model.warm_reset_flow().unwrap();

    ensure_mailbox_idle(&mut model);

    // Re-read after warm reset: should be identical
    let pcrs_ext_after = quote_pcrs_ecc(&mut model).pcrs;
    assert_eq!(
        pcrs_ext_before, pcrs_ext_after,
        "PCR[4] value did not persist across warm reset"
    );
}
