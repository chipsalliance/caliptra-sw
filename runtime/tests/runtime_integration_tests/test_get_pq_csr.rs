// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{
    CommandId, GetPqCsrResp, MailboxReq, MailboxReqHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use openssl::x509::X509Req;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{assert_error, run_pqc_rt_test};

fn get_pq_csr_checksum() -> u32 {
    caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_PQ_CSR), &[])
}

/// Provision the PQ.DevID seed (as PL0) so that PQC mode is enabled and
/// GET_PQ_CSR can produce a CSR.
fn provision_pq_seed(model: &mut caliptra_hw_model::DefaultHwModel) {
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap();
}

/// Error path: PQC mode has not been initialized (no SET_PQ_SEED). The request
/// itself is well-formed, so the command-specific guard is what rejects it.
#[test]
fn test_get_pq_csr_not_initialized() {
    let mut model = run_pqc_rt_test();

    let payload = MailboxReqHeader {
        chksum: get_pq_csr_checksum(),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), payload.as_bytes())
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_PQC_NOT_INITIALIZED, resp);
}

/// Error path: the request header carries an invalid checksum.
#[test]
fn test_get_pq_csr_invalid_checksum() {
    let mut model = run_pqc_rt_test();

    // Corrupt an otherwise-valid checksum.
    let payload = MailboxReqHeader {
        chksum: get_pq_csr_checksum().wrapping_add(1),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), payload.as_bytes())
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_INVALID_CHECKSUM, resp);
}

/// Error path: the request is larger than the (header-only) GET_PQ_CSR request,
/// so the mailbox rejects it before dispatch.
#[test]
fn test_get_pq_csr_request_too_large() {
    let mut model = run_pqc_rt_test();

    // GET_PQ_CSR takes only a MailboxReqHeader; send extra words to overflow it.
    let payload = [0u8; core::mem::size_of::<MailboxReqHeader>() + 4];

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), &payload)
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_INSUFFICIENT_MEMORY, resp);
}

/// Happy path: with PQC mode enabled, GET_PQ_CSR returns a DER-encoded ML-DSA-87
/// CSR that parses, self-verifies, and is reproducible across calls.
#[test]
fn test_get_pq_csr_success() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let payload = MailboxReqHeader {
        chksum: get_pq_csr_checksum(),
    };

    let response = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), payload.as_bytes())
        .unwrap()
        .unwrap();

    let csr_resp = GetPqCsrResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert_ne!(0, csr_resp.data_size);
    let csr_bytes = &csr_resp.data[..csr_resp.data_size as usize];

    // Parses as a CSR and its signature verifies against the embedded key.
    let req = X509Req::from_der(csr_bytes).unwrap();
    let pub_key = req.public_key().unwrap();
    assert!(req.verify(&pub_key).unwrap());

    // Deterministic: regenerating from the same CDI yields the identical CSR.
    let response2 = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CSR), payload.as_bytes())
        .unwrap()
        .unwrap();
    let csr_resp2 = GetPqCsrResp::ref_from_bytes(response2.as_bytes()).unwrap();
    assert_eq!(
        csr_bytes,
        &csr_resp2.data[..csr_resp2.data_size as usize],
        "GET_PQ_CSR should be deterministic across calls"
    );
}
