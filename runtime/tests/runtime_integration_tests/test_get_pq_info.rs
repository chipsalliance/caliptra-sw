// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{
    CommandId, GetPqInfoResp, MailboxReq, MailboxReqHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_mldsa::MLDSA87_PUBLIC_KEY_BYTES;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant as MlDsaVariant};
use openssl::sign::Signer;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{assert_error, run_pqc_rt_test};

/// Seed provisioned via SET_PQ_SEED in these tests.
const PQ_SEED: [u8; SET_PQ_SEED_SEED_SIZE] = [0x5a; SET_PQ_SEED_SEED_SIZE];

fn get_pq_info_checksum() -> u32 {
    caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_PQ_INFO), &[])
}

/// Provision the PQ.DevID seed (as PL0) so that PQC mode is enabled and
/// GET_PQ_INFO can derive the public key.
fn provision_pq_seed(model: &mut caliptra_hw_model::DefaultHwModel) {
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: PQ_SEED,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap();
}

/// SP 800-108 counter-mode KDF (single iteration) with HMAC-SHA384, reproducing
/// the firmware's `hmac384_kdf` fixed-input format: `be32(1) || label` (these
/// derivations use no context). Returns the full 48-byte HMAC-SHA384 output.
fn hmac_sha384_kdf(key: &[u8], label: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
    signer.update(&1u32.to_be_bytes()).unwrap();
    signer.update(label).unwrap();
    signer.sign_to_vec().unwrap()
}

/// Independently reproduce the firmware's PQ.DevID public-key derivation, using
/// OpenSSL as the oracle:
///   seed  --KDF "pq_devid_cdi"-->    PQ.DevID CDI (48 B)
///         --KDF "pq_devid_keygen"--> ML-DSA seed (first 32 B of the output)
///         --ML-DSA-87 KeyGen-->      encoded public key (2,592 B)
///
/// This mirrors `SetPqSeedCmd::derive_pq_devid_cdi` and the runtime's
/// `derive_devid_seed` used by `GetPqInfoCmd`.
fn derive_expected_pq_devid_pubkey(seed: &[u8; SET_PQ_SEED_SEED_SIZE]) -> Vec<u8> {
    let cdi = hmac_sha384_kdf(seed, b"pq_devid_cdi");
    let kdf_out = hmac_sha384_kdf(&cdi, b"pq_devid_keygen");
    let mldsa_seed: [u8; 32] = kdf_out[..32].try_into().unwrap();

    let private_key = PKeyMlDsaBuilder::<Private>::from_seed(MlDsaVariant::MlDsa87, &mldsa_seed)
        .unwrap()
        .build()
        .unwrap();
    PKeyMlDsaParams::<Public>::from_pkey(&private_key)
        .unwrap()
        .public_key()
        .unwrap()
        .to_vec()
}

/// Error path: PQC mode has not been initialized (no SET_PQ_SEED). The request
/// itself is well-formed, so the command-specific guard is what rejects it.
#[test]
fn test_get_pq_info_not_initialized() {
    let mut model = run_pqc_rt_test();

    let payload = MailboxReqHeader {
        chksum: get_pq_info_checksum(),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_INFO), payload.as_bytes())
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_PQC_NOT_INITIALIZED, resp);
}

/// Error path: the request header carries an invalid checksum.
#[test]
fn test_get_pq_info_invalid_checksum() {
    let mut model = run_pqc_rt_test();

    // Corrupt an otherwise-valid checksum.
    let payload = MailboxReqHeader {
        chksum: get_pq_info_checksum().wrapping_add(1),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_INFO), payload.as_bytes())
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_INVALID_CHECKSUM, resp);
}

/// Error path: the request is larger than the (header-only) GET_PQ_INFO request,
/// so the mailbox rejects it before dispatch.
#[test]
fn test_get_pq_info_request_too_large() {
    let mut model = run_pqc_rt_test();

    // GET_PQ_INFO takes only a MailboxReqHeader; send extra words to overflow it.
    let payload = [0u8; core::mem::size_of::<MailboxReqHeader>() + 4];

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_INFO), &payload)
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_INSUFFICIENT_MEMORY, resp);
}

/// Happy path: with PQC mode enabled, GET_PQ_INFO returns the 2,592-byte
/// ML-DSA-87 public key, and it is reproducible across calls.
#[test]
fn test_get_pq_info_success() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let payload = MailboxReqHeader {
        chksum: get_pq_info_checksum(),
    };

    let response = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();

    let info_resp = GetPqInfoResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Deterministic: re-deriving from the same CDI yields the identical key.
    let response2 = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info_resp2 = GetPqInfoResp::ref_from_bytes(response2.as_bytes()).unwrap();
    assert_eq!(
        info_resp.pq_pub_key, info_resp2.pq_pub_key,
        "GET_PQ_INFO should be deterministic across calls"
    );
}

/// The returned public key must match one independently derived from the
/// provisioned seed (via OpenSSL), confirming the firmware derives the PQ.DevID
/// key correctly through the seed -> CDI -> ML-DSA-87 keypair chain.
#[test]
fn test_get_pq_info_public_key_matches_derivation() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let payload = MailboxReqHeader {
        chksum: get_pq_info_checksum(),
    };
    let response = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();
    let info_resp = GetPqInfoResp::ref_from_bytes(response.as_bytes()).unwrap();

    let expected = derive_expected_pq_devid_pubkey(&PQ_SEED);
    assert_eq!(
        expected.len(),
        MLDSA87_PUBLIC_KEY_BYTES,
        "ML-DSA-87 public key is 2,592 bytes"
    );
    assert_eq!(
        info_resp.pq_pub_key.as_slice(),
        expected.as_slice(),
        "GET_PQ_INFO public key must match the key derived from the provisioned seed"
    );
}
