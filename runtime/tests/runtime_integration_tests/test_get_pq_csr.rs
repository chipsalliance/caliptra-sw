// Licensed under the Apache-2.0 license

use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader, SET_PQ_SEED_SEED_SIZE};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant as MlDsaVariant};
use openssl::sign::Signer;
use openssl::x509::X509Req;
use zerocopy::IntoBytes;

use crate::common::{
    assert_error, get_pq_csr, get_pq_csr_checksum, mldsa_csr_public_key, provision_pq_seed,
    run_pqc_rt_test, PQ_SEED,
};

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
/// This mirrors `SetPqSeedCmd::derive_pq_devid_cdi` and
/// `GetPqCsrCmd::derive_devid_seed` in the runtime.
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

    let csr_bytes = get_pq_csr(&mut model);

    // Parses as a CSR and its signature verifies against the embedded key.
    let req = X509Req::from_der(&csr_bytes).unwrap();
    let pub_key = req.public_key().unwrap();
    assert!(req.verify(&pub_key).unwrap());

    // Deterministic: regenerating from the same CDI yields the identical CSR.
    let csr_bytes2 = get_pq_csr(&mut model);
    assert_eq!(
        csr_bytes, csr_bytes2,
        "GET_PQ_CSR should be deterministic across calls"
    );
}

/// The public key embedded in the CSR must match one independently derived from
/// the provisioned seed (via OpenSSL), confirming the firmware derives the
/// PQ.DevID key correctly through the seed -> CDI -> ML-DSA-87 keypair chain.
#[test]
fn test_get_pq_csr_public_key_matches_derivation() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let csr_bytes = get_pq_csr(&mut model);

    let expected = derive_expected_pq_devid_pubkey(&PQ_SEED);
    assert_eq!(expected.len(), 2592, "ML-DSA-87 public key is 2,592 bytes");
    assert_eq!(
        mldsa_csr_public_key(&csr_bytes),
        expected,
        "CSR public key must match the key derived from the provisioned seed"
    );
}
