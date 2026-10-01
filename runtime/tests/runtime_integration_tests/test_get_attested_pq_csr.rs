// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    CommandId, GetAttestedPqCsrReq, GetAttestedPqCsrResp, MailboxReq, MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use coset::cbor::value::Value;
use coset::{iana, CborSerializable, CoseSign1, TaggedCborSerializable};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::sha::{sha256, sha384};
use openssl::x509::X509;
use zerocopy::FromBytes;

use crate::common::{
    assert_error, get_pq_csr, get_rt_alias_cert, provision_pq_seed, run_pqc_rt_test, run_rt_test,
    RuntimeTestArgs,
};

const CBOR_TAG_CWT: u64 = 61;
const CBOR_TAG_OID: u64 = 111;
const CLAIM_KEY_NONCE: i128 = 10;
const CLAIM_KEY_ATTESTED_CSR: i128 = -70001;
const CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB: i128 = -70002;
const CLAIM_KEY_KEYPAIR_INVENTORY: i128 = -70003;
const OCP_SECURITY_OID_KDA: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01, 0x02];

/// PQ.DevID is derived solely from the SoC-provisioned seed; no OCP derivation
/// components apply.
const PQ_DEVID_KDA_BITFIELD: u64 = 0;

const TEST_NONCE: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

fn get_attested_pq_csr(
    model: &mut DefaultHwModel,
    key_id: u32,
    nonce: [u8; 32],
) -> Result<Vec<u8>, ModelError> {
    let mut cmd = MailboxReq::GetAttestedPqCsr(GetAttestedPqCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id,
        nonce,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_PQ_CSR),
            cmd.as_bytes().unwrap(),
        )?
        .expect("expected a response");

    let mut resp_buf = vec![0u8; core::mem::size_of::<GetAttestedPqCsrResp>()];
    resp_buf[..resp.len()].copy_from_slice(&resp);
    let resp = GetAttestedPqCsrResp::ref_from_bytes(&resp_buf).unwrap();
    Ok(resp.data[..resp.data_size as usize].to_vec())
}

fn map_get(map: &[(Value, Value)], key: i128) -> &Value {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("claim {key} not found"))
}

fn as_bytes(v: &Value) -> &[u8] {
    match v {
        Value::Bytes(b) => b,
        other => panic!("expected bstr, got {other:?}"),
    }
}

fn as_map(v: &Value) -> &[(Value, Value)] {
    match v {
        Value::Map(m) => m,
        other => panic!("expected map, got {other:?}"),
    }
}

/// Assert the key-attributes map is `{ 111(OCP_SECURITY_OID_KDA): bitfield }`.
fn assert_kda_attributes(attrs: &Value, expected_bitfield: u64) {
    let attrs = as_map(attrs);
    assert_eq!(attrs.len(), 1, "expected exactly one key attribute");
    let (k, v) = &attrs[0];
    match k {
        Value::Tag(CBOR_TAG_OID, inner) => assert_eq!(as_bytes(inner), OCP_SECURITY_OID_KDA),
        other => panic!("expected tagged OID key, got {other:?}"),
    }
    match v {
        Value::Integer(i) => assert_eq!(i128::from(*i), expected_bitfield as i128),
        other => panic!("expected uint bitfield, got {other:?}"),
    }
}

/// Decode the CWT-tagged COSE_Sign1, check its protected header, verify the
/// ES384 signature against the RT Alias certificate and return the decoded
/// EAT claims map.
fn verify_and_decode(model: &mut DefaultHwModel, token: &[u8]) -> Vec<(Value, Value)> {
    // Outer CWT tag wraps a COSE_Sign1 tag (18).
    let inner = match Value::from_slice(token).expect("token is not CBOR") {
        Value::Tag(CBOR_TAG_CWT, inner) => *inner,
        other => panic!("expected CWT tag, got {other:?}"),
    };
    let cose = CoseSign1::from_tagged_slice(&inner.to_vec().unwrap())
        .expect("payload is not a tagged COSE_Sign1");

    let rt_resp = get_rt_alias_cert(model);
    let rt_cert = X509::from_der(&rt_resp.data[..rt_resp.data_size as usize]).unwrap();
    let rt_pub_key = rt_cert.public_key().unwrap();

    // Protected header: algorithm, content type, and kid == RT Alias SKI.
    let protected = &cose.protected.header;
    assert_eq!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::ESP384
        ))
    );
    assert_eq!(
        protected.content_type,
        Some(coset::RegisteredLabel::Assigned(
            iana::CoapContentFormat::EatCwt
        ))
    );
    let rt_ski = rt_cert
        .subject_key_id()
        .expect("RT Alias cert has no SKI")
        .as_slice()
        .to_vec();
    assert_eq!(protected.key_id, rt_ski, "kid must equal the RT Alias SKI");
    let ec_point = rt_pub_key
        .ec_key()
        .unwrap()
        .public_key()
        .to_bytes(
            rt_pub_key.ec_key().unwrap().group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut openssl::bn::BigNumContext::new().unwrap(),
        )
        .unwrap();
    assert_eq!(protected.key_id, sha256(&ec_point)[..20].to_vec());

    // ES384 signature over the Sig_structure.
    let sig = &cose.signature;
    assert_eq!(sig.len(), 96);
    let ecdsa_sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sig[..48]).unwrap(),
        BigNum::from_slice(&sig[48..]).unwrap(),
    )
    .unwrap();
    let digest = sha384(&cose.tbs_data(b""));
    assert!(
        ecdsa_sig
            .verify(&digest, &rt_pub_key.ec_key().unwrap())
            .unwrap(),
        "COSE_Sign1 signature does not verify with the RT Alias public key"
    );

    let payload = cose.payload.as_ref().expect("COSE_Sign1 payload missing");
    match Value::from_slice(payload).expect("EAT claims are not CBOR") {
        Value::Map(m) => m,
        other => panic!("EAT claims must be a map, got {other:?}"),
    }
}

/// Happy path: the EAT wraps the same CSR GET_PQ_CSR returns, carries the
/// request nonce and the PQ.DevID key attributes, and is signed by RT Alias.
#[test]
fn test_get_attested_pq_csr_success() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let token =
        get_attested_pq_csr(&mut model, GetAttestedPqCsrReq::KEY_ID_PQ_DEVID, TEST_NONCE).unwrap();
    let claims = verify_and_decode(&mut model, &token);
    assert_eq!(claims.len(), 3);

    assert_eq!(as_bytes(map_get(&claims, CLAIM_KEY_NONCE)), TEST_NONCE);
    assert_kda_attributes(
        map_get(&claims, CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB),
        PQ_DEVID_KDA_BITFIELD,
    );

    let csr = as_bytes(map_get(&claims, CLAIM_KEY_ATTESTED_CSR)).to_vec();
    let req = openssl::x509::X509Req::from_der(&csr).unwrap();
    assert!(req.verify(&req.public_key().unwrap()).unwrap());
    assert_eq!(
        csr,
        get_pq_csr(&mut model),
        "attested CSR must match GET_PQ_CSR output"
    );
}

/// key_id 0 returns the signed keypair inventory (static; available before
/// SET_PQ_SEED, matching main's discovery behavior).
#[test]
fn test_get_attested_pq_csr_inventory() {
    let mut model = run_pqc_rt_test();

    let token = get_attested_pq_csr(
        &mut model,
        GetAttestedPqCsrReq::KEY_ID_INVENTORY,
        TEST_NONCE,
    )
    .unwrap();
    let claims = verify_and_decode(&mut model, &token);
    assert_eq!(claims.len(), 2);
    assert_eq!(as_bytes(map_get(&claims, CLAIM_KEY_NONCE)), TEST_NONCE);

    let inventory = match map_get(&claims, CLAIM_KEY_KEYPAIR_INVENTORY) {
        Value::Array(a) => a,
        other => panic!("inventory must be an array, got {other:?}"),
    };
    assert_eq!(inventory.len(), 1, "only PQ.DevID is attestable");
    let entry = match &inventory[0] {
        Value::Array(e) => e,
        other => panic!("inventory entry must be an array, got {other:?}"),
    };
    assert_eq!(entry.len(), 2);
    assert!(
        matches!(&entry[0], Value::Integer(i) if i128::from(*i) == GetAttestedPqCsrReq::KEY_ID_PQ_DEVID as i128)
    );
    assert_kda_attributes(&entry[1], PQ_DEVID_KDA_BITFIELD);
}

/// The nonce is bound into the signed payload, so different nonces give
/// different tokens.
#[test]
fn test_get_attested_pq_csr_nonce_bound() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let mut other_nonce = TEST_NONCE;
    other_nonce[0] ^= 0xff;
    let token = get_attested_pq_csr(
        &mut model,
        GetAttestedPqCsrReq::KEY_ID_PQ_DEVID,
        other_nonce,
    )
    .unwrap();
    let claims = verify_and_decode(&mut model, &token);
    assert_eq!(as_bytes(map_get(&claims, CLAIM_KEY_NONCE)), other_nonce);
}

#[test]
fn test_get_attested_pq_csr_not_initialized() {
    let mut model = run_pqc_rt_test();

    let resp = get_attested_pq_csr(&mut model, GetAttestedPqCsrReq::KEY_ID_PQ_DEVID, TEST_NONCE)
        .unwrap_err();
    assert_error(&mut model, CaliptraError::RUNTIME_PQC_NOT_INITIALIZED, resp);
}

#[test]
fn test_get_attested_pq_csr_invalid_key_id() {
    let mut model = run_pqc_rt_test();
    provision_pq_seed(&mut model);

    let resp = get_attested_pq_csr(&mut model, 2, TEST_NONCE).unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );
}

/// Available to PL1 callers, like GET_PQ_CSR. Only the inventory is checked:
/// with no PL0 PAUSER, SET_PQ_SEED (PL0) cannot run, so key_id 1 is
/// unreachable here.
#[test]
fn test_get_attested_pq_csr_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;
    let mut model = run_rt_test(RuntimeTestArgs {
        test_image_options: Some(image_opts),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let token = get_attested_pq_csr(
        &mut model,
        GetAttestedPqCsrReq::KEY_ID_INVENTORY,
        TEST_NONCE,
    )
    .unwrap();
    let claims = verify_and_decode(&mut model, &token);
    assert_eq!(as_bytes(map_get(&claims, CLAIM_KEY_NONCE)), TEST_NONCE);
}
