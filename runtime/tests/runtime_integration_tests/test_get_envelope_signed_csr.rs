// Licensed under the Apache-2.0 license

use std::u8;

use crate::common::get_certs;
use crate::common::{get_rt_alias_ecc384_cert, run_rt_test, RuntimeTestArgs};
use caliptra_api::mailbox::{GetEnvelopeSignedEccCsrReq, GetFmcAliasEcc384CertReq};
use caliptra_common::mailbox_api::{GetRtAliasEcc384CertReq, GetRtAliasMlDsa87CertReq};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use coset::{cbor::value::Value, iana, iana::CwtClaimName, CborSerializable, CoseSign1};
use openssl::{
    pkey::{PKey, Public},
    x509::{X509Req, X509},
};
use rand::Rng;
use zerocopy::{FromZeros, IntoBytes};

const KEY_ID_LDEV_ID: u32 = 1;
const KEY_ID_FMC_ALIAS: u32 = 2;
const KEY_ID_RT_ALIAS: u32 = 3;

const CBOR_TAG_CWT: u64 = 61;
const CBOR_TAG_COSE_SIGN1: u64 = 18;

// EAT claim keys (private claims from ocp-eat crate)
const ENV_SIGNED_CSR_CLAIM_KEY_CSR: i64 = -70001;
const ENV_SIGNED_CSR_CLAIM_KEY_ATTRIB: i64 = -70002;

fn verify_protected_header(protected: &coset::Header, rt_kid: &[u8]) {
    assert_eq!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::ESP384
        )),
        "Algorithm should be ESP384"
    );
    // Content type is stored as Option<RegisteredLabel<CoapContentFormat>>
    assert_eq!(
        protected.content_type,
        Some(coset::RegisteredLabel::Assigned(
            iana::CoapContentFormat::EatCwt
        )),
        "Content type should be application/eat+cwt"
    );
    let signer_kid = protected.key_id.as_slice();
    assert!(
        !signer_kid.is_empty(),
        "Key ID (kid) should be present in protected header"
    );
    println!(
        "RT Alias subject SN (kid) as ASCII: {}",
        String::from_utf8_lossy(rt_kid)
    );
    println!("RT Alias subject SN (kid) as hex: {:02X?}", rt_kid);
    assert_eq!(
        signer_kid, rt_kid,
        "Key ID (kid) in protected header should match RT Alias subject SN"
    );
}

/// Verify the COSE Sign1 envelope structure and signature, then parse and return the CSR
fn verify_cose_sign1_envelope(
    cose_sign1: &CoseSign1,
    nonce: &[u8; 32],
    rt_pub_key: &PKey<Public>,
    rt_kid: &[u8; 20],
    kda_oids: &[&[u8]],
) -> X509Req {
    // Verify the protected header
    let protected = &cose_sign1.protected.header;
    verify_protected_header(protected, rt_kid);

    // Extract and parse the CSR from the payload
    let payload = cose_sign1
        .payload
        .as_ref()
        .expect("COSE Sign1 payload should be present");

    // Parse the EAT claims (CBOR map)
    let eat_claims = Value::from_slice(payload).expect("Failed to parse EAT claims");

    // Extract CSR from EAT claims (claim key -70001)
    let csr = if let Value::Map(map) = &eat_claims {
        let csr_bytes = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == ENV_SIGNED_CSR_CLAIM_KEY_CSR as i128))
            .and_then(|(_, v)| {
                if let Value::Bytes(bytes) = v {
                    Some(bytes.as_slice())
                } else {
                    None
                }
            })
            .expect("CSR not found in EAT claims");

        X509Req::from_der(csr_bytes).expect("Failed to parse CSR from EAT payload")
    } else {
        panic!("EAT claims should be a CBOR map");
    };

    // Extract and verify attributes from EAT claims (claim key -70002)
    if let Value::Map(map) = &eat_claims {
        let attributes = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == ENV_SIGNED_CSR_CLAIM_KEY_ATTRIB as i128))
            .and_then(|(_, v)| {
                if let Value::Array(arr) = v {
                    Some(arr)
                } else {
                    None
                }
            })
            .expect("Attributes not found in EAT claims");

        // Collect all OIDs from attributes
        let mut found_oids: Vec<Vec<u8>> = Vec::new();

        // Each attribute is a tagged OID (CBOR tag 111)
        for attr in attributes {
            if let Value::Tag(tag, boxed_value) = attr {
                assert_eq!(*tag, 111, "Attribute should be tagged with OID tag (111)");

                if let Value::Bytes(oid_bytes) = boxed_value.as_ref() {
                    // oid_bytes contains the X.690 BER encoded OID value
                    println!("Found OID: {:02X?}", oid_bytes);
                    found_oids.push(oid_bytes.clone());
                }
            }
        }

        // Verify all expected KDA OIDs are present
        for expected_oid in kda_oids {
            assert!(
                found_oids.iter().any(|oid| oid.as_slice() == *expected_oid),
                "Expected KDA OID {:02X?} not found in attributes",
                expected_oid
            );
        }

        // Verify we found at least one attribute
        assert!(
            !found_oids.is_empty(),
            "No OID attributes found in EAT claims"
        );
    }

    // Verify the nonce is present (using IANA CWT claim name)
    if let Value::Map(map) = &eat_claims {
        let nonce_claim = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CwtClaimName::Nonce as i128))
            .and_then(|(_, v)| {
                if let Value::Bytes(bytes) = v {
                    Some(bytes.as_slice())
                } else {
                    None
                }
            })
            .expect("Nonce not found in EAT claims");

        assert_eq!(
            nonce_claim, nonce,
            "Nonce in EAT should match request nonce"
        );
    }

    // Verify COSE Sign1 signature with RT Alias public key
    let signature = cose_sign1.signature.as_slice();

    // Build the Sig_structure for verification (as per RFC 8152)
    // Use empty AAD to match what was used during signing
    let tbs_data = cose_sign1.tbs_data(b"");

    // Verify the signature using OpenSSL
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;
    use openssl::sha::Sha384;

    // Hash the Sig_structure with SHA384
    let mut hasher = Sha384::new();
    hasher.update(&tbs_data);
    let digest = hasher.finish();

    // Parse signature (r||s, each 48 bytes for P-384)
    assert_eq!(
        signature.len(),
        96,
        "Signature should be 96 bytes for ES384"
    );
    let r = BigNum::from_slice(&signature[..48]).expect("Failed to parse r component");
    let s = BigNum::from_slice(&signature[48..]).expect("Failed to parse s component");
    let ecdsa_sig =
        EcdsaSig::from_private_components(r, s).expect("Failed to create ECDSA signature");

    // Verify signature
    assert!(
        ecdsa_sig
            .verify(&digest, rt_pub_key.ec_key().unwrap().as_ref())
            .unwrap(),
        "COSE Sign1 signature verification failed with RT Alias public key"
    );

    csr
}

fn verify_cbor_tags(data: &[u8], expected_tags: &[u64]) -> Value {
    let mut value = Value::from_slice(data).expect("Failed to parse CBOR data");
    let mut tag_index = 0;

    loop {
        match value {
            Value::Tag(tag, boxed) => {
                assert!(
                    tag_index < expected_tags.len(),
                    "Found more tags than expected: found tag {} at position {}, but only {} tags expected",
                    tag, tag_index, expected_tags.len()
                );
                assert_eq!(
                    tag, expected_tags[tag_index],
                    "Tag mismatch at position {}: found {}, expected {}",
                    tag_index, tag, expected_tags[tag_index]
                );
                tag_index += 1;
                value = *boxed;
            }
            Value::Bytes(bytes) => {
                value = Value::from_slice(&bytes).expect("Failed to parse CBOR data");
            }
            Value::Array(_) => break,
            _ => {
                panic!("Invalid COSE_Sign1 structure: expected CBOR tag, byte string, or array");
            }
        }
    }

    // Verify we found all expected tags
    assert_eq!(
        tag_index,
        expected_tags.len(),
        "Tag count mismatch: found {} tags, expected {}",
        tag_index,
        expected_tags.len()
    );

    value
}

/// Parse envelope signed CSR data and extract COSE Sign1 structure
fn parse_envelope_signed_csr(env_signed_csr: &[u8]) -> CoseSign1 {
    // Verify the CBOR tags and extract the signed EAT
    let signed_eat = verify_cbor_tags(env_signed_csr, &[CBOR_TAG_CWT, CBOR_TAG_COSE_SIGN1])
        .to_vec()
        .expect("Failed to extract signed EAT from CBOR tags");

    // Parse the COSE Sign1 envelope
    CoseSign1::from_slice(&signed_eat).expect("Failed to parse COSE Sign1 envelope")
}

fn get_envelope_signed_ecc_csr(model: &mut DefaultHwModel, key_id: u32) -> X509Req {
    // Generate a random nonce locally
    let nonce: [u8; 32] = rand::thread_rng().gen();

    let mut req = GetEnvelopeSignedEccCsrReq {
        hdr: Default::default(),
        key_id,
        nonce,
    };

    // Calculate checksum for the request
    let cmd_id = u32::from(caliptra_api::mailbox::CommandId::GET_ENVELOPE_SIGNED_ECC384_CSR);
    req.hdr.chksum = caliptra_common::checksum::calc_checksum(
        cmd_id,
        &req.as_bytes()[core::mem::size_of_val(&req.hdr.chksum)..],
    );

    let resp_bytes = model
        .mailbox_execute(
            u32::from(caliptra_api::mailbox::CommandId::GET_ENVELOPE_SIGNED_ECC384_CSR),
            req.as_bytes(),
        )
        .unwrap_or_else(|e: caliptra_hw_model::ModelError| {
            eprintln!("Mailbox execute error: {:?}", e);
            panic!(
                "Failed to execute GET_ENVELOPE_SIGNED_ECC384_CSR command: {:x?}",
                e
            );
        })
        .expect("No response received");

    assert!(
        resp_bytes.len() <= std::mem::size_of::<caliptra_api::mailbox::EnvelopeSignedCsrResp>(),
        "CSR Response length exceeds expected size"
    );

    // Parse response using typed struct pattern
    let mut resp = caliptra_api::mailbox::EnvelopeSignedCsrResp::new_zeroed();
    resp.as_mut_bytes()[..resp_bytes.len()].copy_from_slice(&resp_bytes);

    assert!(
        resp.data_size > 0,
        "Envelope Signed CSR data size should be non-zero"
    );

    let env_signed_csr = &resp.data[..resp.data_size as usize];

    // Parse the COSE Sign1 from envelope signed CSR data
    let cose_sign1 = parse_envelope_signed_csr(env_signed_csr);

    // Get RT Alias public key from certificate
    let rt_cert_resp = get_rt_alias_ecc384_cert(model);
    let rt_cert = X509::from_der(&rt_cert_resp.data[..rt_cert_resp.data_size as usize])
        .expect("Failed to parse RT Alias certificate");
    let rt_pub_key = rt_cert
        .public_key()
        .expect("Failed to get RT Alias public key");

    // Get RT subject key identifier from cert
    let rt_key_id = rt_cert
        .subject_key_id()
        .expect("Failed to get RT Alias key identifier");
    let rt_key_id = rt_key_id.as_slice();
    let mut rt_kid = [0u8; 20];
    let len = rt_key_id.len().min(20);
    rt_kid[20 - len..].copy_from_slice(&rt_key_id[..len]);
    // Define expected KDA OIDs based on key type
    let kda_oids: &[&[u8]] = match key_id {
        KEY_ID_LDEV_ID => &[
            // LDevID is derived from owner entropy fuse
            &[
                0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x01,
            ],
        ],
        KEY_ID_FMC_ALIAS => &[
            // FMC Alias is derived from first mutable code
            &[
                0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x02,
            ],
        ],
        KEY_ID_RT_ALIAS => &[
            // RT Alias is derived from non-first mutable code
            &[
                0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCD, 0x1F, 0x01, 0x02, 0x03,
            ],
        ],
        _ => &[],
    };

    // Verify COSE Sign1 envelope, extract and parse CSR
    verify_cose_sign1_envelope(&cose_sign1, &nonce, &rt_pub_key, &rt_kid, kda_oids)
}

#[test]
fn test_get_envelope_signed_ldevid_ecc_csr() {
    fn verify_fmc_alias_ecc_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
        // Get FMC Alias ECC certificate
        let get_fmc_alias_cert_rsp = get_certs::<GetFmcAliasEcc384CertReq>(model);
        assert_ne!(0, get_fmc_alias_cert_rsp.data_size);

        let fmc_cert_der =
            &get_fmc_alias_cert_rsp.data[..get_fmc_alias_cert_rsp.data_size as usize];

        let fmc_cert = X509::from_der(fmc_cert_der).expect("Failed to parse FMC Alias ECC cert");

        assert!(
            fmc_cert.verify(&pub_key).is_ok(),
            "FMC Alias ECC cert verification failed"
        );
    }

    let mut model = run_rt_test(RuntimeTestArgs::default());

    // Get the envelope signed CSR for LDevID
    let csr = get_envelope_signed_ecc_csr(&mut model, KEY_ID_LDEV_ID);

    // Verify the CSR public key
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");

    // Verify the CSR is self-signed correctly
    assert!(
        csr.verify(&pubkey).unwrap(),
        "Invalid public key. Unable to verify LDevID Envelope Signed ECC CSR"
    );

    // Nonce verification is done inside get_envelope_signed_ecc_csr()

    // Verify against FMC Alias certificate
    verify_fmc_alias_ecc_cert(&mut model, pubkey);
}

#[test]
fn test_get_envelope_signed_fmc_alias_ecc_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    // Get the envelope signed CSR for FMC Alias
    let csr = get_envelope_signed_ecc_csr(&mut model, KEY_ID_FMC_ALIAS);
    // Verify the CSR public key
    let pubkey = csr.public_key().expect("Failed to get public key from CSR");
    // Verify the CSR is self-signed correctly
    assert!(
        csr.verify(&pubkey).unwrap(),
        "Invalid public key. Unable to verify FMC Alias Envelope Signed ECC CSR"
    );
    verify_rt_ecc_cert(&mut model, pubkey);

    // Nonce verification is done inside get_envelope_signed_ecc_csr()
}

fn verify_rt_ecc_cert(model: &mut DefaultHwModel, pub_key: PKey<Public>) {
    let get_rt_alias_cert_resp = get_certs::<GetRtAliasEcc384CertReq>(model);
    assert_ne!(0, get_rt_alias_cert_resp.data_size);

    let der = &get_rt_alias_cert_resp.data[..get_rt_alias_cert_resp.data_size as usize];
    let cert = X509::from_der(der).unwrap();

    assert!(
        cert.verify(&pub_key).unwrap(),
        "Invalid public key. Unable to verify RT Alias ECC Cert",
    );
}
