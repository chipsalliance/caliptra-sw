// Licensed under the Apache-2.0 license

mod test_common;
mod test_fmc_alias;
mod test_ldevid;
mod test_rt_alias;

// Shared imports
use caliptra_common::mailbox_api::{
    AttestedCsrResp, CommandId, GetAttestedEccCsrReq, GetAttestedMldsaCsrReq, MailboxReq,
    MailboxReqHeader,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use coset::{cbor::value::Value, iana, iana::CwtClaimName, CborSerializable, CoseSign1};
use ml_dsa_01::{
    signature::Verifier, EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey,
};
use openssl::{
    pkey::{PKey, Public},
    x509::{X509Req, X509},
};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use zerocopy::IntoBytes;

use crate::common::{get_rt_alias_ecc384_cert, get_rt_alias_mldsa87_cert};
use rand::Rng;

// Constants
pub const CBOR_TAG_CWT: u64 = 61;
pub const CBOR_TAG_COSE_SIGN1: u64 = 18;

pub const KEY_ID_LDEV_ID: u32 = 1;
pub const KEY_ID_FMC_ALIAS: u32 = 2;
pub const KEY_ID_RT_ALIAS: u32 = 3;

// EAT claim keys (private claims from ocp-eat crate)
pub const CLAIM_KEY_ATTESTED_CSR: i64 = -70001;
pub const CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB: i64 = -70002;
pub const CLAIM_KEY_KEYPAIR_INVENTORY: i64 = -70003;

pub const OCP_SECURITY_OID_KDA: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xCC, 0x7F, 0x01, 0x02];

/// Verify the COSE Sign1 protected header fields.
pub fn verify_protected_header(
    protected: &coset::Header,
    rt_kid: &[u8],
    expected_alg: iana::Algorithm,
) {
    assert_eq!(
        protected.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(expected_alg)),
        "Algorithm should be {:?}",
        expected_alg,
    );
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

/// Verify the COSE Sign1 envelope structure and signature, then parse and return the CSR.
pub fn verify_cose_sign1_envelope(
    cose_sign1: &CoseSign1,
    nonce: &[u8; 32],
    rt_pub_key: &PKey<Public>,
    rt_kid: &[u8; 20],
    expected_bitfield: u64,
) -> X509Req {
    // Verify the protected header
    let protected = &cose_sign1.protected.header;
    verify_protected_header(protected, rt_kid, iana::Algorithm::ESP384);

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
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_ATTESTED_CSR as i128))
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

    // Extract and verify attributes from EAT claims (claim key -70002) as a CBOR Map
    if let Value::Map(map) = &eat_claims {
        let attr_map = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB as i128))
            .and_then(|(_, v)| {
                if let Value::Map(m) = v {
                    Some(m)
                } else {
                    None
                }
            })
            .expect("Attributes map not found in EAT claims");

        let found_bitfield = attr_map
            .iter()
            .find(|(k, _)| match k {
                Value::Tag(tag, boxed) if *tag == 111 => match boxed.as_ref() {
                    Value::Bytes(b) => b.as_slice() == OCP_SECURITY_OID_KDA,
                    _ => false,
                },
                _ => false,
            })
            .and_then(|(_, v)| match v {
                Value::Integer(i) => Some(Into::<i128>::into(*i) as u64),
                _ => None,
            })
            .expect("OCP Security KDA attribute not found in attributes map");

        assert_eq!(
            found_bitfield, expected_bitfield,
            "Derivation bitfield mismatch: found 0x{:02x}, expected 0x{:02x}",
            found_bitfield, expected_bitfield
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

/// Verify CBOR tags on the outer data and return the inner value.
pub fn verify_cbor_tags(data: &[u8], expected_tags: &[u64]) -> Value {
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

/// Return the expected KDA derivation component bitfield for the given key identity.
pub fn expected_kda_bitfield(key_id: u32) -> u64 {
    match key_id {
        KEY_ID_LDEV_ID => 0x03,   // UDS | FIELD_ENTROPY
        KEY_ID_FMC_ALIAS => 0x13, // UDS | FIELD_ENTROPY | FIRST_MUTABLE_CODE
        KEY_ID_RT_ALIAS => 0x33,  // UDS | FIELD_ENTROPY | FIRST_MUTABLE_CODE | RUNTIME_FIRMWARE
        _ => panic!("Invalid key_id for KDA bitfield"),
    }
}

/// Parse attested CSR data and extract COSE Sign1 structure.
pub fn parse_attested_csr(attested_csr: &[u8]) -> CoseSign1 {
    // Verify the CBOR tags and extract the signed EAT
    let signed_eat = verify_cbor_tags(attested_csr, &[CBOR_TAG_CWT, CBOR_TAG_COSE_SIGN1])
        .to_vec()
        .expect("Failed to extract signed EAT from CBOR tags");

    // Parse the COSE Sign1 envelope
    CoseSign1::from_slice(&signed_eat).expect("Failed to parse COSE Sign1 envelope")
}

/// Send the GetAttestedEcc384Csr command, verify the COSE Sign1 envelope,
/// and extract and return the CSR from the EAT payload.
pub fn verify_and_extract_attested_ecc_csr(model: &mut DefaultHwModel, key_id: u32) -> X509Req {
    let nonce: [u8; 32] = rand::thread_rng().gen();

    let mut cmd = MailboxReq::GetAttestedEcc384Csr(GetAttestedEccCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id,
        nonce,
    });
    cmd.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_ECC384_CSR),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    assert!(resp_bytes.len() <= std::mem::size_of::<AttestedCsrResp>());
    let mut resp = AttestedCsrResp::default();
    resp.as_mut_bytes()[..resp_bytes.len()].copy_from_slice(&resp_bytes);

    assert!(
        resp.data_size > 0,
        "Attested CSR data size should be non-zero"
    );

    let attested_csr = &resp.data[..resp.data_size as usize];
    let cose_sign1 = parse_attested_csr(attested_csr);

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

    let bitfield = expected_kda_bitfield(key_id);

    // Verify COSE Sign1 envelope, extract and parse CSR
    verify_cose_sign1_envelope(&cose_sign1, &nonce, &rt_pub_key, &rt_kid, bitfield)
}

/// Extract the CSR (X509Req) from a COSE Sign1 payload's EAT claims.
pub fn extract_csr_from_cose_payload(cose_sign1: &CoseSign1) -> X509Req {
    let payload = cose_sign1
        .payload
        .as_ref()
        .expect("COSE Sign1 payload should be present");

    let eat_claims = Value::from_slice(payload).expect("Failed to parse EAT claims");

    if let Value::Map(map) = &eat_claims {
        let csr_bytes = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_ATTESTED_CSR as i128))
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
    }
}

/// Send the GetAttestedMldsa87Csr command, verify the COSE Sign1 envelope
/// structure and protected header (ML_DSA_87 algorithm, kid), and extract
/// and return the inner CSR from the EAT payload.
pub fn verify_and_extract_attested_mldsa_csr(model: &mut DefaultHwModel, key_id: u32) -> X509Req {
    let nonce: [u8; 32] = rand::thread_rng().gen();
    let mut cmd = MailboxReq::GetAttestedMldsa87Csr(GetAttestedMldsaCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id,
        nonce,
    });
    cmd.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_MLDSA87_CSR),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    assert!(resp_bytes.len() <= std::mem::size_of::<AttestedCsrResp>());
    let mut csr_resp = AttestedCsrResp::default();
    csr_resp.as_mut_bytes()[..resp_bytes.len()].copy_from_slice(&resp_bytes);

    assert!(csr_resp.data.iter().any(|&x| x != 0));

    let attested_csr = &csr_resp.data[..csr_resp.data_size as usize];

    // Parse the COSE Sign1 envelope and verify ML_DSA_87 in protected header
    let cose_sign1 = parse_attested_csr(attested_csr);
    let protected = &cose_sign1.protected.header;

    // Get RT Alias MLDSA certificate and extract subject key identifier
    let rt_cert_resp = get_rt_alias_mldsa87_cert(model);
    let rt_cert = X509::from_der(&rt_cert_resp.data[..rt_cert_resp.data_size as usize])
        .expect("Failed to parse RT Alias MLDSA certificate");
    let rt_key_id = rt_cert
        .subject_key_id()
        .expect("Failed to get RT Alias MLDSA key identifier");
    let rt_key_id = rt_key_id.as_slice();
    let mut rt_kid = [0u8; 20];
    let len = rt_key_id.len().min(20);
    rt_kid[20 - len..].copy_from_slice(&rt_key_id[..len]);

    verify_protected_header(protected, &rt_kid, iana::Algorithm::ML_DSA_87);

    // Verify claims payload (nonce and attributes)
    let payload = cose_sign1
        .payload
        .as_ref()
        .expect("COSE Sign1 payload should be present");
    let eat_claims = Value::from_slice(payload).expect("Failed to parse EAT claims");
    if let Value::Map(map) = &eat_claims {
        let nonce_claim = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CwtClaimName::Nonce as i128))
            .and_then(|(_, v)| if let Value::Bytes(bytes) = v { Some(bytes.as_slice()) } else { None })
            .expect("Nonce not found in EAT claims");
        assert_eq!(nonce_claim, nonce);

        let attr_map = map
            .iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB as i128))
            .and_then(|(_, v)| if let Value::Map(m) = v { Some(m) } else { None })
            .expect("Attributes map not found in EAT claims");

        let found_bitfield = attr_map
            .iter()
            .find(|(k, _)| match k {
                Value::Tag(tag, boxed) if *tag == 111 => match boxed.as_ref() {
                    Value::Bytes(b) => b.as_slice() == OCP_SECURITY_OID_KDA,
                    _ => false,
                },
                _ => false,
            })
            .and_then(|(_, v)| match v {
                Value::Integer(i) => Some(Into::<i128>::into(*i) as u64),
                _ => None,
            })
            .expect("OCP Security KDA attribute not found in attributes map");

        let expected_bitfield = expected_kda_bitfield(key_id);
        assert_eq!(found_bitfield, expected_bitfield);
    }

    // Verify COSE Sign1 signature using RT Alias ML-DSA public key
    let rt_cert_der = &rt_cert_resp.data[..rt_cert_resp.data_size as usize];
    verify_mldsa_cose_signature(&cose_sign1, rt_cert_der);

    // Extract and return the inner CSR from the EAT payload
    extract_csr_from_cose_payload(&cose_sign1)
}

/// Verify COSE Sign1 signature for ML-DSA-87 envelope using RT Alias certificate
pub fn verify_mldsa_cose_signature(cose_sign1: &CoseSign1, rt_cert_der: &[u8]) {
    let (_, cert_parsed) =
        X509Certificate::from_der(rt_cert_der).expect("Failed to parse RT Alias X509 cert");
    let raw_pubkey = cert_parsed
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data;
    let raw_pubkey: [u8; 2592] = raw_pubkey
        .as_ref()
        .try_into()
        .expect("Invalid ML-DSA public key length in cert");
    let encoded_vk = EncodedVerifyingKey::<ml_dsa_01::MlDsa87>::from(raw_pubkey);
    let vk = VerifyingKey::<ml_dsa_01::MlDsa87>::decode(&encoded_vk);

    let sig_4627: [u8; 4627] = cose_sign1
        .signature
        .as_slice()
        .try_into()
        .expect("Invalid ML-DSA-87 signature length");
    let encoded_sig = EncodedSignature::<ml_dsa_01::MlDsa87>::from(sig_4627);
    let sig = Signature::decode(&encoded_sig).expect("Failed to decode ML-DSA-87 signature");

    assert!(
        vk.verify(&cose_sign1.tbs_data(&[]), &sig).is_ok(),
        "COSE Sign1 ML-DSA-87 signature verification failed"
    );
}

/// Verify keypair inventory payload structure for KeyPairID = 0 discovery
pub fn verify_inventory_payload(cose_sign1: &CoseSign1, nonce: &[u8; 32]) {
    let payload = cose_sign1
        .payload
        .as_ref()
        .expect("Payload should be present");
    let eat_claims = Value::from_slice(payload).expect("Failed to parse EAT claims");

    let map = match &eat_claims {
        Value::Map(map) => map,
        _ => panic!("EAT claims should be a CBOR map"),
    };

    // Check nonce (claim 10)
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
    assert_eq!(nonce_claim, nonce);

    // Ensure -70001 (CSR) and -70002 (CSR attributes) are NOT present in discovery response
    assert!(
        !map.iter().any(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_ATTESTED_CSR as i128)),
        "CSR claim (-70001) must not be present in inventory discovery token"
    );
    assert!(
        !map.iter().any(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_ATTESTED_CSR_KEY_ATTRIB as i128)),
        "CSR attributes claim (-70002) must not be present in inventory discovery token"
    );

    // Extract -70003 (keypair-inventory)
    let inventory_arr = map
        .iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if Into::<i128>::into(*i) == CLAIM_KEY_KEYPAIR_INVENTORY as i128))
        .and_then(|(_, v)| {
            if let Value::Array(arr) = v {
                Some(arr)
            } else {
                None
            }
        })
        .expect("Keypair inventory claim (-70003) not found");

    // Must have 3 entries (LDevID = 1, FMC Alias = 2, RT Alias = 3)
    assert_eq!(inventory_arr.len(), 3, "Inventory must contain 3 keypairs");

    let expected_entries: [(u8, u64); 3] = [
        (1, 0x03), // LDevId: UDS | FIELD_ENTROPY
        (2, 0x13), // FMC Alias: UDS | FIELD_ENTROPY | FIRST_MUTABLE_CODE
        (3, 0x33), // RT Alias: UDS | FIELD_ENTROPY | FIRST_MUTABLE_CODE | RUNTIME_FIRMWARE
    ];

    for (idx, (expected_id, expected_bitfield)) in expected_entries.iter().enumerate() {
        let entry = &inventory_arr[idx];
        let pair = match entry {
            Value::Array(arr) if arr.len() == 2 => arr,
            _ => panic!("Inventory entry must be an array of length 2 [id, attribs]"),
        };

        // Check keypair-id
        let id = match &pair[0] {
            Value::Integer(i) => Into::<i128>::into(*i) as u8,
            _ => panic!("Expected integer for keypair-id"),
        };
        assert_eq!(id, *expected_id);

        // Check key-attributes-map
        let attr_map = match &pair[1] {
            Value::Map(m) => m,
            _ => panic!("Expected map for key attributes"),
        };

        let bitfield = attr_map
            .iter()
            .find(|(k, _)| match k {
                Value::Tag(tag, boxed) if *tag == 111 => match boxed.as_ref() {
                    Value::Bytes(b) => b.as_slice() == OCP_SECURITY_OID_KDA,
                    _ => false,
                },
                _ => false,
            })
            .and_then(|(_, v)| match v {
                Value::Integer(i) => Some(Into::<i128>::into(*i) as u64),
                _ => None,
            })
            .expect("OCP Security KDA attribute not found in entry");

        assert_eq!(bitfield, *expected_bitfield);
    }
}

/// Send the GetAttestedEcc384Csr command with key_id = 0, verify discovery inventory token
pub fn verify_keypair_inventory_discovery_ecc(model: &mut DefaultHwModel) {
    let nonce: [u8; 32] = rand::thread_rng().gen();

    let mut cmd = MailboxReq::GetAttestedEcc384Csr(GetAttestedEccCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id: 0,
        nonce,
    });
    cmd.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_ECC384_CSR),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    assert!(resp_bytes.len() <= std::mem::size_of::<AttestedCsrResp>());
    let mut resp = AttestedCsrResp::default();
    resp.as_mut_bytes()[..resp_bytes.len()].copy_from_slice(&resp_bytes);

    assert!(resp.data_size > 0, "Inventory response data_size > 0");
    let attested_csr = &resp.data[..resp.data_size as usize];
    let cose_sign1 = parse_attested_csr(attested_csr);

    // Get RT Alias public key and kid
    let rt_cert_resp = get_rt_alias_ecc384_cert(model);
    let rt_cert = X509::from_der(&rt_cert_resp.data[..rt_cert_resp.data_size as usize])
        .expect("Failed to parse RT Alias certificate");
    let rt_pub_key = rt_cert
        .public_key()
        .expect("Failed to get RT Alias public key");
    let rt_key_id = rt_cert
        .subject_key_id()
        .expect("Failed to get RT Alias key identifier");
    let rt_key_id = rt_key_id.as_slice();
    let mut rt_kid = [0u8; 20];
    let len = rt_key_id.len().min(20);
    rt_kid[20 - len..].copy_from_slice(&rt_key_id[..len]);

    // Verify protected header
    verify_protected_header(
        &cose_sign1.protected.header,
        &rt_kid,
        iana::Algorithm::ESP384,
    );

    // Verify signature
    let signature = cose_sign1.signature.as_slice();
    let tbs_data = cose_sign1.tbs_data(b"");
    let mut hasher = openssl::sha::Sha384::new();
    hasher.update(&tbs_data);
    let digest = hasher.finish();

    assert_eq!(signature.len(), 96);
    let r = openssl::bn::BigNum::from_slice(&signature[..48]).unwrap();
    let s = openssl::bn::BigNum::from_slice(&signature[48..]).unwrap();
    let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s).unwrap();
    assert!(
        ecdsa_sig
            .verify(&digest, rt_pub_key.ec_key().unwrap().as_ref())
            .unwrap(),
        "Discovery COSE Sign1 signature verification failed"
    );

    // Verify inventory payload
    verify_inventory_payload(&cose_sign1, &nonce);
}

/// Send the GetAttestedMldsa87Csr command with key_id = 0, verify discovery inventory token
pub fn verify_keypair_inventory_discovery_mldsa(model: &mut DefaultHwModel) {
    let nonce: [u8; 32] = rand::thread_rng().gen();

    let mut cmd = MailboxReq::GetAttestedMldsa87Csr(GetAttestedMldsaCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id: 0,
        nonce,
    });
    cmd.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_MLDSA87_CSR),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    assert!(resp_bytes.len() <= std::mem::size_of::<AttestedCsrResp>());
    let mut resp = AttestedCsrResp::default();
    resp.as_mut_bytes()[..resp_bytes.len()].copy_from_slice(&resp_bytes);

    assert!(resp.data_size > 0, "Inventory response data_size > 0");
    let attested_csr = &resp.data[..resp.data_size as usize];
    let cose_sign1 = parse_attested_csr(attested_csr);

    // Get RT Alias MLDSA kid
    let rt_cert_resp = get_rt_alias_mldsa87_cert(model);
    let rt_cert = X509::from_der(&rt_cert_resp.data[..rt_cert_resp.data_size as usize])
        .expect("Failed to parse RT Alias MLDSA certificate");
    let rt_key_id = rt_cert
        .subject_key_id()
        .expect("Failed to get RT Alias MLDSA key identifier");
    let rt_key_id = rt_key_id.as_slice();
    let mut rt_kid = [0u8; 20];
    let len = rt_key_id.len().min(20);
    rt_kid[20 - len..].copy_from_slice(&rt_key_id[..len]);

    // Verify protected header
    verify_protected_header(
        &cose_sign1.protected.header,
        &rt_kid,
        iana::Algorithm::ML_DSA_87,
    );

    // Verify COSE Sign1 signature using RT Alias ML-DSA public key
    let rt_cert_der = &rt_cert_resp.data[..rt_cert_resp.data_size as usize];
    verify_mldsa_cose_signature(&cose_sign1, rt_cert_der);

    // Verify inventory payload
    verify_inventory_payload(&cose_sign1, &nonce);
}
