// Licensed under the Apache-2.0 license

//! End-to-end ML-DSA attestation workflow, modelled on an SPDM certificate +
//! challenge exchange.
//!
//! The flow ties every step together cryptographically:
//!   1. SET_PQ_SEED provisions the PQ.DevID identity.
//!   2. GET_PQ_CSR yields the PQ.DevID CSR (self-signed by the PQ.DevID key).
//!   3. A test Root CA issues a DevID certificate certifying the PQ.DevID key.
//!   4. POPULATE_PQ_CERT loads that DevID cert as the ML-DSA cert chain.
//!   5. GET_CERTIFICATE_CHAIN (SPDM GET_CERTIFICATE) returns the DevID cert;
//!      it verifies under the Root CA and certifies the PQ.DevID key.
//!   6. A measured child DPE context is derived (an attested component).
//!   7. CERTIFY_KEY issues the leaf cert; it is signed directly by the PQ.DevID
//!      key (the ML-DSA DPE profile has no intermediate alias).
//!   8. SIGN over a nonce (SPDM CHALLENGE) verifies under the certified leaf key.

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, PopulatePqCertReq, SignWithExportedMldsaReq,
    SignWithExportedMldsaResp,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus};
use dpe::{
    commands::{
        CertifyKeyCommand, CertifyKeyFlags, CertifyKeyMldsa87Cmd, Command, DeriveContextCmd,
        DeriveContextFlags, GetCertificateChainCmd, SignFlags, SignMldsa87Cmd,
    },
    context::ContextHandle,
    response::{CertifyKeyResp, Response, SignResp},
    tci::TciMeasurement,
    TCI_SIZE,
};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Builder, X509Name, X509NameBuilder, X509NameRef, X509Req, X509};
use platform::MAX_CHUNK_SIZE;
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{
    execute_dpe_cmd, get_pq_csr, mldsa_csr_public_key, provision_pq_seed, run_pqc_rt_test,
    DpeResult, TEST_DIGEST_MLDSA, TEST_LABEL,
};

const PROFILE: CaliptraDpeProfile = CaliptraDpeProfile::Mldsa;

/// Subject CN the ML-DSA DPE stamps as the leaf certificate's Issuer CN (see
/// `runtime/src/dpe_platform.rs`). The populated DevID cert uses the same Subject
/// CN so the leaf's issuer name resolves to it.
const DEVID_SUBJECT_CN: &str = "Caliptra 1.0 Rt Alias";

/// Generate a deterministic ML-DSA-87 key pair from `seed`.
fn gen_mldsa_key(seed: [u8; 32]) -> PKey<Private> {
    PKeyMlDsaBuilder::<Private>::from_seed(Variant::MlDsa87, &seed)
        .unwrap()
        .build()
        .unwrap()
}

/// Extract the raw 2592-byte ML-DSA-87 public key from a PKey.
fn raw_mldsa_pubkey(pkey: &PKey<Public>) -> Vec<u8> {
    PKeyMlDsaParams::<Public>::from_pkey(pkey)
        .unwrap()
        .public_key()
        .unwrap()
        .to_vec()
}

fn x509_name(cn: &str) -> X509Name {
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_text("CN", cn).unwrap();
    nb.build()
}

/// Common bits for building an ML-DSA X.509 cert: version, validity, CA basic
/// constraints, subject public key.
fn new_cert_builder(subject: &X509NameRef, serial: u32, pubkey: &PKey<Public>) -> X509Builder {
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap())
        .unwrap();
    b.set_subject_name(subject).unwrap();
    b.set_pubkey(pubkey).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    b
}

/// A test post-quantum Root CA: an ML-DSA-87 key pair and its self-signed CA
/// certificate. Guides the "stand up a CA, then issue certificates from it"
/// flow so a DevID cert can only be produced from a CA.
struct TestPqCa {
    key: PKey<Private>,
    cert: X509,
}

impl TestPqCa {
    /// Generate a deterministic ML-DSA-87 CA key pair and its self-signed root
    /// certificate.
    fn new() -> Self {
        let key = gen_mldsa_key([0x11; 32]);
        let name = x509_name("Caliptra Test PQ Root CA");
        let ca_pub = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
        let mut b = new_cert_builder(&name, 1, &ca_pub);
        b.set_issuer_name(&name).unwrap();
        b.sign(&key, MessageDigest::null()).unwrap();
        Self {
            key,
            cert: b.build(),
        }
    }

    /// Issue a DevID certificate certifying `devid_pubkey` (the PQ.DevID key),
    /// signed by this CA. The Subject CN matches the DPE leaf issuer CN so the
    /// leaf's issuer name resolves to it.
    fn issue_devid_cert(&self, devid_pubkey: &PKey<Public>) -> X509 {
        let subject = x509_name(DEVID_SUBJECT_CN);
        let mut b = new_cert_builder(&subject, 2, devid_pubkey);
        b.set_issuer_name(self.cert.subject_name()).unwrap();
        b.sign(&self.key, MessageDigest::null()).unwrap();
        b.build()
    }

    /// The CA key, for verifying certificates issued or chained under this CA.
    fn key(&self) -> &PKey<Private> {
        &self.key
    }
}

/// The CN component of an X.509 name, if present.
fn name_cn(name: &X509NameRef) -> Option<String> {
    name.entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
}

/// Load `der` as the ML-DSA cert chain via POPULATE_PQ_CERT.
fn populate_pq_cert_blob(model: &mut DefaultHwModel, der: &[u8]) {
    let mut cert = [0u8; PopulatePqCertReq::MAX_CERT_SIZE];
    cert[..der.len()].copy_from_slice(der);
    let mut cmd = MailboxReq::PopulatePqCert(PopulatePqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: der.len() as u32,
        cert,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_PQ_CERT),
            cmd.as_bytes().unwrap(),
        )
        .expect("POPULATE_PQ_CERT failed");
}

/// Retrieve the full ML-DSA DPE certificate chain (SPDM GET_CERTIFICATE),
/// concatenating chunks.
fn get_certificate_chain(model: &mut DefaultHwModel) -> Vec<u8> {
    let mut chain = Vec::new();
    let mut offset = 0;
    loop {
        let cmd = GetCertificateChainCmd {
            offset,
            size: MAX_CHUNK_SIZE as u32,
        };
        let Some(Response::GetCertificateChain(chunk)) = execute_dpe_cmd(
            PROFILE,
            model,
            &mut Command::GetCertificateChain(&cmd),
            DpeResult::Success,
        ) else {
            panic!("expected GetCertificateChain response");
        };
        chain.extend_from_slice(&chunk.certificate_chain[..chunk.certificate_size as usize]);
        offset += chunk.certificate_size;
        if chunk.certificate_size < MAX_CHUNK_SIZE as u32 {
            break;
        }
    }
    chain
}

#[test]
fn test_mldsa_full_attestation_workflow() {
    let mut model = run_pqc_rt_test();
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // 1. Provision the PQ.DevID identity.
    provision_pq_seed(&mut model);

    // 2. Obtain the PQ.DevID CSR and confirm it is self-signed by the PQ.DevID key.
    let csr_bytes = get_pq_csr(&mut model);
    let csr = X509Req::from_der(&csr_bytes).unwrap();
    let devid_pubkey = csr.public_key().unwrap();
    assert!(
        csr.verify(&devid_pubkey).unwrap(),
        "PQ.DevID CSR must be self-signed by the PQ.DevID key"
    );
    let devid_pubkey_raw = mldsa_csr_public_key(&csr_bytes);

    // 3. Stand up a test Root CA and issue a DevID cert over the PQ.DevID key.
    let ca = TestPqCa::new();
    let devid_cert = ca.issue_devid_cert(&devid_pubkey);
    let devid_der = devid_cert.to_der().unwrap();
    assert!(
        devid_der.len() <= PopulatePqCertReq::MAX_CERT_SIZE,
        "DevID cert ({} bytes) must fit the PQ cert chain buffer",
        devid_der.len()
    );
    // The DevID cert is CA-signed and certifies the PQ.DevID key.
    assert!(
        devid_cert.verify(ca.key()).unwrap(),
        "DevID cert must be signed by the Root CA"
    );
    assert_eq!(
        raw_mldsa_pubkey(&devid_cert.public_key().unwrap()),
        devid_pubkey_raw
    );

    // 4. Populate the ML-DSA cert chain with the DevID cert.
    populate_pq_cert_blob(&mut model, &devid_der);

    // 5. SPDM GET_CERTIFICATE: retrieve the chain, validate Root CA -> DevID.
    let chain = get_certificate_chain(&mut model);
    assert_eq!(
        chain, devid_der,
        "GET_CERTIFICATE_CHAIN must return the populated DevID cert verbatim"
    );
    let chain_devid = X509::from_der(&chain).unwrap();
    assert!(
        chain_devid.verify(ca.key()).unwrap(),
        "DevID cert in the chain must verify under the Root CA"
    );
    assert_eq!(
        raw_mldsa_pubkey(&chain_devid.public_key().unwrap()),
        devid_pubkey_raw,
        "DevID cert in the chain must certify the PQ.DevID key"
    );

    // 6. Derive a measured context (an attested component). MAKE_DEFAULT makes it
    //    the current context; INPUT_ALLOW_X509 lets it be certified as an X.509 leaf.
    let derive_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0xaa; TCI_SIZE]),
        flags: DeriveContextFlags::MAKE_DEFAULT | DeriveContextFlags::INPUT_ALLOW_X509,
        tci_type: u32::from_be_bytes(*b"TEST"),
        target_locality: 0,
        ..Default::default()
    };
    let Some(Response::DeriveContext(_)) = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::DeriveContext(&derive_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected DeriveContext response");
    };

    // 7. CERTIFY_KEY the measured context: the leaf is signed directly by the
    //    PQ.DevID key (the ML-DSA DPE profile has no intermediate alias).
    let certify_cmd = CertifyKeyMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCommand::FORMAT_X509,
    };
    let Some(Response::CertifyKey(CertifyKeyResp::Mldsa87(certify_resp))) = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&certify_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected CertifyKey Mldsa87 response");
    };

    let leaf_der = &certify_resp.cert[..certify_resp.header.cert_size as usize];
    let leaf = X509::from_der(leaf_der).unwrap();
    assert!(
        leaf.verify(&devid_pubkey).unwrap(),
        "DPE leaf cert must be signed by the PQ.DevID key certified in the DevID cert"
    );
    // Name chaining: the leaf's Issuer CN matches the DevID cert's Subject CN.
    assert_eq!(
        name_cn(leaf.issuer_name()).as_deref(),
        Some(DEVID_SUBJECT_CN)
    );
    assert_eq!(
        name_cn(chain_devid.subject_name()).as_deref(),
        Some(DEVID_SUBJECT_CN)
    );

    let leaf_pubkey = certify_resp.header.pubkey;

    // 8. SPDM CHALLENGE: sign a nonce with the leaf key; verify under the leaf pubkey.
    let nonce = TEST_DIGEST_MLDSA;
    let sign_cmd = SignMldsa87Cmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: SignFlags::empty(),
        digest: nonce,
    };
    let Some(Response::Sign(SignResp::Mldsa87(sign_resp))) = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::from(&sign_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected Sign Mldsa87 response");
    };

    assert_eq!(
        caliptra_mldsa::Mldsa87::verify_mu(&leaf_pubkey, &sign_resp.sig, &nonce),
        caliptra_mldsa::Mldsa87Result::Success,
        "challenge signature must verify under the certified leaf public key"
    );
}

/// Issue SIGN_WITH_EXPORTED_MLDSA for an exported-CDI `handle` and return the raw
/// response bytes.
fn sign_with_exported(
    model: &mut DefaultHwModel,
    handle: [u8; 32],
    sign_mode: u32,
    message: &[u8],
) -> Vec<u8> {
    let mut req = SignWithExportedMldsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: handle,
        sign_mode,
        message_size: message.len() as u32,
        message: [0u8; SignWithExportedMldsaReq::MAX_DATA_SIZE],
    };
    req.message[..message.len()].copy_from_slice(message);
    let mut cmd = MailboxReq::SignWithExportedMldsa(req);
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_MLDSA.into(),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("expected a SIGN_WITH_EXPORTED_MLDSA response")
}

/// The exported-CDI variant of the attestation workflow.
///
/// Steps 1-5 build the same CA-rooted DevID chain as
/// `test_mldsa_full_attestation_workflow`. Then, instead of a CERTIFY_KEY leaf,
/// it exercises the exported-CDI leg:
///   6. DeriveContext { EXPORT_CDI | CREATE_CERTIFICATE } produces an exported
///      CDI handle and its certificate, signed by the PQ.DevID key.
///   7. The exported cert chains to PQ.DevID (and thus to the CA-rooted DevID).
///   8. SIGN_WITH_EXPORTED_MLDSA (SPDM CHALLENGE) signs a nonce with the exported
///      key; the returned key matches the exported cert's subject key and the
///      signature verifies under it.
#[test]
fn test_mldsa_exported_cdi_attestation_workflow() {
    let mut model = run_pqc_rt_test();
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // 1. Provision the PQ.DevID identity.
    provision_pq_seed(&mut model);

    // 2. Obtain the PQ.DevID CSR and confirm it is self-signed by the PQ.DevID key.
    let csr_bytes = get_pq_csr(&mut model);
    let csr = X509Req::from_der(&csr_bytes).unwrap();
    let devid_pubkey = csr.public_key().unwrap();
    assert!(
        csr.verify(&devid_pubkey).unwrap(),
        "PQ.DevID CSR must be self-signed by the PQ.DevID key"
    );
    let devid_pubkey_raw = mldsa_csr_public_key(&csr_bytes);

    // 3. Stand up a test Root CA and issue a DevID cert over the PQ.DevID key.
    let ca = TestPqCa::new();
    let devid_cert = ca.issue_devid_cert(&devid_pubkey);
    let devid_der = devid_cert.to_der().unwrap();

    // 4. Populate the ML-DSA cert chain with the DevID cert.
    populate_pq_cert_blob(&mut model, &devid_der);

    // 5. SPDM GET_CERTIFICATE: retrieve the chain and validate Root CA -> DevID.
    let chain = get_certificate_chain(&mut model);
    let chain_devid = X509::from_der(&chain).unwrap();
    assert!(
        chain_devid.verify(ca.key()).unwrap(),
        "DevID cert in the chain must verify under the Root CA"
    );
    assert_eq!(
        raw_mldsa_pubkey(&chain_devid.public_key().unwrap()),
        devid_pubkey_raw,
        "DevID cert in the chain must certify the PQ.DevID key"
    );

    // 6. Export a CDI with a certificate (a measured, exportable component).
    let derive_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: TciMeasurement([0xbb; TCI_SIZE]),
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: u32::from_be_bytes(*b"EXPT"),
        target_locality: 0,
        ..Default::default()
    };
    let Some(Response::DeriveContextExportedCdi(export_resp)) = execute_dpe_cmd(
        PROFILE,
        &mut model,
        &mut Command::DeriveContext(&derive_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected DeriveContextExportedCdi response");
    };

    let handle = export_resp.header.exported_cdi;
    let exported_cert_der =
        &export_resp.new_certificate[..export_resp.header.certificate_size as usize];
    let exported_cert = X509::from_der(exported_cert_der).unwrap();

    // 7. The exported certificate is signed by the PQ.DevID key, so it chains to
    //    the CA-rooted DevID cert.
    assert!(
        exported_cert.verify(&devid_pubkey).unwrap(),
        "exported cert must be signed by the PQ.DevID key"
    );
    assert_eq!(
        name_cn(exported_cert.issuer_name()).as_deref(),
        Some(DEVID_SUBJECT_CN)
    );
    let exported_cert_pubkey_raw = raw_mldsa_pubkey(&exported_cert.public_key().unwrap());

    // 8. SPDM CHALLENGE: sign a nonce with the exported key via
    //    SIGN_WITH_EXPORTED_MLDSA and verify it against the exported cert's key.
    let nonce = b"spdm exported-cdi challenge nonce";
    let resp_bytes = sign_with_exported(
        &mut model,
        handle,
        SignWithExportedMldsaReq::SIGN_MODE_DATA,
        nonce,
    );
    let (sign_resp, _) = SignWithExportedMldsaResp::ref_from_prefix(resp_bytes.as_bytes()).unwrap();

    // The exported signing key matches the exported certificate's subject key.
    assert_eq!(
        sign_resp.derived_pubkey.as_slice(),
        exported_cert_pubkey_raw.as_slice(),
        "SIGN_WITH_EXPORTED_MLDSA key must match the exported certificate's subject key"
    );
    // The challenge signature verifies under that key.
    assert_eq!(
        caliptra_mldsa::Mldsa87::verify(&sign_resp.derived_pubkey, &sign_resp.signature, nonce),
        caliptra_mldsa::Mldsa87Result::Success,
        "challenge signature must verify under the exported key"
    );
}
