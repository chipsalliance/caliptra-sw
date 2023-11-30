// Licensed under the Apache-2.0 license

use crate::common::{execute_dpe_cmd, generate_test_x509_cert, run_rt_test};
use caliptra_common::mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, PopulateIdevCertReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;
use dpe::{
    commands::{Command, GetCertificateChainCmd},
    response::Response,
};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    x509::X509,
};

fn get_full_cert_chain(model: &mut DefaultHwModel, out: &mut [u8; 4096]) -> usize {
    // first half
    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: 0,
        size: 2048,
    };
    let resp = execute_dpe_cmd(model, &mut Command::GetCertificateChain(get_cert_chain_cmd));
    let Response::GetCertificateChain(cert_chunk_1) = resp else {
        panic!("Wrong response type!");
    };
    out[..cert_chunk_1.certificate_size as usize]
        .copy_from_slice(&cert_chunk_1.certificate_chain[..cert_chunk_1.certificate_size as usize]);

    // second half
    let get_cert_chain_cmd = GetCertificateChainCmd {
        offset: cert_chunk_1.certificate_size,
        size: 2048,
    };
    let resp = execute_dpe_cmd(model, &mut Command::GetCertificateChain(get_cert_chain_cmd));
    let Response::GetCertificateChain(cert_chunk_2) = resp else {
        panic!("Wrong response type!");
    };
    out[cert_chunk_1.certificate_size as usize
        ..cert_chunk_1.certificate_size as usize + cert_chunk_2.certificate_size as usize]
        .copy_from_slice(&cert_chunk_2.certificate_chain[..cert_chunk_2.certificate_size as usize]);

    cert_chunk_1.certificate_size as usize + cert_chunk_2.certificate_size as usize
}

// Will panic if any of the cert chain chunks is not a valid X.509 cert
fn parse_cert_chain(cert_chain: &[u8], cert_chain_size: usize, expected_num_certs: u32) {
    let mut i = 0;
    let mut cert_count = 0;
    while i < cert_chain_size {
        let curr_cert = X509::from_der(&cert_chain[i..]).unwrap();
        i += curr_cert.to_der().unwrap().len();
        cert_count += 1;
    }
    assert_eq!(expected_num_certs, cert_count);
}

#[test]
fn test_populate_idev_cert_cmd() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cert_chain_without_idev_cert = [0u8; 4096];
    let cert_chain_len_without_idev_cert =
        get_full_cert_chain(&mut model, &mut cert_chain_without_idev_cert);

    // generate test idev cert
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = PKey::from_ec_key(EcKey::generate(&ec_group).unwrap()).unwrap();

    let cert = generate_test_x509_cert(ec_key);

    // copy der encoded idev cert
    let cert_bytes = cert.to_der().unwrap();
    let mut cert_slice = [0u8; PopulateIdevCertReq::MAX_CERT_SIZE];
    cert_slice[..cert_bytes.len()].copy_from_slice(&cert_bytes);

    let mut pop_idev_cmd = MailboxReq::PopulateIdevCert(PopulateIdevCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: cert_bytes.len() as u32,
        cert: cert_slice,
    });
    pop_idev_cmd.populate_chksum().unwrap();

    // call populate idev cert so that the idev cert is added to the certificate chain
    model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_IDEV_CERT),
            pop_idev_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let mut cert_chain_with_idev_cert = [0u8; 4096];
    let cert_chain_len_with_idev_cert =
        get_full_cert_chain(&mut model, &mut cert_chain_with_idev_cert);

    // read idev cert from prefix of cert chain and parse it as X509
    let idev_len = cert_chain_len_with_idev_cert - cert_chain_len_without_idev_cert;
    let idev_cert = X509::from_der(&cert_chain_with_idev_cert[..idev_len]).unwrap();
    assert_eq!(idev_cert, cert);

    // ensure rest of cert chain is not corrupted
    assert_eq!(
        cert_chain_without_idev_cert[..cert_chain_len_without_idev_cert],
        cert_chain_with_idev_cert[idev_len..cert_chain_len_with_idev_cert]
    );
    parse_cert_chain(
        &cert_chain_with_idev_cert[idev_len..],
        cert_chain_len_with_idev_cert - idev_len,
        3,
    );
}

#[test]
fn test_populate_idev_cert_size_too_big() {
    // Test with cert_size too big.
    let mut pop_idev_cmd = MailboxReq::PopulateIdevCert(PopulateIdevCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cert_size: PopulateIdevCertReq::MAX_CERT_SIZE as u32 + 1,
        cert: [0u8; PopulateIdevCertReq::MAX_CERT_SIZE],
    });
    assert_eq!(
        pop_idev_cmd.populate_chksum(),
        Err(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    );
}
