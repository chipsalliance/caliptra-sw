// Licensed under the Apache-2.0 license

use caliptra_common::{
    checksum::calc_checksum,
    mailbox_api::{CommandId, GetPqCertReq, GetPqCertResp, MailboxReq, MailboxReqHeader},
};
use caliptra_drivers::Mldsa87Signature;
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_x509::MlDsa87CertBuilder;
use openssl::pkey::Private;
use openssl::pkey_ctx::PkeyCtx;
use openssl::pkey_ml_dsa::{PKeyMlDsaBuilder, Variant as MlDsaVariant};
use openssl::signature::Signature;
use zerocopy::FromBytes;

use crate::common::{assert_error, run_pqc_rt_test};

fn make_req() -> GetPqCertReq {
    // Generate an ML-DSA87 key pair
    let pk_builder =
        PKeyMlDsaBuilder::<Private>::from_seed(MlDsaVariant::MlDsa87, &[0u8; 32]).unwrap();
    let priv_key = pk_builder.build().unwrap();

    // Sign the TBS with ML-DSA87
    let tbs: &[u8] = b"this is going to be the TBS";
    let mut sig_bytes = vec![];
    let mut ctx = PkeyCtx::new(&priv_key).unwrap();
    let mut algo = Signature::for_ml_dsa(MlDsaVariant::MlDsa87).unwrap();
    ctx.sign_message_init(&mut algo).unwrap();
    ctx.sign_to_vec(tbs, &mut sig_bytes).unwrap();

    // Build the request
    let sig = Mldsa87Signature::new(sig_bytes.try_into().unwrap());
    let mut tbs_buf = [0u8; GetPqCertReq::DATA_MAX_SIZE];
    tbs_buf[..tbs.len()].copy_from_slice(tbs);

    GetPqCertReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tbs: tbs_buf,
        tbs_size: tbs.len() as u32,
        signature: *sig,
    }
}

#[test]
fn test_get_pq_cert() {
    let mut model = run_pqc_rt_test();
    let req = make_req();

    // Manually build the expected cert
    let sig = Mldsa87Signature::new(req.signature);
    let builder = MlDsa87CertBuilder::new(&req.tbs[..req.tbs_size as usize], &sig).unwrap();
    let mut cert = [0u8; GetPqCertResp::DATA_MAX_SIZE];
    let cert_size = builder.build(&mut cert).unwrap();

    // Invoke the command
    let mut cmd = MailboxReq::GetPqCert(req);
    cmd.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CERT), cmd.as_bytes().unwrap())
        .unwrap()
        .unwrap();
    let (resp, _) = GetPqCertResp::ref_from_prefix(&resp_bytes).unwrap();

    assert_eq!(resp.cert_size as usize, cert_size);
    assert_eq!(&resp.cert[..cert_size], &cert[..cert_size]);
}

#[test]
fn test_get_pq_cert_tbs_size_too_large() {
    let mut model = run_pqc_rt_test();
    let req = make_req();
    let cmd = MailboxReq::GetPqCert(req);

    // Manually patch the request to inject the bad tbs_size, then re-checksum
    let mut raw = cmd.as_bytes().unwrap().to_vec();
    let bad_size = (GetPqCertReq::DATA_MAX_SIZE as u32 + 1).to_le_bytes();
    raw[4..8].copy_from_slice(&bad_size);
    let chksum = calc_checksum(u32::from(CommandId::GET_PQ_CERT), &raw[4..]);
    raw[0..4].copy_from_slice(&chksum.to_le_bytes());

    // Invoke the command
    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PQ_CERT), &raw)
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );
}
