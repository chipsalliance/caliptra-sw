/*++

Licensed under the Apache-2.0 license.

File Name:

    get_attested_pq_csr.rs

Abstract:

    File contains the GET_ATTESTED_PQ_CSR mailbox command.

    Returns the PQ.DevID ML-DSA-87 CSR wrapped in an OCP Device Identity
    Provisioning attested-CSR EAT, signed with the RT Alias ECC P-384 key as a
    CWT-tagged COSE_Sign1 (ES384). With `key_id == 0` it instead returns the
    signed keypair inventory discovery token.

    The CBOR/COSE framing is not encoded at runtime: `build.rs` runs the
    `caliptra-ocp-eat` encoder (from caliptra-sw main) over marker values and
    emits the surrounding bytes as constants. This module splices the runtime
    values (nonce, CSR, key identifier, signature) into those templates.

--*/

use crate::get_pq_csr::{GetPqCsrCmd, PqCsrOutput};
use crate::packet::{copy_from_mbox, finalize_mbox_buffer};
use crate::{Drivers, MboxResponseWriter};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    GetAttestedPqCsrReq, GetAttestedPqCsrResp, MailboxRespHeader, MailboxRespHeaderVarSize,
};
use caliptra_dpe_response_buffer::ResponseBuffer;
use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Ecc384PrivKeyIn, Ecc384Scalar, KeyReadArgs,
    Mldsa87Signature, Sha256Alg,
};
use caliptra_x509::{
    PqDevIdCsrTbsMlDsa87, RtAliasCertTbsEcc384Params, MAX_CERT_FRAMING_LEN,
    MAX_MLDSA87_SIG_DER_LEN, MLDSA87_OID_DER_LEN,
};
use core::mem::size_of;
use zerocopy::{FromZeros, IntoBytes};

include!(concat!(env!("OUT_DIR"), "/attested_csr_template.rs"));

/// Length of the COSE `kid` (RT Alias X.509 subject key identifier).
const KID_LEN: usize = RtAliasCertTbsEcc384Params::SUBJECT_KEY_ID_LEN;

/// ES384 raw signature length (r || s).
const ECC384_SIG_LEN: usize = 2 * size_of::<Ecc384Scalar>();

/// Upper bound on the DER-encoded PQ.DevID CSR: TBS + ML-DSA-87 signature DER
/// + algorithm identifier and outer SEQUENCE framing.
const MAX_PQ_CSR_SIZE: usize = MAX_CERT_FRAMING_LEN
    + PqDevIdCsrTbsMlDsa87::TBS_TEMPLATE_LEN
    + MLDSA87_OID_DER_LEN
    + MAX_MLDSA87_SIG_DER_LEN;

pub struct GetAttestedPqCsrCmd;

impl GetAttestedPqCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        let mut cmd = GetAttestedPqCsrReq::new_zeroed();
        copy_from_mbox(drivers, cmd.as_mut_bytes())?;
        let nonce = cmd.nonce;

        match cmd.key_id {
            GetAttestedPqCsrReq::KEY_ID_INVENTORY => Self::sign_and_send(
                drivers,
                &[&KEYPAIR_INVENTORY_PREFIX, &nonce, &KEYPAIR_INVENTORY_SUFFIX],
            ),
            GetAttestedPqCsrReq::KEY_ID_PQ_DEVID => {
                GetPqCsrCmd::generate_and_emit(drivers, PqCsrOutput::AttestedCsr(nonce))
            }
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }

    /// Assemble the PQ.DevID CSR and wrap it in the CSR EAT claims. Called from
    /// `GetPqCsrCmd::generate_and_emit`; inline-never so the CSR buffer does
    /// not coexist with the ML-DSA keygen/sign frames.
    #[inline(never)]
    pub(crate) fn send_attested_csr(
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        tbs: &[u8],
        sig: &Mldsa87Signature,
    ) -> CaliptraResult<()> {
        let mut csr_buf = [0u8; MAX_PQ_CSR_SIZE];
        let csr_len = GetPqCsrCmd::build_csr(tbs, sig, &mut csr_buf)?;
        let csr = csr_buf
            .get(..csr_len)
            .ok_or(CaliptraError::RUNTIME_PQ_CSR_BUILDER_BUILD_FAILURE)?;

        let mut csr_hdr = [0u8; CBOR_MAX_BSTR_HEADER_LEN];
        let csr_hdr_len = write_cbor_bstr_header(&mut csr_hdr, csr.len())?;

        Self::sign_and_send(
            drivers,
            &[
                &CSR_EAT_PREFIX,
                nonce,
                &CSR_EAT_CLAIM_KEY_CSR,
                &csr_hdr[..csr_hdr_len],
                csr,
                &CSR_EAT_SUFFIX_PQ_DEVID,
            ],
        )
    }

    /// Sign the EAT claims `payload` (given as concatenated pieces) with the RT
    /// Alias key and write the CWT-tagged COSE_Sign1 envelope directly to
    /// mailbox SRAM.
    #[inline(never)]
    fn sign_and_send(drivers: &mut Drivers, payload: &[&[u8]]) -> CaliptraResult<()> {
        let payload_len = payload
            .iter()
            .try_fold(0usize, |acc, p| acc.checked_add(p.len()))
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        let mut payload_hdr = [0u8; CBOR_MAX_BSTR_HEADER_LEN];
        let payload_hdr_len = write_cbor_bstr_header(&mut payload_hdr, payload_len)?;
        let payload_hdr = payload_hdr
            .get(..payload_hdr_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        let data_len = COSE_PREAMBLE_ECC_BEFORE_KID.len()
            + KID_LEN
            + COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN.len()
            + payload_hdr.len()
            + payload_len
            + COSE_ECC_SIG_BSTR_HEADER.len()
            + ECC384_SIG_LEN;
        if data_len > GetAttestedPqCsrResp::DATA_MAX_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE);
        }

        // COSE `kid`: RT Alias subject key identifier, matching the SKI in the
        // RT Alias certificate (first 20 bytes of SHA-256 over the DER pubkey).
        let rt_pub_key = drivers.persistent_data.get().fht.rt_dice_pub_key;
        let ski: [u8; 32] = drivers.sha256.digest(&rt_pub_key.to_der())?.into();
        let kid = ski
            .get(..KID_LEN)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        // SHA-384 over the COSE Sig_structure, streamed.
        let mut digest = Array4x12::default();
        {
            let mut op = drivers.sha384.digest_init()?;
            let head: [&[u8]; 4] = [
                &SIG_PREAMBLE_ECC_BEFORE_KID,
                kid,
                &SIG_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN,
                payload_hdr,
            ];
            for piece in head.iter().chain(payload) {
                op.update(piece)?;
            }
            op.finalize(&mut digest)?;
        }

        // ES384 signature with the RT Alias private key.
        let key_id_rt_priv_key =
            Drivers::get_key_id_rt_priv_key(&drivers.persistent_data.get().fht)?;
        let priv_key = Ecc384PrivKeyIn::Key(KeyReadArgs::new(key_id_rt_priv_key));
        let signature = drivers
            .ecc384
            .sign(&priv_key, &rt_pub_key, &digest, &mut drivers.trng)?;
        let r: [u8; 48] = signature.r.into();
        let s: [u8; 48] = signature.s.into();

        // Emit the COSE_Sign1 envelope after the variable-size response header.
        let mut writer = MboxResponseWriter::from_mbox_base();
        let mut offset = size_of::<MailboxRespHeaderVarSize>();
        let mut write = |bytes: &[u8]| -> CaliptraResult<()> {
            writer
                .write_at(offset, bytes)
                .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE)?;
            offset += bytes.len();
            Ok(())
        };
        write(&COSE_PREAMBLE_ECC_BEFORE_KID)?;
        write(kid)?;
        write(&COSE_ECC_AFTER_KID_BEFORE_PAYLOAD_LEN)?;
        write(payload_hdr)?;
        for piece in payload {
            write(piece)?;
        }
        write(&COSE_ECC_SIG_BSTR_HEADER)?;
        write(&r)?;
        write(&s)?;

        if offset - size_of::<MailboxRespHeaderVarSize>() != data_len {
            return Err(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR);
        }

        let header = MailboxRespHeaderVarSize {
            hdr: MailboxRespHeader::default(),
            data_len: data_len as u32,
        };
        finalize_mbox_buffer(&mut drivers.mbox, &mut writer, header)
    }
}

/// Write a CBOR major-type-2 (byte string) header for `len` into `buf`.
/// Returns the header length.
fn write_cbor_bstr_header(
    buf: &mut [u8; CBOR_MAX_BSTR_HEADER_LEN],
    len: usize,
) -> CaliptraResult<usize> {
    if len <= CBOR_MAX_INLINE_LEN {
        buf[0] = CBOR_BYTE_STRING_TINY_BASE | (len as u8);
        Ok(1)
    } else if len <= u8::MAX as usize {
        buf[0] = CBOR_BYTE_STRING_1BYTE_LEN;
        buf[1] = len as u8;
        Ok(2)
    } else if len <= u16::MAX as usize {
        buf[0] = CBOR_BYTE_STRING_2BYTE_LEN;
        buf[1..3].copy_from_slice(&(len as u16).to_be_bytes());
        Ok(3)
    } else {
        Err(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)
    }
}
