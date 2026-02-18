// Licensed under the Apache-2.0 license

use crate::mutrefbytes;
use crate::Drivers;
use caliptra_api::mailbox::{GetAttestedEccCsrReq, GetAttestedMldsaCsrReq};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{AttestedCsrResp, ResponseVarSize};
use caliptra_common::x509;
use caliptra_drivers::{KeyReadArgs, Mldsa87Seed, Mldsa87SignRnd};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_x509::{
    LocalDevIdCsrTbsEcc384, LocalDevIdCsrTbsEcc384Params, LocalDevIdCsrTbsMlDsa87,
    LocalDevIdCsrTbsMlDsa87Params,
};
use ocp_eat::csr_eat::{oids, CsrEatClaims, TaggedOid};
use ocp_eat::{cbor_tags, CborEncoder, CoseSign1, ProtectedHeader};
use zerocopy::{FromBytes, IntoBytes};

// Maximum size for CSR EAT claims payload (CBOR encoded)
// Calculation for ML-DSA CSR (worst case):
// - Map header: 1 byte
// - Nonce claim (32 bytes): 1 (key) + 2 (byte string header) + 32 (data) = 35 bytes
// - CSR claim (7680 bytes): 5 (key) + 3 (byte string header) + 7680 (data) = 7688 bytes
// - Attributes claim (1 OID): 5 (key) + 1 (array) + 2 (tag) + 1 (byte string) + 11 (OID) = 20 bytes
// Total: ~7744 bytes, rounded to 8KB for safety
const MAX_CSR_EAT_CLAIMS_SIZE: usize = 8192;

// Maximum size for COSE Sign1 signature context (Sig_structure)
// Calculation:
// - Array header (4 items): 1 byte
// - Context string "Signature1": 11 bytes (header + 10 chars)
// - Protected header (byte string): ~102 bytes
//   - Algorithm (alg: -35 for ES384): ~3 bytes
//   - Content-type ("application/eat+cwt"): ~26 bytes
//   - Key ID (64-byte subject SN): ~67 bytes
//   - Encoded map + byte string wrapper: ~6 bytes
// - External AAD (empty): 1 byte
// - Payload (CSR EAT claims as byte string): ~7747 bytes (3 bytes header + 7744 data)
// Total: ~7862 bytes, rounded to 8KB for safety
const MAX_SIGN_CONTEXT_SIZE: usize = 8192;
const MAX_CSR_SIZE: usize = 8192;

enum CryptoType {
    ECC384,
    MLDSA87,
}

struct CsrData {
    data: [u8; MAX_CSR_SIZE],
    len: usize,
}

enum DevIdKeyType {
    LdevId = 1,
    FmcAlias = 2,
    RtAlias = 3,
}

impl TryFrom<u32> for DevIdKeyType {
    type Error = CaliptraError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DevIdKeyType::LdevId),
            2 => Ok(DevIdKeyType::FmcAlias),
            3 => Ok(DevIdKeyType::RtAlias),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }
}

impl DevIdKeyType {
    fn to_kda_oid(&self) -> TaggedOid {
        match self {
            DevIdKeyType::LdevId => TaggedOid::new(oids::OCP_SECURITY_OID_KDA_OWNER_ENTROPY_FUSE),
            DevIdKeyType::FmcAlias => TaggedOid::new(oids::OCP_SECURITY_OID_KDA_FIRST_MUTABLE_CODE),
            DevIdKeyType::RtAlias => {
                TaggedOid::new(oids::OCP_SECURITY_OID_KDA_NON_FIRST_MUTABLE_CODE)
            }
        }
    }

    fn generate_ecc_csr(&self, drivers: &mut Drivers) -> CaliptraResult<CsrData> {
        let mut csr_data = [0u8; 8192]; // 8K should be sufficient for CSR (self signed or null signed)

        let csr_len: usize = match self {
            DevIdKeyType::LdevId => {
                let pub_key = drivers
                    .persistent_data
                    .get()
                    .rom
                    .data_vault
                    .ldev_dice_ecc_pub_key();
                let subject_sn = x509::subj_sn(
                    &mut drivers.sha256,
                    &caliptra_common::crypto::PubKey::Ecc(&pub_key),
                )?;
                let ueid = x509::ueid(&drivers.soc_ifc)?;
                let params = LocalDevIdCsrTbsEcc384Params {
                    public_key: &pub_key.to_der(),
                    subject_sn: &subject_sn,
                    ueid: &ueid,
                };

                let csr = LocalDevIdCsrTbsEcc384::new(&params);
                let len = csr.tbs().len();
                csr_data[..len].copy_from_slice(csr.tbs());

                Ok(len)
            }
            DevIdKeyType::FmcAlias => {
                crate::cprintln!("TODO: Generate attested CSR for FMC Alias key");
                Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
            }
            DevIdKeyType::RtAlias => {
                crate::cprintln!("TODO: Generate attested CSR for RT Alias key");
                Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
            }
        }?;

        Ok(CsrData {
            data: csr_data,
            len: csr_len,
        })
    }

    fn generate_mldsa_csr(&self, drivers: &mut Drivers) -> CaliptraResult<CsrData> {
        let mut csr_data = [0u8; 8192]; // 8K should be sufficient for CSR (self signed or null signed)

        let csr_len: usize = match self {
            DevIdKeyType::LdevId => {
                let pub_key = drivers
                    .persistent_data
                    .get()
                    .rom
                    .data_vault
                    .ldev_dice_mldsa_pub_key();
                let subject_sn = x509::subj_sn(
                    &mut drivers.sha256,
                    &caliptra_common::crypto::PubKey::Mldsa(&pub_key),
                )?;
                let ueid = x509::ueid(&drivers.soc_ifc)?;
                let params = LocalDevIdCsrTbsMlDsa87Params {
                    public_key: &pub_key.into(),
                    subject_sn: &subject_sn,
                    ueid: &ueid,
                };

                let csr = LocalDevIdCsrTbsMlDsa87::new(&params);
                let len = csr.tbs().len();
                csr_data[..len].copy_from_slice(csr.tbs());

                Ok(len)
            }
            DevIdKeyType::FmcAlias => {
                crate::cprintln!("TODO: Generate attested CSR for FMC Alias key");
                Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
            }
            DevIdKeyType::RtAlias => {
                crate::cprintln!("TODO: Generate attested CSR for RT Alias key");
                Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)
            }
        }?;

        Ok(CsrData {
            data: csr_data,
            len: csr_len,
        })
    }

    fn generate_csr_eat_claims(
        &self,
        drivers: &mut Drivers,
        nonce: &[u8; 32],
        eat_buffer: &mut [u8],
        crypto: CryptoType,
    ) -> CaliptraResult<usize> {
        let attributes = [self.to_kda_oid()];
        // generate CSR for key identified by key_id
        let csr_data = match crypto {
            CryptoType::ECC384 => self.generate_ecc_csr(drivers),
            CryptoType::MLDSA87 => self.generate_mldsa_csr(drivers),
        }?;

        let env_signed_csr =
            CsrEatClaims::with_nonce(&csr_data.data[..csr_data.len], &attributes, nonce);
        let mut cbor_eat_encoder = CborEncoder::new(eat_buffer);

        env_signed_csr
            .encode(&mut cbor_eat_encoder)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;

        Ok(cbor_eat_encoder.len())
    }

    fn generate_attested_ecc_csr(
        &self,
        drivers: &mut Drivers,
        payload: &[u8],
        rt_key_id: &[u8; 20],
        signed_eat_buffer: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Get RT public key
        let rt_pub_key = drivers.persistent_data.get().rom.fht.rt_dice_ecc_pub_key;

        // Create protected header
        let mut protected_header = ProtectedHeader::new_es384();
        protected_header.kid = Some(rt_key_id);

        let cose_sign1 = CoseSign1::new(signed_eat_buffer)
            .protected_header(&protected_header)
            .payload(payload);

        let mut signature_ctx_buffer = [0u8; MAX_SIGN_CONTEXT_SIZE];
        let sign_ctx_len = cose_sign1
            .get_signature_context(&mut signature_ctx_buffer)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        // Hash the signature context using SHA384
        let signature_slice = &signature_ctx_buffer
            .get(..sign_ctx_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
        let digest = drivers.sha2_512_384.sha384_digest(signature_slice);
        let digest = caliptra_drivers::okref(&digest)?;

        // Get RT Alias private key from key vault
        let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;

        // Sign the digest with RT Alias private key
        let priv_key_args = KeyReadArgs::new(key_id_rt_priv_key);
        let priv_key = caliptra_drivers::Ecc384PrivKeyIn::Key(priv_key_args);
        let signature = drivers
            .ecc384
            .sign(priv_key, &rt_pub_key, digest, &mut drivers.trng)?;

        // Convert signature to [u8; 96] format (r || s)
        let mut ecc384_signature = [0u8; 96];
        let r_bytes: [u8; 48] = signature.r.into();
        let s_bytes: [u8; 48] = signature.s.into();
        ecc384_signature[..48].copy_from_slice(&r_bytes);
        ecc384_signature[48..].copy_from_slice(&s_bytes);

        // Complete encoding COSE Sign1 structure with signature and CWT tag
        let signed_eat_len = cose_sign1
            .signature(&ecc384_signature)
            .encode(Some(&[cbor_tags::CWT]))
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        Ok(signed_eat_len)
    }

    fn generate_attested_mldsa_csr(
        &self,
        drivers: &mut Drivers,
        payload: &[u8],
        rt_key_id: &[u8; 20],
        signed_eat_buffer: &mut [u8],
    ) -> CaliptraResult<usize> {
        // Get RT public key
        let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;

        // Create protected header
        let mut protected_header = ProtectedHeader::new_es384();
        protected_header.kid = Some(rt_key_id);

        let cose_sign1 = CoseSign1::new(signed_eat_buffer)
            .protected_header(&protected_header)
            .payload(payload);

        let mut signature_ctx_buffer = [0u8; MAX_SIGN_CONTEXT_SIZE];
        let sign_ctx_len = cose_sign1
            .get_signature_context(&mut signature_ctx_buffer)
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        // Hash the signature context using SHA384
        let signature_slice = &signature_ctx_buffer
            .get(..sign_ctx_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;
        let digest = drivers.sha2_512_384.sha384_digest(signature_slice);
        let digest = caliptra_drivers::okref(&digest)?;

        let rt_seed = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
        let key_args = KeyReadArgs::new(rt_seed);

        let signature = drivers.mldsa87.sign_var(
            Mldsa87Seed::Key(key_args),
            &rt_pub_key,
            digest.as_bytes(),
            &Mldsa87SignRnd::default(),
            &mut drivers.trng,
        )?;

        // Complete encoding COSE Sign1 structure with signature and CWT tag
        let signed_eat_len = cose_sign1
            .signature(signature.as_bytes())
            .encode(Some(&[cbor_tags::CWT]))
            .map_err(|_| CaliptraError::RUNTIME_ATTESTED_CSR_COSE_SIGN1_ENCODING_ERROR)?;

        Ok(signed_eat_len)
    }
}

pub struct AttestedEccCsrCmd;

impl AttestedEccCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        crate::cprintln!("Executing attested ECC CSR command");
        // Convert cmd_args to GetAttestedEccCsrReq
        let cmd = GetAttestedEccCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        // Extract key_id and nonce
        let key_type = DevIdKeyType::try_from(cmd.key_id)?;
        let nonce = cmd.nonce;
        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE]; // 8K should be sufficient for CSR (self signed or null signed)
        let csr_eat_len = key_type.generate_csr_eat_claims(
            drivers,
            &nonce,
            &mut env_csr_eat,
            CryptoType::ECC384,
        )?;

        // Compute RT Alias subject key identifier for COSE header kid
        let rt_pub_key = drivers.persistent_data.get().rom.fht.rt_dice_ecc_pub_key;
        let rt_subj_sn = x509::subj_key_id(
            &mut drivers.sha256,
            &caliptra_common::crypto::PubKey::Ecc(&rt_pub_key),
        )?;

        // Sign EAT using COSE Sign1 with RT Alias private key
        let resp = mutrefbytes::<AttestedCsrResp>(mbox_resp)?;
        let csr_slice = &env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        let signed_eat_len = key_type.generate_attested_ecc_csr(
            drivers,
            csr_slice,
            &rt_subj_sn,
            resp.data.as_mut(),
        )?;

        resp.data_size = signed_eat_len as u32;
        resp.partial_len()
    }
}

pub struct AttestedMldsaCsrCmd;

impl AttestedMldsaCsrCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        mbox_resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        crate::cprintln!("Executing attested MLDSA CSR command");
        // Convert cmd_args to GetAttestedMldsaCsrReq
        let cmd = GetAttestedMldsaCsrReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        // Extract key_id and nonce
        let key_type = DevIdKeyType::try_from(cmd.key_id)?;
        let nonce = cmd.nonce;
        let mut env_csr_eat = [0u8; MAX_CSR_EAT_CLAIMS_SIZE]; // 8K should be sufficient for CSR (self signed or null signed)
        let csr_eat_len = key_type.generate_csr_eat_claims(
            drivers,
            &nonce,
            &mut env_csr_eat,
            CryptoType::MLDSA87,
        )?;

        // Compute RT Alias subject key identifier for COSE header kid
        let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers)?;
        let rt_subj_sn = x509::subj_key_id(
            &mut drivers.sha256,
            &caliptra_common::crypto::PubKey::Mldsa(&rt_pub_key),
        )?;

        // Sign EAT using COSE Sign1 with RT Alias private key
        let resp = mutrefbytes::<AttestedCsrResp>(mbox_resp)?;
        let csr_slice = &env_csr_eat
            .get(..csr_eat_len)
            .ok_or(CaliptraError::RUNTIME_ATTESTED_CSR_EAT_ENCODING_ERROR)?;
        let signed_eat_len = key_type.generate_attested_mldsa_csr(
            drivers,
            csr_slice,
            &rt_subj_sn,
            resp.data.as_mut(),
        )?;

        resp.data_size = signed_eat_len as u32;
        resp.partial_len()
    }
}
