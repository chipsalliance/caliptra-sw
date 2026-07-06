/*++

Licensed under the Apache-2.0 license.

File Name:

    get_pq_csr.rs

Abstract:

    File contains the GET_PQ_CSR mailbox command, which returns the PQ.DevID
    ML-DSA-87 self-signed Certificate Signing Request.

    Unlike the ECDSA IDevID/LDevID CSRs -- which are generated once and cached
    in persistent storage -- the ML-DSA-87 CSR (~7.4 KB) is too large to store.
    Instead it is regenerated on demand: the PQ.DevID key pair is re-derived from
    the persisted PQ.DevID CDI, the CSR `To Be Signed` structure is rebuilt from
    a static template, and it is signed deterministically so that repeated calls
    return an identical CSR.

--*/

use crate::packet::{copy_from_mbox, copy_to_mbox};
use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{GetPqCsrReq, GetPqCsrResp};
use caliptra_drivers::{
    hmac384_kdf, Array4x12, CaliptraError, CaliptraResult, Mldsa87, Mldsa87PubKey, Mldsa87Seed,
    Mldsa87Signature, Sha256Alg, MLDSA87_PRIVATE_SEED_BYTES,
};
use caliptra_x509::{MlDsa87CsrBuilder, PqDevIdCsrTbsMlDsa87, PqDevIdCsrTbsMlDsa87Params};
use crypto::Digest;
use zerocopy::{FromZeros, IntoBytes};
use zeroize::{Zeroize, Zeroizing};

pub struct GetPqCsrCmd;

impl GetPqCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        copy_from_mbox(drivers, GetPqCsrReq::new_zeroed().as_mut_bytes())?;

        // The PQ.DevID CDI is only present once a seed has been provisioned via
        // SET_PQ_SEED. Without it there is no identity to certify.
        if !drivers.persistent_data.get().pqc_mode_enabled() {
            return Err(CaliptraError::RUNTIME_PQC_NOT_INITIALIZED);
        }

        // Re-derive the PQ.DevID ML-DSA-87 seed from the PQ.DevID CDI (held in
        // persistent data). The seed is transient and zeroized as soon as the
        // key pair operations are done.
        let mut seed = Mldsa87Seed::default();
        Self::derive_devid_seed(drivers, &mut seed)?;

        // Regenerate the PQ.DevID public key from the seed.
        let mut public_key = Mldsa87PubKey::default();
        Mldsa87::pub_from_seed(&seed, &mut public_key, None)?;

        // Compute the subject serial number (uppercase hex of SHA-256 over the
        // encoded public key) and the unique endpoint identifier.
        let subject_sn = Self::subject_sn(drivers, &public_key)?;
        let ueid = drivers.soc_ifc.fuse_bank().ueid();

        // Build the CSR `To Be Signed` structure from the static template.
        let params = PqDevIdCsrTbsMlDsa87Params {
            public_key: &public_key,
            subject_sn: &subject_sn,
            ueid: &ueid,
        };
        let tbs = PqDevIdCsrTbsMlDsa87::new(&params);

        // Sign the TBS deterministically with the PQ.DevID private key.
        let mut sig = Mldsa87Signature::default();
        Mldsa87::sign_deterministic(&seed, tbs.tbs(), &mut sig)?;

        // Seed and derived key material are no longer needed.
        drop(seed);
        public_key.zeroize();

        // Assemble and send the CSR in a separate (inline-never) frame. The
        // response buffer is ~12.8 KB; keeping it out of this frame ensures it
        // does not coexist on the stack with the large ML-DSA keygen/sign frames
        // above, which together would overflow the runtime stack.
        Self::assemble_and_send_csr(drivers, tbs.tbs(), &sig)
    }

    /// Build the CSR from `tbs`/`sig` into the mailbox response buffer and send
    /// it. Isolated in its own stack frame; see the caller for why.
    #[inline(never)]
    fn assemble_and_send_csr(
        drivers: &mut Drivers,
        tbs: &[u8],
        sig: &Mldsa87Signature,
    ) -> CaliptraResult<()> {
        let mut resp = GetPqCsrResp::new_zeroed();
        let builder = MlDsa87CsrBuilder::new(tbs, sig)
            .ok_or(CaliptraError::RUNTIME_PQ_CSR_BUILDER_INIT_FAILURE)?;
        let csr_len = builder
            .build(&mut resp.data)
            .ok_or(CaliptraError::RUNTIME_PQ_CSR_BUILDER_BUILD_FAILURE)?;
        resp.data_size = csr_len as u32;

        copy_to_mbox(drivers, resp.as_mut_bytes())
    }

    /// Derive the PQ.DevID ML-DSA-87 seed from the PQ.DevID CDI stored in
    /// persistent data.
    ///
    /// This mirrors the ROM DICE convention of deriving the DevID key pair from
    /// the DevID CDI, so the CSR here matches the PQ.DevID identity used
    /// elsewhere in the runtime. The CDI is provisioned by SET_PQ_SEED and lives
    /// in persistent data.
    #[inline(never)]
    fn derive_devid_seed(drivers: &mut Drivers, seed: &mut Mldsa87Seed) -> CaliptraResult<()> {
        let cdi = Zeroizing::new(Array4x12::from(&drivers.persistent_data.get().pq_devid_cdi));
        let mut output = Zeroizing::new(Array4x12::default());
        hmac384_kdf(
            &mut drivers.hmac384,
            (&*cdi).into(),
            b"pq_devid_keygen",
            None,
            &mut drivers.trng,
            (&mut *output).into(),
        )?;

        let bytes = Zeroizing::new(<[u8; core::mem::size_of::<Array4x12>()]>::from(*output));
        seed.copy_from_slice(&bytes[..MLDSA87_PRIVATE_SEED_BYTES]);
        Ok(())
    }

    /// Compute the X.509 subject serial number: the uppercase hex encoding of
    /// the SHA-256 digest of the encoded public key.
    ///
    /// This matches the RT alias serial-number derivation (see
    /// `Drivers::compute_rt_alias_sn` and `DpePlatform::get_issuer_name`), which
    /// hashes the public key and formats it via `Digest::write_hex_str`.
    #[inline(never)]
    fn subject_sn(
        drivers: &mut Drivers,
        public_key: &Mldsa87PubKey,
    ) -> CaliptraResult<[u8; PqDevIdCsrTbsMlDsa87Params::SUBJECT_SN_LEN]> {
        let digest = Digest::Sha256(crypto::Sha256(
            drivers.sha256.digest(public_key.as_slice())?.into(),
        ));
        let mut subject_sn = [0u8; PqDevIdCsrTbsMlDsa87Params::SUBJECT_SN_LEN];
        digest
            .write_hex_str(&mut subject_sn)
            .map_err(|_| CaliptraError::RUNTIME_PQ_CSR_SUBJECT_SN_FAILED)?;
        Ok(subject_sn)
    }
}
