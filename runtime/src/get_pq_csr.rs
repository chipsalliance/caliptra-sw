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

use crate::get_attested_pq_csr::GetAttestedPqCsrCmd;
use crate::packet::{copy_req_hdr_from_mbox, copy_to_mbox};
use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{GetPqCsrReq, GetPqCsrResp};
use caliptra_drivers::{CaliptraError, CaliptraResult, Mldsa87, Mldsa87Signature};
use caliptra_x509::{MlDsa87CsrBuilder, PqDevIdCsrTbsMlDsa87, PqDevIdCsrTbsMlDsa87Params};
use zerocopy::{FromZeros, IntoBytes};

pub struct GetPqCsrCmd;

/// How the regenerated PQ.DevID CSR is returned to the caller.
pub(crate) enum PqCsrOutput {
    /// GET_PQ_CSR: raw DER CSR.
    Csr,
    /// GET_ATTESTED_PQ_CSR: CSR wrapped in an RT Alias-signed EAT bound to
    /// the given nonce.
    AttestedCsr([u8; 32]),
}

impl GetPqCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        copy_req_hdr_from_mbox::<GetPqCsrReq>(drivers)?;
        Self::generate_and_emit(drivers, PqCsrOutput::Csr)
    }

    /// Re-derive the PQ.DevID key pair, build the CSR `To Be Signed` structure,
    /// sign it deterministically with the PQ.DevID private key, then send the
    /// CSR in the requested `output` form.
    ///
    /// Shared by GET_PQ_CSR and GET_ATTESTED_PQ_CSR so the code exists once and
    /// both commands emit the identical CSR. The TBS, public key and signature
    /// (~12 KB together) live in this single frame; the output paths are
    /// inline-never so their buffers occupy a separate frame that does not
    /// overlap the ML-DSA keygen/sign frames.
    #[inline(never)]
    pub(crate) fn generate_and_emit(
        drivers: &mut Drivers,
        output: PqCsrOutput,
    ) -> CaliptraResult<()> {
        // Re-deriving the key material and signing the CSR below exceed the
        // default 20M-cycle command watchdog budget; extend it.
        drivers.extend_wdt_for_pqc();

        // Re-derive the PQ.DevID ML-DSA-87 seed and public key from the PQ.DevID CDI (held in
        // persistent data). The seed is transient and zeroized as soon as the key pair operations
        // are done.
        let (seed, pub_key, digest) = drivers.compute_mldsa_key_material()?;

        // Compute the subject serial number (uppercase hex of SHA-256 over the
        // encoded public key) and the unique endpoint identifier.
        let mut subject_sn = [0u8; PqDevIdCsrTbsMlDsa87Params::SUBJECT_SN_LEN];
        drivers.compute_subject_sn(&digest, &mut subject_sn)?;
        let ueid = drivers.soc_ifc.fuse_bank().ueid();

        // Build the CSR `To Be Signed` structure from the static template.
        let params = PqDevIdCsrTbsMlDsa87Params {
            public_key: &pub_key,
            subject_sn: &subject_sn,
            ueid: &ueid,
        };
        let tbs = PqDevIdCsrTbsMlDsa87::new(&params);

        // Sign the TBS deterministically with the PQ.DevID private key.
        let mut sig = Mldsa87Signature::default();
        Mldsa87::sign_deterministic(&seed, tbs.tbs(), &mut sig)?;

        // Seed and derived key material are no longer needed.
        drop(seed);

        match output {
            PqCsrOutput::Csr => Self::assemble_and_send_csr(drivers, tbs.tbs(), &sig),
            PqCsrOutput::AttestedCsr(nonce) => {
                GetAttestedPqCsrCmd::send_attested_csr(drivers, &nonce, tbs.tbs(), &sig)
            }
        }
    }

    /// DER-assemble the CSR from `tbs`/`sig` into `buf`, returning its length.
    ///
    /// Shared by both output paths. Must only be called from the output frames:
    /// the builder needs a ~4.6 KB signature scratch buffer, which would
    /// overflow the stack if it were part of the keygen/sign frame.
    #[inline(never)]
    pub(crate) fn build_csr(
        tbs: &[u8],
        sig: &Mldsa87Signature,
        buf: &mut [u8],
    ) -> CaliptraResult<usize> {
        MlDsa87CsrBuilder::new(tbs, sig)
            .ok_or(CaliptraError::RUNTIME_PQ_CSR_BUILDER_INIT_FAILURE)?
            .build(buf)
            .ok_or(CaliptraError::RUNTIME_PQ_CSR_BUILDER_BUILD_FAILURE)
    }

    /// Build the CSR into the mailbox response buffer and send it. The
    /// response buffer is ~12.8 KB; it lives in this separate (inline-never)
    /// frame so it does not coexist on the stack with the large ML-DSA
    /// keygen/sign frames, which together would overflow the runtime stack.
    #[inline(never)]
    fn assemble_and_send_csr(
        drivers: &mut Drivers,
        tbs: &[u8],
        sig: &Mldsa87Signature,
    ) -> CaliptraResult<()> {
        let mut resp = GetPqCsrResp::new_zeroed();
        resp.data_size = Self::build_csr(tbs, sig, &mut resp.data)? as u32;

        copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}
