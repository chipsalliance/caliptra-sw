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
use caliptra_drivers::{CaliptraError, CaliptraResult, Mldsa87, Mldsa87Signature};
use caliptra_x509::{MlDsa87CsrBuilder, PqDevIdCsrTbsMlDsa87, PqDevIdCsrTbsMlDsa87Params};
use zerocopy::{FromZeros, IntoBytes};

pub struct GetPqCsrCmd;

impl GetPqCsrCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        copy_from_mbox(drivers, GetPqCsrReq::new_zeroed().as_mut_bytes())?;

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
}
