/*++

Licensed under the Apache-2.0 license.

File Name:

    set_pq_seed.rs

Abstract:

    File contains SET_PQ_SEED mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{MailboxRespHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE};
use caliptra_drivers::{hmac384_kdf, Array4x12, CaliptraError, CaliptraResult};
use crypto::{Digest, Sha256};
use zerocopy::{FromZeros, IntoBytes};
use zeroize::{Zeroize, Zeroizing};

pub struct SetPqSeedCmd;

impl SetPqSeedCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        // SET_PQ_SEED MUST only be called from PL0
        drivers.ensure_pl0()?;

        let mut cmd = SetPqSeedReq::new_zeroed();
        crate::packet::copy_from_mbox(drivers, cmd.as_mut_bytes())?;

        // Deriving the PQ.DevID CDI and computing the ML-DSA-87 key material
        // below exceeds the default 20M-cycle command watchdog budget; extend it.
        drivers.extend_wdt_for_pqc();

        let mut out = Zeroizing::new(Array4x12::default());
        Self::derive_pq_devid_cdi(drivers, &cmd.seed, &mut out)?;

        drivers
            .persistent_data
            .get_mut()
            .set_pq_devid_cdi((*out).into())?;

        // The request buffer still holds the caller-supplied seed.
        cmd.seed.zeroize();

        // Calculate the digest of the PQ.DevID public key and cache it
        // in the persistent data to avoid repeated key generation passes
        // involved in DPE invocation.
        let (_, _, Digest::Sha256(Sha256(digest))) = drivers.compute_mldsa_key_material()? else {
            return Err(CaliptraError::RUNTIME_PQ_INVALID_PUBKEY_DIGEST);
        };
        drivers
            .persistent_data
            .get_mut()
            .set_pq_devid_pub_key_digest(digest)?;

        crate::packet::copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn derive_pq_devid_cdi(
        drivers: &mut Drivers,
        seed: &[u8; SET_PQ_SEED_SEED_SIZE],
        out: &mut Array4x12,
    ) -> CaliptraResult<()> {
        let mut buf = Zeroizing::new([0u8; core::mem::size_of::<Array4x12>()]);

        buf.get_mut(..SET_PQ_SEED_SEED_SIZE)
            .ok_or(CaliptraError::RUNTIME_MLDSA87_DEVID_SEED_TOO_LARGE)?
            .copy_from_slice(seed);

        let key = Zeroizing::new(Array4x12::from(&*buf));

        hmac384_kdf(
            &mut drivers.hmac384,
            (&*key).into(),
            b"pq_devid_cdi",
            None,
            &mut drivers.trng,
            out.into(),
        )
    }
}
