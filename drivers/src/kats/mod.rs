// Licensed under the Apache-2.0 license

mod aes256cbc_kat;
mod aes256cmac_kat;
mod aes256ctr_kat;
mod aes256ecb_kat;
mod aes256gcm_kat;
mod sha1_kat;

pub use aes256cbc_kat::Aes256CbcKat;
pub use aes256cmac_kat::Aes256CmacKat;
pub use aes256ctr_kat::Aes256CtrKat;
pub use aes256ecb_kat::Aes256EcbKat;
pub use aes256gcm_kat::Aes256GcmKat;
pub use sha1_kat::Sha1Kat;

use crate::{Aes, CaliptraResult, Trng};

/// Execute all AES KATs unconditionally.
/// This is used by FIPS self-test to ensure all KATs are run.
#[inline(never)]
pub fn execute_all_aes_kats(aes: &mut Aes, trng: &mut Trng) -> CaliptraResult<()> {
    Aes256EcbKat::default().execute(aes)?;
    Aes256CbcKat::default().execute(aes)?;
    Aes256CtrKat::default().execute(aes)?;
    Aes256CmacKat::default().execute(aes)?;
    Aes256GcmKat::default().execute(aes, trng)?;
    Ok(())
}
