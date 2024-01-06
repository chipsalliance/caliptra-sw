/*++

Licensed under the Apache-2.0 license.

File Name:

    hash_chain.rs

Abstract:

    File contains execution routines for deriving a hash chain based on RT FW's SVN.

Environment:

    FMC

--*/

use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert_eq, cfi_assert_le};

use caliptra_common::keyids::KEY_ID_RT_HASH_CHAIN;
use caliptra_drivers::{cprintln, report_boot_status};
use caliptra_error::{CaliptraError, CaliptraResult};

use crate::{flow::crypto::Crypto, fmc_env::FmcEnv, hand_off::HandOff, FmcBootStatus};

const MAX_RT_SVN: u32 = 128;

pub struct HashChain {}

impl HashChain {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn derive(env: &mut FmcEnv) -> CaliptraResult<()> {
        HandOff::set_rt_hash_chain_max_svn(env, MAX_RT_SVN as u16);

        cprintln!("[hash chain rt] Deriving hash chain");

        let fw_epoch = env.persistent_data.get().manifest1.header.owner_data.epoch;
        Self::compute_chain(env, &fw_epoch)?;

        cprintln!("[hash chain rt] Derivation complete");
        report_boot_status(FmcBootStatus::RtHashChainComplete as u32);
        Ok(())
    }

    fn compute_chain(env: &mut FmcEnv, fw_epoch: &[u8]) -> CaliptraResult<()> {
        let rt_svn = HandOff::rt_svn(env);
        if rt_svn > MAX_RT_SVN {
            return Err(CaliptraError::RT_SVN_EXCEEDS_MAX);
        } else {
            cfi_assert_le(rt_svn, MAX_RT_SVN);
        }

        let chain_len: u32 = MAX_RT_SVN - rt_svn;
        cprintln!(
            "[hash chain rt] SVN = {}, max = {}, chain_len = {}",
            rt_svn,
            MAX_RT_SVN,
            chain_len
        );

        let fmc_cdi = HandOff::fmc_cdi(env);

        Crypto::hmac384_kdf(
            env,
            fmc_cdi,
            b"rt_hash_chain",
            Some(fw_epoch),
            KEY_ID_RT_HASH_CHAIN,
        )?;

        let mut num_iters: u32 = 0;

        for _ in 0..chain_len {
            num_iters += 1;
            Crypto::hmac384_kdf(env, KEY_ID_RT_HASH_CHAIN, &[], None, KEY_ID_RT_HASH_CHAIN)?;
        }

        cfi_assert_eq(num_iters, chain_len);

        HandOff::set_rt_hash_chain_kv_hdl(env, KEY_ID_RT_HASH_CHAIN);
        Ok(())
    }
}
