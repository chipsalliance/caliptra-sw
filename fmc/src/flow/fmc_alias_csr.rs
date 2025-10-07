// Licensed under the Apache-2.0 license

use crate::flow::crypto::Crypto;
use crate::flow::dice::DiceOutput;
use crate::flow::x509::X509;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::{crypto::Ecc384KeyPair, dice};

use crate::flow::crypto::Ecdsa384SignatureAdapter;

use zeroize::Zeroize;

use caliptra_drivers::okmutref;

use caliptra_drivers::FmcAliasCsr;

use caliptra_x509::{FmcAliasCsrTbs, FmcAliasCsrTbsParams};

use caliptra_drivers::{Array4x12, CaliptraError, CaliptraResult};

use caliptra_x509::Ecdsa384CsrBuilder;

/// Retrieve DICE Output from HandOff
///
/// # Arguments
///
/// * `env`    - FMC Environment
///
/// # Returns
///
/// * `DiceInput` - DICE Layer Input
fn dice_output_from_hand_off(env: &mut FmcEnv) -> CaliptraResult<DiceOutput> {
    let auth_pub = HandOff::fmc_pub_key(env);
    let subj_sn = X509::subj_sn(env, &auth_pub)?;
    let subj_key_id = X509::subj_key_id(env, &auth_pub)?;
    // Create initial output
    let output = DiceOutput {
        cdi: HandOff::fmc_cdi(env),
        subj_key_pair: Ecc384KeyPair {
            priv_key: HandOff::fmc_priv_key(env),
            pub_key: auth_pub,
        },
        subj_sn,
        subj_key_id,
    };

    Ok(output)
}

fn write_csr_to_peristent_storage(env: &mut FmcEnv, csr: &FmcAliasCsr) {
    let csr_persistent_mem = &mut env.persistent_data.get_mut().fmc_alias_csr;

    *csr_persistent_mem = csr.clone();
}

#[inline(always)]
pub fn generate_csr(env: &mut FmcEnv) -> CaliptraResult<()> {
    dice_output_from_hand_off(env).and_then(|output| make_csr(env, &output))
}

/// Generate FMC Alias CSR
///
/// # Arguments
///
/// * `env`    - FMC Environment
/// * `output` - DICE Output
// Inlined to reduce FMC size
#[inline(always)]
pub fn make_csr(env: &mut FmcEnv, output: &DiceOutput) -> CaliptraResult<()> {
    let key_pair = &output.subj_key_pair;

    let flags = dice::make_flags(env.soc_ifc.lifecycle(), env.soc_ifc.debug_locked());

    let svn = env.data_vault.fmc_svn() as u8;

    // This info was not saved from ROM so we need to repeat this check
    let fmc_effective_fuse_svn = match env.soc_ifc.fuse_bank().anti_rollback_disable() {
        true => 0_u8,
        false => env.soc_ifc.fuse_bank().fmc_fuse_svn() as u8,
    };
    let owner_pub_keys_digest_in_fuses: bool =
        env.soc_ifc.fuse_bank().owner_pub_key_hash() != Array4x12::default();

    let mut fuse_info_digest = Array4x12::default();
    let mut hasher = env.sha384.digest_init()?;
    hasher.update(&[
        env.soc_ifc.lifecycle() as u8,
        env.soc_ifc.debug_locked() as u8,
        env.soc_ifc.fuse_bank().anti_rollback_disable() as u8,
        env.data_vault.ecc_vendor_pk_index() as u8,
        env.data_vault.lms_vendor_pk_index() as u8,
        env.soc_ifc.fuse_bank().lms_verify() as u8,
        owner_pub_keys_digest_in_fuses as u8,
    ])?;
    hasher.update(&<[u8; 48]>::from(
        env.soc_ifc.fuse_bank().vendor_pub_key_hash(),
    ))?;
    hasher.update(&<[u8; 48]>::from(env.data_vault.owner_pk_hash()))?;
    hasher.finalize(&mut fuse_info_digest)?;

    // CSR `To Be Signed` Parameters
    let params = FmcAliasCsrTbsParams {
        ueid: &X509::ueid(env)?,
        subject_sn: &output.subj_sn,
        public_key: &key_pair.pub_key.to_der(),
        tcb_info_fmc_tci: &(&env.data_vault.fmc_tci()).into(),
        tcb_info_device_info_hash: &fuse_info_digest.into(),
        tcb_info_flags: &flags,
        tcb_info_fmc_svn: &svn.to_be_bytes(),
        tcb_info_fmc_svn_fuses: &fmc_effective_fuse_svn.to_be_bytes(),
    };

    // Generate the `To Be Signed` portion of the CSR
    let tbs = FmcAliasCsrTbs::new(&params);

    // Sign the `To Be Signed` portion
    let mut sig =
        Crypto::ecdsa384_sign_and_verify(env, key_pair.priv_key, &key_pair.pub_key, tbs.tbs());
    let sig = okmutref(&mut sig)?;

    let _pub_x: [u8; 48] = key_pair.pub_key.x.into();
    let _pub_y: [u8; 48] = key_pair.pub_key.y.into();

    let _sig_r: [u8; 48] = (&sig.r).into();
    let _sig_s: [u8; 48] = (&sig.s).into();

    // Build the CSR with `To Be Signed` & `Signature`
    let mut csr_buf = [0; caliptra_drivers::MAX_FMC_ALIAS_CSR_SIZE];
    let result = Ecdsa384CsrBuilder::new(tbs.tbs(), &sig.to_ecdsa())
        .ok_or(CaliptraError::FMC_ALIAS_CSR_BUILDER_INIT_FAILURE);
    sig.zeroize();

    let csr_bldr = result?;
    let csr_len = csr_bldr
        .build(&mut csr_buf)
        .ok_or(CaliptraError::FMC_ALIAS_CSR_BUILDER_BUILD_FAILURE)?;

    if csr_len > csr_buf.len() {
        return Err(CaliptraError::FMC_ALIAS_CSR_OVERFLOW);
    }

    let fmc_alias_csr = FmcAliasCsr::new(&csr_buf, csr_len)?;

    write_csr_to_peristent_storage(env, &fmc_alias_csr);

    csr_buf.zeroize();

    Ok(())
}
