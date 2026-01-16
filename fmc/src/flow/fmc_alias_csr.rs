// Licensed under the Apache-2.0 license

use crate::flow::dice::DiceOutput;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::{
    crypto::{Crypto, Ecc384KeyPair, MlDsaKeyPair, PubKey},
    dice, x509,
};
use caliptra_drivers::{okmutref, CaliptraError, CaliptraResult, Ecc384Signature};
use caliptra_x509::{
    Ecdsa384CsrBuilder, Ecdsa384Signature, FmcAliasCsrTbsEcc384, FmcAliasCsrTbsEcc384Params,
    FmcAliasTbsMlDsa87, FmcAliasTbsMlDsa87Params, MlDsa87CsrBuilder,
};
use zerocopy::IntoBytes;
use zeroize::Zeroize;

pub trait Ecdsa384SignatureAdapter {
    /// Convert to ECDSA Signature
    fn to_ecdsa(&self) -> Ecdsa384Signature;
}

impl Ecdsa384SignatureAdapter for Ecc384Signature {
    /// Convert to ECDSA Signature
    fn to_ecdsa(&self) -> Ecdsa384Signature {
        Ecdsa384Signature {
            r: (&self.r).into(),
            s: (&self.s).into(),
        }
    }
}

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
    let ecc_auth_pub = HandOff::fmc_ecc_pub_key(env);
    let ecc_subj_sn = x509::subj_sn(&mut env.sha256, &PubKey::Ecc(&ecc_auth_pub))?;
    let ecc_subj_key_id = x509::subj_key_id(&mut env.sha256, &PubKey::Ecc(&ecc_auth_pub))?;

    let mldsa_auth_pub = HandOff::fmc_mldsa_pub_key(env);
    let mldsa_subj_sn = x509::subj_sn(&mut env.sha256, &PubKey::Mldsa(&mldsa_auth_pub))?;
    let mldsa_subj_key_id = x509::subj_key_id(&mut env.sha256, &PubKey::Mldsa(&mldsa_auth_pub))?;

    // Create initial output
    let output = DiceOutput {
        cdi: HandOff::fmc_cdi(env),
        ecc_subj_key_pair: Ecc384KeyPair {
            priv_key: HandOff::fmc_ecc_priv_key(env),
            pub_key: ecc_auth_pub,
        },
        ecc_subj_sn,
        ecc_subj_key_id,
        mldsa_subj_key_pair: MlDsaKeyPair {
            key_pair_seed: HandOff::fmc_mldsa_keypair_seed_key(env),
            pub_key: mldsa_auth_pub,
        },
        mldsa_subj_sn,
        mldsa_subj_key_id,
    };

    Ok(output)
}

#[inline(always)]
pub fn generate_csr(env: &mut FmcEnv) -> CaliptraResult<()> {
    dice_output_from_hand_off(env).and_then(|output| make_csr(env, &output))
}

/// Generate FMC Alias ECC and MLDSA CSRs
///
/// # Arguments
///
/// * `env`    - FMC Environment
/// * `output` - DICE Output
// Inlined to reduce FMC size
#[inline(always)]
pub fn make_csr(env: &mut FmcEnv, output: &DiceOutput) -> CaliptraResult<()> {
    make_ecc_csr(env, output)?;
    make_mldsa_csr(env, output)
}

fn make_ecc_csr(env: &mut FmcEnv, output: &DiceOutput) -> CaliptraResult<()> {
    let data_vault = &env.persistent_data.get().rom.data_vault;
    let soc_ifc: &caliptra_drivers::SocIfc = &env.soc_ifc;
    let sha2_512_384 = &mut env.sha2_512_384;

    let key_pair = &output.ecc_subj_key_pair;

    let svn = data_vault.cold_boot_fw_svn() as u8;
    let owner_device_info_hash =
        dice::gen_fmc_alias_owner_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;
    let vendor_device_info_hash =
        dice::gen_fmc_alias_vendor_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;

    // CSR `To Be Signed` Parameters
    let params = FmcAliasCsrTbsEcc384Params {
        ueid: &x509::ueid(soc_ifc)?,
        subject_sn: &output.ecc_subj_sn,
        public_key: &key_pair.pub_key.to_der(),
        tcb_info_fmc_tci: &(&data_vault.fmc_tci()).into(),
        tcb_info_fw_svn: &svn.to_be_bytes(),
        tcb_info_owner_device_info_hash: &owner_device_info_hash,
        tcb_info_vendor_device_info_hash: &vendor_device_info_hash,
    };

    // Generate the `To Be Signed` portion of the CSR
    let tbs = FmcAliasCsrTbsEcc384::new(&params);

    // Sign the `To Be Signed` portion
    let mut sig = Crypto::ecdsa384_sign_and_verify(
        &mut env.sha2_512_384,
        &mut env.ecc384,
        &mut env.trng,
        key_pair.priv_key,
        &key_pair.pub_key,
        tbs.tbs(),
    );
    let sig = okmutref(&mut sig)?;

    let sig_ecdsa = sig.to_ecdsa();
    let result = Ecdsa384CsrBuilder::new(tbs.tbs(), &sig_ecdsa)
        .ok_or(CaliptraError::FMC_ALIAS_CSR_BUILDER_INIT_FAILURE);
    sig.zeroize();

    let csr_bldr = result?;
    let fmc_alias_csr = &mut env.persistent_data.get_mut().fw.fmc_alias_csr;
    let csr_len = csr_bldr
        .build(&mut fmc_alias_csr.ecc_csr)
        .ok_or(CaliptraError::FMC_ALIAS_CSR_BUILDER_BUILD_FAILURE)?;

    if csr_len > fmc_alias_csr.ecc_csr.len() {
        return Err(CaliptraError::FMC_ALIAS_CSR_OVERFLOW);
    }
    fmc_alias_csr.ecc_csr_len = csr_len as u32;

    Ok(())
}

fn make_mldsa_csr(env: &mut FmcEnv, output: &DiceOutput) -> CaliptraResult<()> {
    let data_vault = &env.persistent_data.get().rom.data_vault;
    let soc_ifc: &caliptra_drivers::SocIfc = &env.soc_ifc;
    let sha2_512_384 = &mut env.sha2_512_384;

    let key_pair = &output.mldsa_subj_key_pair;

    let svn = data_vault.cold_boot_fw_svn() as u8;
    let owner_device_info_hash =
        dice::gen_fmc_alias_owner_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;
    let vendor_device_info_hash =
        dice::gen_fmc_alias_vendor_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;

    // CSR `To Be Signed` Parameters
    let params = FmcAliasTbsMlDsa87Params {
        ueid: &x509::ueid(soc_ifc)?,
        subject_sn: &output.mldsa_subj_sn,
        public_key: &key_pair.pub_key.into(),
        tcb_info_fmc_tci: &(&data_vault.fmc_tci()).into(),
        tcb_info_fw_svn: &svn.to_be_bytes(),
        tcb_info_owner_device_info_hash: &owner_device_info_hash,
        tcb_info_vendor_device_info_hash: &vendor_device_info_hash,
    };

    // Generate the `To Be Signed` portion of the CSR
    let tbs = FmcAliasTbsMlDsa87::new(&params);

    // Sign the `To Be Signed` portion
    let mut sig = Crypto::mldsa87_sign_and_verify(
        &mut env.mldsa,
        &mut env.trng,
        key_pair.key_pair_seed,
        &key_pair.pub_key,
        tbs.tbs(),
    )?;

    // Build the CSR with `To Be Signed` & `Signature`
    let mldsa87_signature = caliptra_x509::MlDsa87Signature {
        sig: sig.as_bytes()[..4627].try_into().unwrap(),
    };
    let result = MlDsa87CsrBuilder::new(tbs.tbs(), &mldsa87_signature)
        .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_INIT_FAILURE);
    sig.zeroize();

    let csr_bldr = result?;
    let fmc_alias_csr = &mut env.persistent_data.get_mut().fw.fmc_alias_csr;
    let csr_len = csr_bldr
        .build(&mut fmc_alias_csr.mldsa_csr)
        .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE)?;

    if csr_len > fmc_alias_csr.mldsa_csr.len() {
        return Err(CaliptraError::FMC_ALIAS_CSR_OVERFLOW);
    }
    fmc_alias_csr.mldsa_csr_len = csr_len as u32;

    Ok(())
}
