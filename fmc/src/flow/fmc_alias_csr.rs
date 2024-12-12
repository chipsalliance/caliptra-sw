// Licensed under the Apache-2.0 license

use crate::flow::crypto::Crypto;
use crate::flow::dice::DiceOutput;
use crate::flow::x509::X509;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::crypto::Ecc384KeyPair;

use crate::flow::crypto::Ecdsa384SignatureAdapter;

use zeroize::Zeroize;

use caliptra_drivers::okmutref;
use caliptra_drivers::FmcAliasCsr;

use caliptra_x509::FmcAliasCsrTbs;
use caliptra_x509::FmcAliasCsrTbsParams;

use caliptra_drivers::{CaliptraError, CaliptraResult};

use caliptra_x509::Ecdsa384CsrBuilder;

/// Retrieve DICE Output from HandOff
///
/// # Arguments
///
/// * `hand_off` - HandOff
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

fn write_csr_to_peristent_storage(env: &mut FmcEnv, csr: &FmcAliasCsr) -> CaliptraResult<()> {
    let csr_persistent_mem = &mut env.persistent_data.get_mut().fmc_alias_csr;

    *csr_persistent_mem = csr.clone();

    Ok(())
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

    // CSR `To Be Signed` Parameters
    let params = FmcAliasCsrTbsParams {
        // Unique Endpoint Identifier
        ueid: &X509::ueid(env)?,

        // Subject Name
        subject_sn: &output.subj_sn,

        // Public Key
        public_key: &key_pair.pub_key.to_der(),
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
    let mut csr_buf = [0; caliptra_drivers::MAX_CSR_SIZE];
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

    let result = write_csr_to_peristent_storage(env, &fmc_alias_csr);

    csr_buf.zeroize();

    result
}
