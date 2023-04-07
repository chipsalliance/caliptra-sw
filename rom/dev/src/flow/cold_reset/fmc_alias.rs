/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias.rs

Abstract:

    File contains the implementation of DICE First Mutable Code (FMC)
    layer.

--*/

use super::crypto::{Crypto, Ecc384KeyPair};
use super::dice::{DiceInput, DiceLayer, DiceOutput};
use super::x509::X509;
use crate::verifier::RomImageVerificationEnv;
use crate::{cprint, cprint_slice, cprintln, pcr};
use crate::{rom_env::RomEnv, rom_err_def};
use caliptra_drivers::{
    Array4x12, CaliptraResult, Hmac384Data, Hmac384Key, KeyId, KeyReadArgs, MailboxRecvTxn,
    ResetReason, Sha384DigestOp,
};
use caliptra_image_types::ImageManifest;
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams};
use zerocopy::FromBytes;

extern "C" {
    static mut MAN1_ORG: u8;
}

rom_err_def! {
    FmcAlias,
    FmcAliasErr
    {
        CertVerify = 0x1,
     ManifestReadFailure = 0x2,
    }
}

#[derive(Default)]
pub struct FmcAliasLayer {}

impl DiceLayer for FmcAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(env: &RomEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        cprintln!("[afmc] ++");
        cprintln!("[afmc] CDI.KEYID = {}", input.cdi as u8);
        cprintln!("[afmc] SUBJECT.KEYID = {}", input.subj_priv_key as u8);
        cprintln!(
            "[afmc] AUTHORITY.KEYID = {}",
            input.auth_key_pair.priv_key as u8
        );

        // Download the image
        let txn = Self::download_image(env)?;

        // Load the manifest
        let manifest = Self::load_manifest(&txn)?;

        // Verify the image
        let info = Self::verify_image(env, &manifest)?;

        // Populate data vault
        Self::populate_data_vault(env, &info)?;

        // Extend PCR0
        Self::extend_pcrs(env)?;

        // Load the image
        Self::load_image(env, &manifest, txn)?;

        // Derive the FMC DICE CDI from the FMC measurement
        Self::derive_cdi(env, input.cdi)?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, input.cdi, input.subj_priv_key)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;

        // Generate the output for next layer
        let output = input.to_output(key_pair, subj_sn, subj_key_id);

        // Generate FMC Alias Certificate
        Self::generate_cert_sig(env, input, &output)?;

        cprintln!("[afmc] --");

        Ok(output)
    }
}

impl FmcAliasLayer {
    /// Download firmware mailbox command ID.
    const MBOX_DOWNLOAD_FIRMWARE_CMD_ID: u32 = 0x46574C44;

    /// Download the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    ///
    /// # Returns
    ///
    /// * `MailboxRecvTxn` - Mailbox transaction handle
    fn download_image(env: &RomEnv) -> CaliptraResult<MailboxRecvTxn> {
        env.flow_status().map(|f| f.set_ready_for_firmware());

        cprint!("[afmc] Waiting for Image ");
        loop {
            cprint!(".");
            if let Some(mut txn) = env.mbox().map(|m| m.try_start_recv_txn()) {
                if txn.cmd() != Self::MBOX_DOWNLOAD_FIRMWARE_CMD_ID {
                    cprintln!("Invalid command 0x{:08x} received", txn.cmd());
                    txn.complete(false)?;
                    continue;
                }

                // TODO: Add a check the image is not zero bytes and must be less
                // than or equal to 128 KB

                cprintln!("");
                cprintln!("[afmc] Received Image of size {} bytes" txn.dlen());
                break Ok(txn);
            }
        }
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    fn load_manifest(txn: &MailboxRecvTxn) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = &mut MAN1_ORG as *mut u8;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>())
        };

        txn.copy_request(0, slice)?;

        ImageManifest::read_from(slice).ok_or(err_u32!(ManifestReadFailure))
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    fn verify_image(
        env: &RomEnv,
        manifest: &ImageManifest,
    ) -> CaliptraResult<ImageVerificationInfo> {
        let venv = RomImageVerificationEnv::new(env);
        let verifier = ImageVerifier::new(venv);
        let info = verifier.verify(manifest, (), ResetReason::ColdReset)?;

        cprintln!(
            "[afmc] Image verified using Vendor ECC Key Index {}",
            info.vendor_ecc_pub_key_idx
        );

        Ok(info)
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    fn load_image(
        _env: &RomEnv,
        manifest: &ImageManifest,
        txn: MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        cprintln!(
            "[afmc] Loading FMC at address 0x{:08x} len {}",
            manifest.fmc.load_addr,
            manifest.fmc.size
        );

        let fmc_dest = unsafe {
            let addr = (manifest.fmc.load_addr) as *mut u8;
            core::slice::from_raw_parts_mut(addr, manifest.fmc.size as usize)
        };

        txn.copy_request(0, fmc_dest)?;

        cprintln!(
            "[afmc] Loading Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u8;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize)
        };

        txn.copy_request(0, runtime_dest)?;

        // Drop the tranaction and release the Mailbox lock after the image
        // has been successfully verified and loaded in memory
        drop(txn);

        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    fn populate_data_vault(env: &RomEnv, info: &ImageVerificationInfo) -> CaliptraResult<()> {
        // Write cold-reset data.
        env.data_vault().map(|d| {
            d.set_fmc_tci(&info.fmc.digest.into());
            d.set_fmc_svn(info.fmc.svn);
            d.set_fmc_load_addr(info.fmc.load_addr);
            d.set_fmc_entry_point(info.fmc.entry_point);
            d.set_owner_pk_hash(&info.owner_pub_keys_digest.into());
            d.set_vendor_pk_index(info.vendor_ecc_pub_key_idx);
        });

        // Write warm-reset data.
        env.data_vault().map(|d| {
            d.set_rt_tci(&info.runtime.digest.into());
            d.set_rt_svn(info.runtime.svn);
            d.set_rt_load_addr(info.runtime.load_addr);
            d.set_rt_entry_point(info.runtime.entry_point);
        });

        // TODO: Need a better way to get the Manifest address
        let slice = unsafe {
            let ptr = &MAN1_ORG as *const u8;
            ptr as u32
        };

        env.data_vault().map(|d| d.set_manifest_addr(slice));

        Self::derive_fmc_measurements(env, info)?;

        Ok(())
    }

    /// Derive the FMC measurement digest and place it in the data vault.
    ///
    /// The hash covers fuse state and FMC image state.
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    fn derive_fmc_measurements(env: &RomEnv, info: &ImageVerificationInfo) -> CaliptraResult<()> {
        let sha = env.sha384();
        let mut digest = Array4x12::default();
        let mut op = sha.map(|s| s.digest_init(&mut digest).unwrap());

        let extend_digest_u8 = |op: &mut Sha384DigestOp, data: u8| {
            op.update(&data.to_le_bytes())
        };

        let extend_digest = |op: &mut Sha384DigestOp, data: Array4x12| {
            let bytes: &[u8; 48] = &data.into();
            op.update(bytes)
        };

        extend_digest_u8(&mut op, env.dev_state().map(|d| d.lifecycle()) as u8)?;
        extend_digest_u8(&mut op, env.dev_state().map(|d| d.debug_locked()) as u8)?;
        extend_digest_u8(&mut op, env.fuse_bank().map(|f| f.anti_rollback_disable()) as u8)?;
        extend_digest(&mut op, env.fuse_bank().map(|f| f.vendor_pub_key_hash()))?;
        extend_digest(&mut op, info.owner_pub_keys_digest.into())?;
        extend_digest_u8(&mut op, info.vendor_ecc_pub_key_idx as u8)?;
        extend_digest(&mut op, info.fmc.digest.into())?;
        extend_digest_u8(&mut op, info.fmc.svn as u8)?;

        op.finalize()?;

        env.data_vault().map(|d| d.set_fmc_measurements(&digest));

        Ok(())
    }

    /// Extend PCR0
    ///
    /// PCR0 is a journey PCR and is locked for clear on cold boot.
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    fn extend_pcrs(env: &RomEnv) -> CaliptraResult<()> {
        let measurement = env.data_vault().map(|d| d.fmc_measurements());

        pcr::extend_pcr0(env, measurement)?;

        // TODO: Check PCR0 != 0

        Ok(())
    }

    /// Derive FMC's Composite Device Identity (CDI)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `cdi` - Key Slot to store the generated CDI
    fn derive_cdi(env: &RomEnv, cdi: KeyId) -> CaliptraResult<()> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));

        // CDI measurement
        let data: &[u8; 48] = &env.data_vault().map(|d| d.fmc_measurements()).into();
        let data = Hmac384Data::Slice(data);
        Crypto::hmac384_mac(env, key, data, cdi)?;

        Ok(())
    }

    /// Derive Dice Layer Key Pair
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `cdi`      - Composite Device Identity
    /// * `priv_key` - Key slot to store the private key into
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Derive DICE Layer Key Pair
    fn derive_key_pair(env: &RomEnv, cdi: KeyId, priv_key: KeyId) -> CaliptraResult<Ecc384KeyPair> {
        Crypto::ecc384_key_gen(env, cdi, priv_key)
    }

    /// Generate FMC Alias Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `input`  - DICE Input
    /// * `output` - DICE Output
    fn generate_cert_sig(
        env: &RomEnv,
        input: &DiceInput,
        output: &DiceOutput,
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsParams {
            ueid: &X509::ueid(env)?,
            subject_sn: &output.subj_sn,
            subject_key_id: &output.subj_key_id,
            issuer_sn: &input.auth_sn,
            authority_key_id: &input.auth_key_id,
            serial_number: &X509::cert_sn(env, pub_key)?,
            public_key: &pub_key.to_der(),
            tcb_info_fmc_measurements: &env.data_vault().map(|d| d.fmc_measurements()).into(),
            tcb_info_fmc_tci: &env.data_vault().map(|d| d.fmc_tci()).into(),
            tcb_info_owner_pk_hash: &env.data_vault().map(|d| d.owner_pk_hash()).into(),
        };

        // Generate the `To Be Signed` portion of the certificate
        let tbs = FmcAliasCertTbs::new(&params);

        // Sign the the `To Be Signed` portion
        cprintln!(
            "[afmc] Signing Cert with AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs())?;

        // Clear the authority private key
        cprintln!("[afmc] Erasing AUTHORITY.KEYID = {}", auth_priv_key as u8);
        env.key_vault().map(|k| k.erase_key(auth_priv_key))?;

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), &sig)? {
            raise_err!(CertVerify);
        }

        let _pub_x: [u8; 48] = pub_key.x.into();
        let _pub_y: [u8; 48] = pub_key.y.into();
        cprint_slice!("[afmc] PUB.X", _pub_x);
        cprint_slice!("[afmc] PUB.Y", _pub_y);

        let _sig_r: [u8; 48] = sig.r.into();
        let _sig_s: [u8; 48] = sig.s.into();
        cprint_slice!("[afmc] SIG.R", _sig_r);
        cprint_slice!("[afmc] SIG.S", _sig_s);

        // Lock the FMC Certificate Signature in data vault until next boot
        env.data_vault().map(|d| d.set_fmc_dice_signature(&sig));

        // Lock the FMC Public key in the data vault until next boot
        env.data_vault().map(|d| d.set_fmc_pub_key(pub_key));

        Ok(())
    }
}
