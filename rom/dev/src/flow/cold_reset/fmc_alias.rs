/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias.rs

Abstract:

    File contains the implementation of DICE First Mutable Code (FMC)
    layer.

--*/

use core::mem::ManuallyDrop;

use super::crypto::{Crypto, Ecc384KeyPair};
use super::dice::{DiceInput, DiceLayer, DiceOutput};
use super::x509::X509;
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::flow::cold_reset::{KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY};
use crate::print::HexBytes;
use crate::verifier::RomImageVerificationEnv;
use crate::{cprint, cprintln, pcr};
use crate::{rom_env::RomEnv, rom_err_def};
use caliptra_common::dice;
use caliptra_drivers::{
    okref, Array4x12, CaliptraResult, ColdResetEntry4, ColdResetEntry48, Hmac384Data, Hmac384Key,
    KeyId, KeyReadArgs, Lifecycle, MailboxRecvTxn, ResetReason, WarmResetEntry4, WarmResetEntry48,
};
use caliptra_image_types::{ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams, NotAfter, NotBefore};
use zerocopy::{AsBytes, FromBytes};

extern "C" {
    static mut MAN1_ORG: u32;
}

rom_err_def! {
    FmcAlias,
    FmcAliasErr
    {
        CertVerify = 0x1,
        ManifestReadFailure = 0x2,
        InvalidImageSize = 0x3,
    }
}

#[derive(Default)]
pub struct FmcAliasLayer {}

impl DiceLayer for FmcAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(env: &RomEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        cprintln!("[afmc] ++");
        cprintln!("[afmc] CDI.KEYID = {}", KEY_ID_CDI as u8);
        cprintln!("[afmc] SUBJECT.KEYID = {}", KEY_ID_FMC_PRIV_KEY as u8);
        cprintln!(
            "[afmc] AUTHORITY.KEYID = {}",
            input.auth_key_pair.priv_key as u8
        );

        // Download the image
        let mut txn = Self::download_image(env)?;

        // Load the manifest
        let manifest = Self::load_manifest(&txn);
        let manifest = okref(&manifest)?;

        // Verify the image
        let info = Self::verify_image(env, manifest);
        let info = okref(&info)?;

        // populate data vault
        Self::populate_data_vault(env, info);

        // Extend PCR0
        pcr::extend_pcr0(env)?;

        // Load the image
        Self::load_image(env, manifest, &txn)?;

        // Complete the mailbox transaction indicating success.
        txn.complete(true)?;

        // At this point PCR0 & PCR1 must have the same value. We use the value
        // of PCR1 as the measurement for deriving the CDI
        let measurement = env
            .pcr_bank()
            .map(|p| p.read_pcr(caliptra_drivers::PcrId::PcrId1));

        // Derive the DICE CDI from decrypted UDS
        Self::derive_cdi(env, measurement, KEY_ID_CDI)?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;

        // Generate the output for next layer
        let output = DiceOutput {
            subj_key_pair: key_pair,
            subj_sn,
            subj_key_id,
        };

        // if there is a valid value in the manifest for the not_before and not_after
        // we take it from there.

        let mut nb = NotBefore::default();
        let mut nf = NotAfter::default();
        let null_time = [0u8; 15];

        if manifest.header.vendor_not_after != null_time
            && manifest.header.vendor_not_before != null_time
        {
            nf.not_after = manifest.header.vendor_not_after;
            nb.not_before = manifest.header.vendor_not_before;
        }

        //The owner values takes preference
        if manifest.header.owner_data.owner_not_after != null_time
            && manifest.header.owner_data.owner_not_before != null_time
        {
            nf.not_after = manifest.header.owner_data.owner_not_after;
            nb.not_before = manifest.header.owner_data.owner_not_before;
        }

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, input, &output, &nb.not_before, &nf.not_after)?;

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
    /// Mailbox transaction handle. This transaction is ManuallyDrop because we
    /// don't want the transaction to be completed with failure until after
    /// report_error is called. This prevents a race condition where the SoC
    /// reads FW_ERROR_NON_FATAL immediately after the mailbox transaction
    /// fails, but before caliptra has set the FW_ERROR_NON_FATAL register.
    fn download_image(env: &RomEnv) -> CaliptraResult<ManuallyDrop<MailboxRecvTxn>> {
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
                // This is a download-firmware command; don't drop this, as the
                // transaction will be completed by either report_error() (on
                // failure) or by a manual complete call upon success.
                let txn = ManuallyDrop::new(txn);
                if txn.dlen() == 0 || txn.dlen() > IMAGE_BYTE_SIZE as u32 {
                    cprintln!("Invalid Image of size {} bytes" txn.dlen());
                    raise_err!(InvalidImageSize);
                }

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
            let ptr = &mut MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        txn.copy_request(slice)?;

        ImageManifest::read_from(slice.as_bytes()).ok_or(err_u32!(ManifestReadFailure))
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
        txn: &MailboxRecvTxn,
    ) -> CaliptraResult<()> {
        cprintln!(
            "[afmc] Loading FMC at address 0x{:08x} len {}",
            manifest.fmc.load_addr,
            manifest.fmc.size
        );

        let fmc_dest = unsafe {
            let addr = (manifest.fmc.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.fmc.size as usize / 4)
        };

        txn.copy_request(fmc_dest)?;

        cprintln!(
            "[afmc] Loading Runtime at address 0x{:08x} len {}",
            manifest.runtime.load_addr,
            manifest.runtime.size
        );

        let runtime_dest = unsafe {
            let addr = (manifest.runtime.load_addr) as *mut u32;
            core::slice::from_raw_parts_mut(addr, manifest.runtime.size as usize / 4)
        };

        txn.copy_request(runtime_dest)?;

        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    fn populate_data_vault(env: &RomEnv, info: &ImageVerificationInfo) {
        env.data_vault()
            .map(|d| d.write_cold_reset_entry48(ColdResetEntry48::FmcTci, &info.fmc.digest.into()));

        env.data_vault()
            .map(|d| d.write_cold_reset_entry4(ColdResetEntry4::FmcSvn, info.fmc.svn));

        env.data_vault()
            .map(|d| d.write_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr, info.fmc.load_addr));

        env.data_vault().map(|d| {
            d.write_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint, info.fmc.entry_point)
        });

        env.data_vault().map(|d| {
            d.write_cold_reset_entry48(
                ColdResetEntry48::OwnerPubKeyHash,
                &info.owner_pub_keys_digest.into(),
            )
        });

        env.data_vault().map(|d| {
            d.write_cold_reset_entry4(
                ColdResetEntry4::VendorPubKeyIndex,
                info.vendor_ecc_pub_key_idx,
            )
        });

        env.data_vault().map(|d| {
            d.write_warm_reset_entry48(WarmResetEntry48::RtTci, &info.runtime.digest.into())
        });

        env.data_vault()
            .map(|d| d.write_warm_reset_entry4(WarmResetEntry4::RtSvn, info.runtime.svn));

        env.data_vault().map(|d| {
            d.write_warm_reset_entry4(WarmResetEntry4::RtLoadAddr, info.runtime.load_addr)
        });

        env.data_vault().map(|d| {
            d.write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, info.runtime.entry_point)
        });

        // TODO: Need a better way to get the Manifest address
        let slice = unsafe {
            let ptr = &MAN1_ORG as *const u32;
            ptr as u32
        };

        env.data_vault()
            .map(|d| d.write_warm_reset_entry4(WarmResetEntry4::ManifestAddr, slice));
    }

    /// Derive Composite Device Identity (CDI) from FMC measurements
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `measurements` - Array containing the FMC measurements
    /// * `cdi` - Key Slot to store the generated CDI
    fn derive_cdi(env: &RomEnv, measurements: Array4x12, cdi: KeyId) -> CaliptraResult<()> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let data: [u8; 48] = measurements.into();
        let data = Hmac384Data::Slice(&data);
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

    /// Generate Local Device ID Certificate Signature
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
        not_before: &[u8; FmcAliasCertTbsParams::NOT_BEFORE_LEN],
        not_after: &[u8; FmcAliasCertTbsParams::NOT_AFTER_LEN],
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        let flags = Self::make_flags(
            env.dev_state().map(|d| d.lifecycle()),
            env.dev_state().map(|d| d.debug_locked()),
        );

        let svn = env.data_vault().map(|d| d.fmc_svn()) as u8;
        let min_svn = 0_u8; // TODO: plumb from image header (and set to zero if anti_rollback_disable is set).

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsParams {
            ueid: &X509::ueid(env)?,
            subject_sn: &output.subj_sn,
            subject_key_id: &output.subj_key_id,
            issuer_sn: input.auth_sn,
            authority_key_id: input.auth_key_id,
            serial_number: &X509::cert_sn(env, pub_key)?,
            public_key: &pub_key.to_der(),
            tcb_info_fmc_tci: &(&env.data_vault().map(|d| d.fmc_tci())).into(),
            tcb_info_owner_pk_hash: &(&env.data_vault().map(|d| d.owner_pk_hash())).into(),
            tcb_info_flags: &flags,
            tcb_info_svn: &svn.to_be_bytes(),
            tcb_info_min_svn: &min_svn.to_be_bytes(),
            not_before,
            not_after,
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = FmcAliasCertTbs::new(&params);

        // Sign the the `To Be Signed` portion
        cprintln!(
            "[afmc] Signing Cert with AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs());
        let sig = okref(&sig)?;

        // Clear the authority private key
        cprintln!("[afmc] Erasing AUTHORITY.KEYID = {}", auth_priv_key as u8);
        env.key_vault().map(|k| k.erase_key(auth_priv_key))?;

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), sig)? {
            raise_err!(CertVerify);
        }

        let _pub_x: [u8; 48] = (&pub_key.x).into();
        let _pub_y: [u8; 48] = (&pub_key.y).into();
        cprintln!("[afmc] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[afmc] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[afmc] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[afmc] SIG.S = {}", HexBytes(&_sig_s));

        // Lock the FMC Certificate Signature in data vault until next boot
        env.data_vault().map(|d| d.set_fmc_dice_signature(sig));

        // Lock the FMC Public key in the data vault until next boot
        env.data_vault().map(|d| d.set_fmc_pub_key(pub_key));

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::FmcaliasTbs)?;

        Ok(())
    }

    /// Generate flags for DICE evidence
    ///
    /// # Arguments
    ///
    /// * `device_lifecycle` - Device lifecycle
    /// * `debug_locked`     - Debug locked
    fn make_flags(device_lifecycle: Lifecycle, debug_locked: bool) -> [u8; 4] {
        let mut flags: u32 = dice::FLAG_BIT_FIXED_WIDTH;

        flags |= match device_lifecycle {
            Lifecycle::Unprovisioned => dice::FLAG_BIT_NOT_CONFIGURED,
            Lifecycle::Manufacturing => dice::FLAG_BIT_NOT_SECURE,
            _ => 0,
        };

        if debug_locked {
            flags |= dice::FLAG_BIT_DEBUG;
        }

        flags.to_be_bytes()
    }
}
