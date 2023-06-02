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
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::flow::cold_reset::{KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY};
use crate::fuse::log_fuse_data;
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
use crate::verifier::RomImageVerificationEnv;
use crate::{cprint, cprintln, pcr};
use caliptra_common::dice;
use caliptra_common::fuse::FuseLogEntryId;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{
    okref, report_boot_status, Array4x12, CaliptraResult, ColdResetEntry4, ColdResetEntry48,
    DataVault, Hmac384Data, Hmac384Key, KeyId, KeyReadArgs, Lifecycle, Mailbox, MailboxRecvTxn,
    ResetReason, SocIfc, WarmResetEntry4, WarmResetEntry48,
};
use caliptra_error::CaliptraError;
use caliptra_image_types::{ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{ImageVerificationInfo, ImageVerificationLogInfo, ImageVerifier};
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams, NotAfter, NotBefore};
use core::mem::ManuallyDrop;
use zerocopy::{AsBytes, FromBytes};

extern "C" {
    static mut MAN1_ORG: u32;
}

#[derive(Default)]
pub struct FmcAliasLayer {}

impl DiceLayer for FmcAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(env: &mut RomEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        cprintln!("[afmc] ++");
        cprintln!("[afmc] CDI.KEYID = {}", KEY_ID_CDI as u8);
        cprintln!("[afmc] SUBJECT.KEYID = {}", KEY_ID_FMC_PRIV_KEY as u8);
        cprintln!(
            "[afmc] AUTHORITY.KEYID = {}",
            input.auth_key_pair.priv_key as u8
        );

        // Download the image
        let mut txn = Self::download_image(&mut env.soc_ifc, &mut env.mbox)?;

        // Load the manifest
        let manifest = Self::load_manifest(&mut txn);
        let manifest = okref(&manifest)?;

        let mut venv = RomImageVerificationEnv {
            sha256: &mut env.sha256,
            sha384: &mut env.sha384,
            sha384_acc: &mut env.sha384_acc,
            soc_ifc: &mut env.soc_ifc,
            ecc384: &mut env.ecc384,
            data_vault: &mut env.data_vault,
            pcr_bank: &mut env.pcr_bank,
        };

        // Verify the image
        let info = Self::verify_image(&mut venv, manifest, txn.dlen());
        let info = okref(&info)?;

        Self::update_fuse_log(&info.log_info)?;

        // populate data vault
        Self::populate_data_vault(venv.data_vault, info);

        // Extend PCR0
        pcr::extend_pcr0(&mut venv, info)?;
        report_boot_status(FmcAliasExtendPcrComplete.into());

        // Load the image
        Self::load_image(manifest, &mut txn)?;

        // Complete the mailbox transaction indicating success.
        txn.complete(true)?;
        report_boot_status(FmcAliasFirmwareDownloadTxComplete.into());

        // At this point PCR0 & PCR1 must have the same value. We use the value
        // of PCR1 as the measurement for deriving the CDI
        let measurement = env.pcr_bank.read_pcr(caliptra_drivers::PcrId::PcrId1);

        // Derive the DICE CDI from decrypted UDS
        Self::derive_cdi(env, measurement, KEY_ID_CDI)?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY)?;
        report_boot_status(FmcAliasKeyPairDerivationComplete.into());

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        report_boot_status(FmcAliasSubjIdSnGenerationComplete.into());

        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;
        report_boot_status(FmcAliasSubjKeyIdGenerationComplete.into());

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

        if manifest.header.vendor_data.vendor_not_after != null_time
            && manifest.header.vendor_data.vendor_not_before != null_time
        {
            nf.not_after = manifest.header.vendor_data.vendor_not_after;
            nb.not_before = manifest.header.vendor_data.vendor_not_before;
        }

        //The owner values takes preference
        if manifest.header.owner_data.owner_not_after != null_time
            && manifest.header.owner_data.owner_not_before != null_time
        {
            nf.not_after = manifest.header.owner_data.owner_not_after;
            nb.not_before = manifest.header.owner_data.owner_not_before;
        }

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, info, input, &output, &nb.not_before, &nf.not_after)?;

        report_boot_status(FmcAliasDerivationComplete.into());
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
    fn download_image<'a>(
        soc_ifc: &mut SocIfc,
        mbox: &'a mut Mailbox,
    ) -> CaliptraResult<ManuallyDrop<MailboxRecvTxn<'a>>> {
        soc_ifc.flow_status_set_ready_for_firmware();

        cprint!("[afmc] Waiting for Image ");
        loop {
            if let Some(txn) = mbox.peek_recv() {
                if txn.cmd() != Self::MBOX_DOWNLOAD_FIRMWARE_CMD_ID {
                    cprintln!("Invalid command 0x{:08x} received", txn.cmd());
                    txn.start_txn().complete(false)?;
                    continue;
                }

                // Re-borrow mailbox to work around https://github.com/rust-lang/rust/issues/54663
                let txn = mbox
                    .peek_recv()
                    .ok_or(CaliptraError::FMC_ALIAS_MAILBOX_STATE_INCONSISTENT)?;

                // This is a download-firmware command; don't drop this, as the
                // transaction will be completed by either report_error() (on
                // failure) or by a manual complete call upon success.
                let txn = ManuallyDrop::new(txn.start_txn());
                if txn.dlen() == 0 || txn.dlen() > IMAGE_BYTE_SIZE as u32 {
                    cprintln!("Invalid Image of size {} bytes" txn.dlen());
                    return Err(CaliptraError::FMC_ALIAS_INVALID_IMAGE_SIZE);
                }

                cprintln!("");
                cprintln!("[afmc] Received Image of size {} bytes" txn.dlen());
                report_boot_status(FmcAliasDownloadImageComplete.into());
                return Ok(txn);
            }
        }
    }

    /// Load the manifest
    ///
    /// # Returns
    ///
    /// * `Manifest` - Caliptra Image Bundle Manifest
    fn load_manifest(txn: &mut MailboxRecvTxn) -> CaliptraResult<ImageManifest> {
        let slice = unsafe {
            let ptr = &mut MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };

        txn.copy_request(slice)?;

        if let Some(result) = ImageManifest::read_from(slice.as_bytes()) {
            report_boot_status(FmcAliasManifestLoadComplete.into());
            Ok(result)
        } else {
            Err(CaliptraError::FMC_ALIAS_MANIFEST_READ_FAILURE)
        }
    }

    /// Verify the image
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    fn verify_image(
        venv: &mut RomImageVerificationEnv,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageVerificationInfo> {
        let mut verifier = ImageVerifier::new(venv);
        let info = verifier.verify(manifest, img_bundle_sz, ResetReason::ColdReset)?;

        cprintln!(
            "[afmc] Image verified using Vendor ECC Key Index {}",
            info.vendor_ecc_pub_key_idx,
        );
        report_boot_status(FmcAliasImageVerificationComplete.into());
        Ok(info)
    }

    fn update_fuse_log(log_info: &ImageVerificationLogInfo) -> CaliptraResult<()> {
        // Log VendorPubKeyIndex
        log_fuse_data(
            FuseLogEntryId::VendorPubKeyIndex,
            log_info.vendor_ecc_pub_key_idx.as_bytes(),
        )?;

        // Log VendorPubKeyRevocation
        log_fuse_data(
            FuseLogEntryId::VendorPubKeyRevocation,
            log_info.fuse_vendor_pub_key_revocation.bits().as_bytes(),
        )?;

        // Log ManifestFmcSvn
        log_fuse_data(
            FuseLogEntryId::ManifestFmcSvn,
            log_info.fmc_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestFmcMinSvn
        log_fuse_data(
            FuseLogEntryId::ManifestFmcMinSvn,
            log_info.fmc_log_info.manifest_min_svn.as_bytes(),
        )?;

        // Log FuseFmcSvn
        log_fuse_data(
            FuseLogEntryId::FuseFmcSvn,
            log_info.fmc_log_info.fuse_svn.as_bytes(),
        )?;

        // Log ManifestRtSvn
        log_fuse_data(
            FuseLogEntryId::ManifestRtSvn,
            log_info.rt_log_info.manifest_svn.as_bytes(),
        )?;

        // Log ManifestRtMinSvn
        log_fuse_data(
            FuseLogEntryId::ManifestRtMinSvn,
            log_info.rt_log_info.manifest_min_svn.as_bytes(),
        )?;

        // Log FuseRtSvn
        log_fuse_data(
            FuseLogEntryId::FuseRtSvn,
            log_info.rt_log_info.fuse_svn.as_bytes(),
        )?;
        Ok(())
    }

    /// Load the image to ICCM & DCCM
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `manifest` - Manifest
    /// * `txn`      - Mailbox Receive Transaction
    fn load_image(manifest: &ImageManifest, txn: &mut MailboxRecvTxn) -> CaliptraResult<()> {
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

        report_boot_status(FmcAliasLoadImageComplete.into());
        Ok(())
    }

    /// Populate data vault
    ///
    /// # Arguments
    ///
    /// * `env`  - ROM Environment
    /// * `info` - Image Verification Info
    fn populate_data_vault(data_vault: &mut DataVault, info: &ImageVerificationInfo) {
        data_vault.write_cold_reset_entry48(ColdResetEntry48::FmcTci, &info.fmc.digest.into());

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcSvn, info.fmc.svn);

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcLoadAddr, info.fmc.load_addr);

        data_vault.write_cold_reset_entry4(ColdResetEntry4::FmcEntryPoint, info.fmc.entry_point);

        data_vault.write_cold_reset_entry48(
            ColdResetEntry48::OwnerPubKeyHash,
            &info.owner_pub_keys_digest.into(),
        );

        data_vault.write_cold_reset_entry4(
            ColdResetEntry4::VendorPubKeyIndex,
            info.vendor_ecc_pub_key_idx,
        );

        data_vault.write_warm_reset_entry48(WarmResetEntry48::RtTci, &info.runtime.digest.into());

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtSvn, info.runtime.svn);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtLoadAddr, info.runtime.load_addr);

        data_vault.write_warm_reset_entry4(WarmResetEntry4::RtEntryPoint, info.runtime.entry_point);

        // TODO: Need a better way to get the Manifest address
        let slice = unsafe {
            let ptr = &MAN1_ORG as *const u32;
            ptr as u32
        };

        data_vault.write_warm_reset_entry4(WarmResetEntry4::ManifestAddr, slice);
        report_boot_status(FmcAliasPopulateDataVaultComplete.into());
    }

    /// Derive Composite Device Identity (CDI) from FMC measurements
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `measurements` - Array containing the FMC measurements
    /// * `cdi` - Key Slot to store the generated CDI
    fn derive_cdi(env: &mut RomEnv, measurements: Array4x12, cdi: KeyId) -> CaliptraResult<()> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let data: [u8; 48] = measurements.into();
        let data = Hmac384Data::Slice(&data);
        Crypto::hmac384_mac(env, key, data, cdi)?;
        report_boot_status(FmcAliasDeriveCdiComplete.into());
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
    fn derive_key_pair(
        env: &mut RomEnv,
        cdi: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
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
        env: &mut RomEnv,
        info: &ImageVerificationInfo,
        input: &DiceInput,
        output: &DiceOutput,
        not_before: &[u8; FmcAliasCertTbsParams::NOT_BEFORE_LEN],
        not_after: &[u8; FmcAliasCertTbsParams::NOT_AFTER_LEN],
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        let flags = Self::make_flags(env.soc_ifc.lifecycle(), env.soc_ifc.debug_locked());

        let svn = env.data_vault.fmc_svn() as u8;
        let fuse_svn = info.fmc.effective_fuse_svn as u8;

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsParams {
            ueid: &X509::ueid(env)?,
            subject_sn: &output.subj_sn,
            subject_key_id: &output.subj_key_id,
            issuer_sn: input.auth_sn,
            authority_key_id: input.auth_key_id,
            serial_number: &X509::cert_sn(env, pub_key)?,
            public_key: &pub_key.to_der(),
            tcb_info_fmc_tci: &(&env.data_vault.fmc_tci()).into(),
            tcb_info_owner_pk_hash: &(&env.data_vault.owner_pk_hash()).into(),
            tcb_info_flags: &flags,
            tcb_info_fmc_svn: &svn.to_be_bytes(),
            tcb_info_fmc_svn_fuses: &fuse_svn.to_be_bytes(),
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
        env.key_vault.erase_key(auth_priv_key)?;

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), sig)? {
            return Err(CaliptraError::FMC_ALIAS_CERT_VERIFY);
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
        env.data_vault.set_fmc_dice_signature(sig);

        // Lock the FMC Public key in the data vault until next boot
        env.data_vault.set_fmc_pub_key(pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::FmcaliasTbs)?;

        report_boot_status(FmcAliasCertSigGenerationComplete.into());
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
