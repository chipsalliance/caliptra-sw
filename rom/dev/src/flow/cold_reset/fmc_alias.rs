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
use crate::verifier::RomImageVerificationEnv;
use crate::{cprint, cprint_slice, cprintln, pcr};
use crate::{rom_env::RomEnv, rom_err_def};
use caliptra_drivers::{
    Array4x12, CaliptraResult, ColdResetEntry4, ColdResetEntry48, Hmac384Data, Hmac384Key, KeyId,
    KeyReadArgs, MailboxRecvTxn, ResetReason, WarmResetEntry4, WarmResetEntry48,
};
use caliptra_image_types::{ImageManifest, IMAGE_BYTE_SIZE};
use caliptra_image_verify::{ImageVerificationInfo, ImageVerifier};
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams};
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

        // populate data vault
        Self::populate_data_vault(env, &info);

        // Extend PCR0 & PCR1
        Self::extend_pcrs(env)?;

        // Load the image
        Self::load_image(env, &manifest, &txn)?;

        // At this point PCR0 & PCR1 must have the same value. We use the value
        // of PCR1 as the UDS for deriving the CDI
        let uds = env
            .pcr_bank()
            .map(|p| p.read_pcr(caliptra_drivers::PcrId::PcrId1));

        // Derive the DICE CDI from decrypted UDS
        let cdi = Self::derive_cdi(env, uds, input.cdi)?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, cdi, input.subj_priv_key)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;

        // Generate the output for next layer
        let output = input.to_output(key_pair, subj_sn, subj_key_id);

        // Generate Local Device ID Certificate
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
    /// Mailbox transaction handle. This transaction is ManuallyDrop because we
    /// don't want the transaction to be completed with failure until after
    /// report_error is called. This prevents a race condition where the SoC
    /// tries reads FW_ERROR_NON_FATAL immediately after the mailbox transaction
    /// fails, but before caliptra has set the FW_ERROR_NON_FATAL register.
    ///
    /// Success of the MBOX_DOWNLOAD_
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
                // This is a download-firmware command; don't drop this as the transaction
                // be completed by either report_error() (on failure) or by
                // the runtime firmware (on success)
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

    /// Extend the PCR0 & PCR1
    ///
    /// PCR0 is a journey PCR and is locked for clear on cold boot. PCR1
    /// is the current PCR and is cleared on any reset
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    fn extend_pcrs(env: &RomEnv) -> CaliptraResult<()> {
        pcr::extend_pcr0(env)?;
        pcr::extend_pcr1(env)?;

        // TODO: Check PCR0 != 0

        // TODO: Check PCR0 == PCR1

        Ok(())
    }

    /// Derive Composite Device Identity (CDI) from Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `uds` - Array containing the UDS
    /// * `cdi` - Key Slot to store the generated CDI
    ///
    /// # Returns
    ///
    /// * `KeyId` - KeySlot containing the DICE CDI
    fn derive_cdi(env: &RomEnv, uds: Array4x12, cdi: KeyId) -> CaliptraResult<KeyId> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let data: [u8; 48] = uds.into();
        let data = Hmac384Data::Slice(&data);
        let cdi = Crypto::hmac384_mac(env, key, data, cdi)?;
        Ok(cdi)
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
            tcb_info_fmc_tci: &env.data_vault().map(|d| d.fmc_tci()).into(),
            tcb_info_owner_pk_hash: &env.data_vault().map(|d| d.owner_pk_hash()).into(),
        };

        // Generate the `To Be Signed` portion of the CSR
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
