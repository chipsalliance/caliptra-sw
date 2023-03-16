/*++

Licensed under the Apache-2.0 license.

File Name:

    fuse_bank.rs

Abstract:

    File contains API for Fuse Bank.

--*/

use crate::Array4x12;
use caliptra_registers::soc_ifc;

#[derive(Default, Debug)]
pub struct FuseBank {}

pub enum X509KeyIdAlgo {
    Sha1 = 0,
    Sha256 = 1,
    Sha384 = 2,
    Fuse = 3,
}

bitflags::bitflags! {
    pub struct VendorPubKeyRevocation : u32 {
        const KEY0 = 0b0001;
        const KEY1 = 0b0010;
        const KEY2 = 0b0100;
        const KEY3 = 0b1000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdevidCertAttr {
    Flags = 0,
    SubjectKeyId1 = 1,
    SubjectKeyId2 = 2,
    SubjectKeyId3 = 3,
    SubjectKeyId4 = 4,
    SubjectKeyId5 = 5,
    ManufacturerSerialNumber1 = 6,
    ManufacturerSerialNumber2 = 7,
}

impl From<IdevidCertAttr> for usize {
    fn from(value: IdevidCertAttr) -> Self {
        value as usize
    }
}

impl FuseBank {
    /// Get the key id crypto algorithm.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     key id crypto algorithm  
    ///
    pub fn idev_id_x509_key_id_algo(&self) -> X509KeyIdAlgo {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();

        let flags = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::Flags.into())
            .read();

        match flags & 0x3 {
            0 => X509KeyIdAlgo::Sha1,
            1 => X509KeyIdAlgo::Sha256,
            2 => X509KeyIdAlgo::Sha384,
            3 => X509KeyIdAlgo::Fuse,
            _ => unreachable!(),
        }
    }

    /// Get the manufacturer serial number.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     manufacturer serial number  
    ///
    pub fn ueid(&self) -> [u8; 8] {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();

        let ueid1 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::ManufacturerSerialNumber1.into())
            .read();
        let ueid2 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::ManufacturerSerialNumber2.into())
            .read();

        let mut ueid = [0u8; 8];
        ueid[..4].copy_from_slice(&ueid1.to_le_bytes());
        ueid[4..].copy_from_slice(&ueid2.to_le_bytes());

        ueid
    }

    /// Get the subject key identifier.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     subject key identifier
    ///
    pub fn subject_key_id(&self) -> [u8; 20] {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();

        let subkeyid1 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::SubjectKeyId1.into())
            .read();
        let subkeyid2 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::SubjectKeyId2.into())
            .read();
        let subkeyid3 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::SubjectKeyId3.into())
            .read();
        let subkeyid4 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::SubjectKeyId4.into())
            .read();
        let subkeyid5 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::SubjectKeyId5.into())
            .read();

        let mut subject_key_id = [0u8; 20];
        subject_key_id[..4].copy_from_slice(&subkeyid1.to_le_bytes());
        subject_key_id[4..8].copy_from_slice(&subkeyid2.to_le_bytes());
        subject_key_id[8..12].copy_from_slice(&subkeyid3.to_le_bytes());
        subject_key_id[12..16].copy_from_slice(&subkeyid4.to_le_bytes());
        subject_key_id[16..20].copy_from_slice(&subkeyid5.to_le_bytes());

        subject_key_id
    }

    /// Get the vendor public key hash.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     vendor public key hash
    ///
    pub fn vendor_pub_key_hash(&self) -> Array4x12 {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        Array4x12::read_from_reg(soc_ifc_regs.fuse_key_manifest_pk_hash())
    }

    /// Get the vendor public key revocation mask.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     vendor public key revocation mask
    ///
    pub fn vendor_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        VendorPubKeyRevocation::from_bits_truncate(
            soc_ifc_regs.fuse_key_manifest_pk_hash_mask().read().mask(),
        )
    }

    /// Get the owner public key hash.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     owner public key hash
    ///
    pub fn owner_pub_key_hash(&self) -> Array4x12 {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        Array4x12::read_from_reg(soc_ifc_regs.fuse_owner_pk_hash())
    }

    /// Get the rollback disability setting.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     rollback disability setting
    ///
    pub fn anti_rollback_disable(&self) -> bool {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        soc_ifc_regs.fuse_anti_rollback_disable().read().dis()
    }

    /// Get the fmc security version number.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     fmc security version number
    ///
    pub fn fmc_svn() -> u32 {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        soc_ifc_regs.fuse_fmc_key_manifest_svn().read()
    }

    /// Get the runtime security version number.
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     runtime security version number
    ///
    pub fn runtime_svn() -> u64 {
        let soc_ifc_regs = soc_ifc::RegisterBlock::soc_ifc_reg();
        (soc_ifc_regs.fuse_runtime_svn().at(1).read() as u64) << 32
            | soc_ifc_regs.fuse_runtime_svn().at(0).read() as u64
    }
}
