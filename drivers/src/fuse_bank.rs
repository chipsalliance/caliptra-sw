/*++

Licensed under the Apache-2.0 license.

File Name:

    fuse_bank.rs

Abstract:

    File contains API for Fuse Bank.

--*/

use crate::{Array4x12, Array4x16, Array4x8};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::Launder;
use caliptra_registers::soc_ifc::SocIfcReg;
use zerocopy::IntoBytes;

pub struct FuseBank<'a> {
    pub(crate) soc_ifc: &'a SocIfcReg,
}

fn first_set_msbit(num_le: &[u32; 4]) -> u32 {
    let fuse: u128 = u128::from_le_bytes(num_le.as_bytes().try_into().unwrap());
    128 - fuse.leading_zeros()
}

pub enum X509KeyIdAlgo {
    Sha1 = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
    Fuse = 4,
}

bitflags::bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    #[cfg_attr(not(feature = "no-cfi"), derive(Launder))]
    pub struct VendorEccPubKeyRevocation : u32 {
        const KEY0 = 0b0001;
        const KEY1 = 0b0010;
        const KEY2 = 0b0100;
        const KEY3 = 0b1000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdevidCertAttr {
    Flags = 0,
    EccSubjectKeyId1 = 1,
    EccSubjectKeyId2 = 2,
    EccSubjectKeyId3 = 3,
    EccSubjectKeyId4 = 4,
    EccSubjectKeyId5 = 5,
    MldsaSubjectKeyId1 = 6,
    MldsaSubjectKeyId2 = 7,
    MldsaSubjectKeyId3 = 8,
    MldsaSubjectKeyId4 = 9,
    MldsaSubjectKeyId5 = 10,
    UeidType = 11,
    ManufacturerSerialNumber1 = 12,
    ManufacturerSerialNumber2 = 13,
    ManufacturerSerialNumber3 = 14,
    ManufacturerSerialNumber4 = 15,
}

impl From<IdevidCertAttr> for usize {
    fn from(value: IdevidCertAttr) -> Self {
        value as usize
    }
}

impl FuseBank<'_> {
    /// Get the key id crypto algorithm.
    ///
    /// # Arguments
    /// * `ecc_key_id_algo` - Whether to get ECC or MLDSA key id algorithm
    ///
    /// # Returns
    ///     key id crypto algorithm
    ///
    pub fn idev_id_x509_key_id_algo(&self, ecc_key_id_algo: bool) -> X509KeyIdAlgo {
        let soc_ifc_regs = self.soc_ifc.regs();

        let mut flags = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::Flags.into())
            .read();

        if !ecc_key_id_algo {
            // ECC Key Id Algo is in Bits 0-2.
            // MLDSA Key Id Algo is in Bits 3-5.
            flags >>= 3;
        }

        match flags & 0x7 {
            0 => X509KeyIdAlgo::Sha1,
            1 => X509KeyIdAlgo::Sha256,
            2 => X509KeyIdAlgo::Sha384,
            4 => X509KeyIdAlgo::Sha512,
            _ => X509KeyIdAlgo::Fuse,
        }
    }

    /// Get the manufacturer serial number.
    ///
    /// # Returns
    ///     manufacturer serial number
    ///
    pub fn ueid(&self) -> [u8; 17] {
        let soc_ifc_regs = self.soc_ifc.regs();

        let ueid1 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::ManufacturerSerialNumber1.into())
            .read();
        let ueid2 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::ManufacturerSerialNumber2.into())
            .read();
        let ueid3 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::ManufacturerSerialNumber3.into())
            .read();
        let ueid4 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::ManufacturerSerialNumber4.into())
            .read();
        let ueid_type = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(IdevidCertAttr::UeidType.into())
            .read() as u8;

        let mut ueid = [0u8; 17];
        ueid[0] = ueid_type;
        ueid[1..5].copy_from_slice(&ueid1.to_le_bytes());
        ueid[5..9].copy_from_slice(&ueid2.to_le_bytes());
        ueid[9..13].copy_from_slice(&ueid3.to_le_bytes());
        ueid[13..].copy_from_slice(&ueid4.to_le_bytes());

        ueid
    }

    /// Get the subject key identifier.
    ///
    /// # Arguments
    /// * `ecc_subject_key_id` - Whether to get ECC or MLDSA subject key identifier
    ///
    /// # Returns
    ///     subject key identifier
    ///
    pub fn subject_key_id(&self, ecc_subject_key_id: bool) -> [u8; 20] {
        let key_id = if ecc_subject_key_id {
            [
                IdevidCertAttr::EccSubjectKeyId1,
                IdevidCertAttr::EccSubjectKeyId2,
                IdevidCertAttr::EccSubjectKeyId3,
                IdevidCertAttr::EccSubjectKeyId4,
                IdevidCertAttr::EccSubjectKeyId5,
            ]
        } else {
            [
                IdevidCertAttr::MldsaSubjectKeyId1,
                IdevidCertAttr::MldsaSubjectKeyId2,
                IdevidCertAttr::MldsaSubjectKeyId3,
                IdevidCertAttr::MldsaSubjectKeyId4,
                IdevidCertAttr::MldsaSubjectKeyId5,
            ]
        };

        let soc_ifc_regs = self.soc_ifc.regs();

        let subkeyid1 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(key_id[0].into())
            .read();
        let subkeyid2 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(key_id[1].into())
            .read();
        let subkeyid3 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(key_id[2].into())
            .read();
        let subkeyid4 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(key_id[3].into())
            .read();
        let subkeyid5 = soc_ifc_regs
            .fuse_idevid_cert_attr()
            .at(key_id[4].into())
            .read();

        let mut subject_key_id = [0u8; 20];
        subject_key_id[..4].copy_from_slice(&subkeyid1.to_le_bytes());
        subject_key_id[4..8].copy_from_slice(&subkeyid2.to_le_bytes());
        subject_key_id[8..12].copy_from_slice(&subkeyid3.to_le_bytes());
        subject_key_id[12..16].copy_from_slice(&subkeyid4.to_le_bytes());
        subject_key_id[16..20].copy_from_slice(&subkeyid5.to_le_bytes());

        subject_key_id
    }

    /// Get the vendor public key info hash.
    ///
    /// # Returns
    ///     vendor public key info hash
    ///
    pub fn vendor_pub_key_info_hash(&self) -> Array4x12 {
        let soc_ifc_regs = self.soc_ifc.regs();
        Array4x12::read_from_reg(soc_ifc_regs.fuse_vendor_pk_hash())
    }

    /// Get the ecc vendor public key revocation mask.
    ///
    /// # Returns
    ///     ecc vendor public key revocation mask
    ///
    pub fn vendor_ecc_pub_key_revocation(&self) -> VendorEccPubKeyRevocation {
        let soc_ifc_regs = self.soc_ifc.regs();
        VendorEccPubKeyRevocation::from_bits_truncate(
            soc_ifc_regs.fuse_ecc_revocation().read().into(),
        )
    }

    /// Get the lms vendor public key revocation mask.
    ///
    /// # Returns
    ///     lms vendor public key revocation mask
    ///
    pub fn vendor_lms_pub_key_revocation(&self) -> u32 {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.fuse_lms_revocation().read()
    }

    /// Get the mldsa vendor public key revocation mask.
    ///
    /// # Returns
    ///     mldsa vendor public key revocation mask
    ///
    pub fn vendor_mldsa_pub_key_revocation(&self) -> u32 {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.fuse_mldsa_revocation().read().into()
    }

    /// Get the owner public key hash.
    ///
    /// # Returns
    ///     owner public key hash
    ///
    pub fn owner_pub_key_hash(&self) -> Array4x12 {
        let soc_ifc_regs = self.soc_ifc.regs();
        Array4x12::read_from_reg(soc_ifc_regs.cptra_owner_pk_hash())
    }

    /// Get the rollback disability setting.
    ///
    /// # Returns
    ///     rollback disability setting
    ///
    pub fn anti_rollback_disable(&self) -> bool {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.fuse_anti_rollback_disable().read().dis()
    }

    /// Get the firmware fuse security version number.
    ///
    /// # Returns
    ///     firmware security version number
    ///
    pub fn fw_fuse_svn(&self) -> u32 {
        let soc_ifc_regs = self.soc_ifc.regs();
        // The legacy name of this register is `fuse_runtime_svn`
        first_set_msbit(&soc_ifc_regs.fuse_runtime_svn().read())
    }

    /// Get the lms revocation bits.
    ///
    /// # Returns
    ///     lms revocation bits
    ///
    pub fn lms_revocation(&self) -> u32 {
        let soc_ifc_regs = self.soc_ifc.regs();
        soc_ifc_regs.fuse_lms_revocation().read()
    }

    /// Get the PQC (MLDSA or LMS) key type.
    ///
    /// # Returns
    ///    PQC key type set in the fuses.
    ///
    pub fn pqc_key_type(&self) -> u32 {
        self.soc_ifc.regs().fuse_pqc_key_type().read().into()
    }

    /// Get the manufacturing debug unlock token
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     manufacturing debug unlock token
    ///
    pub fn manuf_dbg_unlock_token(&self) -> Array4x16 {
        let soc_ifc_regs = self.soc_ifc.regs();
        Array4x16::read_from_reg(soc_ifc_regs.fuse_manuf_dbg_unlock_token())
    }

    /// Get the OCP HEK Seed
    ///
    /// # Arguments
    /// * None
    ///
    /// # Returns
    ///     OCP HEK Seed
    pub fn ocp_heck_seed(&self) -> Array4x8 {
        let soc_ifc_regs = self.soc_ifc.regs();
        Array4x8::read_from_reg(soc_ifc_regs.fuse_hek_seed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_set_msbit() {
        let mut svn: u128 = 0;
        let mut svn_arr: [u32; 4] = [0u32, 0u32, 0u32, 0u32];

        for i in 0..128 {
            for (idx, word) in svn_arr.iter_mut().enumerate() {
                *word = u32::from_le_bytes(svn.as_bytes()[idx * 4..][..4].try_into().unwrap())
            }
            let result = first_set_msbit(&svn_arr);
            assert_eq!(result, i);

            svn = (svn << 1) | 1;
        }
    }
}
