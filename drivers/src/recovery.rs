/*++

Licensed under the Apache-2.0 license.

File Name:

recovery.rs

Abstract:

File contains API for recovery register interface operations

--*/

use caliptra_error::CaliptraError;
use caliptra_registers::recovery::RecoveryReg;

pub struct RecoveryCmsReq(pub u8);

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum CmsType {
    CodeSpace = 0,
    Log = 1,
    VendorWriteOnly = 4,
    VendorReadOnly = 5,
}

impl TryFrom<u32> for CmsType {
    type Error = CaliptraError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CmsType::CodeSpace),
            1 => Ok(CmsType::Log),
            4 => Ok(CmsType::VendorReadOnly),
            5 => Ok(CmsType::VendorWriteOnly),
            7 | 15 => Err(CaliptraError::DRIVER_RECOVERY_INVALID_CMS),
            _ => Err(CaliptraError::DRIVER_RECOVERY_INVALID_CMS_TYPE),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct RecoveryCmsRet {
    pub cms_type: CmsType,
    pub size: u32,
}

pub struct Recovery {
    recovery: RecoveryReg,
    image_to_read: u32,
}

impl Recovery {
    pub fn new(recovery: RecoveryReg) -> Self {
        Self {
            recovery,
            image_to_read: 0,
        }
    }

    /// Request a Component memory space
    /// # Returns
    /// * `Ok(RecoveryCmsRet)
    /// * `Err(CaliptraErr)
    pub fn request_cms(&mut self, req: RecoveryCmsReq) -> Result<RecoveryCmsRet, CaliptraError> {
        let recovery = self.recovery.regs_mut();

        recovery
            .indirect_fifo_control()
            .write(|f| f.cms(req.0.into()).reset(true));

        let size = recovery.indirect_fifo_image_size().read();
        self.image_to_read = size;
        let cms_type = recovery
            .indirect_fifo_status()
            .read()
            .region_type()
            .try_into()?;

        Ok(RecoveryCmsRet { cms_type, size })
    }

    /// Get 4 bytes out of the recovery interface
    /// # Returns
    /// * Option(u32)
    pub fn get_word(&mut self) -> Option<u32> {
        let recovery = self.recovery.regs();

        if self.image_to_read == 0 {
            return None;
        }

        // Wait for FIFO to not be empty
        while recovery.indirect_fifo_status().read().empty() {}

        let word = recovery.fifo_data().read();
        self.image_to_read -= 4;
        Some(word)
    }
}

impl Iterator for Recovery {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_word()
    }
}
