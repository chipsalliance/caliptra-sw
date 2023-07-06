/*++

Licensed under the Apache-2.0 license.

File Name:

    kv_access.rs

Abstract:

    File contains helper methods used by peripherals to access keys in
    key vault.

--*/

use crate::array::Array4xN;
use crate::{wait, CaliptraResult, KeyId, KeyUsage, PcrId};
use caliptra_registers::enums::KvErrorE;
use caliptra_registers::regs::{KvReadCtrlRegWriteVal, KvStatusRegReadVal, KvWriteCtrlRegWriteVal};
use ureg::{Mmio, MmioMut};

/// Key read operation arguments
#[derive(Debug, Clone, Copy)]
pub struct KeyReadArgs {
    /// Key Id
    pub id: KeyId,
}

impl KeyReadArgs {
    /// Create an instance of `KeyReadArgs`
    ///
    /// # Arguments
    ///
    /// * `id` - Key Id
    pub fn new(id: KeyId) -> Self {
        Self { id }
    }
}

/// Key write operation arguments
#[derive(Debug, Clone, Copy)]
pub struct KeyWriteArgs {
    /// Key Id
    pub id: KeyId,

    /// Key usage flags
    pub usage: KeyUsage,
}

impl KeyWriteArgs {
    /// Create an instance of `KeyWriteArgs`
    ///
    /// # Arguments
    ///
    /// * `id` - Key Id
    /// * `usage` - Key usage flags
    pub fn new(id: KeyId, usage: KeyUsage) -> Self {
        Self { id, usage }
    }
}

/// Key Access Error
pub(crate) enum KvAccessErr {
    /// Key read error
    KeyRead,

    /// Key write error
    KeyWrite,

    /// Generic error
    Generic,
}

/// Key Access
pub(crate) enum KvAccess {}

impl KvAccess {
    /// Begin copying the array to key vault
    ///
    /// This function disables the write enable bit in control register
    /// to prevent the copy of the key to key vault
    ///
    /// # Arguments
    ///
    /// * `status_reg` - Status register
    /// * `ctrl_reg` - Control register
    pub(crate) fn begin_copy_to_arr<
        StatusReg: ureg::ReadableReg<ReadVal = KvStatusRegReadVal>,
        CtrlReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = KvWriteCtrlRegWriteVal>,
        TMmio: MmioMut,
    >(
        status_reg: ureg::RegRef<StatusReg, TMmio>,
        ctrl_reg: ureg::RegRef<CtrlReg, TMmio>,
    ) -> CaliptraResult<()> {
        wait::until(|| status_reg.read().ready());
        ctrl_reg.write(|w| w.write_en(false));
        Ok(())
    }

    /// Finish copying the key to array
    ///
    /// # Arguments
    ///
    /// * `reg` - Source register to copy from
    /// * `arr` - Destination array to copy the contents of register to
    pub(crate) fn end_copy_to_arr<
        const ARR_WORD_LEN: usize,
        const ARR_BYTE_LEN: usize,
        TReg: ureg::ReadableReg<ReadVal = u32>,
        TMmio: Mmio + Copy,
    >(
        reg: ureg::Array<ARR_WORD_LEN, ureg::RegRef<TReg, TMmio>>,
        arr: &mut Array4xN<ARR_WORD_LEN, ARR_BYTE_LEN>,
    ) -> CaliptraResult<()> {
        *arr = Array4xN::<ARR_WORD_LEN, ARR_BYTE_LEN>::read_from_reg(reg);
        Ok(())
    }

    /// Begin copying the contents of the operation to key slot in key vault
    ///
    /// # Arguments
    ///
    /// * `status_reg` - Status register
    /// * `ctrl_reg` - Control register
    /// * `key` - Key slot in key vault
    pub(crate) fn begin_copy_to_kv<
        StatusReg: ureg::ReadableReg<ReadVal = KvStatusRegReadVal>,
        CtrlReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = KvWriteCtrlRegWriteVal>,
        TMmio: MmioMut,
    >(
        status_reg: ureg::RegRef<StatusReg, TMmio>,
        ctrl_reg: ureg::RegRef<CtrlReg, TMmio>,
        key: KeyWriteArgs,
    ) -> CaliptraResult<()> {
        wait::until(|| status_reg.read().ready());
        ctrl_reg.write(|w| {
            w.write_en(true)
                .write_entry(key.id.into())
                .hmac_key_dest_valid(key.usage.hmac_key())
                .hmac_block_dest_valid(key.usage.hmac_data())
                .sha_block_dest_valid(key.usage.sha_data())
                .ecc_pkey_dest_valid(key.usage.ecc_private_key())
                .ecc_seed_dest_valid(key.usage.ecc_key_gen_seed())
        });
        Ok(())
    }

    /// Finish copying the key to key vault
    ///
    /// # Arguments
    ///
    /// * `status_reg` - Status register
    /// * `key` - Key slot in key vault
    pub(crate) fn end_copy_to_kv<
        SReg: ureg::ReadableReg<ReadVal = KvStatusRegReadVal>,
        TMmio: Mmio,
    >(
        status_reg: ureg::RegRef<SReg, TMmio>,
        _key: KeyWriteArgs,
    ) -> Result<(), KvAccessErr> {
        wait::until(|| status_reg.read().valid());
        match status_reg.read().error() {
            KvErrorE::Success => Ok(()),
            KvErrorE::KvReadFail => Err(KvAccessErr::KeyRead),
            KvErrorE::KvWriteFail => Err(KvAccessErr::KeyWrite),
            _ => Err(KvAccessErr::Generic),
        }
    }

    /// Copy the contents of the array to register
    ///
    /// # Arguments
    ///
    /// * `arr` - Source array to copy from
    /// * `reg` - Destination register to copy to
    pub(crate) fn copy_from_arr<
        const ARR_WORD_LEN: usize,
        const ARR_BYTE_LEN: usize,
        TReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = u32>,
        TMmio: MmioMut + Copy,
    >(
        arr: &Array4xN<ARR_WORD_LEN, ARR_BYTE_LEN>,
        reg: ureg::Array<ARR_WORD_LEN, ureg::RegRef<TReg, TMmio>>,
    ) -> CaliptraResult<()> {
        arr.write_to_reg(reg);
        Ok(())
    }

    /// Copy the contents from key slot in key vault to crypto block
    ///
    /// # Arguments
    ///
    /// * `key` - Key slot to copy the data from
    /// * `status_reg` - Status register
    /// * `ctrl_reg` - Control register
    pub(crate) fn copy_from_kv<
        StatusReg: ureg::ReadableReg<ReadVal = KvStatusRegReadVal>,
        CtrlReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = KvReadCtrlRegWriteVal>,
        TMmio: MmioMut,
    >(
        key: KeyReadArgs,
        status_reg: ureg::RegRef<StatusReg, TMmio>,
        ctrl_reg: ureg::RegRef<CtrlReg, TMmio>,
    ) -> Result<(), KvAccessErr> {
        crate::wait::until(|| status_reg.read().ready());

        ctrl_reg.write(|w| {
            w.read_en(true)
                .read_entry(key.id.into())
                .pcr_hash_extend(false)
        });

        crate::wait::until(|| status_reg.read().valid());

        match status_reg.read().error() {
            KvErrorE::Success => Ok(()),
            KvErrorE::KvReadFail => Err(KvAccessErr::KeyRead),
            KvErrorE::KvWriteFail => Err(KvAccessErr::KeyWrite),
            _ => Err(KvAccessErr::Generic),
        }
    }

    /// Hash extends the contents from pcr slot in pcr vault
    ///
    /// # Arguments
    ///
    /// * `pcr_id` - Pcr slot to hash extend
    /// * `status_reg` - Status register
    /// * `ctrl_reg` - Control register
    pub(crate) fn extend_from_pv<
        StatusReg: ureg::ReadableReg<ReadVal = KvStatusRegReadVal>,
        CtrlReg: ureg::ResettableReg + ureg::WritableReg<WriteVal = KvReadCtrlRegWriteVal>,
        TMmio: MmioMut,
    >(
        pcr_id: PcrId,
        status_reg: ureg::RegRef<StatusReg, TMmio>,
        ctrl_reg: ureg::RegRef<CtrlReg, TMmio>,
    ) -> Result<(), KvAccessErr> {
        crate::wait::until(|| status_reg.read().ready());

        ctrl_reg.write(|w| {
            w.read_en(true)
                .read_entry(pcr_id.into())
                .pcr_hash_extend(true)
        });

        crate::wait::until(|| status_reg.read().valid());

        match status_reg.read().error() {
            KvErrorE::Success => Ok(()),
            KvErrorE::KvReadFail => Err(KvAccessErr::KeyRead),
            KvErrorE::KvWriteFail => Err(KvAccessErr::KeyWrite),
            _ => Err(KvAccessErr::Generic),
        }
    }
}
