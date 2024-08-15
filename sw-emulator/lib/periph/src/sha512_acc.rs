/*++

Licensed under the Apache-2.0 license.

File Name:

    sha512_acc.rs

Abstract:

    File contains SHA accelerator implementation.

--*/
use crate::MailboxRam;
use caliptra_emu_bus::{
    ActionHandle, Bus, BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteRegister, Timer,
};
use caliptra_emu_crypto::{EndianessTransform, Sha512, Sha512Mode};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use smlang::statemachine;
use std::cell::RefCell;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

/// Maximum mailbox capacity in DWORDS.
const MAX_MAILBOX_CAPACITY_WORDS: usize = (128 << 10) >> 2;

/// Maximum mailbox capacity in bytes.
const MAX_MAILBOX_CAPACITY_BYTES: usize = MAX_MAILBOX_CAPACITY_WORDS * RvSize::Word as usize;

/// The number of CPU clock cycles it takes to perform sha operation.
const SHA_ACC_OP_TICKS: u64 = 1000;

const SHA512_BLOCK_SIZE: usize = 128;
const SHA512_HASH_SIZE: usize = 64;

#[cfg(test)]
const SHA384_HASH_SIZE: usize = 48;
const SHA512_HASH_HALF_SIZE: usize = SHA512_HASH_SIZE / 2;

register_bitfields! [
    u32,

    /// Control Register Fields
    ShaMode [
        MODE OFFSET(0) NUMBITS(2) [
            SHA512_ACC_MODE_SHA_STREAM_384 = 0,
            SHA512_ACC_MODE_SHA_STREAM_512 = 1,
            SHA512_ACC_MODE_MBOX_384 = 2,
            SHA512_ACC_MODE_SHA_MBOX_512 = 3,
        ],
        ENDIAN_TOGGLE OFFSET(2) NUMBITS(1) [],
        RSVD OFFSET(3) NUMBITS(29) [],
    ],

    /// Execute Register Fields
    Execute[
        EXECUTE OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Status Register Fields
    Status[
        VALID OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Lock Register Fields
    Lock[
        LOCK OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Control Register Fields
    Control[
        ZEROIZE OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],
];

#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct Sha512AcceleratorRegs {
    /// LOCK register
    #[register(offset = 0x0000_0000, read_fn = on_read_lock, write_fn = on_write_lock)]
    _lock: ReadWriteRegister<u32, Lock::Register>,

    /// USER register
    #[register(offset = 0x0000_0004)]
    user: ReadOnlyRegister<u32>,

    /// MODE register
    #[register(offset = 0x0000_0008, write_fn = on_write_mode)]
    mode: ReadWriteRegister<u32, ShaMode::Register>,

    /// START_ADDRESS register
    #[register(offset = 0x0000_000c, write_fn = on_write_start_address)]
    start_address: ReadWriteRegister<u32>,

    /// DLEN register
    #[register(offset = 0x0000_0010, write_fn = on_write_dlen)]
    dlen: ReadWriteRegister<u32>,

    /// DATAIN register
    #[register(offset = 0x0000_0014, write_fn = on_write_data_in)]
    data_in: ReadWriteRegister<u32>,

    /// EXECUTE register
    #[register(offset = 0x0000_0018, write_fn = on_write_execute)]
    execute: ReadWriteRegister<u32, Execute::Register>,

    /// STATUS register
    #[register(offset = 0x0000_001c)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// SHA512 Hash Memory
    #[peripheral(offset = 0x0000_0020, mask = 0x0000_001F)]
    hash_lower: ReadOnlyMemory<SHA512_HASH_HALF_SIZE>,

    #[peripheral(offset = 0x0000_0040, mask = 0x0000_001F)]
    hash_upper: ReadOnlyMemory<SHA512_HASH_HALF_SIZE>,

    /// Control register
    #[register(offset = 0x0000_0060, write_fn = on_write_control)]
    control: ReadWriteRegister<u32, Control::Register>,

    /// Mailbox Memory
    mailbox_ram: MailboxRam,

    /// Timer
    timer: Timer,

    /// State Machine
    state_machine: StateMachine<Context>,

    /// Operation complete action
    op_complete_action: Option<ActionHandle>,

    /// Hasher for streamed hash data
    sha_stream: Sha512,
}

impl Sha512AcceleratorRegs {
    pub fn new(clock: &Clock, mailbox_ram: MailboxRam) -> Self {
        let mut result = Self {
            status: ReadOnlyRegister::new(Status::VALID::CLEAR.value),
            hash_lower: ReadOnlyMemory::new(),
            hash_upper: ReadOnlyMemory::new(),
            mailbox_ram,
            timer: Timer::new(clock),
            _lock: ReadWriteRegister::new(0),
            user: ReadOnlyRegister::new(0),
            dlen: ReadWriteRegister::new(0),
            data_in: ReadWriteRegister::new(0),
            execute: ReadWriteRegister::new(0),
            mode: ReadWriteRegister::new(0),
            start_address: ReadWriteRegister::new(0),
            op_complete_action: None,
            state_machine: StateMachine::new(Context::new()),
            control: ReadWriteRegister::new(0),
            sha_stream: Sha512::new(Sha512Mode::Sha512),
        };
        // The peripheral needs to be locked at boot by the uC.
        result
            .state_machine
            .process_event(Events::RdLock(Owner(0)))
            .unwrap();
        result
    }

    /// On Read callback for `lock` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::LoadAccessFault`
    pub fn on_read_lock(&mut self, size: RvSize) -> Result<u32, BusError> {
        // Reads have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::LoadAccessFault)?
        }

        if self
            .state_machine
            .process_event(Events::RdLock(Owner(0)))
            .is_ok()
        {
            Ok(0)
        } else {
            Ok(1)
        }
    }

    /// On Write callback for `lock` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_lock(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        let val_reg = InMemoryRegister::<u32, Lock::Register>::new(val);
        if val_reg.read(Lock::LOCK) == 1
            && self
                .state_machine
                .process_event(Events::WrLock(Owner(0)))
                .is_ok()
        {
            // Reset the state.
            self.status.reg.modify(Status::VALID::CLEAR);
            self.dlen.reg.set(0);
            self.start_address.reg.set(0);
            self.execute.reg.set(0);
            self.data_in.reg.set(0);
            self.mode.reg.set(0);
        }
        Ok(())
    }

    /// On Write callback for `mode` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_mode(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.mode.reg.set(val);

        let mode = self.mode.reg.read(ShaMode::MODE);
        if mode == ShaMode::MODE::SHA512_ACC_MODE_SHA_STREAM_384.value {
            self.sha_stream = Sha512::new(Sha512Mode::Sha384);
        } else if mode == ShaMode::MODE::SHA512_ACC_MODE_SHA_STREAM_512.value {
            self.sha_stream = Sha512::new(Sha512Mode::Sha512);
        }
        Ok(())
    }

    /// On Write callback for `start_address` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_start_address(
        &mut self,
        size: RvSize,
        start_address: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word
            || start_address % (RvSize::Word as RvData) != 0
            || start_address >= (MAX_MAILBOX_CAPACITY_WORDS as RvData)
        {
            Err(BusError::StoreAccessFault)?
        }

        // Set the start_address register
        self.start_address.reg.set(start_address);

        Ok(())
    }

    /// On Write callback for `dlen` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_dlen(&mut self, size: RvSize, dlen: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word || dlen > (MAX_MAILBOX_CAPACITY_BYTES as RvData) {
            Err(BusError::StoreAccessFault)?
        }

        // Set the start_address register
        self.dlen.reg.set(dlen);

        Ok(())
    }

    /// On Write callback for `data_in` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_data_in(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.sha_stream.update_bytes(&val.to_be_bytes());

        Ok(())
    }

    /// On Write callback for `execute` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_execute(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the execute register
        self.execute.reg.set(val);

        if self.execute.reg.read(Execute::EXECUTE) == 1 {
            let mode = self.mode.reg.read(ShaMode::MODE);
            if mode == ShaMode::MODE::SHA512_ACC_MODE_MBOX_384.value {
                self.compute_mbox_hash();

                // Schedule a future call to poll() complete the operation.
                self.op_complete_action = Some(self.timer.schedule_poll_in(SHA_ACC_OP_TICKS));
            } else if mode == ShaMode::MODE::SHA512_ACC_MODE_SHA_STREAM_384.value
                || mode == ShaMode::MODE::SHA512_ACC_MODE_SHA_STREAM_512.value
            {
                self.finalize_stream_hash();
            } else {
                return Err(BusError::StoreAccessFault);
            }
        } else {
            Err(BusError::StoreAccessFault)?
        }

        Ok(())
    }

    /// On Write callback for `control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the control register
        self.control.reg.set(val);

        if self.control.reg.is_set(Control::ZEROIZE) {
            self.zeroize();
        }

        Ok(())
    }

    /// Function to retrieve data from the mailbox and compute it's hash.
    ///
    /// # Arguments
    ///
    /// * None
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn compute_mbox_hash(&mut self) {
        let data_len = self.dlen.reg.get() as usize;
        let totaldwords = (data_len + (RvSize::Word as usize - 1)) / (RvSize::Word as usize);
        let totalblocks = ((data_len + 16) + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;
        let totalbytes = totalblocks * SHA512_BLOCK_SIZE;
        let mut block_arr: Vec<u8> = vec![0; totalbytes];
        let start_address = self.start_address.reg.get();

        // Read data from mailbox ram.
        for idx in 0..totaldwords {
            let byte_offset = idx << 2;
            let word = self
                .mailbox_ram
                .read(RvSize::Word, start_address + byte_offset as u32)
                .unwrap();
            block_arr[byte_offset..byte_offset + 4].copy_from_slice(&word.to_le_bytes());
        }

        // Check ENDIAN_TOGGLE bit. If set to 1, data from the mailbox is in big-endian format.
        // Convert it to little-endian for padding operation.
        if self.mode.reg.read(ShaMode::ENDIAN_TOGGLE) == 1 {
            block_arr.to_little_endian();
        }

        // Add block padding.
        block_arr[data_len] = 0b1000_0000;

        // Add block length.
        let len = (data_len as u128) * 8;
        block_arr[totalbytes - 16..].copy_from_slice(&len.to_be_bytes());
        block_arr.to_big_endian();

        let mut sha = Sha512::new(Sha512Mode::Sha384);
        for block_count in 0..totalblocks {
            sha.update(array_ref![
                block_arr,
                block_count * SHA512_BLOCK_SIZE,
                SHA512_BLOCK_SIZE
            ]);
        }

        let mut hash = [0u8; SHA512_HASH_SIZE];
        sha.copy_hash(&mut hash);

        // Place the hash in the DIGEST registers.
        self.hash_lower
            .data_mut()
            .copy_from_slice(&hash[..SHA512_HASH_HALF_SIZE]);

        self.hash_upper
            .data_mut()
            .copy_from_slice(&hash[SHA512_HASH_HALF_SIZE..]);
    }

    fn finalize_stream_hash(&mut self) {
        self.sha_stream.finalize(self.dlen.reg.get());

        let mut hash = [0u8; SHA512_HASH_SIZE];
        self.sha_stream.copy_hash(&mut hash);

        // Place the hash in the DIGEST registers.
        self.hash_lower
            .data_mut()
            .copy_from_slice(&hash[..SHA512_HASH_HALF_SIZE]);

        self.hash_upper
            .data_mut()
            .copy_from_slice(&hash[SHA512_HASH_HALF_SIZE..]);

        self.op_complete();
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        }
    }

    /// Called by Bus::warm_reset() to indicate a warm reset
    fn warm_reset(&mut self) {
        self.state_machine
            .process_event(Events::RdLock(Owner(0)))
            .unwrap();
    }

    /// Called by Bus::update_reset() to indicate an update reset
    fn update_reset(&mut self) {
        // TODO: Reset registers
    }

    fn op_complete(&mut self) {
        // Update the 'Valid' status bit
        self.status.reg.modify(Status::VALID::SET);
    }

    /// Get the length of the hash
    #[cfg(test)]
    pub fn hash_len(&self) -> usize {
        let mode = self.mode.reg.read(ShaMode::MODE);
        if mode == ShaMode::MODE::SHA512_ACC_MODE_MBOX_384.value
            || mode == ShaMode::MODE::SHA512_ACC_MODE_SHA_STREAM_384.value
        {
            SHA384_HASH_SIZE
        } else {
            SHA512_HASH_SIZE
        }
    }

    #[cfg(test)]
    pub fn copy_hash(&self, hash_out: &mut [u8]) {
        let mut hash = [0u8; SHA512_HASH_SIZE];

        hash[..SHA512_HASH_HALF_SIZE].copy_from_slice(&self.hash_lower.data()[..]);
        hash[SHA512_HASH_HALF_SIZE..].copy_from_slice(&self.hash_upper.data()[..]);

        hash.iter()
            .flat_map(|i| i.to_be_bytes())
            .take(self.hash_len())
            .zip(hash_out)
            .for_each(|(src, dest)| *dest = src);
    }

    fn zeroize(&mut self) {
        self.hash_lower.data_mut().fill(0);
        self.hash_upper.data_mut().fill(0);
    }
}

#[derive(Clone)]
pub struct Sha512Accelerator {
    regs: Rc<RefCell<Sha512AcceleratorRegs>>,
}

impl Sha512Accelerator {
    /// Create a new instance of SHA-512 Accelerator
    pub fn new(clock: &Clock, mailbox_ram: MailboxRam) -> Self {
        Self {
            regs: Rc::new(RefCell::new(Sha512AcceleratorRegs::new(clock, mailbox_ram))),
        }
    }
}

impl Bus for Sha512Accelerator {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().write(size, addr, val)
    }

    fn poll(&mut self) {
        self.regs.borrow_mut().poll();
    }

    fn warm_reset(&mut self) {
        self.regs.borrow_mut().warm_reset();
    }

    fn update_reset(&mut self) {
        self.regs.borrow_mut().update_reset();
    }
}

pub struct Owner(pub u32);

statemachine! {
    transitions: {
        // CurrentState Event [guard] / action = NextState
        *Idle + RdLock(Owner) [is_not_locked] / lock = RdyForExc,
        RdyForExc + WrLock(Owner) [is_locked] / unlock = Idle
    }
}

/// State machine extended variables.
pub struct Context {
    /// lock state
    pub locked: u32,
    /// Who acquired the lock.
    pub user: u32,
}

impl Context {
    fn new() -> Self {
        Self { locked: 0, user: 0 }
    }
}

impl StateMachineContext for Context {
    // guards
    fn is_not_locked(&mut self, _user: &Owner) -> Result<(), ()> {
        if self.locked == 1 {
            // no transition
            Err(())
        } else {
            Ok(())
        }
    }
    fn is_locked(&mut self, _user: &Owner) -> Result<(), ()> {
        if self.locked != 0 {
            Ok(())
        } else {
            // no transition
            Err(())
        }
    }

    fn lock(&mut self, user: &Owner) {
        self.locked = 1;
        self.user = user.0;
    }
    fn unlock(&mut self, _user: &Owner) {
        self.locked = 0;
    }
}

#[cfg(test)]
mod tests {
    use crate::{sha512_acc::*, MailboxRam};
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;
    use tock_registers::registers::InMemoryRegister;

    const OFFSET_LOCK: RvAddr = 0x00;
    const OFFSET_MODE: RvAddr = 0x08;
    const OFFSET_START_ADDRESS: RvAddr = 0x0c;
    const OFFSET_DLEN: RvAddr = 0x10;
    const OFFSET_EXECUTE: RvAddr = 0x18;
    const OFFSET_STATUS: RvAddr = 0x1c;

    fn test_sha_accelerator(data: &[u8], expected: &[u8], start_address: usize) {
        // Write to the mailbox.
        let mut mb_ram = MailboxRam::new();
        if !data.is_empty() {
            assert!((start_address % 4) == 0);
            let mut data_word_multiples = vec![0u8; ((start_address + data.len() + 3) / 4) * 4];
            data_word_multiples[start_address..start_address + data.len()].copy_from_slice(data);

            for idx in (0..data_word_multiples.len()).step_by(4) {
                // Convert to big-endian.
                let dword = ((data_word_multiples[idx] as u32) << 24)
                    | ((data_word_multiples[idx + 1] as u32) << 16)
                    | ((data_word_multiples[idx + 2] as u32) << 8)
                    | (data_word_multiples[idx + 3] as u32);

                mb_ram.write(RvSize::Word, idx as u32, dword).unwrap();
            }
        }

        let clock = Clock::new();
        let mut sha_accl = Sha512Accelerator::new(&clock, mb_ram.clone());
        // Unlock the initial state
        sha_accl.write(RvSize::Word, OFFSET_LOCK, 1).unwrap();

        // Acquire the accelerator lock.
        loop {
            let lock = sha_accl.read(RvSize::Word, OFFSET_LOCK).unwrap();
            if lock == 0 {
                break;
            }
        }

        // Confirm it is locked
        let lock = sha_accl.read(RvSize::Word, OFFSET_LOCK).unwrap();
        assert_eq!(lock, 1);

        // Set the mode.
        let mode = InMemoryRegister::<u32, ShaMode::Register>::new(0);
        mode.write(
            ShaMode::MODE.val(ShaMode::MODE::SHA512_ACC_MODE_MBOX_384.value)
                + ShaMode::ENDIAN_TOGGLE.val(1),
        );
        assert_eq!(
            sha_accl.write(RvSize::Word, OFFSET_MODE, mode.get()).ok(),
            Some(())
        );

        // Set the start address.
        assert_eq!(
            sha_accl
                .write(
                    RvSize::Word,
                    OFFSET_START_ADDRESS,
                    start_address.try_into().unwrap()
                )
                .ok(),
            Some(())
        );

        // Set data length.
        assert_eq!(
            sha_accl
                .write(RvSize::Word, OFFSET_DLEN, data.len() as u32)
                .ok(),
            Some(())
        );

        // Trigger thea accelerator by writing to the execute register.
        let execute = InMemoryRegister::<u32, Execute::Register>::new(0);
        execute.write(Execute::EXECUTE.val(1));
        assert_eq!(
            sha_accl
                .write(RvSize::Word, OFFSET_EXECUTE, execute.get())
                .ok(),
            Some(())
        );

        // Wait for operation to complete.
        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                sha_accl.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut sha_accl);
        }

        // Read the hash.
        let mut hash: [u8; SHA512_HASH_SIZE] = [0; SHA512_HASH_SIZE];
        sha_accl.regs.borrow().copy_hash(&mut hash);

        // Release the lock.
        assert_eq!(sha_accl.write(RvSize::Word, OFFSET_LOCK, 1).ok(), Some(()));

        hash.to_little_endian();
        assert_eq!(&hash[..SHA384_HASH_SIZE], expected);
    }

    #[test]
    fn test_accelerator_sha384_1() {
        let data = "abc".as_bytes();
        let expected: [u8; SHA384_HASH_SIZE] = [
            0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6,
            0x50, 0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A,
            0x43, 0xFF, 0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA,
            0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
        ];
        test_sha_accelerator(data, &expected, 0);
    }

    #[test]
    fn test_accelerator_sha384_2() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0x33, 0x91, 0xFD, 0xDD, 0xFC, 0x8D, 0xC7, 0x39, 0x37, 0x07, 0xA6, 0x5B, 0x1B, 0x47,
            0x09, 0x39, 0x7C, 0xF8, 0xB1, 0xD1, 0x62, 0xAF, 0x05, 0xAB, 0xFE, 0x8F, 0x45, 0x0D,
            0xE5, 0xF3, 0x6B, 0xC6, 0xB0, 0x45, 0x5A, 0x85, 0x20, 0xBC, 0x4E, 0x6F, 0x5F, 0xE9,
            0x5B, 0x1F, 0xE3, 0xC8, 0x45, 0x2B,
        ];
        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        test_sha_accelerator(data, &expected, 0);
    }

    #[test]
    fn test_accelerator_sha384_3() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD,
            0x1B, 0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86,
            0xE3, 0xB0, 0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3,
            0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39,
        ];
        let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
        test_sha_accelerator(data, &expected, 0);
    }

    #[test]
    fn test_accelerator_sha384_4() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0x55, 0x23, 0xcf, 0xb7, 0x7f, 0x9c, 0x55, 0xe0, 0xcc, 0xaf, 0xec, 0x5b, 0x87, 0xd7,
            0x9c, 0xde, 0x64, 0x30, 0x12, 0x28, 0x3b, 0x71, 0x18, 0x8e, 0x40, 0x8c, 0x5a, 0xea,
            0xe9, 0x19, 0xa3, 0xf2, 0x93, 0x37, 0x57, 0x4d, 0x5c, 0x72, 0x9b, 0x33, 0x9d, 0x95,
            0x53, 0x98, 0x4a, 0xb0, 0x01, 0x4e,
        ];
        let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh".as_bytes();
        test_sha_accelerator(data, &expected, 0);
    }

    #[test]
    fn test_accelerator_sha384_5() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb,
            0xaa, 0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29,
            0xbd, 0xb6, 0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7,
            0xa3, 0x59, 0x14, 0xfc, 0x1e, 0xcd,
        ];
        let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz".as_bytes();
        test_sha_accelerator(data, &expected, 0);
    }

    #[test]
    fn test_accelerator_sha384_6() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0x33, 0x91, 0xFD, 0xDD, 0xFC, 0x8D, 0xC7, 0x39, 0x37, 0x07, 0xA6, 0x5B, 0x1B, 0x47,
            0x09, 0x39, 0x7C, 0xF8, 0xB1, 0xD1, 0x62, 0xAF, 0x05, 0xAB, 0xFE, 0x8F, 0x45, 0x0D,
            0xE5, 0xF3, 0x6B, 0xC6, 0xB0, 0x45, 0x5A, 0x85, 0x20, 0xBC, 0x4E, 0x6F, 0x5F, 0xE9,
            0x5B, 0x1F, 0xE3, 0xC8, 0x45, 0x2B,
        ];
        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        test_sha_accelerator(data, &expected, 4);
    }

    #[test]
    fn test_accelerator_sha384_no_data() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1,
            0xE3, 0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF,
            0x63, 0xF6, 0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A,
            0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
        ];
        let data = [];
        test_sha_accelerator(&data, &expected, 0);
    }

    #[test]
    fn test_accelerator_sha384_mailbox_max_size() {
        let expected: [u8; SHA384_HASH_SIZE] = [
            0xca, 0xd1, 0x95, 0xe7, 0xc3, 0xf2, 0xb2, 0x50, 0xb3, 0x5a, 0xc7, 0x8b, 0x17, 0xb7,
            0xc2, 0xf2, 0x29, 0xe1, 0x34, 0xb8, 0x61, 0xf2, 0xd0, 0xbe, 0x15, 0xb7, 0xd9, 0x54,
            0x69, 0x71, 0xf8, 0x5e, 0xc0, 0x40, 0x69, 0x3e, 0x5a, 0x22, 0x21, 0x88, 0x79, 0x77,
            0xfd, 0xea, 0x6f, 0x89, 0xef, 0xee,
        ];
        let data: [u8; MAX_MAILBOX_CAPACITY_BYTES] = [0u8; MAX_MAILBOX_CAPACITY_BYTES];
        test_sha_accelerator(&data, &expected, 0);
    }

    #[test]
    fn test_sm_lock() {
        let clock = Clock::new();
        let mut sha_accl = Sha512Accelerator::new(&clock, MailboxRam::new());
        assert_eq!(sha_accl.regs.borrow().state_machine.context.locked, 1);
        // Unlock the initial state
        sha_accl.write(RvSize::Word, OFFSET_LOCK, 1).unwrap();
        assert_eq!(sha_accl.regs.borrow().state_machine.context.locked, 0);

        let _ = sha_accl
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::RdLock(Owner(0)));
        assert!(matches!(
            sha_accl.regs.borrow().state_machine.state(),
            States::RdyForExc
        ));
        assert_eq!(sha_accl.regs.borrow().state_machine.context.locked, 1);

        let _ = sha_accl
            .regs
            .borrow_mut()
            .state_machine
            .process_event(Events::WrLock(Owner(0)));
        assert!(matches!(
            sha_accl.regs.borrow().state_machine.state(),
            States::Idle
        ));
        assert_eq!(sha_accl.regs.borrow().state_machine.context.locked, 0);
    }

    #[test]
    fn test_sha_acc_check_state() {
        let clock = Clock::new();
        let mut sha_accl = Sha512Accelerator::new(&clock, MailboxRam::new());

        // Check init state.
        assert_eq!(
            sha_accl.read(RvSize::Word, OFFSET_START_ADDRESS).unwrap(),
            0
        );
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_DLEN).unwrap(), 0);
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_MODE).unwrap(), 0);
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_STATUS).unwrap(), 0);
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_EXECUTE).unwrap(), 0);

        // Unlock the initial state
        sha_accl.write(RvSize::Word, OFFSET_LOCK, 1).unwrap();

        // Acquire the accelerator lock.
        loop {
            let lock = sha_accl.read(RvSize::Word, OFFSET_LOCK).unwrap();
            if lock == 0 {
                break;
            }
        }

        // Set the mode.
        let mut mode = InMemoryRegister::<u32, ShaMode::Register>::new(0);
        mode.write(
            ShaMode::MODE.val(ShaMode::MODE::SHA512_ACC_MODE_MBOX_384.value)
                + ShaMode::ENDIAN_TOGGLE.val(1),
        );
        assert_eq!(
            sha_accl.write(RvSize::Word, OFFSET_MODE, mode.get()).ok(),
            Some(())
        );

        // Read the mode back.
        mode = InMemoryRegister::<u32, ShaMode::Register>::new(
            sha_accl.read(RvSize::Word, OFFSET_MODE).unwrap(),
        );
        assert_eq!(
            mode.read(ShaMode::MODE),
            ShaMode::MODE::SHA512_ACC_MODE_MBOX_384.value
        );
        assert_eq!(mode.read(ShaMode::ENDIAN_TOGGLE), 1);

        // Set the start address.
        assert_eq!(
            sha_accl.write(RvSize::Word, OFFSET_START_ADDRESS, 4).ok(),
            Some(())
        );
        // Read the start address back.
        assert_eq!(
            sha_accl.read(RvSize::Word, OFFSET_START_ADDRESS).unwrap(),
            4
        );

        // Set data length.
        assert_eq!(sha_accl.write(RvSize::Word, OFFSET_DLEN, 20).ok(), Some(()));

        // Read the data length back.
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_DLEN).unwrap(), 20);

        // Trigger thea accelerator by writing to the execute register.
        let execute = InMemoryRegister::<u32, Execute::Register>::new(0);
        execute.write(Execute::EXECUTE.val(1));
        assert_eq!(
            sha_accl
                .write(RvSize::Word, OFFSET_EXECUTE, execute.get())
                .ok(),
            Some(())
        );

        // Release the lock.
        assert_eq!(sha_accl.write(RvSize::Word, OFFSET_LOCK, 1).ok(), Some(()));

        // Check state after lock release.
        assert_eq!(
            sha_accl.read(RvSize::Word, OFFSET_START_ADDRESS).unwrap(),
            0
        );
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_DLEN).unwrap(), 0);
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_MODE).unwrap(), 0);
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_STATUS).unwrap(), 0);
        assert_eq!(sha_accl.read(RvSize::Word, OFFSET_EXECUTE).unwrap(), 0);
    }
}
