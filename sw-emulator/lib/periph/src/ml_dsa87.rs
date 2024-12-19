/*++

Licensed under the Apache-2.0 license.

File Name:

ml_dsa87.rs

Abstract:

File contains Ml_Dsa87 peripheral implementation.

--*/

use crate::helpers::{bytes_from_words_be, words_from_bytes_be, words_from_bytes_le};
use crate::{KeyUsage, KeyVault};
use caliptra_emu_bus::{ActionHandle, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use fips204::ml_dsa_87::{try_keygen_with_rng, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

/// ML_DSA87 Initialization Vector size
const ML_DSA87_IV_SIZE: usize = 64;

/// ML_DSA87 Key Generation seed
const ML_DSA87_SEED_SIZE: usize = 32;

/// ML_DSA87 SIGN_RND size
const ML_DSA87_SIGN_RND_SIZE: usize = 32;

/// ML_DSA87 MSG size
const ML_DSA87_MSG_SIZE: usize = 64;

/// ML_DSA87 VERIFICATION size
const ML_DSA87_VERIFICATION_SIZE: usize = 64;

/// ML_DSA87 PUBKEY size
const ML_DSA87_PUBKEY_SIZE: usize = PK_LEN;

/// ML_DSA87 SIGNATURE size
// Signature len is unaligned
const ML_DSA87_SIGNATURE_SIZE: usize = SIG_LEN + 1;

/// ML_DSA87 PRIVKEY size
const ML_DSA87_PRIVKEY_SIZE: usize = SK_LEN;

/// The number of CPU clock cycles it takes to perform Ml_Dsa87 operation
const ML_DSA87_OP_TICKS: u64 = 1000;

/// The number of CPU clock cycles to read keys from key vault
const KEY_RW_TICKS: u64 = 100;

register_bitfields! [
    u32,

    /// Control Register Fields
    Control [
        CTRL OFFSET(0) NUMBITS(3) [
            NONE = 0b000,
            KEYGEN = 0b001,
            SIGNING = 0b010,
            VERIFYING = 0b011,
            KEYGEN_AND_SIGN = 0b100,
        ],
        ZEROIZE OFFSET(3) NUMBITS(1) [],
    ],

    /// Status Register Fields
    Status [
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],

    /// Key Vault Read Control Fields
    KvRdSeedCtrl [
        READ_EN OFFSET(0) NUMBITS(1) [],
        READ_ENTRY OFFSET(1) NUMBITS(5) [],
    ],

    /// Key Vault Read Status Fields
    KvRdSeedStatus [
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        ERROR OFFSET(2) NUMBITS(8) [
            SUCCESS = 0,
            KV_READ_FAIL = 1,
            KV_WRITE_FAIL = 2,
        ],
    ],
];

#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct Mldsa87 {
    /// Name registers
    #[register_array(offset = 0x0000_0000)]
    name: [u32; 2],

    /// Version registers
    #[register_array(offset = 0x0000_0008)]
    version: [u32; 2],

    /// Control register
    #[register(offset = 0x0000_0010, write_fn = on_write_control)]
    control: ReadWriteRegister<u32, Control::Register>,

    /// Status register
    #[register(offset = 0x0000_0014)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// Initialization vector for blinding and counter measures
    #[register_array(offset = 0x0000_0018)]
    entropy: [u32; ML_DSA87_IV_SIZE / 4],

    /// Seed size
    #[register_array(offset = 0x0000_0058)]
    seed: [u32; ML_DSA87_SEED_SIZE / 4],

    /// Sign RND
    #[register_array(offset = 0x0000_0078)]
    sign_rnd: [u32; ML_DSA87_SIGN_RND_SIZE / 4],

    /// Message
    #[register_array(offset = 0x0000_0098)]
    msg: [u32; ML_DSA87_MSG_SIZE / 4],

    /// Verification result
    #[register_array(offset = 0x0000_00d8, write_fn = write_access_fault)]
    verify_res: [u32; ML_DSA87_VERIFICATION_SIZE / 4],

    /// Public key
    #[register_array(offset = 0x0000_1000)]
    pubkey: [u32; ML_DSA87_PUBKEY_SIZE / 4],

    /// Signature
    #[register_array(offset = 0x0000_2000)]
    signature: [u32; ML_DSA87_SIGNATURE_SIZE / 4],

    // Private Key In & Out (We don't want to use this)
    /// Key Vault Read Control
    #[register(offset = 0x0000_8000, write_fn = on_write_kv_rd_seed_ctrl)]
    kv_rd_seed_ctrl: ReadWriteRegister<u32, KvRdSeedCtrl::Register>,

    /// Key Vault Read Status
    #[register(offset = 0x0000_8004)]
    kv_rd_seed_status: ReadOnlyRegister<u32, KvRdSeedStatus::Register>,

    /// Error Global Intr register
    #[register(offset = 0x0000_810c)]
    error_global_intr: ReadOnlyRegister<u32>,

    /// Error Internal Intr register
    #[register(offset = 0x0000_8114)]
    error_internal_intr: ReadOnlyRegister<u32>,

    private_key: [u8; ML_DSA87_PRIVKEY_SIZE],

    /// Timer
    timer: Timer,

    /// Key Vault
    key_vault: KeyVault,

    /// Operation complete callback
    op_complete_action: Option<ActionHandle>,

    /// Seed read complete action
    op_seed_read_complete_action: Option<ActionHandle>,
}

impl Mldsa87 {
    /// NAME0 Register Value TODO update when known
    const NAME0_VAL: RvData = 0x73656370; //0x63737065; // secp

    /// NAME1 Register Value TODO update when known
    const NAME1_VAL: RvData = 0x2D333834; // -384

    /// VERSION0 Register Value TODO update when known
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value TODO update when known
    const VERSION1_VAL: RvData = 0x00000000;

    pub fn new(clock: &Clock, key_vault: KeyVault) -> Self {
        Self {
            name: [Self::NAME0_VAL, Self::NAME1_VAL],
            version: [Self::VERSION0_VAL, Self::VERSION1_VAL],
            control: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(Status::READY::SET.value),
            entropy: Default::default(),
            seed: Default::default(),
            sign_rnd: Default::default(),
            msg: Default::default(),
            verify_res: Default::default(),
            pubkey: [0; ML_DSA87_PUBKEY_SIZE / 4],
            signature: [0; ML_DSA87_SIGNATURE_SIZE / 4],
            kv_rd_seed_ctrl: ReadWriteRegister::new(0),
            kv_rd_seed_status: ReadOnlyRegister::new(0),
            error_global_intr: ReadOnlyRegister::new(0),
            error_internal_intr: ReadOnlyRegister::new(0),
            private_key: [0; ML_DSA87_PRIVKEY_SIZE],
            timer: Timer::new(clock),
            key_vault,
            op_complete_action: None,
            op_seed_read_complete_action: None,
        }
    }

    fn write_access_fault(
        &self,
        _size: RvSize,
        _index: usize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }

    fn zeroize(&mut self) {
        self.control.reg.set(0);
        self.seed = Default::default();
        self.sign_rnd = Default::default();
        self.msg = Default::default();
        self.verify_res = Default::default();
        self.pubkey = [0; ML_DSA87_PUBKEY_SIZE / 4];
        self.signature = [0; ML_DSA87_SIGNATURE_SIZE / 4];
        self.kv_rd_seed_ctrl.reg.set(0);
        self.kv_rd_seed_status.reg.write(KvRdSeedStatus::READY::SET);
        self.private_key = [0; ML_DSA87_PRIVKEY_SIZE];
        // Stop actions
        self.op_complete_action = None;
        self.op_seed_read_complete_action = None;
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

        match self.control.reg.read_as_enum(Control::CTRL) {
            Some(Control::CTRL::Value::KEYGEN)
            | Some(Control::CTRL::Value::SIGNING)
            | Some(Control::CTRL::Value::VERIFYING)
            | Some(Control::CTRL::Value::KEYGEN_AND_SIGN) => {
                // Reset the Ready and Valid status bits
                self.status
                    .reg
                    .modify(Status::READY::CLEAR + Status::VALID::CLEAR);

                self.op_complete_action = Some(self.timer.schedule_poll_in(ML_DSA87_OP_TICKS));
            }
            _ => {}
        }

        if self.control.reg.is_set(Control::ZEROIZE) {
            self.zeroize();
        }

        Ok(())
    }

    /// On Write callback for `kv_rd_seed_ctrl` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_kv_rd_seed_ctrl(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.kv_rd_seed_ctrl.reg.set(val);

        if self.kv_rd_seed_ctrl.reg.is_set(KvRdSeedCtrl::READ_EN) {
            self.kv_rd_seed_status.reg.modify(
                KvRdSeedStatus::READY::CLEAR
                    + KvRdSeedStatus::VALID::CLEAR
                    + KvRdSeedStatus::ERROR::CLEAR,
            );

            self.op_seed_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    fn gen_key(&mut self) {
        let seed_bytes = &bytes_from_words_be(&self.seed);
        let mut rng = StdRng::from_seed(*seed_bytes);
        let (pk, sk) = try_keygen_with_rng(&mut rng).unwrap();

        self.pubkey = words_from_bytes_be(&pk.into_bytes());
        self.private_key = sk.into_bytes();
    }

    fn sign(&mut self) {
        let sign_seed = &bytes_from_words_be(&self.sign_rnd);
        let mut rng = StdRng::from_seed(*sign_seed);

        let secret_key = PrivateKey::try_from_bytes(self.private_key).unwrap();

        let message = &bytes_from_words_be(&self.msg);

        // The Ml_Dsa87 signature is 4595 len but the reg is one byte longer
        let signature = secret_key
            .try_sign_with_rng(&mut rng, message, &[])
            .unwrap();
        let signature_extended = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature);
            sig
        };
        self.signature = words_from_bytes_be(&signature_extended);
    }

    fn verify(&mut self) {
        let message = &bytes_from_words_be(&self.msg);

        let public_key = {
            let key_bytes = bytes_from_words_be(&self.pubkey);
            PublicKey::try_from_bytes(key_bytes).unwrap()
        };

        let signature = &bytes_from_words_be(&self.signature);

        let success = public_key.verify(message, &signature[..SIG_LEN].try_into().unwrap(), &[]);

        if success {
            self.verify_res
                .copy_from_slice(&self.signature[..ML_DSA87_VERIFICATION_SIZE / 4]);
        } else {
            self.verify_res = rand::thread_rng().gen::<[u32; 16]>();
        }
    }

    fn op_complete(&mut self) {
        match self.control.reg.read_as_enum(Control::CTRL) {
            Some(Control::CTRL::Value::KEYGEN) => self.gen_key(),
            Some(Control::CTRL::Value::SIGNING) => {
                self.sign();
                todo!()
            } // NOT used?
            Some(Control::CTRL::Value::VERIFYING) => self.verify(),
            Some(Control::CTRL::Value::KEYGEN_AND_SIGN) => {
                self.gen_key();
                self.sign()
            }
            _ => panic!("Invalid value in ML-DSA Control"),
        }

        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::SET);
    }

    fn seed_read_complete(&mut self) {
        let key_id = self.kv_rd_seed_ctrl.reg.read(KvRdSeedCtrl::READ_ENTRY);

        let mut key_usage = KeyUsage::default();
        key_usage.set_mldsa_key_gen_seed(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (seed_read_result, seed) = match result.err() {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => (KvRdSeedStatus::ERROR::KV_READ_FAIL.value, None),
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KvRdSeedStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (KvRdSeedStatus::ERROR::SUCCESS.value, Some(result.unwrap())),
        };

        // Read the first 32 bytes from KV?
        // Key vault already stores seed in hardware format
        if let Some(seed) = seed {
            self.seed = words_from_bytes_le(
                &<[u8; ML_DSA87_SEED_SIZE]>::try_from(&seed[..ML_DSA87_SEED_SIZE]).unwrap(),
            );
        }

        self.kv_rd_seed_status.reg.modify(
            KvRdSeedStatus::READY::SET
                + KvRdSeedStatus::VALID::SET
                + KvRdSeedStatus::ERROR.val(seed_read_result),
        );
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        }
        if self.timer.fired(&mut self.op_seed_read_complete_action) {
            self.seed_read_complete();
        }
    }

    /// Called by Bus::warm_reset() to indicate a warm reset
    fn warm_reset(&mut self) {
        // TODO: Reset registers
    }

    /// Called by Bus::update_reset() to indicate an update reset
    fn update_reset(&mut self) {
        // TODO: Reset registers
    }
}

#[cfg(test)]
mod tests {
    use caliptra_emu_bus::Bus;
    use caliptra_emu_crypto::EndianessTransform;
    use caliptra_emu_types::RvAddr;
    use rand::Rng;
    use tock_registers::registers::InMemoryRegister;

    use super::*;

    const OFFSET_NAME0: RvAddr = 0x0;
    const OFFSET_NAME1: RvAddr = 0x4;
    const OFFSET_VERSION0: RvAddr = 0x8;
    const OFFSET_VERSION1: RvAddr = 0xC;
    const OFFSET_CONTROL: RvAddr = 0x10;
    const OFFSET_STATUS: RvAddr = 0x14;
    const OFFSET_SEED: RvAddr = 0x58;
    const OFFSET_SIGN_RND: RvAddr = 0x78;
    const OFFSET_MSG: RvAddr = 0x98;
    const OFFSET_PK: RvAddr = 0x1000;
    const OFFSET_SIGNATURE: RvAddr = 0x2000;
    const OFFSET_KV_RD_SEED_CONTROL: RvAddr = 0x8000;
    const OFFSET_KV_RD_SEED_STATUS: RvAddr = 0x8004;

    fn make_word(idx: usize, arr: &[u8]) -> RvData {
        let mut res: RvData = 0;
        for i in 0..4 {
            res |= (arr[idx + i] as RvData) << (i * 8);
        }
        res
    }

    #[test]
    fn test_name() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);

        let name0 = ml_dsa87.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let name0 = String::from_utf8_lossy(&name0.to_be_bytes()).to_string();
        assert_eq!(name0, "secp");

        let name1 = ml_dsa87.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_be_bytes()).to_string();
        assert_eq!(name1, "-384");
    }

    #[test]
    fn test_version() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);

        let version0 = ml_dsa87.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = ml_dsa87.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_control() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_gen_key() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);

        let mut seed = rand::thread_rng().gen::<[u8; 32]>();
        seed.to_big_endian(); // Change DWORDs to big-endian. TODO is this needed?
        for i in (0..seed.len()).step_by(4) {
            ml_dsa87
                .write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                .unwrap();
        }

        ml_dsa87
            .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::KEYGEN.into())
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let public_key = bytes_from_words_be(&ml_dsa87.pubkey);

        // Swap endianness again
        seed.to_big_endian();
        let mut rng = StdRng::from_seed(seed);
        let (pk, _sk) = try_keygen_with_rng(&mut rng).unwrap();
        assert_eq!(&public_key, &pk.into_bytes());
    }

    #[test]
    fn test_sign_from_seed() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);

        let mut seed = rand::thread_rng().gen::<[u8; 32]>();
        seed.to_big_endian(); // Change DWORDs to big-endian.
        for i in (0..seed.len()).step_by(4) {
            ml_dsa87
                .write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                .unwrap();
        }

        let mut msg: [u8; 64] = {
            let part0 = rand::thread_rng().gen::<[u8; 32]>();
            let part1 = rand::thread_rng().gen::<[u8; 32]>();
            let concat: Vec<u8> = part0.iter().chain(part1.iter()).copied().collect();
            concat.as_slice().try_into().unwrap()
        };
        msg.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..msg.len()).step_by(4) {
            ml_dsa87
                .write(RvSize::Word, OFFSET_MSG + i as RvAddr, make_word(i, &msg))
                .unwrap();
        }

        let mut sign_rnd = rand::thread_rng().gen::<[u8; 32]>();
        sign_rnd.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..sign_rnd.len()).step_by(4) {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGN_RND + i as RvAddr,
                    make_word(i, &sign_rnd),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_CONTROL,
                Control::CTRL::KEYGEN_AND_SIGN.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let signature = bytes_from_words_be(&ml_dsa87.signature);

        // Swap endianness again to restore original endianness.
        seed.to_big_endian();
        msg.to_big_endian();
        sign_rnd.to_big_endian();
        let mut keygen_rng = StdRng::from_seed(seed);
        let (_pk, sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();
        let mut sign_rng = StdRng::from_seed(sign_rnd);
        let test_signature = sk.try_sign_with_rng(&mut sign_rng, &msg, &[]).unwrap();

        assert_eq!(&signature[..SIG_LEN], &test_signature);
    }

    #[test]
    fn test_verify() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);

        let mut msg: [u8; 64] = {
            let part0 = rand::thread_rng().gen::<[u8; 32]>();
            let part1 = rand::thread_rng().gen::<[u8; 32]>();
            let concat: Vec<u8> = part0.iter().chain(part1.iter()).copied().collect();
            concat.as_slice().try_into().unwrap()
        };

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let mut keygen_rng = StdRng::from_seed(seed);
        let (pk, sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();
        let sign_rnd = rand::thread_rng().gen::<[u8; 32]>();
        let mut sign_rng = StdRng::from_seed(sign_rnd);
        let test_signature = sk.try_sign_with_rng(&mut sign_rng, &msg, &[]).unwrap();

        msg.to_big_endian(); // Change DWORDs to big-endian.
        for i in (0..msg.len()).step_by(4) {
            ml_dsa87
                .write(RvSize::Word, OFFSET_MSG + i as RvAddr, make_word(i, &msg))
                .unwrap();
        }

        let mut pub_key = pk.into_bytes();
        pub_key.to_big_endian();
        for i in (0..pub_key.len()).step_by(4) {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_PK + i as RvAddr,
                    make_word(i, &pub_key),
                )
                .unwrap();
        }

        // Good signature
        let mut signature = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&test_signature);
            sig
        };
        signature.to_big_endian();

        for i in (0..signature.len()).step_by(4) {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGNATURE + i as RvAddr,
                    make_word(i, &signature),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_CONTROL,
                Control::CTRL::VERIFYING.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let result = bytes_from_words_be(&ml_dsa87.verify_res);
        assert_eq!(result, &test_signature[..ML_DSA87_VERIFICATION_SIZE]);

        // Bad signature
        let mut rng = rand::thread_rng();
        let mut signature = [0u8; SIG_LEN + 1];

        rng.fill(&mut signature[..64]);

        signature.to_big_endian();

        for i in (0..signature.len()).step_by(4) {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGNATURE + i as RvAddr,
                    make_word(i, &signature),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_CONTROL,
                Control::CTRL::VERIFYING.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let result = bytes_from_words_be(&ml_dsa87.verify_res);
        assert_ne!(result, &test_signature[..ML_DSA87_VERIFICATION_SIZE]);
    }

    #[test]
    fn test_gen_key_kv_seed() {
        // Test for getting the seed from the key-vault.
        for key_id in 0..KeyVault::KEY_COUNT {
            let clock = Clock::new();
            let mut seed = rand::thread_rng().gen::<[u8; 32]>();
            let mut keygen_rng = StdRng::from_seed(seed);
            let (pk, _sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();
            seed.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_mldsa_key_gen_seed(true);

            key_vault
                .write_key(key_id, &seed, u32::from(key_usage))
                .unwrap();

            let mut ml_dsa87 = Mldsa87::new(&clock, key_vault);

            // We expect the output to match the generated random seed.
            // Write a different seed first to make sure the Kv seed is used
            let mut seed = [0xABu8; 32];
            seed.to_big_endian(); // Change DWORDs to big-endian.
            for i in (0..seed.len()).step_by(4) {
                ml_dsa87
                    .write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                    .unwrap();
            }

            // Instruct seed to be read from key-vault.
            let seed_ctrl = InMemoryRegister::<u32, KvRdSeedCtrl::Register>::new(0);
            seed_ctrl.modify(KvRdSeedCtrl::READ_ENTRY.val(key_id) + KvRdSeedCtrl::READ_EN.val(1));

            ml_dsa87
                .write(RvSize::Word, OFFSET_KV_RD_SEED_CONTROL, seed_ctrl.get())
                .unwrap();

            // Wait for ml_dsa87 periph to retrieve the seed from key-vault.
            loop {
                let seed_read_status = InMemoryRegister::<u32, KvRdSeedStatus::Register>::new(
                    ml_dsa87
                        .read(RvSize::Word, OFFSET_KV_RD_SEED_STATUS)
                        .unwrap(),
                );

                if seed_read_status.is_set(KvRdSeedStatus::VALID) {
                    assert_eq!(
                        seed_read_status.read(KvRdSeedStatus::ERROR),
                        KvRdSeedStatus::ERROR::SUCCESS.value
                    );
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
            }

            ml_dsa87
                .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::KEYGEN.into())
                .unwrap();

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
            }

            let public_key = bytes_from_words_be(&ml_dsa87.pubkey);
            assert_eq!(&public_key, &pk.into_bytes());
        }
    }
}
