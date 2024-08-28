/*++

Licensed under the Apache-2.0 license.

File Name:

ml_dsa87.rs

Abstract:

File contains Ml_Dsa87 peripheral implementation.

--*/

use crate::helpers::{bytes_from_words_le, words_from_bytes_le};
use crate::{KeyUsage, KeyVault};
use caliptra_emu_bus::{ActionHandle, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use fips204::ml_dsa_87::{try_keygen_with_rng, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use rand::rngs::StdRng;
use rand::SeedableRng;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

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

/// The number of CPU clock cycles it takes to perform Ml_Dsa87 operation
const ML_DSA87_OP_TICKS: u64 = 1000;

/// The number of CPU clock cycles read and write keys from key vault
const KEY_RW_TICKS: u64 = 100;

register_bitfields! [
    u32,

    /// Control Register Fields
    Control [
        CTRL OFFSET(0) NUMBITS(2) [
            IDLE = 0b00,
            GEN_KEY = 0b01,
            SIGN = 0b10,
            VERIFY = 0b11,
        ],
        ZEROIZE OFFSET(2) NUMBITS(1) [],
//        PCR_SIGN OFFSET(3) NUMBITS(1) [] TODO remove right??
    ],

    /// Status Register Fields
    Status[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// Key Control Register Fields
    KeyReadControl[
        KEY_READ_EN OFFSET(0) NUMBITS(1) [],
        KEY_ID OFFSET(1) NUMBITS(5) [],
//        PCR_HASH_EXTEND OFFSET(6) NUMBITS(1) [],
        RSVD OFFSET(7) NUMBITS(25) [],
    ],

    /// Key Status Register Fields
    KeyReadStatus[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        ERROR OFFSET(2) NUMBITS(8) [
            KV_SUCCESS = 0,
            KV_READ_FAIL = 1,
            KV_WRITE_FAIL= 2,
        ],
        RSVD OFFSET(10) NUMBITS(22) [],
    ],

];

#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct MlDsa87 {
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
    #[register(offset = 0x0000_0018)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// Initialization vector for blinding and counter measures
    #[register_array(offset = 0x0000_0080)]
    iv: [u32; ML_DSA87_IV_SIZE / 4],

    /// Seed size
    #[register_array(offset = 0x0000_0100)]
    seed: [u32; ML_DSA87_SEED_SIZE / 4],

    /// Sign RND
    #[register_array(offset = 0x0000_0180)]
    sign_rnd: [u32; ML_DSA87_SIGN_RND_SIZE / 4],

    /// Message
    #[register_array(offset = 0x0000_0200)]
    message: [u32; ML_DSA87_MSG_SIZE / 4],

    /// Verification result
    #[register_array(offset = 0x0000_0280, write_fn = write_access_fault)]
    verification_result: [u32; ML_DSA87_VERIFICATION_SIZE / 4],

    /// Secret Key Out (software only?)
    #[register_array(offset = 0x0000_0300, write_fn = write_access_fault)]
    sk_out: [u32; SK_LEN / 4],

    /// Secret Key in
    #[register_array(offset = 0x0000_1620, read_fn = read_access_fault)]
    sk_in: [u32; SK_LEN / 4], // TODO unused as SK is always generated from seed??

    /// Public key
    #[register_array(offset = 0x0000_2940)]
    pk: [u32; PK_LEN / 4],

    /// Signature
    #[register_array(offset = 0x0000_3400)]
    signature: [u32; SIG_LEN / 4 + 1], // Signature len is unaligned

    /// Seed Read Control Register
    #[register(offset = 0x0000_4614, write_fn = on_write_seed_read_control)]
    seed_read_ctrl: ReadWriteRegister<u32, KeyReadControl::Register>,

    /// Seed Read Status Register
    #[register(offset = 0x0000_4618)]
    seed_read_status: ReadOnlyRegister<u32, KeyReadStatus::Register>,

    /// Key Vault
    key_vault: KeyVault,

    /// Timer
    timer: Timer,

    /// Operation complete callback
    op_complete_action: Option<ActionHandle>,

    /// Seed read complete action
    op_seed_read_complete_action: Option<ActionHandle>,
}

impl MlDsa87 {
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
            iv: Default::default(),
            seed: Default::default(),
            sign_rnd: Default::default(),
            message: Default::default(),
            verification_result: Default::default(),
            sk_out: [0; 1224],
            sk_in: [0; 1224],
            pk: [0; 648],
            signature: [0; 1157],
            seed_read_ctrl: ReadWriteRegister::new(0),
            seed_read_status: ReadOnlyRegister::new(KeyReadStatus::READY::SET.value),
            key_vault,
            timer: Timer::new(clock),
            op_complete_action: None,
            op_seed_read_complete_action: None,
        }
    }

    fn read_access_fault(&self, _size: RvSize, _index: usize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
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
        self.control = ReadWriteRegister::new(0);
        self.status = ReadOnlyRegister::new(0);
        self.seed = Default::default();
        self.sign_rnd = Default::default();
        self.sk_out = [0; 1224];
        self.sk_in = [0; 1224];
        self.pk = [0; 648];
        self.signature = [0; 1157];
        self.seed_read_ctrl = ReadWriteRegister::new(0);
        self.seed_read_status = ReadOnlyRegister::new(KeyReadStatus::READY::SET.value);
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
            Some(Control::CTRL::Value::GEN_KEY)
            | Some(Control::CTRL::Value::SIGN)
            | Some(Control::CTRL::Value::VERIFY) => {
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

    /// On Write callback for `seed_read_control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_seed_read_control(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the key control register
        let seed_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(val);

        self.seed_read_ctrl.reg.modify(
            KeyReadControl::KEY_READ_EN.val(seed_ctrl.read(KeyReadControl::KEY_READ_EN))
                + KeyReadControl::KEY_ID.val(seed_ctrl.read(KeyReadControl::KEY_ID)),
        );

        if seed_ctrl.is_set(KeyReadControl::KEY_READ_EN) {
            self.seed_read_status.reg.modify(
                KeyReadStatus::READY::CLEAR
                    + KeyReadStatus::VALID::CLEAR
                    + KeyReadStatus::ERROR::CLEAR,
            );

            self.op_seed_read_complete_action = Some(self.timer.schedule_poll_in(KEY_RW_TICKS));
        }

        Ok(())
    }

    fn gen_key(&mut self) {
        let seed_bytes = &bytes_from_words_le(&self.seed);
        let mut rng = StdRng::from_seed(*seed_bytes);
        let (pk, sk) = try_keygen_with_rng(&mut rng).unwrap();

        self.pk = words_from_bytes_le(&pk.into_bytes());
        self.sk_out = words_from_bytes_le(&sk.into_bytes());
    }

    fn sign(&mut self) {
        // TODO FIPS 204 needs a seed as input unlike dilithium. What to use??
        let seed_bytes = [0x00; 32];
        let mut rng = StdRng::from_seed(seed_bytes);

        let seed_bytes_keys = &bytes_from_words_le(&self.seed);
        let mut rng_keys = StdRng::from_seed(*seed_bytes_keys);
        let (_pk, secret_key) = try_keygen_with_rng(&mut rng_keys).unwrap();

        // TODO can we take secret key from input or is seed always used? How does the hardware know?
        // let secret_key_bytes = &bytes_from_words_le(&self.sk_in);
        // let secret_key = PrivateKey::try_from_bytes(*secret_key_bytes).unwrap();

        let message = &bytes_from_words_le(&self.message);

        // The Ml_Dsa87 signature is 4595 len but the reg is one byte longer
        let signature = secret_key.try_sign_with_rng(&mut rng, message).unwrap();
        let signature_extended = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature);
            sig
        };
        self.signature
            .copy_from_slice(&words_from_bytes_le(&signature_extended));
    }

    fn verify(&mut self) {
        let message = &bytes_from_words_le(&self.message);

        let public_key = {
            let key_bytes = &bytes_from_words_le(&self.pk);
            PublicKey::try_from_bytes(*key_bytes).unwrap()
        };

        let signature = &bytes_from_words_le(&self.signature);

        let result = public_key.verify(message, &signature[..SIG_LEN].try_into().unwrap());

        self.verification_result
            .iter_mut()
            .for_each(|e| *e = if result { 1 } else { 0 });
    }

    fn op_complete(&mut self) {
        match self.control.reg.read_as_enum(Control::CTRL) {
            Some(Control::CTRL::Value::GEN_KEY) => self.gen_key(),
            Some(Control::CTRL::Value::SIGN) => self.sign(),
            Some(Control::CTRL::Value::VERIFY) => self.verify(),
            _ => {}
        }

        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::SET);
    }

    fn seed_read_complete(&mut self) {
        let key_id = self.seed_read_ctrl.reg.read(KeyReadControl::KEY_ID);

        let mut key_usage = KeyUsage::default();
        key_usage.set_ecc_key_gen_seed(true);

        let result = self.key_vault.read_key(key_id, key_usage);
        let (seed_read_result, seed) = match result.err() {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => (KeyReadStatus::ERROR::KV_READ_FAIL.value, None),
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KeyReadStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (
                KeyReadStatus::ERROR::KV_SUCCESS.value,
                Some(result.unwrap()),
            ),
        };

        // TODO read the first 32 bytes from KV?
        if let Some(seed) = seed {
            self.seed = words_from_bytes_le(
                &<[u8; ML_DSA87_SEED_SIZE]>::try_from(&seed[..ML_DSA87_SEED_SIZE]).unwrap(),
            );
        }

        self.seed_read_status.reg.modify(
            KeyReadStatus::READY::SET
                + KeyReadStatus::VALID::SET
                + KeyReadStatus::ERROR.val(seed_read_result),
        );
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        } else if self.timer.fired(&mut self.op_seed_read_complete_action) {
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
    use tock_registers::registers::InMemoryRegister;

    use super::*;

    const OFFSET_NAME0: RvAddr = 0x0;
    const OFFSET_NAME1: RvAddr = 0x4;
    const OFFSET_VERSION0: RvAddr = 0x8;
    const OFFSET_VERSION1: RvAddr = 0xC;
    const OFFSET_CONTROL: RvAddr = 0x10;
    const OFFSET_STATUS: RvAddr = 0x18;
    const OFFSET_SEED: RvAddr = 0x100;
    const OFFSET_SIGN_RND: RvAddr = 0x180;
    const OFFSET_MSG: RvAddr = 0x200;
//    const OFFSET_SK_IN: RvAddr = 0x1620;
    const OFFSET_PK: RvAddr = 0x2940;
    const OFFSET_SIGNATURE: RvAddr = 0x3400;
    const OFFSET_SEED_CONTROL: RvAddr = 0x4614;
    const OFFSET_SEED_STATUS: RvAddr = 0x4618;

    include!("./test_data/ml_dsa87_test_data.rs");

    const VERIFICATION_SUCCES: [u8; 64] = [
        0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0,
        0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,
        0, 0, 0, 1,
    ];

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

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

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

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

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

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_gen_key() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

        let mut seed = [0u8; 32];
        seed.to_big_endian(); // Change DWORDs to big-endian. TODO is this needed?
        for i in (0..seed.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                    .ok(),
                Some(())
            );
        }

        assert_eq!(
            ml_dsa87
                .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::GEN_KEY.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let mut secret_key = bytes_from_words_le(&ml_dsa87.sk_out);
        secret_key.to_little_endian(); // Change DWORDs to little-endian. TODO is this needed?

        let mut public_key = bytes_from_words_le(&ml_dsa87.pk);
        public_key.to_little_endian(); // Change DWORDs to little-endian. TODO is this needed?

        assert_eq!(&secret_key, &SECRET_KEY);
        assert_eq!(&public_key, &PUB_KEY);
    }

    #[test]
    fn test_gen_key_kv_seed() {
        // Test for getting the seed from the key-vault.
        for key_id in 0..KeyVault::KEY_COUNT {
            let clock = Clock::new();
            let mut seed = [0u8; 32];
            seed.to_big_endian(); // Change DWORDs to big-endian.

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_ecc_key_gen_seed(true);

            key_vault
                .write_key(key_id, &seed, u32::from(key_usage))
                .unwrap();

            let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

            // We expect the output to match seed 0. Write a different seed first to make sure the Kv seed is used
            let mut seed = [0xABu8; 32];
            seed.to_big_endian(); // Change DWORDs to big-endian. TODO is this needed?
            for i in (0..seed.len()).step_by(4) {
                assert_eq!(
                    ml_dsa87
                        .write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
                        .ok(),
                    Some(())
                );
            }

            // Instruct seed to be read from key-vault.
            let seed_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
            seed_ctrl
                .modify(KeyReadControl::KEY_ID.val(key_id) + KeyReadControl::KEY_READ_EN.val(1));

            assert_eq!(
                ml_dsa87
                    .write(RvSize::Word, OFFSET_SEED_CONTROL, seed_ctrl.get())
                    .ok(),
                Some(())
            );

            // Wait for ml_dsa87 periph to retrieve the seed from key-vault.
            loop {
                let seed_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                    ml_dsa87.read(RvSize::Word, OFFSET_SEED_STATUS).unwrap(),
                );

                if seed_read_status.is_set(KeyReadStatus::VALID) {
                    assert_eq!(
                        seed_read_status.read(KeyReadStatus::ERROR),
                        KeyReadStatus::ERROR::KV_SUCCESS.value
                    );
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
            }

            assert_eq!(
                ml_dsa87
                    .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::GEN_KEY.into())
                    .ok(),
                Some(())
            );

            loop {
                let status = InMemoryRegister::<u32, Status::Register>::new(
                    ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
                );
                if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
            }

            let mut secret_key = bytes_from_words_le(&ml_dsa87.sk_out);
            secret_key.to_little_endian(); // Change DWORDs to little-endian. TODO is this needed?

            let mut public_key = bytes_from_words_le(&ml_dsa87.pk);
            public_key.to_little_endian(); // Change DWORDs to little-endian. TODO is this needed?

            assert_eq!(&secret_key, &SECRET_KEY);
            assert_eq!(&public_key, &PUB_KEY);
        }
    }

    #[test]
    fn test_sign() {
        let clock = Clock::new();

        let mut seed = [0u8; 32];
        seed.to_big_endian(); // Change DWORDs to big-endian.

        let mut key_vault = KeyVault::new();
        let mut key_usage = KeyUsage::default();
        key_usage.set_ecc_key_gen_seed(true);

        const KEY_ID: u32 = 1;

        key_vault
            .write_key(KEY_ID, &seed, u32::from(key_usage))
            .unwrap();

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

        // TODO is seed used in sign? Dilithium, no. Fip204 yes??
        // let mut seed = [0u8; 32];
        // seed.to_big_endian(); // Change DWORDs to big-endian. TODO is this needed?
        // for i in (0..seed.len()).step_by(4) {
        //     assert_eq!(
        //         ml_dsa87
        //             .write(RvSize::Word, OFFSET_SEED + i as RvAddr, make_word(i, &seed))
        //             .ok(),
        //         Some(())
        //     );
        // }

        let mut msg = [0u8; 64];
        msg.to_big_endian(); // Change DWORDs to big-endian. TODO is this necessary

        for i in (0..msg.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(RvSize::Word, OFFSET_MSG + i as RvAddr, make_word(i, &msg))
                    .ok(),
                Some(())
            );
        }

        // Instruct seed to be read from key-vault.
        let seed_ctrl = InMemoryRegister::<u32, KeyReadControl::Register>::new(0);
        seed_ctrl.modify(KeyReadControl::KEY_ID.val(KEY_ID) + KeyReadControl::KEY_READ_EN.val(1));

        assert_eq!(
            ml_dsa87
                .write(RvSize::Word, OFFSET_SEED_CONTROL, seed_ctrl.get())
                .ok(),
            Some(())
        );

        // Wait for ml_dsa87 periph to retrieve the seed from key-vault.
        loop {
            let seed_read_status = InMemoryRegister::<u32, KeyReadStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_SEED_STATUS).unwrap(),
            );

            if seed_read_status.is_set(KeyReadStatus::VALID) {
                assert_eq!(
                    seed_read_status.read(KeyReadStatus::ERROR),
                    KeyReadStatus::ERROR::KV_SUCCESS.value
                );
                break;
            }
            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        // TODO no secret key input?
        // let mut secret_key = SECRET_KEY;
        // secret_key.to_big_endian(); // Change DWORDs to big-endian.

        // for i in (0..SECRET_KEY.len()).step_by(4) {
        //     assert_eq!(
        //         ml_dsa87
        //             .write(
        //                 RvSize::Word,
        //                 OFFSET_SK_IN + i as RvAddr,
        //                 make_word(i, &secret_key)
        //             )
        //             .ok(),
        //         Some(())
        //     );
        // }

        let mut sign_rnd = SIGN_RND;
        sign_rnd.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..SIGN_RND.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_SIGN_RND + i as RvAddr,
                        make_word(i, &sign_rnd)
                    )
                    .ok(),
                Some(())
            );
        }

        assert_eq!(
            ml_dsa87
                .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::SIGN.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let mut signature = bytes_from_words_le(&ml_dsa87.signature);
        signature.to_little_endian(); // Change DWORDs to little-endian.

        assert_eq!(&signature, &SIGNATURE);
    }

    #[test]
    fn test_verify() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();

        let mut ml_dsa87 = MlDsa87::new(&clock, key_vault);

        let msg = [0u8; 64];
        for i in (0..msg.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(RvSize::Word, OFFSET_MSG + i as RvAddr, make_word(i, &msg))
                    .ok(),
                Some(())
            );
        }

        let mut pub_key = PUB_KEY;
        pub_key.to_big_endian();

        for i in (0..pub_key.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_PK + i as RvAddr,
                        make_word(i, &pub_key)
                    )
                    .ok(),
                Some(())
            );
        }

        // Good signature
        let mut signature = SIGNATURE;
        signature.to_big_endian();

        for i in (0..signature.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_SIGNATURE + i as RvAddr,
                        make_word(i, &signature)
                    )
                    .ok(),
                Some(())
            );
        }

        assert_eq!(
            ml_dsa87
                .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::VERIFY.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let mut result = bytes_from_words_le(&ml_dsa87.verification_result);
        result.to_little_endian();

        assert_eq!(&result, &VERIFICATION_SUCCES);

        // Bad signature
        let mut signature = [0; SIG_LEN + 1];
        signature.to_big_endian();

        for i in (0..signature.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_SIGNATURE + i as RvAddr,
                        make_word(i, &signature)
                    )
                    .ok(),
                Some(())
            );
        }

        assert_eq!(
            ml_dsa87
                .write(RvSize::Word, OFFSET_CONTROL, Control::CTRL::VERIFY.into())
                .ok(),
            Some(())
        );

        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let mut result = bytes_from_words_le(&ml_dsa87.verification_result);
        result.to_little_endian();

        assert_eq!(&result, &[0; 64]);
    }
}
