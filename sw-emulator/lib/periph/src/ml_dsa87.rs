/*++

Licensed under the Apache-2.0 license.

File Name:

ml_dsa87.rs

Abstract:

File contains Ml_Dsa87 peripheral implementation.

--*/

use caliptra_emu_bus::{ActionHandle, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use fips204::ml_dsa_87::{try_keygen_with_rng, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use rand::rngs::StdRng;
use rand::SeedableRng;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

use crate::helpers::{bytes_from_words_le, words_from_bytes_le};

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
    sk_in: [u32; SK_LEN / 4],

    /// Public key
    #[register_array(offset = 0x0000_2940)]
    pk: [u32; PK_LEN / 4],

    /// Signature
    #[register_array(offset = 0x0000_3400)]
    signature: [u32; SIG_LEN / 4 + 1], // Signature len is unaligned

    /// Timer
    timer: Timer,

    /// Operation complete callback
    op_complete_action: Option<ActionHandle>,
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

    pub fn new(clock: &Clock) -> Self {
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
            timer: Timer::new(clock),
            op_complete_action: None,
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

    // TODO Clear registers
    fn zeroize(&mut self) {}

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

    fn gen_key(&mut self) {
        let seed_bytes = &bytes_from_words_le(&self.seed);
        let mut rng = StdRng::from_seed(*seed_bytes);
        let (pk, sk) = try_keygen_with_rng(&mut rng).unwrap();

        self.pk = words_from_bytes_le(&pk.into_bytes());
        self.sk_out = words_from_bytes_le(&sk.into_bytes());
    }

    fn sign(&mut self) {
        let seed_bytes = &bytes_from_words_le(&self.seed);
        let mut rng = StdRng::from_seed(*seed_bytes);

        let secret_key_bytes = &bytes_from_words_le(&self.sk_in);
        let secret_key = PrivateKey::try_from_bytes(*secret_key_bytes).unwrap();

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

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
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
    const OFFSET_SK_IN: RvAddr = 0x1620;
    const OFFSET_PK: RvAddr = 0x2940;
    const OFFSET_SIGNATURE: RvAddr = 0x3400;

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

        let mut ml_dsa87 = MlDsa87::new(&clock);

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

        let mut ml_dsa87 = MlDsa87::new(&clock);

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

        let mut ml_dsa87 = MlDsa87::new(&clock);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let clock = Clock::new();

        let mut ml_dsa87 = MlDsa87::new(&clock);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_gen_key() {
        let clock = Clock::new();

        let mut ml_dsa87 = MlDsa87::new(&clock);

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
    fn test_sign() {
        let clock = Clock::new();

        let mut ml_dsa87 = MlDsa87::new(&clock);

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

        let mut secret_key = SECRET_KEY;
        secret_key.to_big_endian(); // Change DWORDs to big-endian.

        for i in (0..SECRET_KEY.len()).step_by(4) {
            assert_eq!(
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_SK_IN + i as RvAddr,
                        make_word(i, &secret_key)
                    )
                    .ok(),
                Some(())
            );
        }

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

        let mut ml_dsa87 = MlDsa87::new(&clock);

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
