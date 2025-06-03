/*++

Licensed under the Apache-2.0 license.

File Name:

ml_dsa87.rs

Abstract:

File contains Ml_Dsa87 peripheral implementation.

--*/

use crate::helpers::{bytes_from_words_le, words_from_bytes_le};
use crate::{HashSha512, KeyUsage, KeyVault};
use caliptra_emu_bus::{ActionHandle, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use zerocopy::IntoBytes;

use openssl::{
    pkey::{PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    pkey_ml_dsa::{PKeyMlDsaBuilder, PKeyMlDsaParams, Variant},
    signature::Signature,
};

/// ML_DSA87 Initialization Vector size
const ML_DSA87_IV_SIZE: usize = 64;

/// ML_DSA87 Key Generation seed
const ML_DSA87_SEED_SIZE: usize = 32;

/// ML_DSA87 SIGN_RND size
const ML_DSA87_SIGN_RND_SIZE: usize = 32;

/// ML_DSA87 MSG size
const ML_DSA87_MSG_SIZE: usize = 64;

/// ML_DSA87 MSG MAX size (for streaming mode)
const ML_DSA87_MSG_MAX_SIZE: usize = 8192; // Message limit for streamed messages

/// ML_DSA87 external mu size
const ML_DSA87_EXTERNAL_MU_SIZE: usize = 64;

/// ML_DSA87 VERIFICATION size
const ML_DSA87_VERIFICATION_SIZE_BYTES: usize = 64;

/// ML_DSA87 CTX_CONFIG size
const ML_DSA87_CTX_SIZE: usize = 256;

/// ML_DSA87 PUBKEY size
const ML_DSA87_PUBKEY_SIZE: usize = 2592;

/// ML_DSA87 SIGNATURE size
const SIG_LEN: usize = 4627;

/// ML_DSA87 SIGNATURE size
// Signature len is unaligned
const ML_DSA87_SIGNATURE_SIZE: usize = SIG_LEN + 1;

/// ML_DSA87 PRIVKEY size
const ML_DSA87_PRIVKEY_SIZE: usize = 4896;

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
        PCR_SIGN OFFSET(4) NUMBITS(1) [],
        EXTERNAL_MU OFFSET(5) NUMBITS(1) [],
        STREAM_MSG OFFSET(6) NUMBITS(1) [],
    ],

    /// Status Register Fields
    Status [
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        MSG_STREAM_READY OFFSET(2) NUMBITS(1) [],
    ],

    /// Context Config Register Fields
    CtxConfig [
        CTX_SIZE OFFSET(0) NUMBITS(7) [],
    ],

    /// Strobe Register Fields
    Strobe [
        STROBE OFFSET(0) NUMBITS(4) [],
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
    ]
];

fn keygen_with_rng(seed: &[u8; 32]) -> (PKey<Public>, PKey<Private>) {
    let builder = PKeyMlDsaBuilder::<Private>::from_seed(Variant::MlDsa87, seed).unwrap();
    let priv_key = builder.build().unwrap();
    let public_params = PKeyMlDsaParams::<Public>::from_pkey(&priv_key).unwrap();
    let pub_key = PKeyMlDsaBuilder::<Public>::new(
        Variant::MlDsa87,
        public_params.public_key().unwrap(),
        None,
    )
    .unwrap()
    .build()
    .unwrap();

    (pub_key, priv_key)
}

fn pub_key_to_bytes(pub_key: &PKey<Public>) -> [u8; 2592] {
    let pkey_param = PKeyMlDsaParams::<Public>::from_pkey(pub_key).unwrap();
    pkey_param.public_key().unwrap().try_into().unwrap()
}

fn priv_key_to_bytes(priv_key: &PKey<Private>) -> [u8; 4896] {
    let pkey_param = PKeyMlDsaParams::<Private>::from_pkey(priv_key).unwrap();
    pkey_param.private_key().unwrap().try_into().unwrap()
}

fn priv_key_from_bytes(
    pub_key: &[u32; ML_DSA87_PUBKEY_SIZE / 4],
    priv_key: &[u8],
) -> PKey<Private> {
    let builder = PKeyMlDsaBuilder::<Private>::new(
        Variant::MlDsa87,
        &bytes_from_words_le(pub_key),
        Some(priv_key),
    )
    .unwrap();
    builder.build().unwrap()
}

fn pub_key_from_bytes(pub_key: &[u8]) -> PKey<Public> {
    let builder = PKeyMlDsaBuilder::<Public>::new(Variant::MlDsa87, pub_key, None).unwrap();
    builder.build().unwrap()
}

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
    #[register_array(offset = 0x0000_0098, write_fn = on_write_msg)]
    msg: [u32; ML_DSA87_MSG_SIZE / 4],

    /// Verification result
    #[register_array(offset = 0x0000_00d8, write_fn = write_access_fault)]
    verify_res: [u32; ML_DSA87_VERIFICATION_SIZE_BYTES / 4],

    /// External mu
    #[register_array(offset = 0x0000_0118)]
    external_mu: [u32; ML_DSA87_EXTERNAL_MU_SIZE / 4],

    /// Message Strobe
    #[register(offset = 0x0000_0158)]
    msg_strobe: ReadWriteRegister<u32, Strobe::Register>,

    /// Context config
    #[register(offset = 0x0000_015c)]
    ctx_config: ReadWriteRegister<u32, CtxConfig::Register>,

    /// Context
    #[register_array(offset = 0x0000_0160)]
    ctx: [u32; ML_DSA87_CTX_SIZE / 4],

    /// Public key
    #[register_array(offset = 0x0000_1000)]
    pubkey: [u32; ML_DSA87_PUBKEY_SIZE / 4],

    /// Signature
    #[register_array(offset = 0x0000_2000)]
    signature: [u32; ML_DSA87_SIGNATURE_SIZE / 4],

    // Private Key Out
    #[register_array(offset = 0x0000_4000)]
    privkey_out: [u32; ML_DSA87_PRIVKEY_SIZE / 4],

    /// Private Key In
    #[register_array(offset = 0x0000_6000)]
    privkey_in: [u32; ML_DSA87_PRIVKEY_SIZE / 4],

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

    /// SHA512 hash
    hash_sha512: HashSha512,

    /// Operation complete callback
    op_complete_action: Option<ActionHandle>,

    /// Seed read complete action
    op_seed_read_complete_action: Option<ActionHandle>,

    /// Zeroize complete callback
    op_zeroize_complete_action: Option<ActionHandle>,

    /// Msg stream ready callback
    op_msg_stream_ready_action: Option<ActionHandle>,

    /// Streaming message buffer
    streamed_msg: Vec<u8>,
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

    pub fn new(clock: &Clock, key_vault: KeyVault, hash_sha512: HashSha512) -> Self {
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
            external_mu: Default::default(),
            msg_strobe: ReadWriteRegister::new(0xf),
            ctx_config: ReadWriteRegister::new(0),
            ctx: [0; ML_DSA87_CTX_SIZE / 4],
            pubkey: [0; ML_DSA87_PUBKEY_SIZE / 4],
            signature: [0; ML_DSA87_SIGNATURE_SIZE / 4],
            privkey_out: [0; ML_DSA87_PRIVKEY_SIZE / 4],
            privkey_in: [0; ML_DSA87_PRIVKEY_SIZE / 4],
            kv_rd_seed_ctrl: ReadWriteRegister::new(0),
            kv_rd_seed_status: ReadOnlyRegister::new(0),
            error_global_intr: ReadOnlyRegister::new(0),
            error_internal_intr: ReadOnlyRegister::new(0),
            private_key: [0; ML_DSA87_PRIVKEY_SIZE],
            timer: Timer::new(clock),
            key_vault,
            hash_sha512,
            op_complete_action: None,
            op_seed_read_complete_action: None,
            op_zeroize_complete_action: None,
            op_msg_stream_ready_action: None,
            streamed_msg: Vec::with_capacity(ML_DSA87_MSG_MAX_SIZE),
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

    fn set_msg_stream_ready(&mut self) {
        // Set the MSG_STREAM_READY bit unconditionally when called
        self.status.reg.modify(Status::MSG_STREAM_READY::SET);
    }

    fn zeroize(&mut self) {
        self.control.reg.set(0);
        self.seed = Default::default();
        self.sign_rnd = Default::default();
        self.msg = Default::default();
        self.verify_res = Default::default();
        self.external_mu = Default::default();
        self.msg_strobe.reg.set(0xf); // Reset to all bytes valid
        self.ctx_config.reg.set(0);
        self.ctx = [0; ML_DSA87_CTX_SIZE / 4];
        self.pubkey = [0; ML_DSA87_PUBKEY_SIZE / 4];
        self.signature = [0; ML_DSA87_SIGNATURE_SIZE / 4];
        self.privkey_out = [0; ML_DSA87_PRIVKEY_SIZE / 4];
        self.privkey_in = [0; ML_DSA87_PRIVKEY_SIZE / 4];
        self.kv_rd_seed_ctrl.reg.set(0);
        self.kv_rd_seed_status.reg.write(KvRdSeedStatus::READY::SET);
        self.private_key = [0; ML_DSA87_PRIVKEY_SIZE];
        self.streamed_msg.clear();
        // Stop actions
        self.op_complete_action = None;
        self.op_seed_read_complete_action = None;
        self.op_zeroize_complete_action = None;
        self.op_msg_stream_ready_action = None;
        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::CLEAR + Status::MSG_STREAM_READY::CLEAR);
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

                // If streaming message mode is enabled, set the MSG_STREAM_READY bit
                // and wait for the message to be streamed in
                if self.control.reg.is_set(Control::STREAM_MSG)
                    && (self.control.reg.read_as_enum(Control::CTRL)
                        == Some(Control::CTRL::Value::SIGNING)
                        || self.control.reg.read_as_enum(Control::CTRL)
                            == Some(Control::CTRL::Value::VERIFYING)
                        || self.control.reg.read_as_enum(Control::CTRL)
                            == Some(Control::CTRL::Value::KEYGEN_AND_SIGN))
                {
                    // Clear any previous streamed message
                    self.streamed_msg.clear();
                    self.status.reg.modify(Status::MSG_STREAM_READY::CLEAR);
                    // Schedule an action to set the MSG_STREAM_READY bit after a short delay
                    self.op_msg_stream_ready_action = Some(self.timer.schedule_poll_in(10));
                } else {
                    // Not waiting for message streaming, proceed with operation
                    self.op_complete_action = Some(self.timer.schedule_poll_in(ML_DSA87_OP_TICKS));
                }
            }
            _ => {}
        }

        if self.control.reg.is_set(Control::ZEROIZE) {
            // Reset the Ready status bit
            self.status.reg.modify(Status::READY::CLEAR);

            self.op_zeroize_complete_action = Some(self.timer.schedule_poll_in(ML_DSA87_OP_TICKS));
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
        // Unlike ECC, no dword endianness reversal is needed.
        let seed = bytes_from_words_le(&self.seed);
        let (pubkey, privkey) = keygen_with_rng(&seed);
        self.pubkey = words_from_bytes_le(&pub_key_to_bytes(&pubkey));
        self.private_key = priv_key_to_bytes(&privkey);
        if !self.kv_rd_seed_ctrl.reg.is_set(KvRdSeedCtrl::READ_EN) {
            // privkey_out is in hardware format, which is same as library format.
            let privkey_out = self.private_key;
            self.privkey_out = words_from_bytes_le(&privkey_out);
        }
    }

    fn sign(&mut self, caller_provided: bool) {
        // Check if PCR_SIGN is set
        if self.control.reg.is_set(Control::PCR_SIGN) {
            panic!("ML-DSA PCR Sign operation needs to be performed with KEYGEN_AND_SIGN option");
        }

        let secret_key = if caller_provided {
            // Unlike ECC, no dword endianness reversal is needed.
            priv_key_from_bytes(&self.pubkey, &bytes_from_words_le(&self.privkey_in))
        } else {
            priv_key_from_bytes(&self.pubkey, &self.private_key)
        };

        // Get message data based on streaming mode
        let message = if self.control.reg.is_set(Control::STREAM_MSG) {
            // Use the streamed message
            self.streamed_msg.as_slice()
        } else {
            // Use the fixed message register
            &bytes_from_words_le(&self.msg)
        };

        // [TODO][CAP2]: Use context once OpenSSL supports it.

        // Get context if specified
        // let mut ctx: Vec<u8> = Vec::new();
        // if self.control.reg.is_set(Control::STREAM_MSG) {
        //     // Make sure we're not still expecting more message data
        //     assert!(!self.status.reg.is_set(Status::MSG_STREAM_READY));
        //     let ctx_size = self.ctx_config.reg.read(CtxConfig::CTX_SIZE) as usize;
        //     if ctx_size > 0 {
        //         // Convert context array to bytes using functional approach
        //         let ctx_bytes: Vec<u8> = self
        //             .ctx
        //             .iter()
        //             .flat_map(|word| word.to_le_bytes().to_vec())
        //             .collect();
        //         ctx = ctx_bytes[..ctx_size].to_vec();
        //     }
        // }

        // The Ml_Dsa87 signature is 4595 len but the reg is one byte longer
        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
        let mut ctx = PkeyCtx::new(&secret_key).unwrap();
        ctx.sign_message_init(&mut algo).unwrap();
        let mut signature = [0u8; ML_DSA87_SIGNATURE_SIZE];
        ctx.sign(message, Some(&mut signature)).unwrap();

        self.signature = words_from_bytes_le(&signature);
    }

    /// Sign the PCR digest
    fn pcr_digest_sign(&mut self) {
        const PCR_SIGN_KEY: u32 = 8;
        let _ = self.read_seed_from_keyvault(PCR_SIGN_KEY, true);

        // Generate private key from seed.
        self.gen_key();
        let secret_key = priv_key_from_bytes(&self.pubkey, &self.private_key);

        let pcr_digest = self.hash_sha512.pcr_hash_digest();
        let mut temp = words_from_bytes_le(
            &<[u8; ML_DSA87_MSG_SIZE]>::try_from(&pcr_digest[..ML_DSA87_MSG_SIZE]).unwrap(),
        );
        // Reverse the dword order.
        temp.reverse();

        // The Ml_Dsa87 signature is 4595 len but the reg is one byte longer.
        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
        let mut ctx = PkeyCtx::new(&secret_key).unwrap();
        ctx.sign_message_init(&mut algo).unwrap();

        let mut signature = [0u8; ML_DSA87_SIGNATURE_SIZE];
        ctx.sign(temp.as_bytes(), Some(&mut signature)).unwrap();

        self.signature = words_from_bytes_le(&signature);
    }

    fn verify(&mut self) {
        // Get message data based on streaming mode
        let message = if self.control.reg.is_set(Control::STREAM_MSG) {
            // Use the streamed message
            self.streamed_msg.as_slice()
        } else {
            // Unlike ECC, no dword endianness reversal is needed.
            // Use the fixed message register
            &bytes_from_words_le(&self.msg)
        };

        let public_key = {
            let key_bytes = bytes_from_words_le(&self.pubkey);
            pub_key_from_bytes(&key_bytes)
        };

        let signature = bytes_from_words_le(&self.signature);

        // [TODO][CAP2]: Use context once OpenSSL supports it.

        // Get context if specified
        // let mut ctx: Vec<u8> = Vec::new();
        // if self.control.reg.is_set(Control::STREAM_MSG) {
        //     // Make sure we're not still expecting more message data
        //     assert!(!self.status.reg.is_set(Status::MSG_STREAM_READY));
        //     let ctx_size = self.ctx_config.reg.read(CtxConfig::CTX_SIZE) as usize;
        //     if ctx_size > 0 {
        //         // Convert context array to bytes using functional approach
        //         let ctx_bytes: Vec<u8> = self
        //             .ctx
        //             .iter()
        //             .flat_map(|word| word.to_le_bytes().to_vec())
        //             .collect();
        //         ctx = ctx_bytes[..ctx_size].to_vec();
        //     }
        // }

        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
        let mut ctx = PkeyCtx::new(&public_key).unwrap();
        ctx.verify_message_init(&mut algo).unwrap();
        let success = matches!(ctx.verify(message, &signature[..SIG_LEN]), Ok(true));

        if success {
            self.verify_res
                .copy_from_slice(&self.signature[..(ML_DSA87_VERIFICATION_SIZE_BYTES / 4)]);
        } else {
            self.verify_res = [0u32; ML_DSA87_VERIFICATION_SIZE_BYTES / 4];
        }
    }

    fn op_complete(&mut self) {
        match self.control.reg.read_as_enum(Control::CTRL) {
            Some(Control::CTRL::Value::KEYGEN) => self.gen_key(),
            Some(Control::CTRL::Value::SIGNING) => {
                self.sign(true);
            }
            Some(Control::CTRL::Value::VERIFYING) => self.verify(),
            Some(Control::CTRL::Value::KEYGEN_AND_SIGN) => {
                if self.control.reg.is_set(Control::PCR_SIGN) {
                    self.pcr_digest_sign();
                } else {
                    self.gen_key();
                    self.sign(false);
                }
            }
            _ => panic!("Invalid value in ML-DSA Control"),
        }

        self.status
            .reg
            .modify(Status::READY::SET + Status::VALID::SET + Status::MSG_STREAM_READY::CLEAR);
    }

    fn read_seed_from_keyvault(&mut self, key_id: u32, locked: bool) -> u32 {
        let mut key_usage = KeyUsage::default();
        key_usage.set_mldsa_key_gen_seed(true);

        let result = if locked {
            self.key_vault.read_key_locked(key_id, key_usage)
        } else {
            self.key_vault.read_key(key_id, key_usage)
        };
        let (seed_read_result, seed) = match result.err() {
            Some(BusError::LoadAccessFault)
            | Some(BusError::LoadAddrMisaligned)
            | Some(BusError::InstrAccessFault) => (KvRdSeedStatus::ERROR::KV_READ_FAIL.value, None),
            Some(BusError::StoreAccessFault) | Some(BusError::StoreAddrMisaligned) => {
                (KvRdSeedStatus::ERROR::KV_WRITE_FAIL.value, None)
            }
            None => (KvRdSeedStatus::ERROR::SUCCESS.value, Some(result.unwrap())),
        };

        // Read the first 32 bytes from KV.
        // Key vault already stores seed in hardware format
        if let Some(seed) = seed {
            let mut temp = words_from_bytes_le(
                &<[u8; ML_DSA87_SEED_SIZE]>::try_from(&seed[..ML_DSA87_SEED_SIZE]).unwrap(),
            );

            // DOWRD 0 from Key Vault goes to DWORD 7 of Seed.
            temp.reverse();
            self.seed = temp;
        }

        seed_read_result
    }

    fn seed_read_complete(&mut self) {
        let key_id = self.kv_rd_seed_ctrl.reg.read(KvRdSeedCtrl::READ_ENTRY);
        let seed_read_result = self.read_seed_from_keyvault(key_id, false);

        self.kv_rd_seed_status.reg.modify(
            KvRdSeedStatus::READY::SET
                + KvRdSeedStatus::VALID::SET
                + KvRdSeedStatus::ERROR.val(seed_read_result),
        );
    }

    /// On Write callback for message register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `index` - Index of the dword being written
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_msg(
        &mut self,
        size: RvSize,
        index: usize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Regular write for non-streaming mode
        if !self.control.reg.is_set(Control::STREAM_MSG) {
            self.msg[index] = val;
            return Ok(());
        }

        // We're in streaming mode
        assert!(index == 0);

        // Streaming message mode - handle write to index 0
        let strobe_value = self.msg_strobe.reg.read(Strobe::STROBE);
        let mut bytes_to_add: Vec<u8> = Vec::new();

        // Handle the strobe for valid bytes
        if strobe_value == 0xF {
            // All bytes valid
            bytes_to_add.extend_from_slice(&val.to_le_bytes());
        } else {
            let val_bytes = val.to_le_bytes();
            for (i, &byte) in val_bytes.iter().enumerate() {
                if (strobe_value & (1 << i)) != 0 {
                    bytes_to_add.push(byte);
                }
            }

            // Reset the strobe and mark end of message
            self.msg_strobe.reg.write(Strobe::STROBE.val(0xF));

            // If this was the last segment, start processing
            self.status.reg.modify(Status::MSG_STREAM_READY::CLEAR);
            self.op_complete_action = Some(self.timer.schedule_poll_in(ML_DSA87_OP_TICKS));
        }

        // Add the bytes to the streamed message
        self.streamed_msg.extend_from_slice(&bytes_to_add);

        Ok(())
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_complete_action) {
            self.op_complete();
        }
        if self.timer.fired(&mut self.op_seed_read_complete_action) {
            self.seed_read_complete();
        }
        if self.timer.fired(&mut self.op_zeroize_complete_action) {
            self.zeroize();
        }
        if self.timer.fired(&mut self.op_msg_stream_ready_action) {
            self.set_msg_stream_ready();
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
    use caliptra_emu_types::RvAddr;
    use rand::Rng;
    use tock_registers::registers::InMemoryRegister;
    use zerocopy::IntoBytes;

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
    const OFFSET_MSG_STROBE: RvAddr = 0x158;
    const OFFSET_CTX_CONFIG: RvAddr = 0x15c;
    const OFFSET_CTX: RvAddr = 0x160;
    const OFFSET_PK: RvAddr = 0x1000;
    const OFFSET_SIGNATURE: RvAddr = 0x2000;
    const OFFSET_PRIVKEY_IN: RvAddr = 0x6000;
    const OFFSET_KV_RD_SEED_CONTROL: RvAddr = 0x8000;
    const OFFSET_KV_RD_SEED_STATUS: RvAddr = 0x8004;

    #[test]
    fn test_name() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

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
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

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
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_CONTROL).unwrap(), 0);
    }

    #[test]
    fn test_status() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_gen_key() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SEED + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
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

        let public_key = bytes_from_words_le(&ml_dsa87.pubkey);

        let (pk_from_lib, _sk) = keygen_with_rng(&seed);
        let pk_from_lib = pub_key_to_bytes(&pk_from_lib);
        assert_eq!(&public_key, &pk_from_lib);
    }

    #[test]
    fn test_sign_from_seed() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SEED + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        let msg: [u8; 64] = {
            let part0 = rand::thread_rng().gen::<[u8; 32]>();
            let part1 = rand::thread_rng().gen::<[u8; 32]>();
            let concat: Vec<u8> = part0.iter().chain(part1.iter()).copied().collect();
            concat.as_slice().try_into().unwrap()
        };

        for (i, chunk) in msg.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MSG + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        let sign_rnd = rand::thread_rng().gen::<[u8; 32]>();

        for (i, chunk) in sign_rnd.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGN_RND + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
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

        let signature = bytes_from_words_le(&ml_dsa87.signature);

        let (_pk, sk) = keygen_with_rng(&seed);
        let mut ctx = PkeyCtx::new(&sk).unwrap();
        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
        ctx.verify_message_init(&mut algo).unwrap();
        let valid = ctx.verify(&msg, &signature[..SIG_LEN]);
        assert!(matches!(valid, Ok(true)));
    }

    #[test]
    fn test_verify() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

        let msg: [u8; 64] = {
            let part0 = rand::thread_rng().gen::<[u8; 32]>();
            let part1 = rand::thread_rng().gen::<[u8; 32]>();
            let concat: Vec<u8> = part0.iter().chain(part1.iter()).copied().collect();
            concat.as_slice().try_into().unwrap()
        };

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let (pk_from_lib, sk_from_lib) = keygen_with_rng(&seed);
        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
        let mut ctx = PkeyCtx::new(&sk_from_lib).unwrap();
        ctx.sign_message_init(&mut algo).unwrap();

        let mut signature_from_lib = [0u8; ML_DSA87_SIGNATURE_SIZE];
        ctx.sign(&msg, Some(&mut signature_from_lib)).unwrap();

        for (i, chunk) in msg.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MSG + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        let pk_for_hw = pub_key_to_bytes(&pk_from_lib);
        for (i, chunk) in pk_for_hw.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_PK + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Good signature
        for (i, chunk) in signature_from_lib.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGNATURE + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
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

        let result = bytes_from_words_le(&ml_dsa87.verify_res);
        assert_eq!(
            result,
            &signature_from_lib[..ML_DSA87_VERIFICATION_SIZE_BYTES]
        );

        // Bad signature
        let mut rng = rand::thread_rng();
        let mut signature = [0u8; ML_DSA87_SIGNATURE_SIZE];

        rng.fill(&mut signature[..64]);

        for (i, chunk) in signature.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGNATURE + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
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

        let result = bytes_from_words_le(&ml_dsa87.verify_res);
        assert_ne!(
            result,
            &signature_from_lib[signature_from_lib.len() - ML_DSA87_VERIFICATION_SIZE_BYTES..]
        );
    }

    #[test]
    fn test_gen_key_kv_seed() {
        // Test for getting the seed from the key-vault.
        for key_id in 0..KeyVault::KEY_COUNT {
            let clock = Clock::new();
            let seed = rand::thread_rng().gen::<[u8; 32]>();
            let (pk, _sk) = keygen_with_rng(&seed);
            let pk_from_lib = pub_key_to_bytes(&pk);

            let mut key_vault = KeyVault::new();
            let mut key_usage = KeyUsage::default();
            key_usage.set_mldsa_key_gen_seed(true);

            // DOWRD 0 from Seed goes to DWORD 7 of Key Vault.
            let mut seed_dword_reversed = words_from_bytes_le(
                &<[u8; ML_DSA87_SEED_SIZE]>::try_from(&seed[..ML_DSA87_SEED_SIZE]).unwrap(),
            );
            seed_dword_reversed.reverse();
            key_vault
                .write_key(key_id, seed_dword_reversed.as_bytes(), u32::from(key_usage))
                .unwrap();

            let sha512 = HashSha512::new(&clock, key_vault.clone());
            let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

            // We expect the output to match the generated random seed.
            // Write a different seed first to make sure the Kv seed is used
            let seed = [0xABu8; 32];
            for (i, chunk) in seed.chunks_exact(4).enumerate() {
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_SEED + (i * 4) as RvAddr,
                        u32::from_le_bytes(chunk.try_into().unwrap()),
                    )
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

            let public_key = bytes_from_words_le(&ml_dsa87.pubkey);
            let pub_key_comp = pk_from_lib;
            assert_eq!(&public_key, &pub_key_comp);
        }
    }

    #[test]
    fn test_sign_var_from_seed() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

        // Generate seed and write to hardware
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SEED + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Create variable length message (less than 64 bytes)
        let mut msg_short = [0u8; 40];
        for byte in &mut msg_short {
            *byte = rand::thread_rng().gen();
        }

        // Generate random values for sign_rnd
        let sign_rnd = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in sign_rnd.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_SIGN_RND + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Save public key for later verification
        let (pk, _sk) = keygen_with_rng(&seed);

        // Enable key generation and signing with streaming message mode in one operation
        let ctrl_value = Control::CTRL::KEYGEN_AND_SIGN.value | Control::STREAM_MSG::SET.value;
        ml_dsa87
            .write(RvSize::Word, OFFSET_CONTROL, ctrl_value)
            .unwrap();

        // Wait for MSG_STREAM_READY status
        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::MSG_STREAM_READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        // Stream the message in chunks
        let dwords = msg_short.chunks_exact(std::mem::size_of::<u32>());
        let remainder = dwords.remainder();

        // Process full dwords
        for chunk in dwords {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            ml_dsa87.write(RvSize::Word, OFFSET_MSG, word).unwrap();
        }

        // Handle remainder bytes by setting appropriate strobe pattern
        let last_strobe = match remainder.len() {
            0 => 0b0000,
            1 => 0b0001,
            2 => 0b0011,
            3 => 0b0111,
            _ => 0b0000, // should never happen
        };
        ml_dsa87
            .write(RvSize::Word, OFFSET_MSG_STROBE, last_strobe)
            .unwrap();

        // Write last dword, even if no remainder (using 0)
        let mut last_word = 0_u32;
        let mut last_bytes = last_word.to_le_bytes();
        last_bytes[..remainder.len()].copy_from_slice(remainder);
        last_word = u32::from_le_bytes(last_bytes);
        ml_dsa87.write(RvSize::Word, OFFSET_MSG, last_word).unwrap();

        // Wait for operation to complete
        loop {
            let status = InMemoryRegister::<u32, Status::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
            );

            if status.is_set(Status::VALID) && status.is_set(Status::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        // Get the signature
        let signature = bytes_from_words_le(&ml_dsa87.signature);

        // Verify the signature using the crypto library
        let mut algo = Signature::for_ml_dsa(Variant::MlDsa87).unwrap();
        let mut ctx = PkeyCtx::new(&pk).unwrap();
        ctx.verify_message_init(&mut algo).unwrap();

        let valid = ctx.verify(&msg_short, &signature[..SIG_LEN]);
        assert!(matches!(valid, Ok(true)), "Signature verification failed");
    }

    // [TODO][CAP2]: Re-enable this test once OpenSSL supports it.

    // #[test]
    // fn test_sign_var_with_streaming_and_context() {
    //     let clock = Clock::new();
    //     let key_vault = KeyVault::new();
    //     let sha512 = HashSha512::new(&clock, key_vault.clone());

    //     let mut ml_dsa87 = Mldsa87::new(&clock, key_vault, sha512);

    //     // Generate a private key directly
    //     let seed = rand::thread_rng().gen::<[u8; 32]>();
    //     let (pk, sk) = keygen_with_rng(&seed);
    //     let private_key = priv_key_to_bytes(&sk);

    //     // Write the private key to hardware
    //     for (i, chunk) in private_key.chunks_exact(4).enumerate() {
    //         ml_dsa87
    //             .write(
    //                 RvSize::Word,
    //                 OFFSET_PRIVKEY_IN + (i * 4) as RvAddr,
    //                 u32::from_le_bytes(chunk.try_into().unwrap()),
    //             )
    //             .unwrap();
    //     }

    //     // Create a larger message (more than 64 bytes)
    //     let msg_large: Vec<u8> = (0..100).map(|_| rand::thread_rng().gen::<u8>()).collect();

    //     // Generate context data
    //     let ctx_data: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    //     let ctx_size = ctx_data.len();

    //     // Write context data - need to use little endian format for hardware
    //     for (i, chunk) in ctx_data.chunks_exact(4).enumerate() {
    //         ml_dsa87
    //             .write(
    //                 RvSize::Word,
    //                 OFFSET_CTX + (i * 4) as RvAddr,
    //                 u32::from_le_bytes(chunk.try_into().unwrap()),
    //             )
    //             .unwrap();
    //     }

    //     // Handle any remaining bytes (if ctx_data length is not a multiple of 4)
    //     let remainder = ctx_data.chunks_exact(4).remainder();
    //     if !remainder.is_empty() {
    //         let mut last_word = 0_u32;
    //         let mut last_bytes = last_word.to_le_bytes();
    //         last_bytes[..remainder.len()].copy_from_slice(remainder);
    //         last_word = u32::from_le_bytes(last_bytes);
    //         ml_dsa87
    //             .write(
    //                 RvSize::Word,
    //                 OFFSET_CTX + (ctx_data.len() / 4 * 4) as RvAddr,
    //                 last_word,
    //             )
    //             .unwrap();
    //     }

    //     // Set context size in config register
    //     ml_dsa87
    //         .write(RvSize::Word, OFFSET_CTX_CONFIG, ctx_size as u32)
    //         .unwrap();

    //     // Generate random values for sign_rnd
    //     let sign_rnd = rand::thread_rng().gen::<[u8; 32]>();
    //     for (i, chunk) in sign_rnd.chunks_exact(4).enumerate() {
    //         ml_dsa87
    //             .write(
    //                 RvSize::Word,
    //                 OFFSET_SIGN_RND + (i * 4) as RvAddr,
    //                 u32::from_le_bytes(chunk.try_into().unwrap()),
    //             )
    //             .unwrap();
    //     }

    //     // Start signing operation with streaming mode
    //     let ctrl_value = Control::CTRL::SIGNING.value | Control::STREAM_MSG::SET.value;
    //     ml_dsa87
    //         .write(RvSize::Word, OFFSET_CONTROL, ctrl_value)
    //         .unwrap();

    //     // Wait for MSG_STREAM_READY status
    //     loop {
    //         let status = InMemoryRegister::<u32, Status::Register>::new(
    //             ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
    //         );

    //         if status.is_set(Status::MSG_STREAM_READY) {
    //             break;
    //         }

    //         clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
    //     }

    //     // Stream the message in chunks
    //     let dwords = msg_large.chunks_exact(std::mem::size_of::<u32>());
    //     let remainder = dwords.remainder();

    //     // Process full dwords
    //     for chunk in dwords {
    //         let word = u32::from_le_bytes(chunk.try_into().unwrap());
    //         ml_dsa87.write(RvSize::Word, OFFSET_MSG, word).unwrap();
    //     }

    //     // Handle remainder bytes by setting appropriate strobe pattern
    //     let last_strobe = match remainder.len() {
    //         0 => 0b0000,
    //         1 => 0b0001,
    //         2 => 0b0011,
    //         3 => 0b0111,
    //         _ => 0b0000, // should never happen
    //     };
    //     ml_dsa87
    //         .write(RvSize::Word, OFFSET_MSG_STROBE, last_strobe)
    //         .unwrap();

    //     // Write last dword, even if no remainder (using 0)
    //     let mut last_word = 0_u32;
    //     let mut last_bytes = last_word.to_le_bytes();
    //     last_bytes[..remainder.len()].copy_from_slice(remainder);
    //     last_word = u32::from_le_bytes(last_bytes);
    //     ml_dsa87.write(RvSize::Word, OFFSET_MSG, last_word).unwrap();

    //     // Wait for operation to complete
    //     loop {
    //         let status = InMemoryRegister::<u32, Status::Register>::new(
    //             ml_dsa87.read(RvSize::Word, OFFSET_STATUS).unwrap(),
    //         );

    //         if status.is_set(Status::VALID) && status.is_set(Status::READY) {
    //             break;
    //         }

    //         clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
    //     }

    //     // Get the signature
    //     let signature = bytes_from_words_le(&ml_dsa87.signature);

    //     // Verify the signature using the crypto library
    //     let result = pk.verify(
    //         &msg_large,
    //         &signature[..SIG_LEN].try_into().unwrap(),
    //         &ctx_data,
    //     );
    //     assert!(result, "Signature verification with context failed");

    //     // Now verify that it fails with incorrect context
    //     let wrong_ctx = Vec::from([0u8; 16]);
    //     let result_wrong_ctx = pk.verify(
    //         &msg_large,
    //         &signature[..SIG_LEN].try_into().unwrap(),
    //         &wrong_ctx,
    //     );
    //     assert!(
    //         !result_wrong_ctx,
    //         "Signature shouldn't verify with wrong context"
    //     );
    // }
}
