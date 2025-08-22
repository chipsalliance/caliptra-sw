/*++

Licensed under the Apache-2.0 license.

File Name:

abr.rs

Abstract:

File contains Adams Bridge peripheral implementation.

--*/

use crate::helpers::{bytes_from_words_le, words_from_bytes_le};
use crate::{HashSha512, KeyUsage, KeyVault};
use caliptra_emu_bus::{ActionHandle, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use fips204::ml_dsa_87::{try_keygen_with_rng, PrivateKey, PublicKey, PK_LEN, SIG_LEN, SK_LEN};
use fips204::traits::{SerDes, Signer, Verifier};
use rand::{CryptoRng, RngCore};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use zerocopy::IntoBytes;

// RNG that only allows a single call, which returns the fixed seed.
pub(crate) struct SeedOnlyRng {
    seed: [u8; 32],
    called: bool,
}

impl SeedOnlyRng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            called: false,
        }
    }
}

impl RngCore for SeedOnlyRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        if self.called {
            panic!("Can only call fill_bytes once");
        }
        assert_eq!(out.len(), 32);
        out.copy_from_slice(&self.seed[..32]);
        self.called = true;
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}

impl CryptoRng for SeedOnlyRng {}

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
    MlDsaControl [
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
    MlDsaStatus [
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
        MSG_STREAM_READY OFFSET(2) NUMBITS(1) [],
    ],

    /// Context Config Register Fields
    MlDsaCtxConfig [
        CTX_SIZE OFFSET(0) NUMBITS(7) [],
    ],

    /// Strobe Register Fields
    MlDsaStrobe [
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

#[derive(Bus)]
#[poll_fn(poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct Abr {
    /// MLDSA Name registers
    #[register_array(offset = 0x0000_0000)]
    mldsa_name: [u32; 2],

    /// MLDSA Version registers
    #[register_array(offset = 0x0000_0008)]
    mldsa_version: [u32; 2],

    /// MLDSA Control register
    #[register(offset = 0x0000_0010, write_fn = on_write_mldsa_control)]
    mldsa_ctrl: ReadWriteRegister<u32, MlDsaControl::Register>,

    /// MLDSA Status register
    #[register(offset = 0x0000_0014)]
    mldsa_status: ReadOnlyRegister<u32, MlDsaStatus::Register>,

    /// ABR Entropy (shared between MLDSA and MLKEM)
    #[register_array(offset = 0x0000_0018)]
    abr_entropy: [u32; ML_DSA87_IV_SIZE / 4],

    /// MLDSA Seed
    #[register_array(offset = 0x0000_0058)]
    mldsa_seed: [u32; ML_DSA87_SEED_SIZE / 4],

    /// MLDSA Sign RND
    #[register_array(offset = 0x0000_0078)]
    mldsa_sign_rnd: [u32; ML_DSA87_SIGN_RND_SIZE / 4],

    /// MLDSA Message
    #[register_array(offset = 0x0000_0098, write_fn = on_write_mldsa_msg)]
    mldsa_msg: [u32; ML_DSA87_MSG_SIZE / 4],

    /// MLDSA Verification result
    #[register_array(offset = 0x0000_00d8, write_fn = write_mldsa_access_fault)]
    mldsa_verify_res: [u32; ML_DSA87_VERIFICATION_SIZE_BYTES / 4],

    /// MLDSA External mu
    #[register_array(offset = 0x0000_0118)]
    mldsa_external_mu: [u32; ML_DSA87_EXTERNAL_MU_SIZE / 4],

    /// MLDSA Message Strobe
    #[register(offset = 0x0000_0158)]
    mldsa_msg_strobe: ReadWriteRegister<u32, MlDsaStrobe::Register>,

    /// MLDSA Context config
    #[register(offset = 0x0000_015c)]
    mldsa_ctx_config: ReadWriteRegister<u32, MlDsaCtxConfig::Register>,

    /// MLDSA Context
    #[register_array(offset = 0x0000_0160)]
    mldsa_ctx: [u32; ML_DSA87_CTX_SIZE / 4],

    /// MLDSA Public key
    #[register_array(offset = 0x0000_1000)]
    mldsa_pubkey: [u32; ML_DSA87_PUBKEY_SIZE / 4],

    /// MLDSA Signature
    #[register_array(offset = 0x0000_2000)]
    mldsa_signature: [u32; ML_DSA87_SIGNATURE_SIZE / 4],

    /// MLDSA Private Key Out
    #[register_array(offset = 0x0000_4000)]
    mldsa_privkey_out: [u32; ML_DSA87_PRIVKEY_SIZE / 4],

    /// MLDSA Private Key In
    #[register_array(offset = 0x0000_6000)]
    mldsa_privkey_in: [u32; ML_DSA87_PRIVKEY_SIZE / 4],

    /// Key Vault MLDSA Seed Read Control
    #[register(offset = 0x0000_8000, write_fn = on_write_mldsa_kv_rd_seed_ctrl)]
    kv_mldsa_seed_rd_ctrl: ReadWriteRegister<u32, KvRdSeedCtrl::Register>,

    /// Key Vault MLDSA Seed Read Status
    #[register(offset = 0x0000_8004)]
    kv_mldsa_seed_rd_status: ReadOnlyRegister<u32, KvRdSeedStatus::Register>,

    /// MLKEM Name registers
    #[register_array(offset = 0x0000_9000)]
    mlkem_name: [u32; 2],

    /// MLKEM Version registers
    #[register_array(offset = 0x0000_9008)]
    mlkem_version: [u32; 2],

    /// MLKEM Control register
    #[register(offset = 0x0000_9010)]
    mlkem_ctrl: ReadWriteRegister<u32, MlDsaControl::Register>,

    /// MLKEM Status register
    #[register(offset = 0x0000_9014)]
    mlkem_status: ReadOnlyRegister<u32, MlDsaStatus::Register>,

    /// MLKEM Seed D
    #[register_array(offset = 0x0000_9018)]
    mlkem_seed_d: [u32; 8],

    /// MLKEM Seed Z
    #[register_array(offset = 0x0000_9038)]
    mlkem_seed_z: [u32; 8],

    /// MLKEM Shared Key
    #[register_array(offset = 0x0000_9058)]
    mlkem_shared_key: [u32; 8],

    /// MLKEM Message
    #[register_array(offset = 0x0000_A000)]
    mlkem_msg: [u32; 8],

    /// MLKEM Decapsulation Key
    #[register_array(offset = 0x0000_B000)]
    mlkem_decaps_key: [u32; 792],

    /// MLKEM Encapsulation Key
    #[register_array(offset = 0x0000_C000)]
    mlkem_encaps_key: [u32; 392],

    /// MLKEM Ciphertext
    #[register_array(offset = 0x0000_D000)]
    mlkem_ciphertext: [u32; 392],

    /// Key Vault MLKEM Seed Read Control
    #[register(offset = 0x0000_E000)]
    kv_mlkem_seed_rd_ctrl: ReadWriteRegister<u32, KvRdSeedCtrl::Register>,

    /// Key Vault MLKEM Seed Read Status
    #[register(offset = 0x0000_E004)]
    kv_mlkem_seed_rd_status: ReadOnlyRegister<u32, KvRdSeedStatus::Register>,

    /// Key Vault MLKEM Message Read Control
    #[register(offset = 0x0000_E008)]
    kv_mlkem_msg_rd_ctrl: ReadWriteRegister<u32, KvRdSeedCtrl::Register>,

    /// Key Vault MLKEM Message Read Status
    #[register(offset = 0x0000_E00C)]
    kv_mlkem_msg_rd_status: ReadOnlyRegister<u32, KvRdSeedStatus::Register>,

    /// Key Vault MLKEM Shared Key Write Control
    #[register(offset = 0x0000_E010)]
    kv_mlkem_sharedkey_wr_ctrl: ReadWriteRegister<u32, KvRdSeedCtrl::Register>,

    /// Key Vault MLKEM Shared Key Write Status
    #[register(offset = 0x0000_E014)]
    kv_mlkem_sharedkey_wr_status: ReadOnlyRegister<u32, KvRdSeedStatus::Register>,

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

impl Abr {
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
            mldsa_name: [Self::NAME0_VAL, Self::NAME1_VAL],
            mldsa_version: [Self::VERSION0_VAL, Self::VERSION1_VAL],
            mldsa_ctrl: ReadWriteRegister::new(0),
            mldsa_status: ReadOnlyRegister::new(MlDsaStatus::READY::SET.value),
            abr_entropy: Default::default(),
            mldsa_seed: Default::default(),
            mldsa_sign_rnd: Default::default(),
            mldsa_msg: Default::default(),
            mldsa_verify_res: Default::default(),
            mldsa_external_mu: Default::default(),
            mldsa_msg_strobe: ReadWriteRegister::new(0xf),
            mldsa_ctx_config: ReadWriteRegister::new(0),
            mldsa_ctx: [0; ML_DSA87_CTX_SIZE / 4],
            mldsa_pubkey: [0; ML_DSA87_PUBKEY_SIZE / 4],
            mldsa_signature: [0; ML_DSA87_SIGNATURE_SIZE / 4],
            mldsa_privkey_out: [0; ML_DSA87_PRIVKEY_SIZE / 4],
            mldsa_privkey_in: [0; ML_DSA87_PRIVKEY_SIZE / 4],
            kv_mldsa_seed_rd_ctrl: ReadWriteRegister::new(0),
            kv_mldsa_seed_rd_status: ReadOnlyRegister::new(0),
            mlkem_name: [Self::NAME0_VAL, Self::NAME1_VAL],
            mlkem_version: [Self::VERSION0_VAL, Self::VERSION1_VAL],
            mlkem_ctrl: ReadWriteRegister::new(0),
            mlkem_status: ReadOnlyRegister::new(MlDsaStatus::READY::SET.value),
            mlkem_seed_d: Default::default(),
            mlkem_seed_z: Default::default(),
            mlkem_shared_key: Default::default(),
            mlkem_msg: Default::default(),
            mlkem_decaps_key: [0; 792],
            mlkem_encaps_key: [0; 392],
            mlkem_ciphertext: [0; 392],
            kv_mlkem_seed_rd_ctrl: ReadWriteRegister::new(0),
            kv_mlkem_seed_rd_status: ReadOnlyRegister::new(0),
            kv_mlkem_msg_rd_ctrl: ReadWriteRegister::new(0),
            kv_mlkem_msg_rd_status: ReadOnlyRegister::new(0),
            kv_mlkem_sharedkey_wr_ctrl: ReadWriteRegister::new(0),
            kv_mlkem_sharedkey_wr_status: ReadOnlyRegister::new(0),
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

    fn write_mldsa_access_fault(
        &self,
        _size: RvSize,
        _index: usize,
        _val: RvData,
    ) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }

    fn set_msg_stream_ready(&mut self) {
        // Set the MSG_STREAM_READY bit unconditionally when called
        self.mldsa_status
            .reg
            .modify(MlDsaStatus::MSG_STREAM_READY::SET);
    }

    fn zeroize(&mut self) {
        self.mldsa_ctrl.reg.set(0);
        self.mldsa_seed = Default::default();
        self.mldsa_sign_rnd = Default::default();
        self.mldsa_msg = Default::default();
        self.mldsa_verify_res = Default::default();
        self.mldsa_external_mu = Default::default();
        self.mldsa_msg_strobe.reg.set(0xf); // Reset to all bytes valid
        self.mldsa_ctx_config.reg.set(0);
        self.mldsa_ctx = [0; ML_DSA87_CTX_SIZE / 4];
        self.mldsa_pubkey = [0; ML_DSA87_PUBKEY_SIZE / 4];
        self.mldsa_signature = [0; ML_DSA87_SIGNATURE_SIZE / 4];
        self.mldsa_privkey_out = [0; ML_DSA87_PRIVKEY_SIZE / 4];
        self.mldsa_privkey_in = [0; ML_DSA87_PRIVKEY_SIZE / 4];
        self.kv_mldsa_seed_rd_ctrl.reg.set(0);
        self.kv_mldsa_seed_rd_status
            .reg
            .write(KvRdSeedStatus::READY::SET);
        self.private_key = [0; ML_DSA87_PRIVKEY_SIZE];
        self.streamed_msg.clear();
        // Stop actions
        self.op_complete_action = None;
        self.op_seed_read_complete_action = None;
        self.op_zeroize_complete_action = None;
        self.op_msg_stream_ready_action = None;
        self.mldsa_status.reg.modify(
            MlDsaStatus::READY::SET
                + MlDsaStatus::VALID::CLEAR
                + MlDsaStatus::MSG_STREAM_READY::CLEAR,
        );
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
    pub fn on_write_mldsa_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the control register
        self.mldsa_ctrl.reg.set(val);

        match self.mldsa_ctrl.reg.read_as_enum(MlDsaControl::CTRL) {
            Some(MlDsaControl::CTRL::Value::KEYGEN)
            | Some(MlDsaControl::CTRL::Value::SIGNING)
            | Some(MlDsaControl::CTRL::Value::VERIFYING)
            | Some(MlDsaControl::CTRL::Value::KEYGEN_AND_SIGN) => {
                // Reset the Ready and Valid status bits
                self.mldsa_status
                    .reg
                    .modify(MlDsaStatus::READY::CLEAR + MlDsaStatus::VALID::CLEAR);

                // If streaming message mode is enabled, set the MSG_STREAM_READY bit
                // and wait for the message to be streamed in
                if self.mldsa_ctrl.reg.is_set(MlDsaControl::STREAM_MSG)
                    && (self.mldsa_ctrl.reg.read_as_enum(MlDsaControl::CTRL)
                        == Some(MlDsaControl::CTRL::Value::SIGNING)
                        || self.mldsa_ctrl.reg.read_as_enum(MlDsaControl::CTRL)
                            == Some(MlDsaControl::CTRL::Value::VERIFYING)
                        || self.mldsa_ctrl.reg.read_as_enum(MlDsaControl::CTRL)
                            == Some(MlDsaControl::CTRL::Value::KEYGEN_AND_SIGN))
                {
                    // Clear any previous streamed message
                    self.streamed_msg.clear();
                    self.mldsa_status
                        .reg
                        .modify(MlDsaStatus::MSG_STREAM_READY::CLEAR);
                    // Schedule an action to set the MSG_STREAM_READY bit after a short delay
                    self.op_msg_stream_ready_action = Some(self.timer.schedule_poll_in(10));
                } else {
                    // Not waiting for message streaming, proceed with operation
                    self.op_complete_action = Some(self.timer.schedule_poll_in(ML_DSA87_OP_TICKS));
                }
            }
            _ => {}
        }

        if self.mldsa_ctrl.reg.is_set(MlDsaControl::ZEROIZE) {
            // Reset the Ready status bit
            self.mldsa_status.reg.modify(MlDsaStatus::READY::CLEAR);

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
    pub fn on_write_mldsa_kv_rd_seed_ctrl(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.kv_mldsa_seed_rd_ctrl.reg.set(val);

        if self.kv_mldsa_seed_rd_ctrl.reg.is_set(KvRdSeedCtrl::READ_EN) {
            self.kv_mldsa_seed_rd_status.reg.modify(
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
        let seed = bytes_from_words_le(&self.mldsa_seed);
        let mut rng = SeedOnlyRng::new(seed);
        let (pubkey, privkey) = try_keygen_with_rng(&mut rng).unwrap();
        let pubkey = pubkey.into_bytes();
        self.mldsa_pubkey = words_from_bytes_le(&pubkey);
        self.private_key = privkey.into_bytes();
        if !self.kv_mldsa_seed_rd_ctrl.reg.is_set(KvRdSeedCtrl::READ_EN) {
            // privkey_out is in hardware format, which is same as library format.
            let privkey_out = self.private_key;
            self.mldsa_privkey_out = words_from_bytes_le(&privkey_out);
        }
    }

    fn sign(&mut self, caller_provided: bool) {
        // Check if PCR_SIGN is set
        if self.mldsa_ctrl.reg.is_set(MlDsaControl::PCR_SIGN) {
            panic!("ML-DSA PCR Sign operation needs to be performed with KEYGEN_AND_SIGN option");
        }

        let secret_key = if caller_provided {
            //  Unlike ECC, no dword endianness reversal is needed.
            let privkey = bytes_from_words_le(&self.mldsa_privkey_in);
            PrivateKey::try_from_bytes(privkey).unwrap()
        } else {
            PrivateKey::try_from_bytes(self.private_key).unwrap()
        };

        // Get message data based on streaming mode
        let message = if self.mldsa_ctrl.reg.is_set(MlDsaControl::STREAM_MSG) {
            // Use the streamed message
            self.streamed_msg.as_slice()
        } else {
            // Use the fixed message register
            &bytes_from_words_le(&self.mldsa_msg)
        };

        // Get context if specified
        let mut ctx: Vec<u8> = Vec::new();
        if self.mldsa_ctrl.reg.is_set(MlDsaControl::STREAM_MSG) {
            // Make sure we're not still expecting more message data
            assert!(!self.mldsa_status.reg.is_set(MlDsaStatus::MSG_STREAM_READY));
            let ctx_size = self.mldsa_ctx_config.reg.read(MlDsaCtxConfig::CTX_SIZE) as usize;
            if ctx_size > 0 {
                // Convert context array to bytes using functional approach
                let ctx_bytes: Vec<u8> = self
                    .mldsa_ctx
                    .iter()
                    .flat_map(|word| word.to_le_bytes().to_vec())
                    .collect();
                ctx = ctx_bytes[..ctx_size].to_vec();
            }
        }

        // The Ml_Dsa87 signature is 4595 len but the reg is one byte longer
        let signature = secret_key
            .try_sign_with_seed(&[0u8; 32], message, &ctx)
            .unwrap();
        let signature_extended = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature);
            sig
        };
        self.mldsa_signature = words_from_bytes_le(&signature_extended);
    }

    /// Sign the PCR digest
    fn pcr_digest_sign(&mut self) {
        const PCR_SIGN_KEY: u32 = 8;
        let _ = self.read_seed_from_keyvault(PCR_SIGN_KEY, true);

        // Generate private key from seed.
        self.gen_key();
        let secret_key = PrivateKey::try_from_bytes(self.private_key).unwrap();

        let pcr_digest = self.hash_sha512.pcr_hash_digest();
        let mut temp = words_from_bytes_le(
            &<[u8; ML_DSA87_MSG_SIZE]>::try_from(&pcr_digest[..ML_DSA87_MSG_SIZE]).unwrap(),
        );
        // Reverse the dword order.
        temp.reverse();

        // The Ml_Dsa87 signature is 4595 len but the reg is one byte longer
        let signature = secret_key
            .try_sign_with_seed(&[0u8; 32], temp.as_bytes(), &[])
            .unwrap();
        let signature_extended = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature);
            sig
        };
        self.mldsa_signature = words_from_bytes_le(&signature_extended);
    }

    fn verify(&mut self) {
        // Get message data based on streaming mode
        let message = if self.mldsa_ctrl.reg.is_set(MlDsaControl::STREAM_MSG) {
            // Use the streamed message
            self.streamed_msg.as_slice()
        } else {
            // Unlike ECC, no dword endianness reversal is needed.
            // Use the fixed message register
            &bytes_from_words_le(&self.mldsa_msg)
        };

        let public_key = {
            let key_bytes = bytes_from_words_le(&self.mldsa_pubkey);
            PublicKey::try_from_bytes(key_bytes).unwrap()
        };

        let signature = bytes_from_words_le(&self.mldsa_signature);

        // Get context if specified
        let mut ctx: Vec<u8> = Vec::new();
        if self.mldsa_ctrl.reg.is_set(MlDsaControl::STREAM_MSG) {
            // Make sure we're not still expecting more message data
            assert!(!self.mldsa_status.reg.is_set(MlDsaStatus::MSG_STREAM_READY));
            let ctx_size = self.mldsa_ctx_config.reg.read(MlDsaCtxConfig::CTX_SIZE) as usize;
            if ctx_size > 0 {
                // Convert context array to bytes using functional approach
                let ctx_bytes: Vec<u8> = self
                    .mldsa_ctx
                    .iter()
                    .flat_map(|word| word.to_le_bytes().to_vec())
                    .collect();
                ctx = ctx_bytes[..ctx_size].to_vec();
            }
        }

        let success = public_key.verify(message, &signature[..SIG_LEN].try_into().unwrap(), &ctx);

        if success {
            self.mldsa_verify_res
                .copy_from_slice(&self.mldsa_signature[..(ML_DSA87_VERIFICATION_SIZE_BYTES / 4)]);
        } else {
            self.mldsa_verify_res = [0u32; ML_DSA87_VERIFICATION_SIZE_BYTES / 4];
        }
    }

    fn op_complete(&mut self) {
        match self.mldsa_ctrl.reg.read_as_enum(MlDsaControl::CTRL) {
            Some(MlDsaControl::CTRL::Value::KEYGEN) => self.gen_key(),
            Some(MlDsaControl::CTRL::Value::SIGNING) => {
                self.sign(true);
            }
            Some(MlDsaControl::CTRL::Value::VERIFYING) => self.verify(),
            Some(MlDsaControl::CTRL::Value::KEYGEN_AND_SIGN) => {
                if self.mldsa_ctrl.reg.is_set(MlDsaControl::PCR_SIGN) {
                    self.pcr_digest_sign();
                } else {
                    self.gen_key();
                    self.sign(false);
                }
            }
            _ => panic!("Invalid value in ML-DSA Control"),
        }

        self.mldsa_status.reg.modify(
            MlDsaStatus::READY::SET
                + MlDsaStatus::VALID::SET
                + MlDsaStatus::MSG_STREAM_READY::CLEAR,
        );
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
            self.mldsa_seed = temp;
        }

        seed_read_result
    }

    fn seed_read_complete(&mut self) {
        let key_id = self
            .kv_mldsa_seed_rd_ctrl
            .reg
            .read(KvRdSeedCtrl::READ_ENTRY);
        let seed_read_result = self.read_seed_from_keyvault(key_id, false);

        self.kv_mldsa_seed_rd_status.reg.modify(
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
    pub fn on_write_mldsa_msg(
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
        if !self.mldsa_ctrl.reg.is_set(MlDsaControl::STREAM_MSG) {
            self.mldsa_msg[index] = val;
            return Ok(());
        }

        // We're in streaming mode
        assert!(index == 0);

        // Streaming message mode - handle write to index 0
        let strobe_value = self.mldsa_msg_strobe.reg.read(MlDsaStrobe::STROBE);
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
            self.mldsa_msg_strobe
                .reg
                .write(MlDsaStrobe::STROBE.val(0xF));

            // If this was the last segment, start processing
            self.mldsa_status
                .reg
                .modify(MlDsaStatus::MSG_STREAM_READY::CLEAR);
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

    const OFFSET_MLDSA_NAME0: RvAddr = 0x0;
    const OFFSET_MLDSA_NAME1: RvAddr = 0x4;
    const OFFSET_MLDSA_VERSION0: RvAddr = 0x8;
    const OFFSET_MLDSA_VERSION1: RvAddr = 0xC;
    const OFFSET_MLDSA_CONTROL: RvAddr = 0x10;
    const OFFSET_MLDSA_STATUS: RvAddr = 0x14;
    const OFFSET_MLDSA_SEED: RvAddr = 0x58;
    const OFFSET_MLDSA_SIGN_RND: RvAddr = 0x78;
    const OFFSET_MLDSA_MSG: RvAddr = 0x98;
    const OFFSET_MLDSA_MSG_STROBE: RvAddr = 0x158;
    const OFFSET_MLDSA_CTX_CONFIG: RvAddr = 0x15c;
    const OFFSET_MLDSA_CTX: RvAddr = 0x160;
    const OFFSET_MLDSA_PK: RvAddr = 0x1000;
    const OFFSET_MLDSA_SIGNATURE: RvAddr = 0x2000;
    const OFFSET_MLDSA_PRIVKEY_IN: RvAddr = 0x6000;
    const OFFSET_MLDSA_KV_RD_SEED_CONTROL: RvAddr = 0x8000;
    const OFFSET_MLDSA_KV_RD_SEED_STATUS: RvAddr = 0x8004;

    #[test]
    fn test_mldsa_name() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        let name0 = ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_NAME0).unwrap();
        let name0 = String::from_utf8_lossy(&name0.to_be_bytes()).to_string();
        assert_eq!(name0, "secp");

        let name1 = ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_be_bytes()).to_string();
        assert_eq!(name1, "-384");
    }

    #[test]
    fn test_mldsa_version() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        let version0 = ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_mldsa_control() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);
        assert_eq!(
            ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_CONTROL).unwrap(),
            0
        );
    }

    #[test]
    fn test_mldsa_status() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);
        assert_eq!(ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(), 1);
    }

    #[test]
    fn test_mldsa_gen_key() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SEED + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_MLDSA_CONTROL,
                MlDsaControl::CTRL::KEYGEN.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let public_key = bytes_from_words_le(&ml_dsa87.mldsa_pubkey);

        let mut rng = SeedOnlyRng::new(seed);
        let (pk_from_lib, _sk) = try_keygen_with_rng(&mut rng).unwrap();
        let pk_from_lib = pk_from_lib.into_bytes();
        assert_eq!(&public_key, &pk_from_lib);
    }

    #[test]
    fn test_mldsa_sign_from_seed() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SEED + (i * 4) as RvAddr,
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
                    OFFSET_MLDSA_MSG + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        let sign_rnd = rand::thread_rng().gen::<[u8; 32]>();

        for (i, chunk) in sign_rnd.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SIGN_RND + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_MLDSA_CONTROL,
                MlDsaControl::CTRL::KEYGEN_AND_SIGN.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let signature = bytes_from_words_le(&ml_dsa87.mldsa_signature);

        let mut keygen_rng = SeedOnlyRng::new(seed);
        let (_pk, sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();
        let test_signature = sk.try_sign_with_seed(&[0u8; 32], &msg, &[]).unwrap();
        let signature_extended = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&test_signature);
            sig
        };

        assert_eq!(&signature[..SIG_LEN], &signature_extended[..SIG_LEN]);
    }

    #[test]
    fn test_mldsa_verify() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        let msg: [u8; 64] = {
            let part0 = rand::thread_rng().gen::<[u8; 32]>();
            let part1 = rand::thread_rng().gen::<[u8; 32]>();
            let concat: Vec<u8> = part0.iter().chain(part1.iter()).copied().collect();
            concat.as_slice().try_into().unwrap()
        };

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let mut keygen_rng = SeedOnlyRng::new(seed);
        let (pk_from_lib, sk_from_lib) = try_keygen_with_rng(&mut keygen_rng).unwrap();
        let signature_from_lib = sk_from_lib
            .try_sign_with_seed(&[0u8; 32], &msg, &[])
            .unwrap();

        for (i, chunk) in msg.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_MSG + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        let pk_for_hw = pk_from_lib.into_bytes();
        for (i, chunk) in pk_for_hw.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_PK + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Good signature
        let sig_for_hw = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature_from_lib);
            sig
        };

        for (i, chunk) in sig_for_hw.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SIGNATURE + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_MLDSA_CONTROL,
                MlDsaControl::CTRL::VERIFYING.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let result = bytes_from_words_le(&ml_dsa87.mldsa_verify_res);
        let sig_for_comp = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature_from_lib);
            sig
        };
        assert_eq!(result, &sig_for_comp[..ML_DSA87_VERIFICATION_SIZE_BYTES]);

        // Bad signature
        let mut rng = rand::thread_rng();
        let mut signature = [0u8; SIG_LEN + 1];

        rng.fill(&mut signature[..64]);

        for (i, chunk) in signature.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SIGNATURE + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        ml_dsa87
            .write(
                RvSize::Word,
                OFFSET_MLDSA_CONTROL,
                MlDsaControl::CTRL::VERIFYING.into(),
            )
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        let result = bytes_from_words_le(&ml_dsa87.mldsa_verify_res);
        assert_ne!(
            result,
            &sig_for_comp[sig_for_comp.len() - ML_DSA87_VERIFICATION_SIZE_BYTES..]
        );
    }

    #[test]
    fn test_mldsa_gen_key_kv_seed() {
        // Test for getting the seed from the key-vault.
        for key_id in 0..KeyVault::KEY_COUNT {
            let clock = Clock::new();
            let seed = rand::thread_rng().gen::<[u8; 32]>();
            let mut keygen_rng = SeedOnlyRng::new(seed);
            let (pk, _sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();
            let pk_from_lib = pk.into_bytes();

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
            let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

            // We expect the output to match the generated random seed.
            // Write a different seed first to make sure the Kv seed is used
            let seed = [0xABu8; 32];
            for (i, chunk) in seed.chunks_exact(4).enumerate() {
                ml_dsa87
                    .write(
                        RvSize::Word,
                        OFFSET_MLDSA_SEED + (i * 4) as RvAddr,
                        u32::from_le_bytes(chunk.try_into().unwrap()),
                    )
                    .unwrap();
            }

            // Instruct seed to be read from key-vault.
            let seed_ctrl = InMemoryRegister::<u32, KvRdSeedCtrl::Register>::new(0);
            seed_ctrl.modify(KvRdSeedCtrl::READ_ENTRY.val(key_id) + KvRdSeedCtrl::READ_EN.val(1));

            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_KV_RD_SEED_CONTROL,
                    seed_ctrl.get(),
                )
                .unwrap();

            // Wait for ml_dsa87 periph to retrieve the seed from key-vault.
            loop {
                let seed_read_status = InMemoryRegister::<u32, KvRdSeedStatus::Register>::new(
                    ml_dsa87
                        .read(RvSize::Word, OFFSET_MLDSA_KV_RD_SEED_STATUS)
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
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_CONTROL,
                    MlDsaControl::CTRL::KEYGEN.into(),
                )
                .unwrap();

            loop {
                let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                    ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
                );
                if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                    break;
                }
                clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
            }

            let public_key = bytes_from_words_le(&ml_dsa87.mldsa_pubkey);
            let pub_key_comp = pk_from_lib;
            assert_eq!(&public_key, &pub_key_comp);
        }
    }

    #[test]
    fn test_mldsa_sign_var_from_seed() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        // Generate seed and write to hardware
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SEED + (i * 4) as RvAddr,
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
                    OFFSET_MLDSA_SIGN_RND + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Save public key for later verification
        let mut keygen_rng = SeedOnlyRng::new(seed);
        let (pk, _sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();

        // Enable key generation and signing with streaming message mode in one operation
        let ctrl_value =
            MlDsaControl::CTRL::KEYGEN_AND_SIGN.value | MlDsaControl::STREAM_MSG::SET.value;
        ml_dsa87
            .write(RvSize::Word, OFFSET_MLDSA_CONTROL, ctrl_value)
            .unwrap();

        // Wait for MSG_STREAM_READY status
        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::MSG_STREAM_READY) {
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
            ml_dsa87
                .write(RvSize::Word, OFFSET_MLDSA_MSG, word)
                .unwrap();
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
            .write(RvSize::Word, OFFSET_MLDSA_MSG_STROBE, last_strobe)
            .unwrap();

        // Write last dword, even if no remainder (using 0)
        let mut last_word = 0_u32;
        let mut last_bytes = last_word.to_le_bytes();
        last_bytes[..remainder.len()].copy_from_slice(remainder);
        last_word = u32::from_le_bytes(last_bytes);
        ml_dsa87
            .write(RvSize::Word, OFFSET_MLDSA_MSG, last_word)
            .unwrap();

        // Wait for operation to complete
        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        // Get the signature
        let signature = bytes_from_words_le(&ml_dsa87.mldsa_signature);

        // Verify the signature using the crypto library
        let result = pk.verify(&msg_short, &signature[..SIG_LEN].try_into().unwrap(), &[]);
        assert!(result, "Signature verification failed");
    }

    #[test]
    fn test_mldsa_sign_var_with_streaming_and_context() {
        let clock = Clock::new();
        let key_vault = KeyVault::new();
        let sha512 = HashSha512::new(&clock, key_vault.clone());

        let mut ml_dsa87 = Abr::new(&clock, key_vault, sha512);

        // Generate a private key directly
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let mut keygen_rng = SeedOnlyRng::new(seed);
        let (pk, sk) = try_keygen_with_rng(&mut keygen_rng).unwrap();
        let private_key = sk.into_bytes();

        // Write the private key to hardware
        for (i, chunk) in private_key.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_PRIVKEY_IN + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Create a larger message (more than 64 bytes)
        let msg_large: Vec<u8> = (0..100).map(|_| rand::thread_rng().gen::<u8>()).collect();

        // Generate context data
        let ctx_data: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
        let ctx_size = ctx_data.len();

        // Write context data - need to use little endian format for hardware
        for (i, chunk) in ctx_data.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_CTX + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Handle any remaining bytes (if ctx_data length is not a multiple of 4)
        let remainder = ctx_data.chunks_exact(4).remainder();
        if !remainder.is_empty() {
            let mut last_word = 0_u32;
            let mut last_bytes = last_word.to_le_bytes();
            last_bytes[..remainder.len()].copy_from_slice(remainder);
            last_word = u32::from_le_bytes(last_bytes);
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_CTX + (ctx_data.len() / 4 * 4) as RvAddr,
                    last_word,
                )
                .unwrap();
        }

        // Set context size in config register
        ml_dsa87
            .write(RvSize::Word, OFFSET_MLDSA_CTX_CONFIG, ctx_size as u32)
            .unwrap();

        // Generate random values for sign_rnd
        let sign_rnd = rand::thread_rng().gen::<[u8; 32]>();
        for (i, chunk) in sign_rnd.chunks_exact(4).enumerate() {
            ml_dsa87
                .write(
                    RvSize::Word,
                    OFFSET_MLDSA_SIGN_RND + (i * 4) as RvAddr,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                )
                .unwrap();
        }

        // Start signing operation with streaming mode
        let ctrl_value = MlDsaControl::CTRL::SIGNING.value | MlDsaControl::STREAM_MSG::SET.value;
        ml_dsa87
            .write(RvSize::Word, OFFSET_MLDSA_CONTROL, ctrl_value)
            .unwrap();

        // Wait for MSG_STREAM_READY status
        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::MSG_STREAM_READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        // Stream the message in chunks
        let dwords = msg_large.chunks_exact(std::mem::size_of::<u32>());
        let remainder = dwords.remainder();

        // Process full dwords
        for chunk in dwords {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            ml_dsa87
                .write(RvSize::Word, OFFSET_MLDSA_MSG, word)
                .unwrap();
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
            .write(RvSize::Word, OFFSET_MLDSA_MSG_STROBE, last_strobe)
            .unwrap();

        // Write last dword, even if no remainder (using 0)
        let mut last_word = 0_u32;
        let mut last_bytes = last_word.to_le_bytes();
        last_bytes[..remainder.len()].copy_from_slice(remainder);
        last_word = u32::from_le_bytes(last_bytes);
        ml_dsa87
            .write(RvSize::Word, OFFSET_MLDSA_MSG, last_word)
            .unwrap();

        // Wait for operation to complete
        loop {
            let status = InMemoryRegister::<u32, MlDsaStatus::Register>::new(
                ml_dsa87.read(RvSize::Word, OFFSET_MLDSA_STATUS).unwrap(),
            );

            if status.is_set(MlDsaStatus::VALID) && status.is_set(MlDsaStatus::READY) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut ml_dsa87);
        }

        // Get the signature
        let signature = bytes_from_words_le(&ml_dsa87.mldsa_signature);

        // Verify the signature using the crypto library
        let result = pk.verify(
            &msg_large,
            &signature[..SIG_LEN].try_into().unwrap(),
            &ctx_data,
        );
        assert!(result, "Signature verification with context failed");

        // Now verify that it fails with incorrect context
        let wrong_ctx = Vec::from([0u8; 16]);
        let result_wrong_ctx = pk.verify(
            &msg_large,
            &signature[..SIG_LEN].try_into().unwrap(),
            &wrong_ctx,
        );
        assert!(
            !result_wrong_ctx,
            "Signature shouldn't verify with wrong context"
        );
    }
}
