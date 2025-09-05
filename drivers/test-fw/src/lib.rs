// Licensed under the Apache-2.0 license

#![no_std]

use caliptra_drivers::{
    dma::MCU_SRAM_OFFSET, Aes, Array4x16, AxiAddr, DeobfuscationEngine, Dma, DmaWriteOrigin,
    DmaWriteTransaction, Ecc384PubKey, Hmac, HmacData, HmacKey, HmacMode, KeyId, KeyReadArgs,
    KeyUsage, KeyWriteArgs, SocIfc, Trng,
};
use caliptra_kat::CaliptraResult;
use caliptra_registers::{
    aes::AesReg, aes_clp::AesClpReg, csrng::CsrngReg, doe::DoeReg, entropy_src::EntropySrcReg,
    hmac::HmacReg, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};

/// Code shared between the caliptra-drivers integration_test.rs (running on the
/// host) and the test binaries (running inside the hw-model).
use core::fmt::Debug;

use itertools::Itertools;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const DOE_TEST_IV: [u32; 4] = [0xc6b407a2, 0xd119a37d, 0xb7a5bdeb, 0x26214aed];

pub const DOE_TEST_HMAC_KEY: [u32; 12] = [
    0x15f4a700, 0xd79bd4e1, 0x0f92b714, 0x3a38d570, 0x7cf2ebb4, 0xab47cc6e, 0xa4827e80, 0x32e6d3b4,
    0xc6879874, 0x0aa49a0f, 0x4e740e9c, 0x2c9f9aad,
];

/// Constant for OCP LOCK tests.
pub const ENCRYPTED_MEK: [u8; 64] = [
    0xd7, 0x92, 0x11, 0xc4, 0x11, 0x8b, 0x51, 0x65, 0x77, 0x1c, 0xfe, 0x91, 0xb6, 0xcb, 0xd4, 0xd5,
    0xe2, 0x5a, 0xba, 0x50, 0x89, 0x8a, 0xa9, 0x8b, 0x37, 0xee, 0xe8, 0x81, 0x4b, 0x7b, 0xe1, 0x69,
    0x71, 0x38, 0x98, 0x10, 0x71, 0x6b, 0x58, 0xf5, 0x0f, 0x94, 0x99, 0xe3, 0x71, 0x44, 0x98, 0x26,
    0x8b, 0x0e, 0x5e, 0x03, 0xbe, 0xfa, 0x8f, 0xbf, 0x36, 0x0b, 0x77, 0x97, 0x08, 0xfd, 0x36, 0x01,
];

/// Constant for OCP LOCK tests.
pub const PLAINTEXT_MEK: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

#[derive(IntoBytes, KnownLayout, Immutable, Clone, Copy, Default, Eq, PartialEq, FromBytes)]
#[repr(C)]
pub struct DoeTestResults {
    /// HMAC result of the UDS as key, and b"Hello world!" as data.
    pub hmac_uds_as_key_out_pub: Ecc384PubKey,

    /// HMAC result of HMAC_KEY as key, and UDS as data.
    pub hmac_uds_as_data_out_pub: Ecc384PubKey,

    // HMAC result of of the field entropy (including padding) as key, and
    // b"Hello world" as data.
    pub hmac_field_entropy_as_key_out_pub: Ecc384PubKey,

    /// HMAC result of HMAC_KEY as key, and field entropy (excluding padding) as
    /// data.
    pub hmac_field_entropy_as_data_out_pub: Ecc384PubKey,
}
impl Debug for DoeTestResults {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DoeTestResults")
            .field("hmac_uds_as_key_out_pub", &self.hmac_uds_as_key_out_pub)
            .field("hmac_uds_as_data_out_pub", &self.hmac_uds_as_data_out_pub)
            .field(
                "hmac_field_entropy_as_key_out_pub",
                &self.hmac_field_entropy_as_key_out_pub,
            )
            .field(
                "hmac_field_entropy_as_data_out_pub",
                &self.hmac_field_entropy_as_data_out_pub,
            )
            .finish()
    }
}

pub struct TestRegisters {
    pub soc: SocIfc,
    pub hmac: Hmac,
    pub aes: Aes,
    pub trng: Trng,
    pub dma: Dma,
    pub doe: DeobfuscationEngine,
}

impl Default for TestRegisters {
    fn default() -> Self {
        let soc_ifc = unsafe { SocIfcReg::new() };
        let soc = SocIfc::new(soc_ifc);
        let hmac = unsafe { Hmac::new(HmacReg::new()) };
        let aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
        let trng = unsafe {
            Trng::new(
                CsrngReg::new(),
                EntropySrcReg::new(),
                SocIfcTrngReg::new(),
                &SocIfcReg::new(),
            )
            .unwrap()
        };
        let dma = Dma::default();
        let doe = unsafe { DeobfuscationEngine::new(DoeReg::new()) };

        Self {
            soc,
            hmac,
            aes,
            trng,
            dma,
            doe,
        }
    }
}

// OCP LOCK helpers

/// Checks KV rules enforced by OCP LOCK hardware.
pub fn hmac_kv_sequence_check<T: Iterator<Item = u8> + Clone>(
    input_key_ids: T,
    output_key_ids: T,
    populate_kv: bool,
    check_result: impl Fn(CaliptraResult<()>),
) {
    let mut test_regs = TestRegisters::default();

    for (input_kv, output_kv) in input_key_ids.cartesian_product(output_key_ids) {
        let input = KeyId::try_from(input_kv).unwrap();
        let output = KeyId::try_from(output_kv).unwrap();
        let kv_filter_set = [KeyId::KeyId16, KeyId::KeyId23];

        // Only populate the KV in the first test.
        if populate_kv {
            populate_slot(
                &mut test_regs.hmac,
                &mut test_regs.trng,
                input,
                KeyUsage::default().set_hmac_key_en(),
            )
            .unwrap();
        }

        // Skip overwriting MDK and MEK. They have special rules exercised elsewhere.
        if kv_filter_set.contains(&input) || kv_filter_set.contains(&output) {
            continue;
        }

        check_result(hmac_helper(
            input,
            output,
            &mut test_regs.hmac,
            &mut test_regs.trng,
        ));
    }
}

/// Populates a KV slot with a known constant.
pub fn populate_slot(
    hmac: &mut Hmac,
    trng: &mut Trng,
    slot: KeyId,
    usage: KeyUsage,
) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Array4x16(&Array4x16::default()),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(slot, usage).into(),
        HmacMode::Hmac512,
    )
}

/// Performs a HMAC from a KV to another KV.
pub fn hmac_helper(
    input: KeyId,
    output: KeyId,
    hmac: &mut Hmac,
    trng: &mut Trng,
) -> CaliptraResult<()> {
    hmac.hmac(
        HmacKey::Key(KeyReadArgs::new(input)),
        HmacData::from(&[0]),
        trng,
        KeyWriteArgs::new(
            output,
            KeyUsage::default().set_aes_key_en().set_hmac_key_en(),
        )
        .into(),
        HmacMode::Hmac512,
    )
}

/// Verifies the OCP LOCK KV release flow
pub fn kv_release(test_regs: &mut TestRegisters) {
    let mcu_sram_base_addr = test_regs.soc.mci_base_addr() + MCU_SRAM_OFFSET;
    let fuse_addr = test_regs.soc.ocp_lock_get_key_release_addr();
    let kv_release_size = test_regs.soc.ocp_lock_get_key_size();

    // We expect the MCU TEST ROM to point the OCP LOCK key release to the start of MCU SRAM.
    assert_eq!(mcu_sram_base_addr, fuse_addr);

    // We expect the MCU TEST ROM to set the OCP LOCK key release size to 0x40.
    assert_eq!(0x40, kv_release_size);

    let write_addr = AxiAddr::from(fuse_addr);
    let write_transaction = DmaWriteTransaction {
        write_addr,
        fixed_addr: false,
        length: kv_release_size,
        origin: DmaWriteOrigin::KeyVault,
        aes_mode: false,
        aes_gcm: false,
    };
    test_regs.dma.setup_dma_write(write_transaction, 0);
    test_regs.dma.wait_for_dma_complete();

    let mut output = [0; 16];
    test_regs
        .dma
        .read_buffer(AxiAddr::from(fuse_addr), &mut output);
    let output = <[u8; 64]>::read_from_bytes(output.as_bytes()).unwrap();
    assert_eq!(output, PLAINTEXT_MEK);
}
