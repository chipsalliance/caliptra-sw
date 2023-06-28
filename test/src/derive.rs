// Licensed under the Apache-2.0 license

/// Caliptra key derivation logic implemented independently from the hardware /
/// firmware, for use in end-to-end test-cases.
///
/// DO NOT REFACTOR THIS FILE TO RE-USE CODE FROM OTHER PARTS OF CALIPTRA
use caliptra_hw_model_types::SecurityState;
use openssl::{
    pkey::{PKey, Public},
    sha::sha384,
};
use zerocopy::{transmute, AsBytes};

#[cfg(test)]
use caliptra_hw_model_types::DeviceLifecycle;

use crate::{
    crypto::{derive_ecdsa_key, hmac384, hmac384_drbg_keygen},
    swap_word_bytes, swap_word_bytes_inplace,
};

// The IV fed to the DOE when the ROM deobfuscates the UDS seed (as passed to doe registers)
pub const DOE_UDS_IV: [u32; 4] = [0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e];

// The IV fed to the DOE when the ROM deobfuscates the field entropy seed (as passed to doe registers)
pub const DOE_FE_IV: [u32; 4] = [0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e];

/// Key used to derive the Composite Device Identity(CDI) for Initial Device Identity (IDEVID)
pub const IDEVID_CDI_KEY: [u32; 12] = [
    0x5bd3c575, 0x2ba359a2, 0x696c97f0, 0x56f594a3, 0x6130c106, 0xedcddddb, 0xd01044f6, 0xf2d302d8,
    0xeeefec92, 0xa0ebfaa0, 0x36bf2d20, 0x0535df6f,
];

pub const ECDSA_KEYGEN_NONCE: [u32; 12] = [0u32; 12];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoeInput {
    // The DOE obfuscation key, as wired to caliptra_top
    pub doe_obf_key: [u32; 8],

    // The DOE initialization vector, as given to the DOE_IV register by the
    // firmware when decrypting the UDS.
    pub doe_uds_iv: [u32; 4],

    // The DOE initialization vector, as given to the DOE_IV register by the
    // firmware when decrypting the field entropy.
    pub doe_fe_iv: [u32; 4],

    // The UDS seed, as stored in the fuses
    pub uds_seed: [u32; 12],

    // The field entropy, as stored in the fuses
    pub field_entropy_seed: [u32; 8],

    // The initial value of key-vault entry words at startup
    pub keyvault_initial_word_value: u32,
}
impl Default for DoeInput {
    fn default() -> Self {
        Self {
            doe_obf_key: caliptra_hw_model_types::DEFAULT_CPTRA_OBF_KEY,

            doe_uds_iv: DOE_UDS_IV,
            doe_fe_iv: DOE_FE_IV,

            uds_seed: caliptra_hw_model_types::DEFAULT_UDS_SEED,
            field_entropy_seed: caliptra_hw_model_types::DEFAULT_FIELD_ENTROPY,

            // in debug-locked mode, this defaults to 0
            keyvault_initial_word_value: 0x0000_0000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoeOutput {
    // The decrypted UDS as stored in the key vault
    pub uds: [u32; 12],

    // The decrypted field entropy as stored in the key vault (with padding)
    pub field_entropy: [u32; 12],
}
impl DoeOutput {
    /// A standalone implementation of the cryptographic operations necessary to
    /// generate the expected DOE output from fuse values and silicon secrets.
    pub fn generate(input: &DoeInput) -> Self {
        use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};

        fn aes256_decrypt_blocks(key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
            let cipher = Cipher::aes_256_cbc();
            let mut ctx = CipherCtx::new().unwrap();
            ctx.decrypt_init(Some(cipher), Some(key), Some(iv)).unwrap();
            ctx.set_padding(false);
            let mut result = vec![];
            ctx.cipher_update_vec(input, &mut result).unwrap();
            ctx.cipher_final_vec(&mut result).unwrap();
            result
        }

        let mut result = Self {
            uds: [0_u32; 12],

            // After reset, the key-vault registers are filled with a particular
            // word, depending on the debug-locked mode.  The field entropy only
            // takes up 8 of the 12 words, so the 4 remaining words keep their
            // original value (their contents are used when the key-vault entry is
            // used as a HMAC key, but not when used as HMAC
            // data).
            field_entropy: [input.keyvault_initial_word_value; 12],
        };

        result
            .uds
            .as_bytes_mut()
            .copy_from_slice(&aes256_decrypt_blocks(
                swap_word_bytes(&input.doe_obf_key).as_bytes(),
                swap_word_bytes(&input.doe_uds_iv).as_bytes(),
                swap_word_bytes(&input.uds_seed).as_bytes(),
            ));
        swap_word_bytes_inplace(&mut result.uds);

        result.field_entropy[0..8]
            .as_bytes_mut()
            .copy_from_slice(&aes256_decrypt_blocks(
                swap_word_bytes(&input.doe_obf_key).as_bytes(),
                swap_word_bytes(&input.doe_fe_iv).as_bytes(),
                swap_word_bytes(&input.field_entropy_seed).as_bytes(),
            ));
        swap_word_bytes_inplace(&mut result.field_entropy);

        result
    }
}

#[test]
fn test_doe_output() {
    let output = DoeOutput::generate(&crate::derive::DoeInput {
        doe_obf_key: [
            0x4f0b1c83, 0xb231c258, 0x7759c92b, 0xf22ac83f, 0x97c4e162, 0x3580ca0f, 0xb79529c2,
            0x8a340dfd,
        ],
        doe_uds_iv: [0x455ba825, 0x45e16ca6, 0xf97d1f86, 0xb3718021],
        doe_fe_iv: [0x848049fb, 0x4951e297, 0xbe60edba, 0xa24b77bb],
        uds_seed: [
            0x86c65f40, 0x04d45413, 0x5041da9a, 0x8580ec9a, 0xc7007ee6, 0xceb4a4b8, 0xce485f47,
            0xbf6976b8, 0xc906de7b, 0xb0cd2dce, 0x8d2b8eed, 0xa537255f,
        ],
        field_entropy_seed: [
            0x8531a3db, 0xc1725f07, 0x05f5a301, 0x047c1e27, 0xd0f18efa, 0x6a33e9d2, 0x3827ead4,
            0x690aaee2,
        ],
        keyvault_initial_word_value: 0x5555_5555,
    });
    assert_eq!(
        output,
        DoeOutput {
            uds: [
                0x92121902, 0xbefa4497, 0x3d36f1db, 0x485a3ed6, 0x2d7b2eb3, 0x53929c34, 0x879e64ef,
                0x6b25eaee, 0x0029fa17, 0x92f7f8da, 0x3b2ac8db, 0x21411551,
            ],
            field_entropy: [
                0xdbca1cfa, 0x149c0355, 0x7ee48ddb, 0xb022238b, 0x057c9b49, 0x6c9e5b66, 0x119bcff5,
                0xe82d50e0, 0x55555555, 0x55555555, 0x55555555, 0x55555555,
            ],
        }
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IDevId {
    pub cdi: [u32; 12],

    pub priv_key: [u32; 12],
}
impl IDevId {
    pub fn derive(doe_output: &DoeOutput) -> Self {
        let mut cdi: [u32; 12] = transmute!(hmac384(
            swap_word_bytes(&IDEVID_CDI_KEY).as_bytes(),
            swap_word_bytes(&doe_output.uds).as_bytes(),
        ));
        swap_word_bytes_inplace(&mut cdi);

        let mut priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            swap_word_bytes(&cdi).as_bytes(),
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut priv_key);
        Self { cdi, priv_key }
    }

    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.priv_key)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    }
}

#[test]
fn test_idevid() {
    let idevid = IDevId::derive(&DoeOutput {
        uds: [
            0x92121902, 0xbefa4497, 0x3d36f1db, 0x485a3ed6, 0x2d7b2eb3, 0x53929c34, 0x879e64ef,
            0x6b25eaee, 0x0029fa17, 0x92f7f8da, 0x3b2ac8db, 0x21411551,
        ],
        field_entropy: [
            0xdbca1cfa, 0x149c0355, 0x7ee48ddb, 0xb022238b, 0x057c9b49, 0x6c9e5b66, 0x119bcff5,
            0xe82d50e0, 0x55555555, 0x55555555, 0x55555555, 0x55555555,
        ],
    });
    assert_eq!(
        idevid,
        IDevId {
            cdi: [
                0x08ca3379, 0x6c481a99, 0xd59530a4, 0xd00146a8, 0x1410a0f8, 0x7d4da304, 0x85b3f8a6,
                0xe6f4467e, 0x8c6bab77, 0xd8456d3d, 0x8cacf5c6, 0x188399e5,
            ],
            priv_key: [
                0x73e2bcd3, 0x9ffd7448, 0xea3971b9, 0x8954fcc4, 0x48776771, 0x6dbeccce, 0x8efc5740,
                0x203afa4d, 0xbf143779, 0x760a45f7, 0x1db6d76a, 0xd9da3186,
            ],
        }
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LDevId {
    pub cdi: [u32; 12],

    pub priv_key: [u32; 12],
}
impl LDevId {
    pub fn derive(doe_output: &DoeOutput) -> Self {
        let idevid = IDevId::derive(doe_output);
        let mut cdi: [u32; 12] = transmute!(hmac384(
            swap_word_bytes(&idevid.cdi).as_bytes(),
            swap_word_bytes(&doe_output.field_entropy[0..8]).as_bytes(),
        ));
        swap_word_bytes_inplace(&mut cdi);

        let mut priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            swap_word_bytes(&cdi).as_bytes(),
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut priv_key);
        Self { cdi, priv_key }
    }

    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.priv_key)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    }
}

#[test]
fn test_ldevid() {
    let ldevid = LDevId::derive(&DoeOutput {
        uds: [
            0x92121902, 0xbefa4497, 0x3d36f1db, 0x485a3ed6, 0x2d7b2eb3, 0x53929c34, 0x879e64ef,
            0x6b25eaee, 0x0029fa17, 0x92f7f8da, 0x3b2ac8db, 0x21411551,
        ],
        field_entropy: [
            0xdbca1cfa, 0x149c0355, 0x7ee48ddb, 0xb022238b, 0x057c9b49, 0x6c9e5b66, 0x119bcff5,
            0xe82d50e0, 0x55555555, 0x55555555, 0x55555555, 0x55555555,
        ],
    });
    assert_eq!(
        ldevid,
        LDevId {
            cdi: [
                0x0e7b8a15, 0x0cc1476b, 0x28d395d9, 0x233f9f05, 0x670bd435, 0x96758224, 0xd3dd5081,
                0x3da916e5, 0x94f2b09e, 0x257f151d, 0x261ade90, 0x73a9b3fb,
            ],
            priv_key: [
                0xd3ef1bff, 0x0b52919d, 0xe084ee81, 0x47544a50, 0xf7ff4c2d, 0x18038a26, 0x0695a0b1,
                0x8103e7f4, 0x30651311, 0xc5658261, 0xe30ae241, 0xa8d9ad51,
            ],
        }
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pcr0Input {
    pub security_state: SecurityState,
    pub fuse_anti_rollback_disable: bool,
    pub vendor_pub_key_hash: [u32; 12],
    pub owner_pub_key_hash: [u32; 12],
    pub vendor_pub_key_index: u32,
    pub fmc_digest: [u32; 12],
    pub fmc_svn: u32,
    pub fmc_fuse_svn: u32,
}
impl Pcr0Input {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pcr0(pub [u32; 12]);
impl Pcr0 {
    pub fn derive(input: &Pcr0Input) -> Self {
        let mut value = [0u8; 48];
        let extend = |value: &mut [u8; 48], buf: &[u8]| {
            *value = sha384(&[value.as_slice(), buf].concat());
        };

        extend(&mut value, &[input.security_state.device_lifecycle() as u8]);
        extend(&mut value, &[input.security_state.debug_locked() as u8]);
        extend(&mut value, &[input.fuse_anti_rollback_disable as u8]);
        extend(
            &mut value,
            swap_word_bytes(&input.vendor_pub_key_hash).as_bytes(),
        );
        extend(
            &mut value,
            swap_word_bytes(&input.owner_pub_key_hash).as_bytes(),
        );
        extend(&mut value, &[input.vendor_pub_key_index as u8]);
        extend(&mut value, swap_word_bytes(&input.fmc_digest).as_bytes());
        extend(&mut value, &[input.fmc_svn as u8]);
        extend(&mut value, &[input.fmc_fuse_svn as u8]);

        let mut result: [u32; 12] = zerocopy::transmute!(value);
        swap_word_bytes_inplace(&mut result);
        Self(result)
    }
}

#[test]
fn test_derive_pcr0() {
    let pcr0 = Pcr0::derive(&Pcr0Input {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fuse_anti_rollback_disable: false,
        vendor_pub_key_hash: [
            0xed6dd78c, 0x131d69e2, 0x313b5d89, 0x0acd8e4e, 0xe2a1db67, 0x790721de, 0x01346b64,
            0x1c5cf3c9, 0xcf284e7d, 0x0e114d50, 0xe894b381, 0xd874ba94,
        ],
        owner_pub_key_hash: [
            0xdc1a27ef, 0x0c08201a, 0x8b066094, 0x118c29fe, 0x0bc2270e, 0xbd965c43, 0xf7b9a68d,
            0x8eaf37fa, 0x968ca8d8, 0x13b2920b, 0x3b88b026, 0xf2f0ebb0,
        ],
        vendor_pub_key_index: 0,
        fmc_digest: [
            0xe44ea855, 0x9fcf4063, 0xd3110a9a, 0xd60579db, 0xe03e6dd7, 0x4556cd98, 0xb2b941f5,
            0x1bb5034b, 0x587eea1f, 0xfcdd0e0f, 0x8e88d406, 0x3327a3fe,
        ],
        fmc_svn: 5,
        fmc_fuse_svn: 2,
    });
    assert_eq!(
        pcr0,
        Pcr0([
            0xd8f3fd4, 0x4698aaae, 0x7bacaf67, 0x714a8035, 0x9a8d3a51, 0x3fcde890, 0x8039f4c1,
            0x77f9d5a9, 0x77b8ecd5, 0xf29b3fa9, 0x30e25097, 0xe1d82b14,
        ],)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FmcAliasKey {
    // The FMC alias private key as stored in the key-vault
    pub priv_key: [u32; 12],
}
impl FmcAliasKey {
    pub fn derive(pcr0: &Pcr0, ldevid: &LDevId) -> Self {
        let mut priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            hmac384(
                swap_word_bytes(&ldevid.cdi).as_bytes(),
                swap_word_bytes(&pcr0.0).as_bytes()
            )
            .as_bytes(),
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut priv_key);
        Self { priv_key }
    }
    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.priv_key)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    }
}

#[test]
fn test_derive_fmc_alias_key() {
    let fmc_alias_key = FmcAliasKey::derive(
        &Pcr0([
            0xd8f3fd4, 0x4698aaae, 0x7bacaf67, 0x714a8035, 0x9a8d3a51, 0x3fcde890, 0x8039f4c1,
            0x77f9d5a9, 0x77b8ecd5, 0xf29b3fa9, 0x30e25097, 0xe1d82b14,
        ]),
        &LDevId {
            cdi: [
                0x0e7b8a15, 0x0cc1476b, 0x28d395d9, 0x233f9f05, 0x670bd435, 0x96758224, 0xd3dd5081,
                0x3da916e5, 0x94f2b09e, 0x257f151d, 0x261ade90, 0x73a9b3fb,
            ],
            priv_key: [
                0xd3ef1bff, 0x0b52919d, 0xe084ee81, 0x47544a50, 0xf7ff4c2d, 0x18038a26, 0x0695a0b1,
                0x8103e7f4, 0x30651311, 0xc5658261, 0xe30ae241, 0xa8d9ad51,
            ],
        },
    );
    assert_eq!(
        fmc_alias_key,
        FmcAliasKey {
            priv_key: [
                0xdf093069, 0x08c9812d, 0x4d081b82, 0xcd0927db, 0xf530e2da, 0xe0d41dba, 0x112e7925,
                0xa45d5af5, 0xf978a082, 0x275836f0, 0x013293d5, 0x53e6fe60,
            ],
        }
    );
}
