// Licensed under the Apache-2.0 license

// The IV fed to the DOE when the ROM deobfuscates the UDS seed (as passed to doe registers)
pub const DOE_UDS_IV: [u32; 4] = [0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e];

// The IV fed to the DOE when the ROM deobfuscates the field entropy seed (as passed to doe registers)
pub const DOE_FE_IV: [u32; 4] = [0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e];

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
        use zerocopy::AsBytes;

        fn swap_word_bytes(words: &[u32]) -> Vec<u32> {
            words.iter().map(|word| word.swap_bytes()).collect()
        }
        fn swap_word_bytes_inplace(words: &mut [u32]) {
            for word in words.iter_mut() {
                *word = word.swap_bytes()
            }
        }
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
