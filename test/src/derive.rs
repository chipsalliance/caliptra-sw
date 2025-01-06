// Licensed under the Apache-2.0 license

/// Caliptra key derivation logic implemented independently from the hardware /
/// firmware, for use in end-to-end test-cases.
///
/// DO NOT REFACTOR THIS FILE TO RE-USE CODE FROM OTHER PARTS OF CALIPTRA
use caliptra_api_types::SecurityState;
use caliptra_image_types::ImageManifest;
use openssl::{
    pkey::{PKey, Public},
    sha::{sha256, sha384},
};
use zerocopy::{transmute, AsBytes};

#[cfg(test)]
use caliptra_api_types::DeviceLifecycle;

use crate::{
    crypto::{self, derive_ecdsa_key, hmac384_drbg_keygen, hmac512, hmac512_kdf},
    swap_word_bytes, swap_word_bytes_inplace,
};

// The IV fed to the DOE when the ROM deobfuscates the UDS seed / field entropy (as passed to doe registers)
pub const DOE_IV: [u32; 4] = [0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e];

pub const ECDSA_KEYGEN_NONCE: [u32; 12] = [0u32; 12];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoeInput {
    // The DOE obfuscation key, as wired to caliptra_top
    pub doe_obf_key: [u32; 8],

    // The DOE initialization vector, as given to the DOE_IV register by the
    // firmware when decrypting the UDS and field entropy.
    pub doe_iv: [u32; 4],

    // The UDS seed, as stored in the fuses
    pub uds_seed: [u32; 16],

    // The field entropy, as stored in the fuses
    pub field_entropy_seed: [u32; 8],

    // The initial value of key-vault entry words at startup
    pub keyvault_initial_word_value: u32,
}
impl Default for DoeInput {
    fn default() -> Self {
        Self {
            doe_obf_key: caliptra_hw_model_types::DEFAULT_CPTRA_OBF_KEY,

            doe_iv: DOE_IV,

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
    pub uds: [u32; 16],

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
            uds: [0_u32; 16],

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
                swap_word_bytes(&input.doe_iv).as_bytes(),
                swap_word_bytes(&input.uds_seed).as_bytes(),
            ));
        swap_word_bytes_inplace(&mut result.uds);

        result.field_entropy[0..8]
            .as_bytes_mut()
            .copy_from_slice(&aes256_decrypt_blocks(
                swap_word_bytes(&input.doe_obf_key).as_bytes(),
                swap_word_bytes(&input.doe_iv).as_bytes(),
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
        doe_iv: [0x455ba825, 0x45e16ca6, 0xf97d1f86, 0xb3718021],
        uds_seed: [
            0x86c65f40, 0x04d45413, 0x5041da9a, 0x8580ec9a, 0xc7007ee6, 0xceb4a4b8, 0xce485f47,
            0xbf6976b8, 0xc906de7b, 0xb0cd2dce, 0x8d2b8eed, 0xa537255f, 0x2fd70f7c, 0xda37caeb,
            0xa748021, 0x34d2fd94,
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
                2450659586, 3204072599, 1027011035, 1213873878, 763047603, 1402117172, 2275304687,
                1797647086, 2750999, 2465724634, 992659675, 557913425, 1982584393, 56096072,
                3122931436, 3177452069
            ],
            field_entropy: [
                437386532, 405572964, 972652519, 2702758929, 92052297, 1822317414, 295423989,
                3895283936, 1431655765, 1431655765, 1431655765, 1431655765
            ]
        }
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IDevId {
    pub cdi: [u32; 16],

    pub ecc_priv_key: [u32; 12],
}
impl IDevId {
    pub fn derive(doe_output: &DoeOutput) -> Self {
        let mut cdi: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&doe_output.uds).as_bytes(),
            b"idevid_cdi",
            None
        ));
        swap_word_bytes_inplace(&mut cdi);

        let mut priv_key_seed: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&cdi).as_bytes(),
            b"idevid_ecc_key",
            None
        ));
        swap_word_bytes_inplace(&mut priv_key_seed);

        let mut ecc_priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            &swap_word_bytes(&priv_key_seed).as_bytes()[..48],
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut ecc_priv_key);
        Self { cdi, ecc_priv_key }
    }

    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.ecc_priv_key)
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
            0x6b25eaee, 0x0029fa17, 0x92f7f8da, 0x3b2ac8db, 0x21411551, 0xed0e3d62, 0x5e51aed,
            0x14199450, 0x45b540a1,
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
                0xe047693d, 0x5038cf58, 0xbafff529, 0x4308aced, 0xd356fd37, 0x620386b3, 0xb2cfdd97,
                0x602e5b26, 0x29ff1601, 0xe3196949, 0xe04109ab, 0x9b6bcab1, 0xef5dc70d, 0xbd2d0875,
                0xf17a7559, 0x2328baa2,
            ],
            ecc_priv_key: [
                0x34d9279, 0x2e58660b, 0xcfa3e026, 0x90ac31dc, 0xb97a6b6c, 0xf259f7d4, 0xaa3b7a0d,
                0x565232ff, 0x38560790, 0x73ff1c04, 0x34501150, 0x48641108,
            ],
        }
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LDevId {
    pub cdi: [u32; 16],

    pub ecc_priv_key: [u32; 12],
}
impl LDevId {
    pub fn derive(doe_output: &DoeOutput) -> Self {
        let idevid = IDevId::derive(doe_output);
        let mut cdi_seed: [u32; 16] = transmute!(hmac512(
            swap_word_bytes(&idevid.cdi).as_bytes(),
            b"ldevid_cdi",
        ));
        swap_word_bytes_inplace(&mut cdi_seed);

        let mut cdi: [u32; 16] = transmute!(hmac512(
            swap_word_bytes(&cdi_seed).as_bytes(),
            swap_word_bytes(&doe_output.field_entropy[0..8]).as_bytes(),
        ));
        swap_word_bytes_inplace(&mut cdi);

        let mut priv_key_seed: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&cdi).as_bytes(),
            b"ldevid_ecc_key",
            None
        ));
        swap_word_bytes_inplace(&mut priv_key_seed);

        let mut ecc_priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            &swap_word_bytes(&priv_key_seed).as_bytes()[..48],
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut ecc_priv_key);
        Self { cdi, ecc_priv_key }
    }

    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.ecc_priv_key)
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
            0x6b25eaee, 0x0029fa17, 0x92f7f8da, 0x3b2ac8db, 0x21411551, 0x57d115c, 0xfade7a,
            0xb8cca563, 0xe1f504a2,
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
                0x5c705f09, 0x63f7edfb, 0x9cf0cb89, 0x7306da3f, 0xff1acde2, 0xf1f0b333, 0xafb85fa3,
                0x8783a424, 0x6c6aa9db, 0x43ce3297, 0x2568332, 0x53670f99, 0x9e4fff07, 0xdc1911f7,
                0xd7af58ed, 0xab20aff0,
            ],
            ecc_priv_key: [
                0x15e65daa, 0x3e7dedbb, 0x60eb7ea6, 0xd7e9e441, 0xf2adaa7a, 0x35ca904c, 0x9076d1a1,
                0x69972589, 0x274a2869, 0x48eb0fb4, 0xee749db1, 0x15cbe26e,
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
    pub owner_pub_key_hash_from_fuses: bool,
    pub ecc_vendor_pub_key_index: u32,
    pub fmc_digest: [u32; 12],
    pub fmc_svn: u32,
    pub fmc_fuse_svn: u32,
    pub lms_vendor_pub_key_index: u32,
    pub rom_verify_config: u32,
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

        extend(
            &mut value,
            &[
                input.security_state.device_lifecycle() as u8,
                input.security_state.debug_locked() as u8,
                input.fuse_anti_rollback_disable as u8,
                input.ecc_vendor_pub_key_index as u8,
                input.fmc_svn as u8,
                input.fmc_fuse_svn as u8,
                input.lms_vendor_pub_key_index as u8,
                input.rom_verify_config as u8,
                input.owner_pub_key_hash_from_fuses as u8,
            ],
        );
        extend(
            &mut value,
            swap_word_bytes(&input.vendor_pub_key_hash).as_bytes(),
        );
        extend(
            &mut value,
            swap_word_bytes(&input.owner_pub_key_hash).as_bytes(),
        );
        extend(&mut value, swap_word_bytes(&input.fmc_digest).as_bytes());

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
        owner_pub_key_hash_from_fuses: true,
        ecc_vendor_pub_key_index: 0,
        fmc_digest: [
            0xe44ea855, 0x9fcf4063, 0xd3110a9a, 0xd60579db, 0xe03e6dd7, 0x4556cd98, 0xb2b941f5,
            0x1bb5034b, 0x587eea1f, 0xfcdd0e0f, 0x8e88d406, 0x3327a3fe,
        ],
        fmc_svn: 5,
        fmc_fuse_svn: 2,
        lms_vendor_pub_key_index: u32::MAX,
        rom_verify_config: 1, // RomVerifyConfig::EcdsaAndLms
    });
    assert_eq!(
        pcr0,
        Pcr0([
            132444429, 987394663, 2275449643, 2729083116, 322701188, 1268620383, 68534608,
            1944581982, 1207702945, 1427901733, 3489811836, 435454516
        ])
    )
}

pub struct PcrRtCurrentInput {
    pub runtime_digest: [u32; 12],
    pub manifest: ImageManifest,
}

pub struct PcrRtCurrent(pub [u32; 12]);
impl PcrRtCurrent {
    pub fn derive(input: &PcrRtCurrentInput) -> Self {
        let mut value = [0u8; 48];
        let extend = |value: &mut [u8; 48], buf: &[u8]| {
            *value = sha384(&[value.as_slice(), buf].concat());
        };
        extend(
            &mut value,
            swap_word_bytes(&input.runtime_digest).as_bytes(),
        );

        let manifest_digest = sha384(input.manifest.as_bytes());
        extend(&mut value, &manifest_digest);
        println!("Pcr is {:02x?}", value);

        let mut result: [u32; 12] = zerocopy::transmute!(value);
        swap_word_bytes_inplace(&mut result);
        Self(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FmcAliasKey {
    // The FMC alias private key as stored in the key-vault
    pub ecc_priv_key: [u32; 12],

    pub cdi: [u32; 16],
}
impl FmcAliasKey {
    pub fn derive(pcr0: &Pcr0, ldevid: &LDevId) -> Self {
        let mut cdi: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&ldevid.cdi).as_bytes(),
            b"alias_fmc_cdi",
            Some(swap_word_bytes(&pcr0.0).as_bytes()),
        ));
        swap_word_bytes_inplace(&mut cdi);

        let mut priv_key_seed: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&cdi).as_bytes(),
            b"alias_fmc_ecc_key",
            None
        ));
        swap_word_bytes_inplace(&mut priv_key_seed);

        let mut ecc_priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            &swap_word_bytes(&priv_key_seed).as_bytes()[..48],
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut ecc_priv_key);
        Self { ecc_priv_key, cdi }
    }
    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.ecc_priv_key)
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtAliasKey {
    pub cdi: [u32; 16],

    // The FMC alias ECC private key as stored in the key-vault
    pub ecc_priv_key: [u32; 12],
}
impl RtAliasKey {
    pub fn derive(tci_input: &PcrRtCurrentInput, fmc_key: &FmcAliasKey) -> Self {
        // NOTE: This works differently than FmcAliasKey. FmcAliasKey takes the
        // 48-byte value from Pcr0 as context, this version uses a 96-byte
        // concatenation of the runtime digest and manifest digest.
        let mut tci: [u8; 96] = [0; 96];
        tci[0..48].copy_from_slice(swap_word_bytes(&tci_input.runtime_digest).as_bytes());
        tci[48..96]
            .as_bytes_mut()
            .copy_from_slice(&sha384(tci_input.manifest.as_bytes()));

        let mut cdi: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&fmc_key.cdi).as_bytes(),
            b"alias_rt_cdi",
            Some(&tci),
        ));
        swap_word_bytes_inplace(&mut cdi);

        let mut priv_key_seed: [u32; 16] = transmute!(hmac512_kdf(
            swap_word_bytes(&cdi).as_bytes(),
            b"alias_rt_ecc_key",
            None
        ));
        swap_word_bytes_inplace(&mut priv_key_seed);

        let mut ecc_priv_key: [u32; 12] = transmute!(hmac384_drbg_keygen(
            &swap_word_bytes(&priv_key_seed).as_bytes()[..48],
            swap_word_bytes(&ECDSA_KEYGEN_NONCE).as_bytes()
        ));
        swap_word_bytes_inplace(&mut ecc_priv_key);
        Self { ecc_priv_key, cdi }
    }
    pub fn derive_public_key(&self) -> PKey<Public> {
        derive_ecdsa_key(
            swap_word_bytes(&self.ecc_priv_key)
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
                0x3da916e5, 0x94f2b09e, 0x257f151d, 0x261ade90, 0x73a9b3fb, 0xf35c0619, 0x0856f1e3,
                0x7d560cf2, 0xaa227256,
            ],
            ecc_priv_key: [
                0xd3ef1bff, 0x0b52919d, 0xe084ee81, 0x47544a50, 0xf7ff4c2d, 0x18038a26, 0x0695a0b1,
                0x8103e7f4, 0x30651311, 0xc5658261, 0xe30ae241, 0xa8d9ad51,
            ],
        },
    );
    assert_eq!(
        fmc_alias_key,
        FmcAliasKey {
            ecc_priv_key: [
                0xfcd8c50e, 0x45ddf47b, 0xe272c12c, 0x2a49576f, 0xb57f994d, 0x723de453, 0x14229ac9,
                0x714b2a8a, 0x6f1ce75f, 0x788cf75c, 0xdbe9da02, 0x51a22e82,
            ],
            cdi: [
                0x41529a09, 0xe976d227, 0x456a211c, 0x86187b33, 0x15c88587, 0x60c51cb8, 0xfbcbb695,
                0xf67988dc, 0x14f6ae96, 0xc3dbdaa2, 0xad287006, 0x33a7f284, 0x81d964ce, 0x45af6c6b,
                0xdd8b95fd, 0x5cbcbc4b,
            ],
        }
    );
}

pub fn key_id(pub_key: &PKey<Public>) -> [u8; 20] {
    key_id_from_der(&crypto::pubkey_ecdsa_der(pub_key))
}

pub fn cert_serial_number(pub_key: &PKey<Public>) -> [u8; 20] {
    cert_serial_number_from_der(&crypto::pubkey_ecdsa_der(pub_key))
}

pub fn serial_number_str(pub_key: &PKey<Public>) -> String {
    serial_number_str_from_der(&crypto::pubkey_ecdsa_der(pub_key))
}

fn key_id_from_der(pub_key_der: &[u8]) -> [u8; 20] {
    sha256(pub_key_der)[..20].try_into().unwrap()
}

fn serial_number_str_from_der(pub_key_der: &[u8]) -> String {
    use std::fmt::Write;
    let digest = sha256(pub_key_der);
    let mut result = String::new();
    for byte in digest {
        write!(&mut result, "{byte:02X}").unwrap();
    }
    result
}

fn cert_serial_number_from_der(pub_key_der: &[u8]) -> [u8; 20] {
    let mut result = key_id_from_der(pub_key_der);
    // ensure integer is positive and first octet is non-zero
    result[0] &= !0x80;
    result[0] |= 0x04;
    result
}

#[test]
fn test_key_id() {
    assert_eq!(
        key_id_from_der(&[
            0x04, 0x84, 0x2c, 0x00, 0xaf, 0x05, 0xac, 0xcc, 0xeb, 0x14, 0x51, 0x4e, 0x2d, 0x37,
            0xb0, 0xc3, 0xaa, 0xa2, 0x18, 0xf1, 0x50, 0x57, 0xf1, 0xdc, 0xb8, 0x24, 0xa2, 0x14,
            0x98, 0x0b, 0x74, 0x46, 0x88, 0xa0, 0x88, 0x8a, 0x02, 0x97, 0xfa, 0x7d, 0xc5, 0xe1,
            0xea, 0xd8, 0xca, 0x12, 0x91, 0xdb, 0x22, 0x9c, 0x28, 0xeb, 0x86, 0x78, 0xbc, 0xe8,
            0x00, 0x82, 0x2c, 0x07, 0x22, 0x8f, 0x41, 0x6a, 0xe4, 0x9d, 0x21, 0x8e, 0x5d, 0xa2,
            0xf2, 0xd1, 0xa8, 0xa2, 0x7d, 0xc1, 0x9a, 0xdf, 0x66, 0x8a, 0x74, 0x62, 0x89, 0x99,
            0xd2, 0x22, 0xb4, 0x01, 0x59, 0xd8, 0x07, 0x6f, 0xaf, 0xbb, 0x8c, 0x5e, 0xdb
        ]),
        [
            0x21, 0xee, 0xef, 0x9a, 0x4c, 0x61, 0xd4, 0xb9, 0xe3, 0xd9, 0x4b, 0xea, 0x46, 0xf9,
            0xa1, 0x2a, 0xc6, 0x88, 0x7c, 0xe2
        ]
    );
    assert_eq!(
        key_id_from_der(&[
            0x04, 0x1a, 0xe7, 0x83, 0xc2, 0xd0, 0x47, 0xcb, 0xc4, 0xc9, 0x54, 0x26, 0x8b, 0x70,
            0xff, 0x5e, 0x75, 0x18, 0xb9, 0xb7, 0xda, 0x0e, 0x26, 0x4b, 0xde, 0x4d, 0x52, 0x8b,
            0xe4, 0x6c, 0x79, 0x5e, 0xd2, 0x1a, 0x3c, 0x8d, 0xa6, 0xa9, 0x5c, 0xcd, 0x08, 0x11,
            0xf6, 0x7e, 0x26, 0x6d, 0x27, 0xf2, 0x1c, 0xb0, 0x73, 0x36, 0x22, 0xff, 0x64, 0xcb,
            0x6a, 0x29, 0xf7, 0xeb, 0x57, 0x25, 0x8b, 0xe9, 0xa2, 0xac, 0x5c, 0xe1, 0x9d, 0x78,
            0xd3, 0x36, 0x50, 0xa5, 0x45, 0x3f, 0x19, 0x2c, 0x2c, 0x48, 0x2c, 0x77, 0x55, 0x8c,
            0x19, 0x6e, 0x30, 0xba, 0x1a, 0x05, 0xe2, 0x6e, 0xd2, 0xe0, 0x9d, 0xfe, 0x4a
        ]),
        [
            0xe7, 0x35, 0xc1, 0x7c, 0x08, 0x2c, 0xfc, 0xbc, 0x3e, 0x1b, 0x8f, 0xbf, 0xbe, 0xa4,
            0x90, 0x79, 0xbc, 0xb7, 0x22, 0x10
        ]
    );
}

#[test]
fn test_cert_serial_number() {
    assert_eq!(
        cert_serial_number_from_der(&[
            0x04, 0x84, 0x2c, 0x00, 0xaf, 0x05, 0xac, 0xcc, 0xeb, 0x14, 0x51, 0x4e, 0x2d, 0x37,
            0xb0, 0xc3, 0xaa, 0xa2, 0x18, 0xf1, 0x50, 0x57, 0xf1, 0xdc, 0xb8, 0x24, 0xa2, 0x14,
            0x98, 0x0b, 0x74, 0x46, 0x88, 0xa0, 0x88, 0x8a, 0x02, 0x97, 0xfa, 0x7d, 0xc5, 0xe1,
            0xea, 0xd8, 0xca, 0x12, 0x91, 0xdb, 0x22, 0x9c, 0x28, 0xeb, 0x86, 0x78, 0xbc, 0xe8,
            0x00, 0x82, 0x2c, 0x07, 0x22, 0x8f, 0x41, 0x6a, 0xe4, 0x9d, 0x21, 0x8e, 0x5d, 0xa2,
            0xf2, 0xd1, 0xa8, 0xa2, 0x7d, 0xc1, 0x9a, 0xdf, 0x66, 0x8a, 0x74, 0x62, 0x89, 0x99,
            0xd2, 0x22, 0xb4, 0x01, 0x59, 0xd8, 0x07, 0x6f, 0xaf, 0xbb, 0x8c, 0x5e, 0xdb
        ]),
        [
            0x25, 0xee, 0xef, 0x9a, 0x4c, 0x61, 0xd4, 0xb9, 0xe3, 0xd9, 0x4b, 0xea, 0x46, 0xf9,
            0xa1, 0x2a, 0xc6, 0x88, 0x7c, 0xe2
        ]
    );
    assert_eq!(
        cert_serial_number_from_der(&[
            0x04, 0x1a, 0xe7, 0x83, 0xc2, 0xd0, 0x47, 0xcb, 0xc4, 0xc9, 0x54, 0x26, 0x8b, 0x70,
            0xff, 0x5e, 0x75, 0x18, 0xb9, 0xb7, 0xda, 0x0e, 0x26, 0x4b, 0xde, 0x4d, 0x52, 0x8b,
            0xe4, 0x6c, 0x79, 0x5e, 0xd2, 0x1a, 0x3c, 0x8d, 0xa6, 0xa9, 0x5c, 0xcd, 0x08, 0x11,
            0xf6, 0x7e, 0x26, 0x6d, 0x27, 0xf2, 0x1c, 0xb0, 0x73, 0x36, 0x22, 0xff, 0x64, 0xcb,
            0x6a, 0x29, 0xf7, 0xeb, 0x57, 0x25, 0x8b, 0xe9, 0xa2, 0xac, 0x5c, 0xe1, 0x9d, 0x78,
            0xd3, 0x36, 0x50, 0xa5, 0x45, 0x3f, 0x19, 0x2c, 0x2c, 0x48, 0x2c, 0x77, 0x55, 0x8c,
            0x19, 0x6e, 0x30, 0xba, 0x1a, 0x05, 0xe2, 0x6e, 0xd2, 0xe0, 0x9d, 0xfe, 0x4a
        ]),
        [
            0x67, 0x35, 0xc1, 0x7c, 0x08, 0x2c, 0xfc, 0xbc, 0x3e, 0x1b, 0x8f, 0xbf, 0xbe, 0xa4,
            0x90, 0x79, 0xbc, 0xb7, 0x22, 0x10
        ]
    );
}

#[test]
fn test_issuer_serial_number() {
    assert_eq!(
        serial_number_str_from_der(&[
            0x04, 0x84, 0x2c, 0x00, 0xaf, 0x05, 0xac, 0xcc, 0xeb, 0x14, 0x51, 0x4e, 0x2d, 0x37,
            0xb0, 0xc3, 0xaa, 0xa2, 0x18, 0xf1, 0x50, 0x57, 0xf1, 0xdc, 0xb8, 0x24, 0xa2, 0x14,
            0x98, 0x0b, 0x74, 0x46, 0x88, 0xa0, 0x88, 0x8a, 0x02, 0x97, 0xfa, 0x7d, 0xc5, 0xe1,
            0xea, 0xd8, 0xca, 0x12, 0x91, 0xdb, 0x22, 0x9c, 0x28, 0xeb, 0x86, 0x78, 0xbc, 0xe8,
            0x00, 0x82, 0x2c, 0x07, 0x22, 0x8f, 0x41, 0x6a, 0xe4, 0x9d, 0x21, 0x8e, 0x5d, 0xa2,
            0xf2, 0xd1, 0xa8, 0xa2, 0x7d, 0xc1, 0x9a, 0xdf, 0x66, 0x8a, 0x74, 0x62, 0x89, 0x99,
            0xd2, 0x22, 0xb4, 0x01, 0x59, 0xd8, 0x07, 0x6f, 0xaf, 0xbb, 0x8c, 0x5e, 0xdb
        ]),
        "21EEEF9A4C61D4B9E3D94BEA46F9A12AC6887CE2188559F40FF95777E8014889"
    );
    assert_eq!(
        serial_number_str_from_der(&[
            0x04, 0x1a, 0xe7, 0x83, 0xc2, 0xd0, 0x47, 0xcb, 0xc4, 0xc9, 0x54, 0x26, 0x8b, 0x70,
            0xff, 0x5e, 0x75, 0x18, 0xb9, 0xb7, 0xda, 0x0e, 0x26, 0x4b, 0xde, 0x4d, 0x52, 0x8b,
            0xe4, 0x6c, 0x79, 0x5e, 0xd2, 0x1a, 0x3c, 0x8d, 0xa6, 0xa9, 0x5c, 0xcd, 0x08, 0x11,
            0xf6, 0x7e, 0x26, 0x6d, 0x27, 0xf2, 0x1c, 0xb0, 0x73, 0x36, 0x22, 0xff, 0x64, 0xcb,
            0x6a, 0x29, 0xf7, 0xeb, 0x57, 0x25, 0x8b, 0xe9, 0xa2, 0xac, 0x5c, 0xe1, 0x9d, 0x78,
            0xd3, 0x36, 0x50, 0xa5, 0x45, 0x3f, 0x19, 0x2c, 0x2c, 0x48, 0x2c, 0x77, 0x55, 0x8c,
            0x19, 0x6e, 0x30, 0xba, 0x1a, 0x05, 0xe2, 0x6e, 0xd2, 0xe0, 0x9d, 0xfe, 0x4a
        ]),
        "E735C17C082CFCBC3E1B8FBFBEA49079BCB7221096001C4730C4EE2A64009B62"
    );
}
