// Licensed under the Apache-2.0 license

use caliptra_image_gen::{ImageGeneratorOwnerConfig, ImageGeneratorVendorConfig};
use caliptra_image_types::{
    ImageEccPrivKey, ImageEccPubKey, ImageLmsPrivKey, ImageLmsPublicKey, ImageOwnerPrivKeys,
    ImageOwnerPubKeys, ImageVendorPrivKeys, ImageVendorPubKeys, IMAGE_LMS_OTS_TYPE,
    IMAGE_LMS_TREE_TYPE,
};
use caliptra_lms_types::bytes_to_words_6;

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::Write; // bring trait into scope
#[cfg(test)]
use zerocopy::AsBytes;

/// Generated with
///
/// ```no_run
/// use caliptra_image_crypto;
/// use std::path::PathBuf;
///
/// fn print_public_key(name: &str, path: &str) {
///     let key = caliptra_image_crypto::ecc_pub_key_from_pem(&PathBuf::from(path)).unwrap();
///     println!("pub const {name}_PUBLIC: ImageEccPubKey = {key:#010x?};");
/// }
/// fn print_private_key(name: &str, path: &str) {
///     let key = caliptra_image_crypto::ecc_priv_key_from_pem(&PathBuf::from(path)).unwrap();
///     println!("pub const {name}_PRIVATE: ImageEccPrivKey = {key:#010x?};");
/// }
///
/// print_public_key("VENDOR_KEY_0", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-0.pem");
/// print_private_key("VENDOR_KEY_0", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-0.pem");
/// print_public_key("VENDOR_KEY_1", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-1.pem");
/// print_private_key("VENDOR_KEY_1", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-1.pem");
/// print_public_key("VENDOR_KEY_2", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-2.pem");
/// print_private_key("VENDOR_KEY_2", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-2.pem");
/// print_public_key("VENDOR_KEY_3", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-pub-key-3.pem");
/// print_private_key("VENDOR_KEY_3", "../../target/riscv32imc-unknown-none-elf/firmware/vnd-priv-key-3.pem");
/// print_public_key("OWNER_KEY", "../../target/riscv32imc-unknown-none-elf/firmware/own-pub-key.pem");
/// print_private_key("OWNER_KEY", "../../target/riscv32imc-unknown-none-elf/firmware/own-priv-key.pem");
/// ```
pub const VENDOR_ECC_KEY_0_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xc69fe67f, 0x97ea3e42, 0x21a7a603, 0x6c2e070d, 0x1657327b, 0xc3f1e7c1, 0x8dccb9e4,
        0xffda5c3f, 0x4db0a1c0, 0x567e0973, 0x17bf4484, 0x39696a07,
    ],
    y: [
        0xc126b913, 0x5fc82572, 0x8f1cd403, 0x19109430, 0x994fe3e8, 0x74a8b026, 0xbe14794d,
        0x27789964, 0x7735fde8, 0x328afd84, 0xcd4d4aa8, 0x72d40b42,
    ],
};
pub const VENDOR_ECC_KEY_0_PRIVATE: ImageEccPrivKey = [
    0x29f939ea, 0x41746499, 0xd550c6fa, 0x6368b0d7, 0x61e09b4c, 0x75b21922, 0x86f96240, 0x00ea1d99,
    0xace94ba6, 0x7ae89b0e, 0x3f210cf1, 0x9a45b6b5,
];
pub const VENDOR_ECC_KEY_1_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xa6309750, 0xf0a05ddb, 0x956a7f86, 0x2812ec4f, 0xec454e95, 0x3b53dbfb, 0x9eb54140,
        0x15ea7507, 0x084af93c, 0xb7fa33fe, 0x51811ad5, 0xe754232e,
    ],
    y: [
        0xef5a5987, 0x7a0ce0be, 0x2621d2a9, 0x8bf3c5df, 0xaf7b3d6d, 0x97f24183, 0xa4a42038,
        0x58c39b86, 0x272ef548, 0xe572b937, 0x1ecf1994, 0x1b8d4ea7,
    ],
};
pub const VENDOR_ECC_KEY_1_PRIVATE: ImageEccPrivKey = [
    0xf2ee427b, 0x4412f46f, 0x8fb020a5, 0xc23b0154, 0xb3fcb201, 0xf93c2ee2, 0x923fd577, 0xf85320bb,
    0x289eb276, 0x2b6b21d3, 0x5cdb3925, 0xa57d5043,
];
pub const VENDOR_ECC_KEY_2_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xa0d25693, 0xc4251e48, 0x185615b0, 0xa6c27f6d, 0xe62c39f5, 0xa9a32f75, 0x9553226a,
        0x4d1926c1, 0x7928910f, 0xb7adc1b6, 0x89996733, 0x10134881,
    ],
    y: [
        0xbbdf72d7, 0x07c08100, 0xd54fcdad, 0xb1567bb0, 0x0522762b, 0x76b8dc4a, 0x846c175a,
        0x3fbd0501, 0x9bdc8118, 0x4be5f33c, 0xbb21b41d, 0x93a8c523,
    ],
};
pub const VENDOR_ECC_KEY_2_PRIVATE: ImageEccPrivKey = [
    0xaf72a74c, 0xfbbacc3c, 0x7ad2f9d9, 0xc969d1c9, 0x19c2d803, 0x0a53749a, 0xee730267, 0x7c11a52d,
    0xee63e4c8, 0x0b5c0293, 0x28d35c27, 0x5f959aee,
];
pub const VENDOR_ECC_KEY_3_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0x002a82b6, 0x8e03e9a0, 0xfd3b4c14, 0xca2cb3e8, 0x14350a71, 0x0e43956d, 0x21694fb4,
        0xf34485e8, 0xf0e33583, 0xf7ea142d, 0x50e16f8b, 0x0225bb95,
    ],
    y: [
        0x5802641c, 0x7c45a4a2, 0x408e03a6, 0xa4100a92, 0x50fcc468, 0xd238cd0d, 0x449cc3e5,
        0x1abc25e7, 0x0b05c426, 0x843dcd6f, 0x944ef6ff, 0xfa53ec5b,
    ],
};
pub const VENDOR_ECC_KEY_3_PRIVATE: ImageEccPrivKey = [
    0xafbdfc7d, 0x36b54629, 0xd12c4cb5, 0x33926c30, 0x20611617, 0x86b50b23, 0x6046ff93, 0x17ea0144,
    0xbc900c70, 0xb8cb36ac, 0x268b8079, 0xe3aeaaaf,
];

pub const VENDOR_LMS_KEY_0_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x49, 0x08, 0xa1, 0x7b, 0xca, 0xdb, 0x18, 0x29, 0x1e, 0x28, 0x90, 0x58, 0xd5, 0xa8, 0xe3,
        0xe8,
    ],
    seed: bytes_to_words_6([
        0x4d, 0xce, 0x1e, 0x1e, 0x77, 0x52, 0x53, 0xec, 0x07, 0xbc, 0x07, 0x90, 0xcb, 0x59, 0xb2,
        0x73, 0x45, 0x86, 0xb0, 0x32, 0x86, 0xc7, 0x69, 0x74,
    ]),
};
pub const VENDOR_LMS_KEY_0_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x49, 0x08, 0xa1, 0x7b, 0xca, 0xdb, 0x18, 0x29, 0x1e, 0x28, 0x90, 0x58, 0xd5, 0xa8, 0xe3,
        0xe8,
    ],
    digest: bytes_to_words_6([
        0x64, 0xad, 0x3e, 0xb8, 0xbe, 0x68, 0x64, 0xf1, 0x7c, 0xcd, 0xa3, 0x8b, 0xde, 0x35, 0xed,
        0xaa, 0x6c, 0x0d, 0xa5, 0x27, 0x64, 0x54, 0x07, 0xc6,
    ]),
};

pub const VENDOR_LMS_KEY_1_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x7c, 0xb5, 0x36, 0x9d, 0x64, 0xe4, 0x28, 0x1d, 0x04, 0x6e, 0x97, 0x7c, 0x70, 0xd4, 0xd0,
        0xa3,
    ],
    seed: bytes_to_words_6([
        0x57, 0x68, 0x5b, 0xb6, 0xe9, 0x46, 0x2b, 0x6b, 0xd3, 0x60, 0x21, 0xeb, 0xf0, 0x43, 0xb7,
        0x56, 0x0c, 0x58, 0x1e, 0xbf, 0x7b, 0x50, 0xc5, 0x14,
    ]),
};
pub const VENDOR_LMS_KEY_1_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x7c, 0xb5, 0x36, 0x9d, 0x64, 0xe4, 0x28, 0x1d, 0x04, 0x6e, 0x97, 0x7c, 0x70, 0xd4, 0xd0,
        0xa3,
    ],
    digest: bytes_to_words_6([
        0x8e, 0xa4, 0x70, 0x1d, 0xad, 0xf7, 0xd7, 0x00, 0x05, 0x64, 0xb7, 0xd6, 0x1d, 0x1c, 0x95,
        0x87, 0x9d, 0xd6, 0x47, 0x5c, 0x9c, 0x3a, 0xae, 0x0b,
    ]),
};

pub const VENDOR_LMS_KEY_2_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x2b, 0xbb, 0x4b, 0x72, 0xc5, 0xb4, 0x1e, 0x05, 0xd2, 0xfa, 0xbe, 0x76, 0xf4, 0x17, 0x04,
        0xbd,
    ],
    seed: bytes_to_words_6([
        0x73, 0xce, 0x8c, 0x94, 0xf7, 0xc9, 0xb0, 0x1c, 0xb8, 0x3a, 0x44, 0x27, 0xa9, 0x47, 0xb2,
        0xa9, 0x44, 0x44, 0x46, 0xbd, 0xe2, 0x86, 0xe5, 0xe6,
    ]),
};
pub const VENDOR_LMS_KEY_2_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x2b, 0xbb, 0x4b, 0x72, 0xc5, 0xb4, 0x1e, 0x05, 0xd2, 0xfa, 0xbe, 0x76, 0xf4, 0x17, 0x04,
        0xbd,
    ],
    digest: bytes_to_words_6([
        0xdc, 0xb5, 0x3f, 0x96, 0x24, 0xd4, 0xc7, 0xb3, 0xc9, 0xae, 0x4d, 0x4c, 0x0e, 0x41, 0xe0,
        0x8e, 0x3b, 0x15, 0x93, 0x96, 0x0f, 0xe6, 0xa2, 0x77,
    ]),
};

pub const VENDOR_LMS_KEY_3_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x42, 0xcb, 0xa2, 0xe5, 0x57, 0x5b, 0x52, 0x35, 0x7e, 0xa7, 0xae, 0xad, 0xef, 0x54, 0x07,
        0x4c,
    ],
    seed: bytes_to_words_6([
        0xba, 0x49, 0x06, 0x67, 0x17, 0x3f, 0xfe, 0x67, 0x15, 0x6e, 0xf2, 0x61, 0xac, 0xb4, 0xbc,
        0x90, 0xcb, 0x4f, 0xa1, 0xbc, 0x26, 0xbb, 0xa2, 0x34,
    ]),
};
pub const VENDOR_LMS_KEY_3_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0x42, 0xcb, 0xa2, 0xe5, 0x57, 0x5b, 0x52, 0x35, 0x7e, 0xa7, 0xae, 0xad, 0xef, 0x54, 0x07,
        0x4c,
    ],
    digest: bytes_to_words_6([
        0x5a, 0xa6, 0x0e, 0x27, 0x69, 0x25, 0x15, 0x99, 0x3a, 0xe8, 0xe2, 0x1f, 0x27, 0xcc, 0xdd,
        0xed, 0x8f, 0xfc, 0xd3, 0xd2, 0x8e, 0xfb, 0xde, 0xc2,
    ]),
};

pub const OWNER_LMS_KEY_PRIVATE: ImageLmsPrivKey = ImageLmsPrivKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0xe5, 0x6d, 0x3e, 0x53, 0xa5, 0xc2, 0x5b, 0xea, 0xf3, 0x3a, 0x90, 0x15, 0x5b, 0x27, 0x3a,
        0xe3,
    ],
    seed: bytes_to_words_6([
        0x65, 0xc4, 0xfb, 0xac, 0xd3, 0xab, 0xa2, 0x8f, 0x77, 0xe7, 0xc5, 0x1c, 0x7f, 0x39, 0xba,
        0x4d, 0x59, 0xd0, 0xb0, 0x83, 0x79, 0xa9, 0xf7, 0x5d,
    ]),
};
pub const OWNER_LMS_KEY_PUBLIC: ImageLmsPublicKey = ImageLmsPublicKey {
    tree_type: IMAGE_LMS_TREE_TYPE,
    otstype: IMAGE_LMS_OTS_TYPE,
    id: [
        0xe5, 0x6d, 0x3e, 0x53, 0xa5, 0xc2, 0x5b, 0xea, 0xf3, 0x3a, 0x90, 0x15, 0x5b, 0x27, 0x3a,
        0xe3,
    ],
    digest: bytes_to_words_6([
        0x47, 0xb2, 0x15, 0x6c, 0xa3, 0x64, 0x1c, 0xc4, 0x02, 0xc0, 0xfd, 0x95, 0x79, 0x72, 0xba,
        0x56, 0x08, 0x6f, 0x8f, 0x8c, 0xfa, 0x05, 0xb5, 0xbb,
    ]),
};
pub const OWNER_ECC_KEY_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xc6f82e2b, 0xdcf3e157, 0xa162e7f3, 0x3eca35c4, 0x55ea08a9, 0x13811779, 0xb6f2646d,
        0x92c817cd, 0x4094bd1a, 0xdb215f62, 0xcf36f017, 0x012d5aeb,
    ],
    y: [
        0xa4674593, 0x6cb5a379, 0x99b08264, 0x862b2c1c, 0x517f12c6, 0x573e1f94, 0x7142291a,
        0xf9624bd7, 0x2733dcdd, 0xce24ec5e, 0x961c00e3, 0x4372ba17,
    ],
};
pub const OWNER_ECC_KEY_PRIVATE: ImageEccPrivKey = [
    0x59fdf849, 0xe39f4256, 0x19342ed2, 0x81d28d3d, 0x45ab3219, 0x5174582c, 0xecb4e9df, 0x9cc2e991,
    0xb75f88fd, 0xfa4bc6a4, 0x6b88340f, 0x05dd8890,
];
pub const VENDOR_PUBLIC_KEYS: ImageVendorPubKeys = ImageVendorPubKeys {
    ecc_pub_keys: [
        VENDOR_ECC_KEY_0_PUBLIC,
        VENDOR_ECC_KEY_1_PUBLIC,
        VENDOR_ECC_KEY_2_PUBLIC,
        VENDOR_ECC_KEY_3_PUBLIC,
    ],
    lms_pub_keys: [
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
        VENDOR_LMS_KEY_0_PUBLIC,
        VENDOR_LMS_KEY_1_PUBLIC,
        VENDOR_LMS_KEY_2_PUBLIC,
        VENDOR_LMS_KEY_3_PUBLIC,
    ],
};

pub const OWNER_PUBLIC_KEYS: ImageOwnerPubKeys = ImageOwnerPubKeys {
    ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
    lms_pub_key: OWNER_LMS_KEY_PUBLIC,
};
pub const VENDOR_PRIVATE_KEYS: ImageVendorPrivKeys = ImageVendorPrivKeys {
    ecc_priv_keys: [
        VENDOR_ECC_KEY_0_PRIVATE,
        VENDOR_ECC_KEY_1_PRIVATE,
        VENDOR_ECC_KEY_2_PRIVATE,
        VENDOR_ECC_KEY_3_PRIVATE,
    ],
    lms_priv_keys: [
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
        VENDOR_LMS_KEY_0_PRIVATE,
        VENDOR_LMS_KEY_1_PRIVATE,
        VENDOR_LMS_KEY_2_PRIVATE,
        VENDOR_LMS_KEY_3_PRIVATE,
    ],
};

pub const OWNER_PRIVATE_KEYS: ImageOwnerPrivKeys = ImageOwnerPrivKeys {
    ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
    lms_priv_key: OWNER_LMS_KEY_PRIVATE,
};

pub const VENDOR_CONFIG_KEY_0: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    pub_keys: VENDOR_PUBLIC_KEYS,
    ecc_key_idx: 0,
    lms_key_idx: 0,
    priv_keys: Some(VENDOR_PRIVATE_KEYS),
    not_before: [0u8; 15],
    not_after: [0u8; 15],
    pl0_pauser: Some(0x1),
};

pub const VENDOR_CONFIG_KEY_1: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    ecc_key_idx: 1,
    lms_key_idx: 1,
    ..VENDOR_CONFIG_KEY_0
};

pub const VENDOR_CONFIG_KEY_2: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    ecc_key_idx: 2,
    lms_key_idx: 2,
    ..VENDOR_CONFIG_KEY_0
};

pub const VENDOR_CONFIG_KEY_3: ImageGeneratorVendorConfig = ImageGeneratorVendorConfig {
    ecc_key_idx: 3,
    lms_key_idx: 3,
    ..VENDOR_CONFIG_KEY_0
};

pub const OWNER_CONFIG: ImageGeneratorOwnerConfig = ImageGeneratorOwnerConfig {
    pub_keys: ImageOwnerPubKeys {
        ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
        lms_pub_key: OWNER_LMS_KEY_PUBLIC,
    },
    priv_keys: Some(ImageOwnerPrivKeys {
        ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
        lms_priv_key: OWNER_LMS_KEY_PRIVATE,
    }),
    not_before: [0u8; 15],
    not_after: [0u8; 15],
    epoch: [0u8; 2],
};

#[test]
#[ignore]
fn test_write_lms_keys() {
    for i in 0..VENDOR_PRIVATE_KEYS.lms_priv_keys.len() {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(format!(
                "../../target/riscv32imc-unknown-none-elf/firmware/vnd-lms-priv-key-{}.pem",
                i
            ))
            .unwrap();
        file.write_all(VENDOR_PRIVATE_KEYS.lms_priv_keys[i].as_bytes())
            .unwrap();
    }
    for i in 0..VENDOR_PUBLIC_KEYS.lms_pub_keys.len() {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(format!(
                "../../target/riscv32imc-unknown-none-elf/firmware/vnd-lms-pub-key-{}.pem",
                i
            ))
            .unwrap();
        file.write_all(VENDOR_PUBLIC_KEYS.lms_pub_keys[i].as_bytes())
            .unwrap();
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("../../target/riscv32imc-unknown-none-elf/firmware/own-lms-priv-key.pem")
        .unwrap();
    file.write_all(OWNER_PRIVATE_KEYS.lms_priv_key.as_bytes())
        .unwrap();

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("../../target/riscv32imc-unknown-none-elf/firmware/own-lms-pub-key.pem")
        .unwrap();
    file.write_all(OWNER_PUBLIC_KEYS.lms_pub_key.as_bytes())
        .unwrap();
}
