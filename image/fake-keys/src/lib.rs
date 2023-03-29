// Licensed under the Apache-2.0 license

use caliptra_image_types::{ImageEccPrivKey, ImageEccPubKey};

/// Generated with
///
/// ```no_run
/// use caliptra_image_openssl;
/// use std::path::PathBuf;
///
/// fn print_public_key(name: &str, path: &str) {
///     let key = caliptra_image_openssl::ecc_pub_key_from_pem(&PathBuf::from(path)).unwrap();
///     println!("pub const {name}_PUBLIC: ImageEccPubKey = {key:#010x?};");
/// }
/// fn print_private_key(name: &str, path: &str) {
///     let key = caliptra_image_openssl::ecc_priv_key_from_pem(&PathBuf::from(path)).unwrap();
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
pub const VENDOR_KEY_0_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xc69fe67f, 0x97ea3e42, 0x21a7a603, 0x6c2e070d, 0x1657327b, 0xc3f1e7c1, 0x8dccb9e4,
        0xffda5c3f, 0x4db0a1c0, 0x567e0973, 0x17bf4484, 0x39696a07,
    ],
    y: [
        0xc126b913, 0x5fc82572, 0x8f1cd403, 0x19109430, 0x994fe3e8, 0x74a8b026, 0xbe14794d,
        0x27789964, 0x7735fde8, 0x328afd84, 0xcd4d4aa8, 0x72d40b42,
    ],
};
pub const VENDOR_KEY_0_PRIVATE: ImageEccPrivKey = [
    0x29f939ea, 0x41746499, 0xd550c6fa, 0x6368b0d7, 0x61e09b4c, 0x75b21922, 0x86f96240, 0x00ea1d99,
    0xace94ba6, 0x7ae89b0e, 0x3f210cf1, 0x9a45b6b5,
];
pub const VENDOR_KEY_1_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xa6309750, 0xf0a05ddb, 0x956a7f86, 0x2812ec4f, 0xec454e95, 0x3b53dbfb, 0x9eb54140,
        0x15ea7507, 0x084af93c, 0xb7fa33fe, 0x51811ad5, 0xe754232e,
    ],
    y: [
        0xef5a5987, 0x7a0ce0be, 0x2621d2a9, 0x8bf3c5df, 0xaf7b3d6d, 0x97f24183, 0xa4a42038,
        0x58c39b86, 0x272ef548, 0xe572b937, 0x1ecf1994, 0x1b8d4ea7,
    ],
};
pub const VENDOR_KEY_1_PRIVATE: ImageEccPrivKey = [
    0xf2ee427b, 0x4412f46f, 0x8fb020a5, 0xc23b0154, 0xb3fcb201, 0xf93c2ee2, 0x923fd577, 0xf85320bb,
    0x289eb276, 0x2b6b21d3, 0x5cdb3925, 0xa57d5043,
];
pub const VENDOR_KEY_2_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xa0d25693, 0xc4251e48, 0x185615b0, 0xa6c27f6d, 0xe62c39f5, 0xa9a32f75, 0x9553226a,
        0x4d1926c1, 0x7928910f, 0xb7adc1b6, 0x89996733, 0x10134881,
    ],
    y: [
        0xbbdf72d7, 0x07c08100, 0xd54fcdad, 0xb1567bb0, 0x0522762b, 0x76b8dc4a, 0x846c175a,
        0x3fbd0501, 0x9bdc8118, 0x4be5f33c, 0xbb21b41d, 0x93a8c523,
    ],
};
pub const VENDOR_KEY_2_PRIVATE: ImageEccPrivKey = [
    0xaf72a74c, 0xfbbacc3c, 0x7ad2f9d9, 0xc969d1c9, 0x19c2d803, 0x0a53749a, 0xee730267, 0x7c11a52d,
    0xee63e4c8, 0x0b5c0293, 0x28d35c27, 0x5f959aee,
];
pub const VENDOR_KEY_3_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0x002a82b6, 0x8e03e9a0, 0xfd3b4c14, 0xca2cb3e8, 0x14350a71, 0x0e43956d, 0x21694fb4,
        0xf34485e8, 0xf0e33583, 0xf7ea142d, 0x50e16f8b, 0x0225bb95,
    ],
    y: [
        0x5802641c, 0x7c45a4a2, 0x408e03a6, 0xa4100a92, 0x50fcc468, 0xd238cd0d, 0x449cc3e5,
        0x1abc25e7, 0x0b05c426, 0x843dcd6f, 0x944ef6ff, 0xfa53ec5b,
    ],
};
pub const VENDOR_KEY_3_PRIVATE: ImageEccPrivKey = [
    0xafbdfc7d, 0x36b54629, 0xd12c4cb5, 0x33926c30, 0x20611617, 0x86b50b23, 0x6046ff93, 0x17ea0144,
    0xbc900c70, 0xb8cb36ac, 0x268b8079, 0xe3aeaaaf,
];
pub const OWNER_KEY_PUBLIC: ImageEccPubKey = ImageEccPubKey {
    x: [
        0xc6f82e2b, 0xdcf3e157, 0xa162e7f3, 0x3eca35c4, 0x55ea08a9, 0x13811779, 0xb6f2646d,
        0x92c817cd, 0x4094bd1a, 0xdb215f62, 0xcf36f017, 0x012d5aeb,
    ],
    y: [
        0xa4674593, 0x6cb5a379, 0x99b08264, 0x862b2c1c, 0x517f12c6, 0x573e1f94, 0x7142291a,
        0xf9624bd7, 0x2733dcdd, 0xce24ec5e, 0x961c00e3, 0x4372ba17,
    ],
};
pub const OWNER_KEY_PRIVATE: ImageEccPrivKey = [
    0x59fdf849, 0xe39f4256, 0x19342ed2, 0x81d28d3d, 0x45ab3219, 0x5174582c, 0xecb4e9df, 0x9cc2e991,
    0xb75f88fd, 0xfa4bc6a4, 0x6b88340f, 0x05dd8890,
];
