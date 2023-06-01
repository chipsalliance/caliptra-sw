/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_24_tests.rs

Abstract:

    File contains test cases for LMS signature verification using SHA256/192.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    lookup_lmots_algorithm_type, lookup_lms_algorithm_type, HashValue, LmotsAlgorithmType,
    LmotsSignature, Lms, LmsAlgorithmType, LmsIdentifier, LmsSignature, Sha192Digest, Sha256,
};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::test_suite;

fn test_lms_lookup() {
    let result = lookup_lms_algorithm_type(0);
    assert_eq!(LmsAlgorithmType::LmsReserved, result.unwrap())
}
const fn bytes_to_words_6(bytes: [u8; 24]) -> HashValue<6> {
    let mut result = [0_u32; 6];
    let mut i = 0;
    while i < result.len() {
        result[i] = u32::from_be_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
        i += 1;
    }
    HashValue(result)
}
fn test_get_lms_parameters() {
    // Full size SHA256 hashes
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H5)
        .unwrap();
    assert_eq!(32, width);
    assert_eq!(5, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H10)
        .unwrap();
    assert_eq!(32, width);
    assert_eq!(10, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H15)
        .unwrap();
    assert_eq!(32, width);
    assert_eq!(15, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H20)
        .unwrap();
    assert_eq!(32, width);
    assert_eq!(20, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H25)
        .unwrap();
    assert_eq!(32, width);
    assert_eq!(25, height);

    // Truncated 192 bit SHA256 hashes
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H5)
        .unwrap();
    assert_eq!(24, width);
    assert_eq!(5, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H10)
        .unwrap();
    assert_eq!(24, width);
    assert_eq!(10, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H15)
        .unwrap();
    assert_eq!(24, width);
    assert_eq!(15, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H20)
        .unwrap();
    assert_eq!(24, width);
    assert_eq!(20, height);
    let (width, height) = Lms::default()
        .get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H25)
        .unwrap();
    assert_eq!(24, width);
    assert_eq!(25, height);
}

fn test_lmots_lookup() {
    let result = lookup_lmots_algorithm_type(0);
    assert_eq!(LmotsAlgorithmType::LmotsReserved, result.unwrap())
}

// test case from https://datatracker.ietf.org/doc/html/rfc8554#section-3.1.3
fn test_coefficient() {
    let input_value = [0x12u8, 0x34u8];
    let result = Lms::default().coefficient(&input_value, 7, 1).unwrap();
    assert_eq!(result, 0);

    let result = Lms::default().coefficient(&input_value, 0, 4).unwrap();
    assert_eq!(result, 1);
}

fn test_hash_message_24() {
    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };
    let message: [u8; 33] = [
        116, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 109, 101, 115, 115, 97, 103, 101,
        32, 73, 32, 119, 97, 110, 116, 32, 115, 105, 103, 110, 101, 100,
    ];
    let lms_identifier: LmsIdentifier = [
        102, 40, 233, 90, 126, 166, 161, 73, 107, 57, 114, 28, 121, 57, 28, 123,
    ];
    let nonce: [u32; 6] = bytes_to_words_6([
        108, 201, 169, 93, 130, 206, 214, 173, 223, 138, 178, 150, 192, 86, 115, 139, 157, 213,
        182, 55, 196, 22, 212, 216,
    ])
    .0;
    let q: u32 = 0;
    let q_str = q.to_be_bytes();
    let expected_hash = HashValue::from([
        175, 160, 9, 71, 29, 26, 61, 20, 90, 217, 142, 152, 112, 68, 51, 17, 154, 191, 74, 150,
        161, 238, 102, 161,
    ]);
    let hash = Lms::default()
        .hash_message(&mut sha256, &message, &lms_identifier, &q_str, &nonce)
        .unwrap();
    assert_eq!(expected_hash, hash);
}

fn test_lms_24_height_15() {
    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };
    const MESSAGE: [u8; 33] = [
        116, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 109, 101, 115, 115, 97, 103, 101,
        32, 73, 32, 119, 97, 110, 116, 32, 115, 105, 103, 110, 101, 100,
    ];
    const LMS_IDENTIFIER: LmsIdentifier = [
        158, 20, 249, 74, 242, 177, 66, 175, 101, 91, 176, 36, 80, 31, 240, 7,
    ];
    const Q: u32 = 0;
    const LMOTS_TYPE: LmotsAlgorithmType = LmotsAlgorithmType::LmotsSha256N24W4;
    const LMS_TYPE: LmsAlgorithmType = LmsAlgorithmType::LmsSha256N24H15;

    const LMS_PUBLIC_HASH: HashValue<6> = bytes_to_words_6([
        0x03, 0x2a, 0xa2, 0xbd, 0x9b, 0x31, 0xe9, 0xbd, 0x33, 0x4b, 0x46, 0x2e, 0x27, 0x79, 0x20,
        0x75, 0xbd, 0xad, 0xdd, 0xae, 0xf9, 0xed, 0xb1, 0x24,
    ]);

    const NONCE: [u32; 6] = bytes_to_words_6([
        0xb4, 0x24, 0x09, 0xdb, 0xdd, 0x4a, 0x1c, 0x49, 0xfc, 0x79, 0x37, 0x94, 0x75, 0xe9, 0xc7,
        0x67, 0x1c, 0x7f, 0x51, 0x53, 0xf7, 0x53, 0x5a, 0xc4,
    ])
    .0;

    const Y: [HashValue<6>; 51] = [
        bytes_to_words_6([
            0x72, 0x53, 0xaf, 0x69, 0xc8, 0x5a, 0x5b, 0x96, 0x10, 0x55, 0xcc, 0x03, 0xb7, 0xe1,
            0xee, 0x83, 0xab, 0xb0, 0x32, 0xb3, 0x14, 0x58, 0xfa, 0x69,
        ]),
        bytes_to_words_6([
            0x00, 0xd4, 0xf4, 0xfc, 0xda, 0x35, 0x7d, 0xc9, 0xa9, 0x44, 0x10, 0x23, 0x3d, 0x4b,
            0x00, 0xb4, 0xb9, 0x2c, 0xa8, 0x6e, 0xf0, 0xf8, 0xfd, 0x13,
        ]),
        bytes_to_words_6([
            0xd2, 0xad, 0x7e, 0x03, 0xec, 0x32, 0xc0, 0x59, 0x8f, 0x9b, 0x64, 0xfd, 0x8c, 0x6f,
            0x82, 0x79, 0xf7, 0x8e, 0x88, 0xe7, 0x7b, 0x4c, 0xdb, 0x89,
        ]),
        bytes_to_words_6([
            0x6c, 0xe4, 0x9e, 0x66, 0x3b, 0x32, 0x6b, 0x29, 0x1d, 0xe5, 0xc9, 0xdb, 0xdf, 0xab,
            0x05, 0x68, 0x1d, 0xb5, 0x86, 0x68, 0x1e, 0x80, 0xe6, 0xaf,
        ]),
        bytes_to_words_6([
            0xba, 0x95, 0x8f, 0xbe, 0x1c, 0x83, 0xbe, 0x4e, 0x1a, 0xd2, 0x3f, 0x0e, 0x0e, 0x97,
            0xa6, 0xb0, 0xe8, 0x00, 0xf3, 0xce, 0x97, 0xb5, 0xfc, 0xb0,
        ]),
        bytes_to_words_6([
            0x94, 0x9e, 0x57, 0xed, 0x65, 0xb9, 0x5c, 0x2c, 0xb9, 0xbb, 0x4c, 0x84, 0x4e, 0x4e,
            0x4c, 0xe3, 0x1f, 0x63, 0xf1, 0x2b, 0x01, 0x5d, 0x35, 0xbc,
        ]),
        bytes_to_words_6([
            0xad, 0xef, 0xb1, 0xee, 0x3a, 0xb2, 0xc4, 0x6d, 0x0c, 0x3b, 0x52, 0x4d, 0x92, 0x40,
            0xed, 0xf1, 0xcc, 0xc7, 0x09, 0xa7, 0xf9, 0x78, 0x55, 0x13,
        ]),
        bytes_to_words_6([
            0xf7, 0x8c, 0xf3, 0xcc, 0x15, 0xe1, 0xb9, 0xb1, 0x71, 0xa9, 0x2f, 0x26, 0x33, 0x47,
            0x59, 0x5c, 0x24, 0xf2, 0xd5, 0xbe, 0xae, 0xa6, 0x97, 0x93,
        ]),
        bytes_to_words_6([
            0x4a, 0x52, 0x99, 0xfe, 0x4c, 0x7e, 0x6c, 0x83, 0x30, 0x9f, 0x98, 0xc0, 0x5e, 0xc3,
            0xd6, 0x27, 0x9d, 0x33, 0x50, 0x81, 0xef, 0xa7, 0x48, 0x31,
        ]),
        bytes_to_words_6([
            0x6b, 0x34, 0x75, 0x7d, 0xf9, 0x1a, 0x72, 0x39, 0xaf, 0xf2, 0x6b, 0x46, 0x5e, 0xc4,
            0x80, 0x9e, 0x22, 0x22, 0x9b, 0xee, 0x79, 0xac, 0x90, 0x11,
        ]),
        bytes_to_words_6([
            0xac, 0xb3, 0xee, 0xa6, 0x42, 0x30, 0xb3, 0xd4, 0xeb, 0x54, 0x1a, 0xad, 0xa7, 0xb5,
            0x6d, 0x44, 0x15, 0x93, 0x81, 0x7a, 0x1c, 0x0a, 0x47, 0x3b,
        ]),
        bytes_to_words_6([
            0x02, 0x02, 0x95, 0xb8, 0x60, 0x41, 0x64, 0xb9, 0xbe, 0xdb, 0x11, 0xef, 0xb0, 0x39,
            0x43, 0x9e, 0x88, 0xa3, 0x0e, 0x5d, 0x9a, 0xf4, 0x80, 0x69,
        ]),
        bytes_to_words_6([
            0x16, 0xca, 0xa9, 0x22, 0xec, 0x5d, 0x33, 0x0b, 0x09, 0x54, 0xa3, 0x17, 0x8d, 0x1c,
            0xd8, 0xbd, 0xd2, 0x8c, 0x64, 0xfc, 0x07, 0x9e, 0xd8, 0x23,
        ]),
        bytes_to_words_6([
            0xbc, 0x7a, 0xbb, 0x42, 0x76, 0xda, 0x10, 0x58, 0xa2, 0x3c, 0xf4, 0x00, 0x08, 0x63,
            0xea, 0x20, 0x04, 0x5b, 0xe2, 0xf2, 0xb8, 0xdc, 0x7e, 0xcf,
        ]),
        bytes_to_words_6([
            0x0b, 0x30, 0xc2, 0x12, 0x8e, 0xa5, 0x37, 0xb9, 0x0e, 0x76, 0x4b, 0x3a, 0x49, 0x79,
            0xd6, 0x6d, 0x67, 0x30, 0x71, 0x90, 0x90, 0xdb, 0x89, 0x5b,
        ]),
        bytes_to_words_6([
            0x61, 0xbb, 0xc3, 0x6a, 0x85, 0x37, 0x69, 0x4c, 0x23, 0x4f, 0x5a, 0x11, 0xe5, 0xc3,
            0x0d, 0xa5, 0x39, 0x7b, 0x7f, 0x7c, 0x87, 0xf4, 0xec, 0xdc,
        ]),
        bytes_to_words_6([
            0xd6, 0x63, 0x57, 0xdb, 0xa0, 0x08, 0xa1, 0x87, 0x8a, 0x89, 0x2a, 0x58, 0x0c, 0x5a,
            0x72, 0x7a, 0xf2, 0x03, 0x16, 0x1c, 0x13, 0x54, 0x14, 0xc9,
        ]),
        bytes_to_words_6([
            0x3e, 0xe0, 0xf7, 0xa9, 0x34, 0xc5, 0xd2, 0x2b, 0xf5, 0x93, 0x05, 0x03, 0xaa, 0xd9,
            0xb8, 0x6d, 0x79, 0x7e, 0xf9, 0xea, 0xce, 0x0d, 0x39, 0x9e,
        ]),
        bytes_to_words_6([
            0x6f, 0x80, 0xb7, 0x3e, 0x9a, 0x46, 0xa9, 0x23, 0x11, 0x09, 0xa1, 0x54, 0x1d, 0xf7,
            0x21, 0x36, 0x13, 0x87, 0x3f, 0x73, 0xb6, 0xb9, 0xb8, 0xca,
        ]),
        bytes_to_words_6([
            0x7e, 0x66, 0xc4, 0x94, 0x75, 0xd8, 0xc1, 0x7e, 0xea, 0xf4, 0xa2, 0x2b, 0x1e, 0x9c,
            0x0f, 0x74, 0xfc, 0x5a, 0xb0, 0xe2, 0x16, 0xba, 0x54, 0x75,
        ]),
        bytes_to_words_6([
            0xb0, 0x82, 0x56, 0x96, 0x36, 0xdc, 0xbf, 0xfd, 0xd8, 0xea, 0x96, 0x55, 0xb7, 0x8b,
            0x3a, 0x99, 0x1d, 0x32, 0xd7, 0xf2, 0x96, 0x7a, 0xd8, 0x74,
        ]),
        bytes_to_words_6([
            0xd5, 0x39, 0x88, 0x92, 0xfb, 0xd4, 0x5d, 0xba, 0x66, 0xa7, 0xc5, 0x01, 0x46, 0xf2,
            0x29, 0x7c, 0x3c, 0x27, 0xac, 0xd8, 0x8c, 0xe0, 0x10, 0x8b,
        ]),
        bytes_to_words_6([
            0xd1, 0x50, 0x2d, 0x6a, 0x79, 0xb4, 0x93, 0xc5, 0x35, 0x00, 0xc2, 0x36, 0xba, 0x26,
            0xab, 0xad, 0x8f, 0x57, 0x91, 0x23, 0xe6, 0xc1, 0x0e, 0xc9,
        ]),
        bytes_to_words_6([
            0xf4, 0xa0, 0x60, 0xd3, 0xe2, 0x85, 0x2b, 0x9a, 0xd9, 0x7f, 0xe4, 0xb4, 0x58, 0x70,
            0x33, 0x8a, 0x3f, 0xcc, 0x47, 0xb1, 0xf1, 0xd1, 0x0c, 0xd2,
        ]),
        bytes_to_words_6([
            0xfd, 0x28, 0x15, 0xbd, 0x21, 0xdd, 0x0a, 0xea, 0x78, 0xac, 0x0b, 0xe6, 0xd9, 0xb1,
            0x34, 0xe0, 0xc2, 0x50, 0x73, 0xd9, 0x42, 0x5b, 0xea, 0x4e,
        ]),
        bytes_to_words_6([
            0x8e, 0x2d, 0x99, 0x28, 0xf2, 0x3e, 0x8b, 0xf3, 0xed, 0x62, 0x8f, 0xf8, 0x88, 0x39,
            0x6e, 0x74, 0x9e, 0x55, 0xae, 0x66, 0xf5, 0x9a, 0x84, 0x6c,
        ]),
        bytes_to_words_6([
            0x7f, 0xc4, 0x7b, 0x8b, 0x66, 0xd5, 0xd3, 0xdc, 0x47, 0xac, 0x7f, 0x28, 0x58, 0xb9,
            0x3b, 0xa0, 0x46, 0xa4, 0x6e, 0x82, 0x6b, 0x8f, 0x3a, 0xa9,
        ]),
        bytes_to_words_6([
            0x6a, 0x9b, 0x98, 0x75, 0x46, 0x04, 0xea, 0x7c, 0xbc, 0xc8, 0xb9, 0xb4, 0xba, 0xb9,
            0x43, 0xda, 0xcf, 0x60, 0x21, 0x9c, 0xb1, 0xd4, 0xed, 0x67,
        ]),
        bytes_to_words_6([
            0x1c, 0x32, 0x0a, 0xf7, 0xae, 0x84, 0x83, 0x75, 0xeb, 0x9c, 0xc7, 0xb0, 0xec, 0x30,
            0x45, 0xbe, 0x79, 0xfd, 0x11, 0x7c, 0xcd, 0x26, 0x97, 0x5e,
        ]),
        bytes_to_words_6([
            0x3c, 0x2d, 0x4a, 0x35, 0x2e, 0x10, 0x3c, 0x3d, 0x76, 0x89, 0xb3, 0xac, 0xf2, 0xcc,
            0x56, 0xd0, 0xed, 0x7a, 0x6f, 0x58, 0x76, 0xec, 0x40, 0x96,
        ]),
        bytes_to_words_6([
            0x1a, 0x5a, 0xad, 0x8c, 0xe1, 0x08, 0xa7, 0xcb, 0x3b, 0xf1, 0x1b, 0x01, 0x1c, 0xb6,
            0x0e, 0x47, 0xf3, 0x45, 0x87, 0xf3, 0xf7, 0x95, 0x47, 0x72,
        ]),
        bytes_to_words_6([
            0x86, 0xe5, 0x24, 0xa6, 0x0d, 0xfa, 0xef, 0x82, 0xfc, 0x6c, 0x8d, 0xa1, 0x81, 0x95,
            0x85, 0x58, 0x93, 0x27, 0xf6, 0x29, 0x69, 0xc9, 0x77, 0xb7,
        ]),
        bytes_to_words_6([
            0xe9, 0x4a, 0xe9, 0xbf, 0xae, 0x42, 0x14, 0x93, 0xfc, 0xb7, 0x14, 0x38, 0x47, 0x2f,
            0x0d, 0x03, 0x7c, 0x82, 0x43, 0xe1, 0x6e, 0x29, 0x75, 0x3f,
        ]),
        bytes_to_words_6([
            0xd4, 0x9c, 0xc3, 0xdd, 0xc5, 0x59, 0x7b, 0x23, 0x87, 0xe7, 0x03, 0xa9, 0x9a, 0xc9,
            0x97, 0x73, 0x13, 0xfa, 0xa7, 0x19, 0x5b, 0x41, 0xda, 0x72,
        ]),
        bytes_to_words_6([
            0x6c, 0xe0, 0x02, 0xa4, 0xe9, 0x27, 0x72, 0xf4, 0xea, 0x74, 0xf4, 0xe9, 0x09, 0xbf,
            0x80, 0x28, 0xfd, 0xd7, 0x7f, 0x8a, 0x09, 0xc0, 0x60, 0x51,
        ]),
        bytes_to_words_6([
            0x19, 0xc7, 0xb9, 0x88, 0x70, 0x58, 0xd5, 0x45, 0x6b, 0xba, 0x3c, 0x62, 0x80, 0x27,
            0xc8, 0x8d, 0xf7, 0xa8, 0xf7, 0xa9, 0xfe, 0xf5, 0xa6, 0x41,
        ]),
        bytes_to_words_6([
            0x9a, 0x5b, 0x69, 0xed, 0xc4, 0xac, 0x81, 0x98, 0x1f, 0xeb, 0x40, 0xb8, 0xc7, 0xa9,
            0xa7, 0x6d, 0x1c, 0x5a, 0x81, 0x72, 0x17, 0xcb, 0xa8, 0xf8,
        ]),
        bytes_to_words_6([
            0x5c, 0x67, 0xb8, 0x99, 0x6f, 0x89, 0xda, 0x71, 0x20, 0xae, 0x5e, 0xe6, 0x2c, 0x16,
            0xab, 0x59, 0x1c, 0x81, 0xb5, 0x82, 0xc6, 0x88, 0x6f, 0x6e,
        ]),
        bytes_to_words_6([
            0x7f, 0xca, 0xf9, 0x20, 0xad, 0xd6, 0xe6, 0x0d, 0x89, 0xb9, 0xf9, 0xa1, 0x32, 0xcf,
            0x69, 0xbb, 0xf8, 0x73, 0xf5, 0x80, 0xc9, 0x69, 0x63, 0xf4,
        ]),
        bytes_to_words_6([
            0x01, 0x9d, 0x0d, 0x47, 0x23, 0xdd, 0xc6, 0x64, 0xd7, 0x7d, 0xcc, 0x4d, 0x5f, 0x5b,
            0x6d, 0x14, 0xa6, 0x9a, 0xe2, 0x2b, 0x36, 0x3c, 0x61, 0x48,
        ]),
        bytes_to_words_6([
            0x7f, 0xe2, 0xb3, 0xcb, 0xa1, 0x23, 0x2b, 0x2f, 0x94, 0x2e, 0x0e, 0x33, 0x04, 0x40,
            0xd4, 0xd3, 0x1b, 0x68, 0xdc, 0xe4, 0x83, 0x4a, 0xd7, 0x28,
        ]),
        bytes_to_words_6([
            0xf0, 0x45, 0xa8, 0x69, 0x91, 0x8c, 0x0f, 0x7f, 0x11, 0x6c, 0x06, 0xf7, 0x03, 0xcb,
            0x76, 0x9b, 0x6a, 0x6c, 0x36, 0x20, 0x77, 0xcf, 0xf4, 0x4f,
        ]),
        bytes_to_words_6([
            0x81, 0x03, 0xed, 0xe3, 0x52, 0x13, 0xcb, 0x73, 0x98, 0x0e, 0x15, 0xd9, 0xa6, 0x32,
            0xdb, 0xcd, 0xaa, 0x77, 0xa8, 0xdb, 0x71, 0xc4, 0x63, 0xd7,
        ]),
        bytes_to_words_6([
            0xb5, 0x1f, 0x08, 0xcb, 0x63, 0x81, 0x18, 0x3e, 0xa1, 0x35, 0x13, 0xbe, 0xea, 0x35,
            0x6a, 0xcd, 0x5a, 0x35, 0xc4, 0x4f, 0x57, 0x82, 0xdc, 0xbf,
        ]),
        bytes_to_words_6([
            0xd2, 0xf2, 0x32, 0x3b, 0xbb, 0x5c, 0x57, 0x71, 0x72, 0xfd, 0x27, 0xf3, 0x70, 0x96,
            0x9d, 0xf5, 0x91, 0x0a, 0x9e, 0x0e, 0xb9, 0x9c, 0xd0, 0x29,
        ]),
        bytes_to_words_6([
            0x3b, 0xae, 0x2c, 0x0d, 0xeb, 0x53, 0x95, 0x20, 0x71, 0xc7, 0x0d, 0xd5, 0x19, 0x46,
            0x9f, 0x55, 0x24, 0xec, 0x52, 0xde, 0x83, 0xe1, 0x0d, 0x28,
        ]),
        bytes_to_words_6([
            0x5a, 0x60, 0x9b, 0xcb, 0x30, 0x30, 0xe7, 0xdd, 0xdc, 0x50, 0x30, 0xb6, 0x68, 0xe3,
            0xfb, 0x84, 0x41, 0x90, 0x18, 0x3f, 0xd5, 0xa1, 0x1e, 0xe4,
        ]),
        bytes_to_words_6([
            0xb4, 0xce, 0x3e, 0x30, 0xb6, 0x24, 0xae, 0x97, 0x70, 0x5f, 0xac, 0x89, 0x1c, 0x7e,
            0x22, 0x6e, 0x2e, 0x0d, 0xfd, 0xd3, 0x12, 0x7e, 0xfe, 0x7d,
        ]),
        bytes_to_words_6([
            0x80, 0x51, 0x45, 0x80, 0x62, 0xfd, 0xa1, 0xff, 0x6e, 0x81, 0x70, 0x39, 0x43, 0xf5,
            0xb7, 0xd2, 0x39, 0xa2, 0xfc, 0xee, 0x1d, 0xd2, 0xc0, 0x4f,
        ]),
        bytes_to_words_6([
            0x43, 0x72, 0xfd, 0x39, 0xf2, 0xaa, 0x8b, 0x76, 0xda, 0x11, 0x2a, 0xb7, 0x28, 0x4e,
            0xc2, 0xff, 0xce, 0xde, 0x59, 0x5e, 0x87, 0xd8, 0x42, 0x1a,
        ]),
        bytes_to_words_6([
            0x3f, 0xbe, 0x60, 0x0b, 0x2f, 0x2a, 0x0f, 0x44, 0x12, 0xde, 0xcf, 0x64, 0xb7, 0x97,
            0xb7, 0x1d, 0xb2, 0x46, 0xfc, 0xdd, 0x46, 0xca, 0xf9, 0x11,
        ]),
    ];
    const PATH: [HashValue<6>; 15] = [
        bytes_to_words_6([
            0xbe, 0x59, 0x73, 0xbc, 0xe7, 0x93, 0x5f, 0x53, 0x40, 0xe9, 0x26, 0xa9, 0xfc, 0xb3,
            0xcb, 0x9d, 0x2d, 0x29, 0x22, 0x19, 0x28, 0xd3, 0x77, 0x01,
        ]),
        bytes_to_words_6([
            0xac, 0xca, 0x20, 0x2f, 0x08, 0x49, 0x75, 0x99, 0xf8, 0x3e, 0xd4, 0x24, 0xff, 0x25,
            0xd2, 0xa8, 0xb6, 0x16, 0xf1, 0xe2, 0x48, 0xf0, 0xf1, 0xba,
        ]),
        bytes_to_words_6([
            0xcd, 0xd8, 0x16, 0x9b, 0x7e, 0x86, 0xba, 0x21, 0xd1, 0x59, 0xaa, 0x85, 0x62, 0x2e,
            0x9d, 0x21, 0x7c, 0x74, 0x76, 0xd5, 0xf3, 0xa7, 0xcd, 0xfb,
        ]),
        bytes_to_words_6([
            0xeb, 0x44, 0x55, 0x41, 0xa7, 0xa5, 0xa3, 0xab, 0x78, 0x92, 0xb3, 0x71, 0x81, 0x43,
            0x94, 0x6e, 0xa0, 0xc1, 0xe4, 0xff, 0x83, 0x7f, 0xb0, 0xf3,
        ]),
        bytes_to_words_6([
            0x68, 0xfe, 0xed, 0x20, 0xc9, 0x09, 0x01, 0xc1, 0xda, 0xcd, 0xf3, 0x0b, 0x90, 0xd3,
            0x3f, 0x6f, 0x4b, 0x17, 0x93, 0xa5, 0x57, 0x06, 0xc5, 0x43,
        ]),
        bytes_to_words_6([
            0x3a, 0x01, 0x82, 0x46, 0xba, 0xe1, 0x03, 0xe7, 0x97, 0x94, 0xfc, 0x1f, 0xa5, 0xc2,
            0x03, 0xfd, 0x8b, 0xf0, 0xc7, 0x77, 0xb4, 0x07, 0xaa, 0xde,
        ]),
        bytes_to_words_6([
            0xa1, 0x63, 0x82, 0xeb, 0x04, 0x9d, 0x45, 0x83, 0x62, 0xf7, 0xb6, 0x3e, 0x30, 0x04,
            0xf9, 0x2c, 0x92, 0x66, 0x0e, 0x63, 0x17, 0x18, 0xf7, 0x60,
        ]),
        bytes_to_words_6([
            0x08, 0x42, 0x49, 0x45, 0x57, 0xac, 0x9b, 0x94, 0x7a, 0x21, 0x46, 0xb1, 0x22, 0xd2,
            0xe7, 0x5f, 0x3a, 0x3d, 0x75, 0x9e, 0x5a, 0xba, 0xee, 0x58,
        ]),
        bytes_to_words_6([
            0x1c, 0xbb, 0xea, 0x87, 0xbc, 0x7a, 0xf8, 0xfe, 0x78, 0xc7, 0x0c, 0x66, 0x00, 0x41,
            0xc5, 0x3e, 0xda, 0xcf, 0x17, 0x3d, 0x95, 0x7a, 0x2c, 0xe1,
        ]),
        bytes_to_words_6([
            0xaa, 0x37, 0x7c, 0x8c, 0x02, 0x5b, 0xb4, 0x98, 0xc7, 0x6d, 0x96, 0x07, 0x21, 0x44,
            0x82, 0x06, 0x7d, 0xe2, 0xb5, 0x4a, 0x0e, 0xf4, 0xec, 0xec,
        ]),
        bytes_to_words_6([
            0x50, 0x86, 0x6a, 0x67, 0x69, 0xe6, 0xef, 0xb3, 0x9d, 0xaf, 0x9e, 0xc4, 0xaf, 0x6c,
            0xe9, 0x3b, 0xe8, 0x72, 0x3d, 0x8c, 0xa5, 0xd8, 0x98, 0x07,
        ]),
        bytes_to_words_6([
            0x4b, 0xe3, 0x74, 0xde, 0xa1, 0x9a, 0x32, 0x52, 0xf9, 0xc5, 0xbe, 0x94, 0x37, 0x97,
            0xf7, 0xa1, 0x01, 0xb7, 0x43, 0x68, 0xe6, 0x6f, 0x2f, 0x55,
        ]),
        bytes_to_words_6([
            0x1e, 0xec, 0xde, 0xb6, 0xde, 0xcb, 0x87, 0x2d, 0x70, 0x47, 0x59, 0x93, 0x50, 0xc2,
            0x06, 0xaf, 0x36, 0xb2, 0x09, 0x63, 0xb9, 0x7e, 0xc6, 0x87,
        ]),
        bytes_to_words_6([
            0x25, 0xf0, 0x11, 0x78, 0x5c, 0x1f, 0xe2, 0x2d, 0xee, 0x81, 0xe8, 0x1f, 0x60, 0x8a,
            0x76, 0xb7, 0xac, 0x8b, 0xb9, 0xc3, 0xf1, 0xac, 0x68, 0x4f,
        ]),
        bytes_to_words_6([
            0x73, 0xd6, 0x27, 0xd5, 0x6a, 0xf2, 0x6e, 0x31, 0x2d, 0xbf, 0xf6, 0x7f, 0x94, 0x0a,
            0x83, 0x0a, 0xd5, 0x38, 0x67, 0x4b, 0xc5, 0x9b, 0x4e, 0x39,
        ]),
    ];

    const OTS: LmotsSignature<6, 51> = LmotsSignature {
        ots_type: LMOTS_TYPE,
        nonce: NONCE,
        y: Y,
    };

    const LMS_SIG: LmsSignature<6, 51> = LmsSignature {
        q: Q,
        lmots_signature: OTS,
        sig_type: LMS_TYPE,
        lms_path: &PATH,
    };

    let success = Lms::default()
        .verify_lms_signature(
            &mut sha256,
            &MESSAGE,
            &LMS_IDENTIFIER,
            Q,
            &LMS_PUBLIC_HASH,
            &LMS_SIG,
        )
        .unwrap();
    assert_eq!(success, true);
}

fn _test_lms_24_height_20() {
    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };
    const MESSAGE: [u8; 33] = [
        116, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 109, 101, 115, 115, 97, 103, 101,
        32, 73, 32, 119, 97, 110, 116, 32, 115, 105, 103, 110, 101, 100,
    ];
    const LMS_IDENTIFIER: LmsIdentifier = [
        69, 136, 206, 137, 163, 10, 230, 185, 177, 120, 219, 80, 34, 70, 71, 93,
    ];
    let q: u32 = 0;
    let lmots_type = LmotsAlgorithmType::LmotsSha256N24W4;
    let lms_type = LmsAlgorithmType::LmsSha256N24H20;
    let lms_public_key: HashValue<6> = HashValue::from([
        180, 158, 253, 95, 46, 160, 158, 176, 138, 132, 212, 106, 19, 251, 152, 71, 149, 125, 57,
        221, 202, 204, 143, 224,
    ]);
    let u8_nonce: [u8; 24] = [
        212, 38, 50, 98, 221, 141, 147, 187, 22, 227, 203, 231, 132, 97, 130, 157, 22, 242, 183,
        46, 70, 120, 159, 206,
    ];
    let mut nonce = [0u32; 6];
    for i in 0..6 {
        nonce[i] = u32::from_be_bytes([
            u8_nonce[i * 4],
            u8_nonce[i * 4 + 1],
            u8_nonce[i * 4 + 2],
            u8_nonce[i * 4 + 3],
        ]);
    }

    let y = [
        Sha192Digest::from([
            23, 160, 192, 134, 4, 191, 164, 110, 108, 186, 231, 54, 220, 199, 250, 190, 52, 10,
            161, 28, 251, 82, 251, 76,
        ]),
        Sha192Digest::from([
            235, 99, 69, 32, 240, 42, 68, 226, 161, 49, 95, 109, 193, 61, 217, 223, 180, 209, 179,
            118, 137, 142, 8, 103,
        ]),
        Sha192Digest::from([
            111, 122, 243, 79, 206, 87, 232, 67, 66, 45, 232, 71, 231, 221, 102, 158, 117, 91, 179,
            126, 68, 111, 184, 69,
        ]),
        Sha192Digest::from([
            186, 110, 170, 29, 52, 13, 148, 37, 247, 139, 138, 93, 85, 213, 252, 35, 191, 171, 85,
            29, 120, 107, 47, 209,
        ]),
        Sha192Digest::from([
            168, 102, 201, 171, 37, 94, 5, 140, 199, 205, 71, 226, 141, 216, 107, 40, 169, 169,
            200, 166, 156, 68, 8, 140,
        ]),
        Sha192Digest::from([
            125, 129, 23, 182, 216, 242, 65, 5, 159, 126, 142, 57, 113, 213, 121, 191, 38, 26, 144,
            109, 14, 28, 140, 250,
        ]),
        Sha192Digest::from([
            251, 132, 26, 208, 121, 198, 137, 166, 210, 130, 129, 248, 151, 69, 191, 129, 234, 179,
            185, 3, 7, 19, 193, 172,
        ]),
        Sha192Digest::from([
            149, 96, 163, 99, 209, 204, 251, 83, 106, 89, 155, 242, 203, 89, 78, 6, 22, 85, 53,
            137, 161, 232, 105, 185,
        ]),
        Sha192Digest::from([
            219, 173, 177, 176, 90, 39, 138, 197, 51, 64, 33, 91, 155, 181, 38, 41, 238, 238, 5,
            44, 6, 115, 178, 248,
        ]),
        Sha192Digest::from([
            80, 238, 173, 176, 192, 186, 40, 60, 58, 79, 114, 219, 158, 75, 79, 122, 155, 48, 121,
            255, 127, 171, 83, 203,
        ]),
        Sha192Digest::from([
            250, 39, 3, 146, 18, 249, 38, 112, 116, 53, 124, 65, 77, 225, 52, 166, 62, 253, 221,
            175, 147, 244, 129, 207,
        ]),
        Sha192Digest::from([
            32, 192, 195, 104, 29, 123, 42, 211, 146, 56, 163, 73, 81, 88, 125, 243, 0, 137, 239,
            85, 157, 81, 254, 55,
        ]),
        Sha192Digest::from([
            124, 57, 24, 101, 117, 122, 30, 234, 31, 192, 148, 174, 144, 69, 5, 165, 143, 169, 117,
            156, 150, 187, 1, 113,
        ]),
        Sha192Digest::from([
            252, 56, 9, 248, 53, 25, 187, 70, 57, 73, 26, 219, 4, 139, 86, 113, 142, 142, 31, 103,
            174, 231, 68, 56,
        ]),
        Sha192Digest::from([
            135, 38, 77, 90, 216, 158, 13, 86, 254, 37, 143, 19, 103, 122, 86, 87, 224, 154, 142,
            240, 75, 205, 192, 184,
        ]),
        Sha192Digest::from([
            78, 210, 174, 19, 247, 196, 16, 242, 49, 160, 47, 83, 99, 5, 229, 189, 11, 80, 223,
            229, 200, 200, 157, 91,
        ]),
        Sha192Digest::from([
            211, 178, 86, 185, 56, 31, 33, 195, 202, 40, 113, 63, 224, 195, 202, 126, 72, 9, 40,
            85, 86, 51, 168, 111,
        ]),
        Sha192Digest::from([
            243, 224, 105, 8, 81, 96, 155, 248, 32, 188, 245, 138, 16, 222, 181, 216, 25, 15, 163,
            47, 115, 183, 71, 55,
        ]),
        Sha192Digest::from([
            174, 104, 219, 219, 182, 204, 128, 232, 154, 196, 139, 1, 90, 89, 4, 186, 98, 37, 1,
            141, 49, 41, 15, 253,
        ]),
        Sha192Digest::from([
            143, 116, 99, 0, 17, 225, 89, 11, 26, 197, 237, 132, 237, 51, 1, 103, 124, 13, 234,
            160, 113, 145, 197, 52,
        ]),
        Sha192Digest::from([
            119, 101, 211, 157, 200, 32, 58, 76, 41, 186, 215, 156, 47, 31, 191, 119, 138, 174,
            247, 212, 107, 182, 221, 249,
        ]),
        Sha192Digest::from([
            47, 197, 219, 248, 126, 171, 60, 4, 4, 133, 65, 96, 177, 173, 149, 217, 143, 156, 173,
            14, 175, 249, 108, 159,
        ]),
        Sha192Digest::from([
            129, 160, 29, 76, 159, 210, 128, 175, 75, 243, 136, 197, 173, 122, 242, 12, 96, 175,
            165, 122, 64, 93, 77, 234,
        ]),
        Sha192Digest::from([
            136, 69, 237, 247, 76, 229, 210, 65, 197, 120, 72, 199, 204, 206, 61, 51, 148, 10, 12,
            176, 67, 100, 17, 46,
        ]),
        Sha192Digest::from([
            255, 73, 186, 55, 124, 137, 66, 122, 7, 106, 35, 50, 236, 202, 150, 238, 246, 9, 53,
            33, 151, 244, 115, 37,
        ]),
        Sha192Digest::from([
            71, 58, 218, 52, 116, 226, 225, 191, 100, 154, 124, 119, 130, 88, 92, 32, 116, 130, 52,
            120, 147, 233, 248, 100,
        ]),
        Sha192Digest::from([
            232, 88, 112, 250, 11, 242, 213, 244, 99, 76, 222, 131, 47, 246, 103, 38, 116, 96, 172,
            60, 70, 197, 119, 252,
        ]),
        Sha192Digest::from([
            55, 142, 139, 25, 23, 233, 209, 157, 191, 37, 159, 66, 162, 65, 38, 57, 204, 135, 180,
            130, 137, 25, 253, 40,
        ]),
        Sha192Digest::from([
            93, 248, 37, 89, 123, 186, 24, 25, 125, 201, 37, 14, 62, 247, 18, 138, 249, 199, 12,
            233, 173, 224, 202, 58,
        ]),
        Sha192Digest::from([
            189, 104, 182, 236, 30, 66, 40, 219, 45, 232, 65, 9, 203, 247, 98, 45, 108, 240, 175,
            232, 202, 240, 71, 49,
        ]),
        Sha192Digest::from([
            35, 225, 109, 90, 242, 250, 145, 196, 204, 229, 53, 189, 48, 234, 194, 14, 255, 200,
            125, 62, 23, 210, 14, 69,
        ]),
        Sha192Digest::from([
            114, 128, 217, 72, 117, 245, 215, 181, 93, 17, 200, 158, 158, 194, 46, 135, 66, 217,
            161, 74, 24, 151, 250, 180,
        ]),
        Sha192Digest::from([
            45, 109, 116, 221, 107, 139, 181, 92, 231, 185, 87, 224, 191, 221, 215, 104, 162, 32,
            12, 145, 119, 79, 227, 7,
        ]),
        Sha192Digest::from([
            51, 179, 217, 176, 40, 233, 148, 179, 128, 87, 105, 93, 46, 221, 120, 175, 117, 45,
            131, 30, 253, 243, 129, 133,
        ]),
        Sha192Digest::from([
            111, 193, 94, 56, 57, 163, 83, 202, 183, 9, 145, 168, 101, 222, 72, 247, 71, 244, 176,
            168, 153, 129, 125, 94,
        ]),
        Sha192Digest::from([
            206, 127, 246, 221, 196, 141, 125, 58, 241, 236, 91, 192, 101, 235, 105, 156, 45, 14,
            122, 17, 65, 136, 132, 67,
        ]),
        Sha192Digest::from([
            1, 6, 247, 140, 202, 223, 152, 195, 88, 24, 197, 244, 184, 13, 116, 46, 45, 239, 120,
            182, 176, 92, 110, 243,
        ]),
        Sha192Digest::from([
            229, 205, 47, 49, 126, 138, 104, 104, 84, 220, 144, 245, 218, 93, 178, 22, 118, 151,
            58, 218, 63, 0, 205, 108,
        ]),
        Sha192Digest::from([
            188, 107, 111, 235, 146, 49, 25, 31, 225, 200, 64, 104, 60, 119, 240, 222, 13, 37, 218,
            179, 100, 36, 228, 56,
        ]),
        Sha192Digest::from([
            247, 40, 31, 125, 156, 183, 31, 84, 69, 87, 240, 137, 216, 182, 109, 223, 184, 152,
            185, 7, 112, 240, 3, 47,
        ]),
        Sha192Digest::from([
            11, 101, 220, 176, 247, 202, 193, 137, 85, 42, 103, 19, 0, 125, 150, 33, 47, 50, 48,
            59, 87, 133, 114, 125,
        ]),
        Sha192Digest::from([
            29, 64, 210, 159, 189, 200, 219, 113, 109, 34, 235, 211, 216, 5, 11, 181, 20, 51, 152,
            153, 51, 142, 102, 153,
        ]),
        Sha192Digest::from([
            9, 181, 87, 97, 63, 87, 11, 75, 220, 28, 223, 69, 115, 50, 54, 209, 82, 205, 253, 120,
            98, 0, 36, 138,
        ]),
        Sha192Digest::from([
            199, 211, 206, 239, 57, 18, 248, 204, 10, 125, 200, 126, 28, 26, 7, 124, 44, 236, 250,
            96, 247, 23, 108, 69,
        ]),
        Sha192Digest::from([
            84, 161, 229, 121, 202, 199, 147, 22, 38, 125, 100, 19, 216, 89, 160, 131, 118, 137,
            120, 38, 229, 11, 219, 136,
        ]),
        Sha192Digest::from([
            170, 54, 161, 94, 45, 6, 117, 108, 173, 52, 212, 152, 139, 44, 53, 28, 90, 204, 183,
            136, 232, 0, 173, 46,
        ]),
        Sha192Digest::from([
            53, 181, 197, 95, 220, 187, 103, 104, 101, 139, 103, 70, 220, 144, 250, 227, 44, 88,
            40, 169, 43, 17, 228, 132,
        ]),
        Sha192Digest::from([
            198, 5, 6, 99, 72, 41, 38, 56, 73, 180, 191, 26, 107, 180, 157, 38, 106, 56, 41, 11,
            85, 177, 40, 121,
        ]),
        Sha192Digest::from([
            82, 64, 121, 76, 108, 126, 42, 205, 249, 230, 120, 80, 100, 179, 134, 85, 12, 100, 12,
            82, 218, 105, 97, 207,
        ]),
        Sha192Digest::from([
            93, 30, 135, 26, 208, 246, 1, 13, 23, 140, 117, 213, 140, 24, 148, 90, 220, 150, 86,
            248, 89, 141, 10, 217,
        ]),
        Sha192Digest::from([
            92, 200, 225, 254, 151, 59, 166, 122, 15, 19, 6, 121, 148, 51, 172, 81, 176, 151, 38,
            101, 65, 126, 254, 167,
        ]),
    ];
    let path = [
        Sha192Digest::from([
            5, 71, 54, 208, 167, 144, 150, 170, 61, 2, 223, 28, 242, 147, 99, 217, 76, 200, 219,
            68, 65, 123, 205, 114,
        ]),
        Sha192Digest::from([
            225, 113, 19, 160, 185, 193, 223, 22, 7, 37, 8, 66, 36, 231, 43, 173, 210, 91, 211, 96,
            32, 104, 51, 238,
        ]),
        Sha192Digest::from([
            206, 74, 21, 195, 175, 17, 187, 93, 180, 0, 130, 45, 232, 36, 196, 205, 109, 38, 124,
            249, 140, 116, 198, 201,
        ]),
        Sha192Digest::from([
            224, 228, 181, 187, 72, 182, 186, 3, 227, 247, 162, 178, 162, 166, 144, 210, 209, 179,
            222, 108, 36, 54, 135, 225,
        ]),
        Sha192Digest::from([
            46, 168, 146, 50, 58, 62, 52, 23, 21, 29, 171, 109, 140, 172, 87, 161, 128, 193, 74,
            105, 252, 244, 181, 154,
        ]),
        Sha192Digest::from([
            206, 36, 161, 152, 211, 117, 253, 49, 223, 194, 163, 223, 105, 221, 254, 117, 160, 171,
            36, 96, 80, 33, 30, 220,
        ]),
        Sha192Digest::from([
            163, 203, 70, 60, 90, 99, 148, 205, 66, 205, 190, 205, 57, 11, 53, 248, 179, 243, 192,
            21, 184, 2, 194, 32,
        ]),
        Sha192Digest::from([
            54, 253, 197, 102, 138, 111, 208, 11, 179, 49, 248, 91, 82, 126, 43, 141, 215, 14, 203,
            112, 147, 9, 207, 254,
        ]),
        Sha192Digest::from([
            176, 193, 11, 180, 116, 135, 90, 6, 146, 15, 138, 127, 187, 105, 124, 25, 66, 153, 198,
            178, 117, 162, 60, 203,
        ]),
        Sha192Digest::from([
            253, 237, 188, 14, 88, 239, 110, 235, 40, 94, 96, 104, 233, 139, 167, 17, 116, 58, 238,
            140, 245, 132, 155, 52,
        ]),
        Sha192Digest::from([
            64, 192, 199, 169, 27, 211, 58, 113, 36, 223, 110, 37, 170, 225, 206, 211, 146, 134,
            46, 41, 52, 32, 57, 92,
        ]),
        Sha192Digest::from([
            68, 97, 151, 244, 43, 246, 64, 206, 130, 87, 81, 158, 43, 83, 112, 128, 168, 246, 188,
            130, 6, 215, 152, 128,
        ]),
        Sha192Digest::from([
            203, 102, 135, 137, 184, 203, 208, 177, 109, 227, 250, 249, 178, 65, 38, 169, 162, 138,
            168, 221, 51, 13, 175, 239,
        ]),
        Sha192Digest::from([
            77, 195, 47, 104, 93, 246, 33, 54, 48, 39, 193, 206, 185, 130, 106, 150, 169, 25, 64,
            50, 183, 206, 92, 31,
        ]),
        Sha192Digest::from([
            198, 96, 14, 165, 145, 110, 96, 24, 32, 226, 19, 98, 130, 202, 38, 7, 194, 4, 97, 184,
            191, 50, 103, 221,
        ]),
        Sha192Digest::from([
            168, 37, 88, 211, 230, 242, 0, 90, 238, 58, 1, 36, 122, 116, 238, 144, 112, 147, 71,
            21, 155, 16, 8, 222,
        ]),
        Sha192Digest::from([
            196, 185, 169, 76, 142, 198, 200, 148, 169, 87, 217, 205, 167, 88, 232, 166, 81, 236,
            27, 87, 59, 138, 48, 205,
        ]),
        Sha192Digest::from([
            163, 255, 13, 121, 172, 99, 152, 244, 2, 49, 9, 69, 60, 194, 234, 90, 236, 83, 12, 246,
            92, 221, 19, 126,
        ]),
        Sha192Digest::from([
            90, 135, 239, 176, 230, 215, 36, 58, 67, 50, 17, 9, 183, 98, 53, 6, 130, 212, 70, 134,
            84, 62, 198, 212,
        ]),
        Sha192Digest::from([
            118, 22, 167, 149, 221, 76, 51, 216, 183, 67, 152, 84, 49, 157, 83, 119, 164, 48, 249,
            4, 245, 16, 212, 150,
        ]),
    ];
    let ots = LmotsSignature {
        ots_type: lmots_type,
        nonce,
        y,
    };

    let lms_sig = LmsSignature {
        q,
        lmots_signature: ots,
        sig_type: lms_type,
        lms_path: &path,
    };

    let success = Lms::default()
        .verify_lms_signature(
            &mut sha256,
            &MESSAGE,
            &LMS_IDENTIFIER,
            q,
            &lms_public_key,
            &lms_sig,
        )
        .unwrap();
    assert_eq!(success, true);
}

test_suite! {
    test_coefficient,
    test_lms_lookup,
    test_lmots_lookup,
    test_get_lms_parameters,
    test_hash_message_24,
    test_lms_24_height_15,
    //test_lms_24_height_20,
}
