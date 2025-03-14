/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_24_tests.rs

Abstract:

    File contains test cases for LMS signature verification using SHA256/192.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{HashValue, Lms, LmsResult, Sha256, get_lms_parameters};
use caliptra_error::CaliptraError;
use caliptra_lms_types::{
    LmotsAlgorithmType, LmotsSignature, LmsAlgorithmType, LmsIdentifier, LmsPublicKey,
    LmsSignature, bytes_to_words_6,
};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::test_suite;
use zerocopy::{BigEndian, LittleEndian, U32};

fn test_get_lms_parameters() {
    // Full size SHA256 hashes
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N32H5).unwrap();
    assert_eq!(32, width);
    assert_eq!(5, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N32H10).unwrap();
    assert_eq!(32, width);
    assert_eq!(10, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N32H15).unwrap();
    assert_eq!(32, width);
    assert_eq!(15, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N32H20).unwrap();
    assert_eq!(32, width);
    assert_eq!(20, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N32H25).unwrap();
    assert_eq!(32, width);
    assert_eq!(25, height);

    // Truncated 192 bit SHA256 hashes
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N24H5).unwrap();
    assert_eq!(24, width);
    assert_eq!(5, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N24H10).unwrap();
    assert_eq!(24, width);
    assert_eq!(10, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N24H15).unwrap();
    assert_eq!(24, width);
    assert_eq!(15, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N24H20).unwrap();
    assert_eq!(24, width);
    assert_eq!(20, height);
    let (width, height) = get_lms_parameters(LmsAlgorithmType::LmsSha256N24H25).unwrap();
    assert_eq!(24, width);
    assert_eq!(25, height);
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
    let nonce: [U32<LittleEndian>; 6] = bytes_to_words_6([
        108, 201, 169, 93, 130, 206, 214, 173, 223, 138, 178, 150, 192, 86, 115, 139, 157, 213,
        182, 55, 196, 22, 212, 216,
    ]);
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
    const Q: U32<BigEndian> = U32::ZERO;
    const LMOTS_TYPE: LmotsAlgorithmType = LmotsAlgorithmType::LmotsSha256N24W4;
    const LMS_TYPE: LmsAlgorithmType = LmsAlgorithmType::LmsSha256N24H15;

    const LMS_PUBLIC_HASH: [U32<LittleEndian>; 6] = bytes_to_words_6([
        0x03, 0x2a, 0xa2, 0xbd, 0x9b, 0x31, 0xe9, 0xbd, 0x33, 0x4b, 0x46, 0x2e, 0x27, 0x79, 0x20,
        0x75, 0xbd, 0xad, 0xdd, 0xae, 0xf9, 0xed, 0xb1, 0x24,
    ]);

    const NONCE: [U32<LittleEndian>; 6] = bytes_to_words_6([
        0xb4, 0x24, 0x09, 0xdb, 0xdd, 0x4a, 0x1c, 0x49, 0xfc, 0x79, 0x37, 0x94, 0x75, 0xe9, 0xc7,
        0x67, 0x1c, 0x7f, 0x51, 0x53, 0xf7, 0x53, 0x5a, 0xc4,
    ]);

    const Y: [[U32<LittleEndian>; 6]; 51] = [
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
    const PATH: [[U32<LittleEndian>; 6]; 15] = [
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

    const LMS_SIG: LmsSignature<6, 51, 15> = LmsSignature {
        q: Q,
        ots: LmotsSignature {
            ots_type: LMOTS_TYPE,
            nonce: NONCE,
            y: Y,
        },
        tree_type: LMS_TYPE,
        tree_path: PATH,
    };

    const LMS_PUBLIC_KEY: LmsPublicKey<6> = LmsPublicKey {
        id: LMS_IDENTIFIER,
        digest: LMS_PUBLIC_HASH,
        tree_type: LMS_TYPE,
        otstype: LMOTS_TYPE,
    };

    let result = Lms::default()
        .verify_lms_signature(&mut sha256, &MESSAGE, &LMS_PUBLIC_KEY, &LMS_SIG)
        .unwrap();
    assert_eq!(result, LmsResult::Success);

    let candidate_key = Lms::default()
        .verify_lms_signature_cfi(&mut sha256, &MESSAGE, &LMS_PUBLIC_KEY, &LMS_SIG)
        .unwrap();
    assert_eq!(candidate_key, HashValue::from(LMS_PUBLIC_KEY.digest));

    // add a test that uses an invalid q value
    // in this case we are using the maximum value for q
    let invalid_q_sig = LmsSignature {
        q: <U32<BigEndian>>::from(32767u32),
        ..LMS_SIG
    };
    let result = Lms::default()
        .verify_lms_signature(&mut sha256, &MESSAGE, &LMS_PUBLIC_KEY, &invalid_q_sig)
        .unwrap();
    assert_eq!(result, LmsResult::SigVerifyFailed);

    // add a test that uses an invalid p value
    // in this case we are using one greater than the maximum value for Q
    // this should result in an invalid p value error (meaning the path is invalid)
    let invalid_q_sig = LmsSignature {
        q: <U32<BigEndian>>::from(32768u32),
        ..LMS_SIG
    };
    let result =
        Lms::default().verify_lms_signature(&mut sha256, &MESSAGE, &LMS_PUBLIC_KEY, &invalid_q_sig);
    assert_eq!(result, Err(CaliptraError::DRIVER_LMS_INVALID_Q_VALUE));
}

test_suite! {
    test_coefficient,
    test_get_lms_parameters,
    test_hash_message_24,
    test_lms_24_height_15,
}
