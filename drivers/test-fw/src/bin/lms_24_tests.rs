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
    get_lms_parameters, lookup_lmots_algorithm_type, lookup_lms_algorithm_type, HashValue,
    LmotsAlgorithmType, Lms, LmsAlgorithmType, LmsIdentifier, LmsPublicKey, LmsSignature, Sha256,
};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::test_suite;

fn test_lms_lookup() {
    let result = lookup_lms_algorithm_type(0);
    assert_eq!(LmsAlgorithmType::LmsReserved, result.unwrap())
}

fn test_get_lms_parameters() {
    // Full size SHA256 hashes
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H5).unwrap();
    assert_eq!(32, width);
    assert_eq!(5, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H10).unwrap();
    assert_eq!(32, width);
    assert_eq!(10, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H15).unwrap();
    assert_eq!(32, width);
    assert_eq!(15, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H20).unwrap();
    assert_eq!(32, width);
    assert_eq!(20, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N32H25).unwrap();
    assert_eq!(32, width);
    assert_eq!(25, height);

    // Truncated 192 bit SHA256 hashes
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H5).unwrap();
    assert_eq!(24, width);
    assert_eq!(5, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H10).unwrap();
    assert_eq!(24, width);
    assert_eq!(10, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H15).unwrap();
    assert_eq!(24, width);
    assert_eq!(15, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H20).unwrap();
    assert_eq!(24, width);
    assert_eq!(20, height);
    let (width, height) = get_lms_parameters(&LmsAlgorithmType::LmsSha256N24H25).unwrap();
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
    let u8_nonce: [u8; 24] = [
        108, 201, 169, 93, 130, 206, 214, 173, 223, 138, 178, 150, 192, 86, 115, 139, 157, 213,
        182, 55, 196, 22, 212, 216,
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
    const LMS_PUBLIC_HASH: HashValue<6> = HashValue([
        53125821, 2603739581, 860571182, 662249589, 3182288302, 4193104164,
    ]);
    const NONCE: [u32; 6] = [
        3022260699, 3712621641, 4235802516, 1978255207, 478105939, 4149435076,
    ];
    const Y: [HashValue<6>; 51] = [
        HashValue([
            1918087017, 3361364886, 274058243, 3085037187, 2880451251, 341375593,
        ]),
        HashValue([
            13956348, 3660938697, 2839810083, 1028325556, 3106711662, 4042849555,
        ]),
        HashValue([
            3534585347, 3962749017, 2409325821, 2356118137, 4153313511, 2068634505,
        ]),
        HashValue([
            1826922086, 993159977, 501598683, 3752527208, 498435688, 511764143,
        ]),
        HashValue([
            3130363838, 478395982, 449986318, 244819632, 3892376526, 2545286320,
        ]),
        HashValue([
            2493405165, 1706646572, 3116059780, 1313754339, 526643499, 22885820,
        ]),
        HashValue([
            2918167022, 984794221, 205214285, 2453728753, 3435596199, 4185412883,
        ]),
        HashValue([
            4153209804, 367114673, 1906913062, 860313948, 619894206, 2930153363,
        ]),
        HashValue([
            1246927358, 1283353731, 815765696, 1589892647, 2637385857, 4020717617,
        ]),
        HashValue([
            1798600061, 4179259961, 2951899974, 1589936286, 572693486, 2041352209,
        ]),
        HashValue([
            2897473190, 1110488020, 3948157613, 2813685060, 361988474, 470435643,
        ]),
        HashValue([
            33723832, 1614898361, 3202028015, 2956542878, 2292387421, 2599714921,
        ]),
        HashValue([
            382380322, 3965530891, 156541719, 2367477949, 3532416252, 127850531,
        ]),
        HashValue([
            3162159938, 1994002520, 2721903616, 140765728, 73130738, 3101458127,
        ]),
        HashValue([
            187744786, 2393192377, 242633530, 1232721517, 1731228048, 2430306651,
        ]),
        HashValue([
            1639695210, 2235001164, 592402961, 3854765477, 964394876, 2280975580,
        ]),
        HashValue([
            3596834779, 2684920199, 2324245080, 207254138, 4060288540, 324277449,
        ]),
        HashValue([
            1054930857, 885379627, 4120052995, 2866395245, 2038364650, 3456973214,
        ]),
        HashValue([
            1870706494, 2588322083, 285843796, 502735158, 327630707, 3065624778,
        ]),
        HashValue([
            2120664212, 1977139582, 3941900843, 513544052, 4233801954, 381310069,
        ]),
        HashValue([
            2961331862, 920436733, 3639252565, 3079355033, 489871346, 2524633204,
        ]),
        HashValue([
            3577317522, 4224998842, 1722270977, 1190275452, 1009233112, 2363494539,
        ]),
        HashValue([
            3511692650, 2041877445, 889242166, 3123096493, 2404880675, 3871411913,
        ]),
        HashValue([
            4104151251, 3800378266, 3649037492, 1483748234, 1070352305, 4057009362,
        ]),
        HashValue([
            4247262653, 568134378, 2024541158, 3652269280, 3260052441, 1113320014,
        ]),
        HashValue([
            2385353000, 4064185331, 3982659576, 2285465204, 2656415334, 4120544364,
        ]),
        HashValue([
            2143583115, 1725289436, 1202487080, 1488534432, 1185181314, 1804548777,
        ]),
        HashValue([
            1788582005, 1174727292, 3167271348, 3132703706, 3479183772, 2983521639,
        ]),
        HashValue([
            473041655, 2927919989, 3952920496, 3962586558, 2046628220, 3441858398,
        ]),
        HashValue([
            1009601077, 772815933, 1988735916, 4073477840, 3984224088, 1995194518,
        ]),
        HashValue([
            442150284, 3775440843, 1005656833, 481693255, 4081420275, 4153755506,
        ]),
        HashValue([
            2263164070, 234549122, 4234972577, 2174059864, 2468869673, 1774811063,
        ]),
        HashValue([
            3914000831, 2923566227, 4239856696, 1194265859, 2088911841, 1848210751,
        ]),
        HashValue([
            3567043549, 3310975779, 2280063913, 2596902771, 335193881, 1531042418,
        ]),
        HashValue([
            1826620068, 3911676660, 3933533417, 163545128, 4258758538, 163602513,
        ]),
        HashValue([
            432519560, 1884869957, 1807367266, 2150090893, 4155045801, 4277511745,
        ]),
        HashValue([
            2589682157, 3299639704, 535511224, 3349784429, 475693426, 399223032,
        ]),
        HashValue([
            1550301337, 1871305329, 548298470, 739683161, 478262658, 3330830190,
        ]),
        HashValue([
            2144008480, 2916541965, 2310666657, 852453819, 4168349056, 3379127284,
        ]),
        HashValue([
            27069767, 601736804, 3615345741, 1599827220, 2795168299, 909926728,
        ]),
        HashValue([
            2145563595, 2703436591, 2486046259, 71357651, 459857124, 2202720040,
        ]),
        HashValue([
            4031096937, 2441875327, 292292343, 63665819, 1785476640, 2010117199,
        ]),
        HashValue([
            2164518371, 1377028979, 2551059929, 2788350925, 2859968731, 1908696023,
        ]),
        HashValue([
            3038709963, 1669404734, 2704610238, 3929369293, 1513473103, 1468193983,
        ]),
        HashValue([
            3539087931, 3143391089, 1929193459, 1888919029, 2433392142, 3114061865,
        ]),
        HashValue([
            1001270285, 3948123424, 1908870613, 424058709, 619467486, 2212564264,
        ]),
        HashValue([
            1516280779, 808511453, 3696242870, 1759771524, 1099962431, 3584106212,
        ]),
        HashValue([
            3033415216, 3055857303, 1885318281, 478028398, 772668883, 310312573,
        ]),
        HashValue([
            2152809856, 1660789247, 1853976633, 1140176850, 966982894, 500351055,
        ]),
        HashValue([
            1131609401, 4071263094, 3658558135, 676250367, 3470678366, 2279096858,
        ]),
        HashValue([
            1069441035, 791285572, 316591972, 3080173341, 2990996701, 1187707153,
        ]),
    ];

    const PATH: [HashValue<6>; 15] = [
        HashValue([
            3193533372, 3885195091, 1089021609, 4239641501, 757670425, 684947201,
        ]),
        HashValue([
            2898927663, 139031961, 4164867108, 4280668840, 3054957026, 1223750074,
        ]),
        HashValue([
            3453490843, 2122758689, 3512314501, 1647222049, 2088007381, 4087860731,
        ]),
        HashValue([
            3947124033, 2812650411, 2022880113, 2168689774, 2697061631, 2206183667,
        ]),
        HashValue([
            1761537312, 3372810689, 3670930187, 2429763439, 1259836325, 1460061507,
        ]),
        HashValue([
            973177414, 3135308775, 2543123487, 2780955645, 2347812727, 3020401374,
        ]),
        HashValue([
            2707653355, 77415811, 1660401214, 805632300, 2456161891, 387512160,
        ]),
        HashValue([
            138561861, 1470929812, 2049001137, 584247135, 977106334, 1522200152,
        ]),
        HashValue([
            482077319, 3162175742, 2026310758, 4310334, 3671004989, 2507812065,
        ]),
        HashValue([
            2855763084, 39564440, 3345847815, 558137862, 2112009546, 250932460,
        ]),
        HashValue([
            1350986343, 1776742323, 2645532356, 2943150395, 3899800972, 2782435335,
        ]),
        HashValue([
            1273197790, 2711237202, 4190486164, 932706209, 28787560, 3866046293,
        ]),
        HashValue([
            518839990, 3737880365, 1883724179, 1354892975, 917637475, 3112093319,
        ]),
        HashValue([
            636490104, 1545593389, 4001490975, 1619687095, 2894838211, 4054607951,
        ]),
        HashValue([
            1943414741, 1794272817, 767555199, 2483716874, 3577243467, 3315289657,
        ]),
    ];

    const LMS_SIG: LmsSignature<6, 51, 15> = LmsSignature {
        q: Q,
        ots_type: LMOTS_TYPE,
        nonce: NONCE,
        y: Y,
        lms_type: LMS_TYPE,
        path: PATH,
    };

    const LMS_PUBLIC_KEY: LmsPublicKey<6> = LmsPublicKey {
        lms_identifier: LMS_IDENTIFIER,
        root_hash: LMS_PUBLIC_HASH,
        lms_type: LMS_TYPE,
        lmots_type: LMOTS_TYPE,
    };

    let success = Lms::default()
        .verify_lms_signature(&mut sha256, &MESSAGE, &LMS_PUBLIC_KEY, &LMS_SIG)
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
}
