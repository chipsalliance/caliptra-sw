/*++

Licensed under the Apache-2.0 license.

File Name:

    mlkem_tests.rs

Abstract:

    File contains test cases for ML-KEM-1024 API tests

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    Aes, Array4x12, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs, KeyUsage,
    KeyWriteArgs, LEArray4x8, MlKem1024, MlKem1024Message, MlKem1024MessageSource, MlKem1024Seeds,
    MlKem1024SharedKey, MlKem1024SharedKeyOut, MlKemPctKvContext, PersistentDataAccessor, Trng,
};
use caliptra_registers::abr::AbrReg;
use caliptra_registers::aes::AesReg;
use caliptra_registers::aes_clp::AesClpReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;
use zerocopy::IntoBytes;

// Test vectors for ML-KEM-1024
const SEED_D: [u32; 8] = [
    0x12345678, 0x9abcdef0, 0x11223344, 0x55667788, 0xaabbccdd, 0xeeff0011, 0x22334455, 0x66778899,
];

const SEED_Z: [u32; 8] = [
    0x87654321, 0x0fedcba9, 0x44332211, 0x88776655, 0xddccbbaa, 0x1100ffee, 0x55443322, 0x99887766,
];

const MESSAGE: [u32; 8] = [
    0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0, 0x11223344, 0x55667788, 0xaabbccdd, 0xeeff0011,
];

const KEY_ID: KeyId = KeyId::KeyId2;

/// Seed the ABR entropy registers with fresh randomness.
/// This must be called before any MLKEM (or MLDSA) operation.
fn seed_abr_entropy() {
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };
    let mut abr_reg = unsafe { AbrReg::new() };
    let regs = abr_reg.regs_mut();
    let entropy = trng.generate16().unwrap();
    entropy.write_to_reg(regs.entropy());
}

fn test_mlkem_name() {
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };
    let mut entropy_gen = || {
        trng.generate4()
            .map_err(|e| caliptra_cfi_lib::CfiError(u32::from(e)))
    };

    // This needs to happen in the first test
    CfiCounter::reset(&mut entropy_gen);

    let abr_reg = unsafe { AbrReg::new() };
    let regs = abr_reg.regs();

    let name = regs.mlkem_name().read();

    // MLKEM_CORE_NAME from RTL: 64'h32343130_4D2D4B45 representing "KEM-1024"
    assert_eq!(name, [0x4D2D4B45, 0x32343130]);
}

fn test_key_pair_generation() {
    seed_abr_entropy();
    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);

    // Test key pair generation with arrays
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, decaps_key) = mlkem.key_pair(seeds, None).unwrap();

    // Keys should be non-zero (basic sanity check)
    assert_ne!(encaps_key.0, [0u32; 392]);
    assert!(!decaps_key.is_zero());

    assert_eq!(
        encaps_key.0,
        [
            0x4814898e, 0xb15b7012, 0x40445527, 0x89bef849, 0x675b39a1, 0xa9521326, 0xe68578dc,
            0x2ca846a9, 0x5ab3e598, 0x6a2205d6, 0xc82885a5, 0x4192cca4, 0x860f738f, 0xd1829988,
            0x3eb59864, 0x1e7c6912, 0xb81432e5, 0x923ab46b, 0xb6fa547, 0x96b67123, 0x6a698bc1,
            0xf28c41a8, 0x550720ca, 0x1bc9b953, 0x108c7b8e, 0x423cb260, 0x3ea0c055, 0xbd92c17f,
            0x39415d06, 0x49b3002b, 0xec77164d, 0x869f9360, 0x5d2714c4, 0xe94dacb8, 0xbc9e9433,
            0x9d891a50, 0x2435231a, 0xa8574f6c, 0xbeaac48c, 0x732b2305, 0x35d073c6, 0x6c15ec8a,
            0x4c9dd55f, 0x3ae705b5, 0x751b9519, 0x4cab896, 0xc27e46d8, 0x722b3b22, 0x4643c9e0,
            0x6b25a917, 0x4d419158, 0x903056be, 0x78a5b31, 0x295cd2bd, 0xb202f300, 0x3ca0cba1,
            0x7e08b44c, 0x9c9c3159, 0x9cb5c7ea, 0x38f6e456, 0xcc6f9ade, 0xf42a6887, 0x9455fc0d,
            0xcf451598, 0xd0c2e8, 0x8bb2df6d, 0xd4afc83c, 0x26507968, 0x3dc9b835, 0x7811bb31,
            0x87447cd9, 0x14166497, 0xbecb9706, 0xf2ab64fc, 0x4270b818, 0xc81d51dc, 0x536a4e58,
            0x8181f726, 0x3b7060d3, 0x613d2c2c, 0x56e963a2, 0x819f92f7, 0x94d7a406, 0xb9917e31,
            0xacbb058c, 0x30f07490, 0x24080842, 0xf09a604c, 0xe8286d2c, 0xb0624e24, 0xd65e0584,
            0x55397138, 0xc4510f75, 0xdfb15255, 0x2c7c06d6, 0x236785a6, 0xdd953c91, 0xec147b14,
            0x4d2c221c, 0x8787aa4c, 0xf1b02101, 0x9f241c9a, 0x1d2b686b, 0x1a6ac75b, 0xe71f7a7,
            0xbc2910c2, 0x256a0050, 0xfe7e421, 0x20852850, 0x29675bc3, 0x54e01eb9, 0x93529149,
            0x44429b64, 0x997a29c2, 0xfc2fe436, 0x599a3f05, 0x5318632f, 0xdd7fc0b2, 0x399c3b85,
            0x664b5e3f, 0x30273089, 0x18b75ed0, 0x33934615, 0x4d628b07, 0xf2880248, 0x14f79305,
            0xe74ffb98, 0xe14d5c89, 0x72860532, 0xae6b73ca, 0x25cc719a, 0xa2481604, 0x6a138055,
            0x185a0b36, 0x8156c22c, 0x2ac47024, 0xc494bbdc, 0x5050ae32, 0xb32c3aeb, 0x83b79a69,
            0x35d8395c, 0x14cc25a6, 0x8c3bbeb, 0x6ed25b87, 0xd3366672, 0xe8b56a99, 0x744a52cb,
            0x684af8e5, 0xf068adcc, 0xa5e3ec1d, 0x98cd9289, 0xc24309e6, 0xb3c6c070, 0x8d001ae2,
            0xbac9b8ba, 0xdb7c2ac, 0xf0998b6d, 0x7bda9185, 0xa204149c, 0x58400a4b, 0x5469c053,
            0x15779d79, 0xf6b09cb0, 0x17c07ed2, 0x5be86726, 0x5238a57d, 0x5a0d75b2, 0xa5f7be74,
            0x23530294, 0x158616b6, 0x49751244, 0x68959817, 0x54380769, 0xb6c54845, 0x32461948,
            0x95c008bb, 0xafbcde48, 0x92c2f5c3, 0x96f307d0, 0x1fd07219, 0x2740c41b, 0xa7f63226,
            0x83576b2f, 0xd8984c0f, 0x990553f0, 0x9d734da1, 0x1043e78c, 0x3ba21d6, 0x15e3d43b,
            0x78835bc8, 0x758e6331, 0x6b46a91b, 0xf25ba5eb, 0x4b969ec6, 0xcf4900ad, 0xaf423626,
            0xa576ba52, 0x6f65fa63, 0x890375f5, 0x4b88b8f2, 0x2e511d36, 0xb3547249, 0x16abba50,
            0x9681be17, 0x453c13d5, 0x586a5c23, 0x6d45dac3, 0x20108956, 0x23a510c4, 0x6cc43e80,
            0xc95ab937, 0xe83f1d75, 0xac9640c3, 0x7b6b3c66, 0xe78661f2, 0xc5bb3554, 0xa5260add,
            0x294fa807, 0xb4144e8b, 0x83591ba1, 0xe86db4b8, 0x23f14e3b, 0x8a41a00e, 0x9c8fa2fb,
            0x1cd87f54, 0xb4633142, 0x9c8f8154, 0x1591d05e, 0x7270cbdf, 0x94525c2a, 0xe734b15,
            0x53a01c76, 0x7dcb3a4, 0xafa0d081, 0xc1a8f711, 0x9267c753, 0xbff89aab, 0x5f4cfb0d,
            0x8a6eb8b5, 0x55858850, 0xa36dd1ca, 0xcc93c10a, 0x79e1f83b, 0x2e443271, 0x33b43113,
            0xabf9844a, 0x264399f9, 0x40faa747, 0x4d08bf4e, 0x630034fd, 0xda6921c5, 0x87a9b73b,
            0xd741d35d, 0x830f69c4, 0x3e57a43d, 0x98838ab5, 0x75dc7840, 0x8d091002, 0xe1734bc6,
            0xf065618b, 0x5f128159, 0x32dea1d, 0x43860de1, 0xbc52b08, 0x665926da, 0xab8c3df8,
            0x937790a5, 0x30a5e58e, 0x59ef9891, 0xce23e24f, 0xb77e876c, 0x8a3f9f38, 0xbdd33a18,
            0x7e4730b4, 0x9c4a42f6, 0x627971aa, 0xf6c5fb99, 0xc08e29a6, 0x6bb47ca2, 0xd01daae8,
            0x59581309, 0x44732399, 0x5f5fa281, 0xd36c6e58, 0xb7194851, 0x98b2e3c0, 0xb5cb4372,
            0x4ef0529b, 0xdb2b67e9, 0x279aa100, 0x90cbc290, 0xee1b7b93, 0x77116c81, 0x9cd1b382,
            0xc09b93fc, 0x7bea81e1, 0x3cb53161, 0xb55377e4, 0xa26a01d9, 0xafc13b66, 0x87b6cccc,
            0xb25c336a, 0xa3a80247, 0x2329e58d, 0x62dd38ca, 0xca9bbdb0, 0x2f2b396a, 0x464453f4,
            0xca5afe76, 0x414cc4d6, 0xd53ba33a, 0x3e529a0d, 0xa63a034b, 0xb41d3c56, 0x2d65b443,
            0x451af08b, 0xda1bb9aa, 0x6b9b9027, 0x13775176, 0x950b2d46, 0x4e67e399, 0x3d263cd4,
            0xa20f00b4, 0xa982bd02, 0x47595ae4, 0x252715c3, 0x6c0a9ccb, 0xd2c93ba, 0xe94467d1,
            0x1d18448, 0xbfaf87f7, 0x14715861, 0x1863263d, 0xf772d0d2, 0x24077ef9, 0x6dd1439a,
            0xb521552d, 0x83c52dea, 0xaf137114, 0xa834884a, 0xea74b94b, 0x2be1e902, 0xe94d3087,
            0x3639bba5, 0x8ba31360, 0x3a52a036, 0x140a7ecb, 0x1520a850, 0xd55e0bcc, 0x5b324252,
            0x36fc921c, 0x14abf3fd, 0x33626f41, 0x8aba09a7, 0x2492a028, 0xd1809657, 0xc543c96c,
            0x8db8349a, 0x6c9abd6a, 0xb0389d26, 0x9d7014f8, 0x1c98be57, 0x4b291a3a, 0xb2806a0c,
            0x22dc8294, 0xa5e87928, 0xa08f35fd, 0x1cce97d5, 0x2bfc2b24, 0x28708a27, 0x29a34f5a,
            0x8ed4ea9e, 0xf167462f, 0x8b3e0725, 0x2657286b, 0x13242825, 0x96564db5, 0xbe059f6a,
            0x452b280, 0xa44e0d87, 0xb21aa2cd, 0xdf6aa565, 0x3bfa112, 0x56e9348f, 0xb884d50d,
            0xd40cd04e, 0xd83ca4b2, 0xc4aa9a68, 0x5a02a685, 0x637b46b1, 0x17002fe1, 0xc65ab9f6
        ]
    );

    assert!(decaps_key.matches(&[
        0xdac07e1, 0x16073c76, 0x71eba683, 0xfb57db5f, 0xd5d590f6, 0x7f536c03, 0x3c816829,
        0xf8188c38, 0xbd1b4f8c, 0x5e4a6b3f, 0x41890576, 0x5e2b3441, 0x4b05270a, 0xb2f4306c,
        0x8ae634ad, 0x338a029d, 0x705dceba, 0x2c9d1c6, 0xde4e4074, 0xf1079b98, 0xa6e5be2e,
        0x2d5bd4fd, 0xb00861b3, 0x48c9578c, 0xc334282c, 0x29fbbbf4, 0xb4b75cbc, 0xbe23d5dd,
        0xd6eb652a, 0x8c210916, 0xe6543b72, 0xf21f9832, 0xc3930933, 0xa2b08736, 0x88987ca0,
        0xc3b3295e, 0x528d74bc, 0x97eebd47, 0x575ef4c, 0x3cab9927, 0xf5b43d79, 0x62c85446,
        0x836e1a03, 0xc16f3c97, 0x99419cc2, 0x6e5c2363, 0x28d499da, 0x6eca2f6b, 0xcc04b476,
        0xb7d3c31b, 0x8349a7c, 0x294a67d8, 0x2011c649, 0x65296c81, 0x444b6931, 0xa2c95882,
        0x7af6a8a4, 0xee8e08f8, 0xb561ac62, 0x135453cd, 0xf587fbe9, 0x78e381eb, 0xd58e765,
        0x44c511a6, 0x3b395754, 0xad9cd4aa, 0x47cc7a71, 0x6b5bb71c, 0x92b49f4c, 0x9a6854a3,
        0xb7edce44, 0x40e6830a, 0x64c4a249, 0x931ec820, 0x4d47075b, 0x466b1551, 0x2487c5fa,
        0xe00081c, 0x889241c1, 0xa3f4cfd5, 0xa9495a59, 0x170d76b0, 0x47b2310a, 0x30523ebf,
        0xee16c9b5, 0x4bb41314, 0x510a27a5, 0x9b62f259, 0xd7bd6261, 0x2416d02f, 0xcd4fdb6b,
        0xc32939e4, 0xae121a52, 0x8491c1ad, 0x7ac59a74, 0x836abf3d, 0xd49a54e8, 0x32746645,
        0x2b6565ca, 0x979274e6, 0xb9f0cb31, 0x6e9242f, 0xe47aaadc, 0x51983377, 0x3a9a9c9f,
        0x1c60eb98, 0x1b9bbd1c, 0x3673c66f, 0xc20115a6, 0x5bb11d88, 0xc1b94a8d, 0x385147ba,
        0xf6599a34, 0x628a0e86, 0x7f112575, 0x906a2b15, 0x2426e636, 0x8968cb00, 0xea1e080b,
        0xb4450b58, 0x5beb9c3, 0x2853088, 0x63606608, 0x743a6bca, 0x9985091b, 0x8a621191,
        0xd4217410, 0x292a8734, 0x5d2c9a7d, 0x214482ad, 0x80b36035, 0x32c3d202, 0x2cc09290,
        0x99594102, 0x69751699, 0xccc7b474, 0x89a48c51, 0x7b9bb629, 0xb8c390d2, 0x27306c40,
        0x5ba9cf9c, 0xa27040fc, 0x33ca2002, 0x6b0a530, 0xcb53a47d, 0x96c36332, 0xa797ab7,
        0x862c3ca8, 0xb1426093, 0x59779495, 0x5c25f2ab, 0x2b8b186c, 0x51bb1399, 0x126cd312,
        0xe89ab39b, 0x9535af1a, 0xbc8f86c2, 0x3329b288, 0xabaf484, 0x228c7395, 0x87e812c5,
        0x56fa240a, 0xc4a5804a, 0x7bb77231, 0x40c3b022, 0xc51b793a, 0x52ce6661, 0x9b301eba,
        0xd922c874, 0xe57c5d55, 0xc9127700, 0xc403bd7, 0x62fe33f8, 0x7a00708b, 0x491a4b7b,
        0x8819e94, 0x167aeb87, 0xc16068e6, 0xb1078b51, 0xb708e673, 0x6488432f, 0x85ba3d26,
        0x64b5b43b, 0x74435c29, 0xf29131fc, 0x9996c93d, 0x4989463a, 0x41a87dd0, 0xb2c936b6,
        0x686d7b5d, 0x866d1936, 0x3f4c4869, 0xdea21c83, 0x4433b53c, 0x33313892, 0x322621a3,
        0xc2aa1d63, 0xa14128b8, 0xa5970389, 0x5faa44a, 0x2a4bb435, 0x347181d6, 0xa0ac94fc,
        0xae809714, 0xcb8ffadd, 0x70249503, 0xa56cc210, 0xe6467540, 0x88678512, 0xc4a5ca83,
        0xfc195ad3, 0x62940d0a, 0x6120f71c, 0xbfcfa4bc, 0x7bfa5f1c, 0x4101268d, 0xf87e6514,
        0xb92b7685, 0x33186507, 0xa23db6a3, 0xa11e5f42, 0x25853d56, 0x20847c56, 0x59dc90e4,
        0x32c01a9e, 0x1d2e087d, 0xe4693205, 0x420c4f08, 0x2c44b147, 0xdbada2b9, 0xacb16946,
        0x29be243f, 0x92dbcbc3, 0x8fcce1c9, 0x11976cdf, 0xa1735fd6, 0x3863a766, 0xffcf6a08,
        0x9744ae87, 0xc7e0acb6, 0xea69b692, 0x38e8c574, 0xb271fc28, 0x5986276d, 0xd90219ab,
        0x9aead799, 0x263af3f6, 0xd296a264, 0x8a58ce17, 0x698bc69c, 0x49d1c941, 0xa4bb1d29,
        0xf68f12e7, 0xb04a6fb0, 0xecc5a09, 0x146437e, 0xe2bc94b6, 0x59e3af29, 0x19bc1508,
        0xaf35bfa, 0x7bcc8605, 0x4596b40a, 0x356c9af8, 0x2414debd, 0xbb3562ca, 0xa7627017,
        0xb994b440, 0x1929d6fb, 0xfcb95226, 0xc5130112, 0x3233f659, 0x39958984, 0x1dfa9103,
        0x252224f5, 0x83e501c7, 0xa9632907, 0x4051a64f, 0xd9289dac, 0x6a6a529c, 0xa20e1636,
        0xc469890, 0x62d93041, 0x40aad658, 0x50893883, 0xbe0b3c9b, 0xbb1f3399, 0xa93c9e48,
        0x4c828a33, 0x2ea10710, 0xd7cd86e3, 0x50203a62, 0xf957b1ab, 0x6a7ec2e7, 0x39109e6f,
        0x6a76a7cf, 0x47435227, 0x4572f7d, 0xf123a02d, 0x7c692a04, 0x4f619063, 0x7c9df847,
        0x73ccb270, 0x16b4d227, 0x956f17f, 0x482f9715, 0xaf98e683, 0x715796ba, 0xbc49ad0,
        0x2c50d8bc, 0x6a6817f, 0x851c6260, 0x9c93980c, 0x999330a, 0xd66f8979, 0x3cac2cc5,
        0x304c8435, 0x29d42810, 0x4cf83a89, 0xa405b8f7, 0x27f5c8d5, 0x2887dfcb, 0xf479f25e,
        0xe0130d00, 0x121c472a, 0x53144c23, 0x77a2ba6a, 0x1661831e, 0xbb6c8167, 0xc7c09a4c,
        0x8dd89938, 0x39c5f3f6, 0x8aea5599, 0xb51af26e, 0xcb4cf585, 0xf977ba08, 0x503b754a,
        0xff1a699c, 0xa7d7847a, 0xbb58af4b, 0x3aa2e3ba, 0xc2e35ae7, 0xadf2dd4c, 0x9bb6b057,
        0xab28810a, 0x6566e802, 0x4cc9208c, 0xa9252392, 0xbda1b428, 0x21cab702, 0x40cd7b92,
        0x6b073f8f, 0x86557699, 0xa5cc330a, 0x37435528, 0xd17c91ab, 0xeac428f8, 0x31569be,
        0x808920d7, 0x322040cb, 0x6ae6175a, 0x5d874233, 0x11e7b227, 0xa1430e79, 0xb3975993,
        0xa38a4064, 0x88d1525a, 0xcaced83f, 0xa9c956f0, 0xc72c135e, 0xd6c6f45e, 0x931b96c8,
        0xce19a0bc, 0x4db8d077, 0xf86f1d51, 0x36fa936c, 0xdc1ad739, 0xa9af1388, 0x24a04655,
        0xb4ab042b, 0xb26d5ae0, 0xbe7bbdab, 0xf64f9920, 0xe6615c19, 0x327864bc, 0x4814898e,
        0xb15b7012, 0x40445527, 0x89bef849, 0x675b39a1, 0xa9521326, 0xe68578dc, 0x2ca846a9,
        0x5ab3e598, 0x6a2205d6, 0xc82885a5, 0x4192cca4, 0x860f738f, 0xd1829988, 0x3eb59864,
        0x1e7c6912, 0xb81432e5, 0x923ab46b, 0xb6fa547, 0x96b67123, 0x6a698bc1, 0xf28c41a8,
        0x550720ca, 0x1bc9b953, 0x108c7b8e, 0x423cb260, 0x3ea0c055, 0xbd92c17f, 0x39415d06,
        0x49b3002b, 0xec77164d, 0x869f9360, 0x5d2714c4, 0xe94dacb8, 0xbc9e9433, 0x9d891a50,
        0x2435231a, 0xa8574f6c, 0xbeaac48c, 0x732b2305, 0x35d073c6, 0x6c15ec8a, 0x4c9dd55f,
        0x3ae705b5, 0x751b9519, 0x4cab896, 0xc27e46d8, 0x722b3b22, 0x4643c9e0, 0x6b25a917,
        0x4d419158, 0x903056be, 0x78a5b31, 0x295cd2bd, 0xb202f300, 0x3ca0cba1, 0x7e08b44c,
        0x9c9c3159, 0x9cb5c7ea, 0x38f6e456, 0xcc6f9ade, 0xf42a6887, 0x9455fc0d, 0xcf451598,
        0xd0c2e8, 0x8bb2df6d, 0xd4afc83c, 0x26507968, 0x3dc9b835, 0x7811bb31, 0x87447cd9,
        0x14166497, 0xbecb9706, 0xf2ab64fc, 0x4270b818, 0xc81d51dc, 0x536a4e58, 0x8181f726,
        0x3b7060d3, 0x613d2c2c, 0x56e963a2, 0x819f92f7, 0x94d7a406, 0xb9917e31, 0xacbb058c,
        0x30f07490, 0x24080842, 0xf09a604c, 0xe8286d2c, 0xb0624e24, 0xd65e0584, 0x55397138,
        0xc4510f75, 0xdfb15255, 0x2c7c06d6, 0x236785a6, 0xdd953c91, 0xec147b14, 0x4d2c221c,
        0x8787aa4c, 0xf1b02101, 0x9f241c9a, 0x1d2b686b, 0x1a6ac75b, 0xe71f7a7, 0xbc2910c2,
        0x256a0050, 0xfe7e421, 0x20852850, 0x29675bc3, 0x54e01eb9, 0x93529149, 0x44429b64,
        0x997a29c2, 0xfc2fe436, 0x599a3f05, 0x5318632f, 0xdd7fc0b2, 0x399c3b85, 0x664b5e3f,
        0x30273089, 0x18b75ed0, 0x33934615, 0x4d628b07, 0xf2880248, 0x14f79305, 0xe74ffb98,
        0xe14d5c89, 0x72860532, 0xae6b73ca, 0x25cc719a, 0xa2481604, 0x6a138055, 0x185a0b36,
        0x8156c22c, 0x2ac47024, 0xc494bbdc, 0x5050ae32, 0xb32c3aeb, 0x83b79a69, 0x35d8395c,
        0x14cc25a6, 0x8c3bbeb, 0x6ed25b87, 0xd3366672, 0xe8b56a99, 0x744a52cb, 0x684af8e5,
        0xf068adcc, 0xa5e3ec1d, 0x98cd9289, 0xc24309e6, 0xb3c6c070, 0x8d001ae2, 0xbac9b8ba,
        0xdb7c2ac, 0xf0998b6d, 0x7bda9185, 0xa204149c, 0x58400a4b, 0x5469c053, 0x15779d79,
        0xf6b09cb0, 0x17c07ed2, 0x5be86726, 0x5238a57d, 0x5a0d75b2, 0xa5f7be74, 0x23530294,
        0x158616b6, 0x49751244, 0x68959817, 0x54380769, 0xb6c54845, 0x32461948, 0x95c008bb,
        0xafbcde48, 0x92c2f5c3, 0x96f307d0, 0x1fd07219, 0x2740c41b, 0xa7f63226, 0x83576b2f,
        0xd8984c0f, 0x990553f0, 0x9d734da1, 0x1043e78c, 0x3ba21d6, 0x15e3d43b, 0x78835bc8,
        0x758e6331, 0x6b46a91b, 0xf25ba5eb, 0x4b969ec6, 0xcf4900ad, 0xaf423626, 0xa576ba52,
        0x6f65fa63, 0x890375f5, 0x4b88b8f2, 0x2e511d36, 0xb3547249, 0x16abba50, 0x9681be17,
        0x453c13d5, 0x586a5c23, 0x6d45dac3, 0x20108956, 0x23a510c4, 0x6cc43e80, 0xc95ab937,
        0xe83f1d75, 0xac9640c3, 0x7b6b3c66, 0xe78661f2, 0xc5bb3554, 0xa5260add, 0x294fa807,
        0xb4144e8b, 0x83591ba1, 0xe86db4b8, 0x23f14e3b, 0x8a41a00e, 0x9c8fa2fb, 0x1cd87f54,
        0xb4633142, 0x9c8f8154, 0x1591d05e, 0x7270cbdf, 0x94525c2a, 0xe734b15, 0x53a01c76,
        0x7dcb3a4, 0xafa0d081, 0xc1a8f711, 0x9267c753, 0xbff89aab, 0x5f4cfb0d, 0x8a6eb8b5,
        0x55858850, 0xa36dd1ca, 0xcc93c10a, 0x79e1f83b, 0x2e443271, 0x33b43113, 0xabf9844a,
        0x264399f9, 0x40faa747, 0x4d08bf4e, 0x630034fd, 0xda6921c5, 0x87a9b73b, 0xd741d35d,
        0x830f69c4, 0x3e57a43d, 0x98838ab5, 0x75dc7840, 0x8d091002, 0xe1734bc6, 0xf065618b,
        0x5f128159, 0x32dea1d, 0x43860de1, 0xbc52b08, 0x665926da, 0xab8c3df8, 0x937790a5,
        0x30a5e58e, 0x59ef9891, 0xce23e24f, 0xb77e876c, 0x8a3f9f38, 0xbdd33a18, 0x7e4730b4,
        0x9c4a42f6, 0x627971aa, 0xf6c5fb99, 0xc08e29a6, 0x6bb47ca2, 0xd01daae8, 0x59581309,
        0x44732399, 0x5f5fa281, 0xd36c6e58, 0xb7194851, 0x98b2e3c0, 0xb5cb4372, 0x4ef0529b,
        0xdb2b67e9, 0x279aa100, 0x90cbc290, 0xee1b7b93, 0x77116c81, 0x9cd1b382, 0xc09b93fc,
        0x7bea81e1, 0x3cb53161, 0xb55377e4, 0xa26a01d9, 0xafc13b66, 0x87b6cccc, 0xb25c336a,
        0xa3a80247, 0x2329e58d, 0x62dd38ca, 0xca9bbdb0, 0x2f2b396a, 0x464453f4, 0xca5afe76,
        0x414cc4d6, 0xd53ba33a, 0x3e529a0d, 0xa63a034b, 0xb41d3c56, 0x2d65b443, 0x451af08b,
        0xda1bb9aa, 0x6b9b9027, 0x13775176, 0x950b2d46, 0x4e67e399, 0x3d263cd4, 0xa20f00b4,
        0xa982bd02, 0x47595ae4, 0x252715c3, 0x6c0a9ccb, 0xd2c93ba, 0xe94467d1, 0x1d18448,
        0xbfaf87f7, 0x14715861, 0x1863263d, 0xf772d0d2, 0x24077ef9, 0x6dd1439a, 0xb521552d,
        0x83c52dea, 0xaf137114, 0xa834884a, 0xea74b94b, 0x2be1e902, 0xe94d3087, 0x3639bba5,
        0x8ba31360, 0x3a52a036, 0x140a7ecb, 0x1520a850, 0xd55e0bcc, 0x5b324252, 0x36fc921c,
        0x14abf3fd, 0x33626f41, 0x8aba09a7, 0x2492a028, 0xd1809657, 0xc543c96c, 0x8db8349a,
        0x6c9abd6a, 0xb0389d26, 0x9d7014f8, 0x1c98be57, 0x4b291a3a, 0xb2806a0c, 0x22dc8294,
        0xa5e87928, 0xa08f35fd, 0x1cce97d5, 0x2bfc2b24, 0x28708a27, 0x29a34f5a, 0x8ed4ea9e,
        0xf167462f, 0x8b3e0725, 0x2657286b, 0x13242825, 0x96564db5, 0xbe059f6a, 0x452b280,
        0xa44e0d87, 0xb21aa2cd, 0xdf6aa565, 0x3bfa112, 0x56e9348f, 0xb884d50d, 0xd40cd04e,
        0xd83ca4b2, 0xc4aa9a68, 0x5a02a685, 0x637b46b1, 0x17002fe1, 0xc65ab9f6, 0xb6b26546,
        0xae6a2074, 0x7621ee62, 0xe9b7863c, 0xf0fb834f, 0x52005fb0, 0x7a5b738b, 0x77cccbea,
        0x87654321, 0xfedcba9, 0x44332211, 0x88776655, 0xddccbbaa, 0x1100ffee, 0x55443322,
        0x99887766,
    ]));
}

fn test_key_pair_generation_from_kv() {
    seed_abr_entropy();
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };

    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut aes = Aes::new(unsafe { AesReg::new() }, unsafe { AesClpReg::new() }).unwrap();

    // Store seeds in key vault
    let key_out = KeyWriteArgs {
        id: KEY_ID,
        usage: KeyUsage::default().set_mlkem_seed_en(),
    };

    hmac.hmac(
        HmacKey::from(&Array4x12::default()),
        HmacData::from(&[]),
        &mut trng,
        HmacTag::Key(key_out),
        // ML-KEM needs both 32-byte seeds; HMAC-384 only fills 48 bytes.
        HmacMode::Hmac512,
    )
    .unwrap();

    // Test key pair generation from key vault with KV-based PCT
    let seeds = MlKem1024Seeds::Key(KeyReadArgs::new(KEY_ID));
    let (encaps_key, decaps_key) = mlkem
        .key_pair(
            seeds,
            Some(MlKemPctKvContext {
                aes: &mut aes,
                shared_key_id: KeyId::KeyId3,
            }),
        )
        .unwrap();

    // Encapsulation key should be non-zero (basic sanity check)
    assert_ne!(encaps_key.0, [0u32; 392]);
    // Decapsulation key should be zero (because the seed is from the KV)
    assert!(decaps_key.is_zero());

    assert_eq!(
        encaps_key.0,
        include!("test_vectors/mlkem_kv_seed512_ek.rs")
    )
}

fn test_encapsulate_and_decapsulate() {
    seed_abr_entropy();
    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);

    // Generate key pair
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, decaps_key) = mlkem.key_pair(seeds, None).unwrap();

    // Test encapsulation with array message and array output
    let message = MlKem1024Message::from(MESSAGE);
    let mut shared_key_out = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut shared_key_out),
        )
        .unwrap();

    // Ciphertext should be non-zero
    assert_ne!(ciphertext.0, [0u32; 392]);
    // Shared key should be non-zero
    assert_ne!(shared_key_out.0, [0u32; 8]);

    // Test decapsulation
    let mut decaps_shared_key = MlKem1024SharedKey::default();
    mlkem
        .decapsulate(
            &decaps_key,
            &ciphertext,
            MlKem1024SharedKeyOut::Array(&mut decaps_shared_key),
        )
        .unwrap();

    // The decapsulated shared key should match the encapsulated one
    assert_eq!(shared_key_out.0, decaps_shared_key.0);
}

fn test_encapsulate_with_kv_message() {
    seed_abr_entropy();
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
        .unwrap()
    };

    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };

    // Generate key pair
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, _decaps_key) = mlkem.key_pair(seeds, None).unwrap();

    // Store message in key vault
    let msg_key_id = KeyId::KeyId3;
    let msg_key_out = KeyWriteArgs {
        id: msg_key_id,
        usage: KeyUsage::default().set_mlkem_msg_en(),
    };

    let message_array = LEArray4x8::from(MESSAGE);
    let message_bytes = message_array.as_bytes();
    hmac.hmac(
        HmacKey::from(&Array4x12::default()),
        HmacData::from(message_bytes),
        &mut trng,
        HmacTag::Key(msg_key_out),
        HmacMode::Hmac384,
    )
    .unwrap();

    // Test encapsulation with key vault message
    let mut shared_key_out = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Key(KeyReadArgs::new(msg_key_id)),
            MlKem1024SharedKeyOut::Array(&mut shared_key_out),
        )
        .unwrap();

    // Ciphertext should be non-zero
    assert_eq!(
        ciphertext.0,
        include!("test_vectors/mlkem_kv_message_ciphertext.rs")
    );
    // Shared key should be zero (since we are using KV)
    assert_eq!(shared_key_out.0, [0u32; 8]);

    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Key(KeyReadArgs::new(msg_key_id)),
            MlKem1024SharedKeyOut::Key(KeyWriteArgs::new(
                msg_key_id,
                KeyUsage::default().set_aes_key_en(),
            )),
        )
        .unwrap();

    // Ciphertext should be non-zero
    assert_eq!(
        ciphertext.0,
        include!("test_vectors/mlkem_kv_message_ciphertext.rs")
    );
}

fn test_encapsulate_with_kv_output() {
    seed_abr_entropy();
    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);

    // Generate key pair
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, _decaps_key) = mlkem.key_pair(seeds, None).unwrap();

    // Test encapsulation with key vault shared key output
    let shared_key_id = KeyId::KeyId4;
    let mut shared_key_usage = KeyUsage::default();
    shared_key_usage.set_hmac_key(true);
    let shared_key_out = KeyWriteArgs {
        id: shared_key_id,
        usage: shared_key_usage,
    };

    let message = MlKem1024Message::from(MESSAGE);
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Key(shared_key_out),
        )
        .unwrap();

    // Ciphertext should be non-zero
    assert_ne!(ciphertext.0, [0u32; 392]);
}

fn test_keygen_decapsulate() {
    seed_abr_entropy();
    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);

    // Generate key pair for encapsulation
    let seed_d = LEArray4x8::from(SEED_D);
    let seed_z = LEArray4x8::from(SEED_Z);
    let seeds_enc = MlKem1024Seeds::Arrays(&seed_d, &seed_z);
    let (encaps_key, _) = mlkem.key_pair(seeds_enc, None).unwrap();

    // Encapsulate with the encaps key
    let message = MlKem1024Message::from(MESSAGE);
    let mut original_shared_key = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut original_shared_key),
        )
        .unwrap();

    // Test keygen + decapsulate in one operation
    let seed_d2 = LEArray4x8::from(SEED_D);
    let seed_z2 = LEArray4x8::from(SEED_Z);
    let seeds_dec = MlKem1024Seeds::Arrays(&seed_d2, &seed_z2);
    let mut keygen_decaps_shared_key = MlKem1024SharedKey::default();
    mlkem
        .keygen_decapsulate(
            seeds_dec,
            &ciphertext,
            MlKem1024SharedKeyOut::Array(&mut keygen_decaps_shared_key),
        )
        .unwrap();

    // The shared keys should match since we used the same seeds
    assert_eq!(original_shared_key.0, keygen_decaps_shared_key.0);
}

fn test_keygen_decapsulate_with_kv() {
    seed_abr_entropy();
    let mut abr_reg = unsafe { AbrReg::new() };
    let mut mlkem = MlKem1024::new(&mut abr_reg);
    let mut aes = Aes::new(unsafe { AesReg::new() }, unsafe { AesClpReg::new() }).unwrap();

    // Generate key pair for encapsulation using KV
    let seeds_kv = MlKem1024Seeds::Key(KeyReadArgs::new(KEY_ID));
    let (encaps_key, _) = mlkem
        .key_pair(
            seeds_kv,
            Some(MlKemPctKvContext {
                aes: &mut aes,
                shared_key_id: KeyId::KeyId3,
            }),
        )
        .unwrap();

    // Encapsulate
    let message = MlKem1024Message::from(MESSAGE);
    let mut original_shared_key = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &encaps_key,
            MlKem1024MessageSource::Array(&message),
            MlKem1024SharedKeyOut::Array(&mut original_shared_key),
        )
        .unwrap();

    // Test keygen + decapsulate with KV seeds and KV output
    let shared_key_out_id = KeyId::KeyId5;
    let mut shared_key_out_usage = KeyUsage::default();
    shared_key_out_usage.set_aes_key(true);
    let shared_key_out = KeyWriteArgs {
        id: shared_key_out_id,
        usage: shared_key_out_usage,
    };

    mlkem
        .keygen_decapsulate(
            MlKem1024Seeds::Key(KeyReadArgs::new(KEY_ID)),
            &ciphertext,
            MlKem1024SharedKeyOut::Key(shared_key_out),
        )
        .unwrap();

    // If we got here without error, the operation succeeded
}

test_suite! {
    test_mlkem_name,
    test_key_pair_generation,
    test_key_pair_generation_from_kv,
    test_encapsulate_and_decapsulate,
    test_encapsulate_with_kv_message,
    test_encapsulate_with_kv_output,
    test_keygen_decapsulate,
    test_keygen_decapsulate_with_kv,
}
