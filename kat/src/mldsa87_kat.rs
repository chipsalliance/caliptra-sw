/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for MLDSA cryptography operations.

--*/

use caliptra_drivers::{
    Array4x16, Array4x8, Array4xN, CaliptraError, CaliptraResult, Mldsa87, Mldsa87PrivKey,
    Mldsa87PubKey, Mldsa87Seed, Mldsa87SignRnd, Sha2_512_384, Trng,
};
use caliptra_registers::sha512::Sha512Reg;

use zerocopy::IntoBytes;

const KAT_PUB_KEY: Mldsa87PubKey = Array4xN::new([
    0x7aed27b5, 0xa562dd2f, 0x10f310cc, 0x99f6bf11, 0xec184836, 0x372625fd, 0xfb5c0b87, 0x06883dcd,
    0x5247bbf9, 0xef5c32ba, 0xf4764326, 0xbe01105c, 0x091fb624, 0x04255894, 0xbf8183be, 0x17f78397,
    0xfe8db74e, 0x14ff1b56, 0x846a7c3b, 0x0dace661, 0xef9ee21a, 0x9f0fe727, 0xd18f8904, 0xe5dbdfec,
    0x3fa93849, 0x44462fa5, 0x25d12e8a, 0xc56d1b20, 0x0330c59c, 0xcf27de40, 0x268a4c0f, 0x24048891,
    0x523f6039, 0x0dda85d5, 0x5d353f97, 0x5a6e6e94, 0x063926db, 0x54a8bfe3, 0x60e097cd, 0x6972eab5,
    0x3daccccb, 0x4255017f, 0xbc722547, 0x7790dc0d, 0xea3a4395, 0x6e7c8f52, 0xa9db3d2f, 0xdee33d4b,
    0x9b4a1f09, 0x4b0f3dd6, 0x57f31488, 0xfe001de2, 0xc828b5b4, 0x76d5b6f0, 0xeda04398, 0x551781e0,
    0xa3220e53, 0x7dde0d74, 0xcf391758, 0x25c1c281, 0x959d7d30, 0xe9924f10, 0xd9211ae0, 0x8b96cc04,
    0x3001cdf3, 0x7c5e416c, 0xe6b25413, 0xb57b4b3c, 0x00339027, 0x332c608a, 0xcc44e3cd, 0x1d37b809,
    0x295173f3, 0x5f3c6785, 0x7ef62145, 0x94381494, 0x772d448c, 0xbd62c3ad, 0xb67034d1, 0xa9df95e4,
    0x96aaf67f, 0x068a767c, 0xdd744d6b, 0x34c9722f, 0x3828bc5f, 0x21f6470f, 0x89c46247, 0xf95ae1dc,
    0xff58dd7c, 0x80ced308, 0x24c05432, 0x95f50e3d, 0x4ce59644, 0x21175006, 0xa3420db6, 0x7f0233dc,
    0x3c76b4da, 0x872e9986, 0xe2f0a111, 0xedd774c2, 0x7f72a687, 0x3d0b77f1, 0x5fa9cd1f, 0x158d4743,
    0xce4f4b84, 0x63dd6477, 0xdc3ada61, 0xe9df21e1, 0xf9874a59, 0x09a2a762, 0x2eaa04bc, 0x6b3660c1,
    0xdaedc89b, 0xcd5e509f, 0xfcdd9f82, 0x464633b9, 0x7e0abd8a, 0xb281f7c9, 0xf10cfcf9, 0xa18af897,
    0x0daadbdd, 0x22727509, 0x2be47f8e, 0xc18f6ee7, 0x264fc786, 0x9449cd10, 0xae7a6ffe, 0x7b162d3f,
    0xfba57f3e, 0x4fc52563, 0x3bb5019e, 0xbef12f1b, 0x2c41c523, 0xaf56cb15, 0xb5293cf9, 0x836b787c,
    0xe6360aa5, 0x42b93a52, 0xeb9c0862, 0x6bf01a0c, 0xdf1ce5cd, 0x5c32cd02, 0xd7dbd1d7, 0xd25939ea,
    0x360556dd, 0x0cd0fed8, 0x9676fe5a, 0x568ceb80, 0x42504e47, 0x7f27d0a2, 0xf67ad693, 0xe102a7fb,
    0x10f0b5df, 0x9bb5c6f1, 0xa77a5481, 0x9100a102, 0x36a4698f, 0xa20e94b8, 0xaf79e336, 0xaf26015c,
    0xb9194799, 0x64cf0fb2, 0xb929f730, 0x27ffc2f0, 0x7418ce1a, 0x32600f5c, 0xa03e7384, 0x35f3c2d0,
    0x3b141fa6, 0x89127435, 0x9fe4e0f6, 0x98e6db17, 0xb740600a, 0x2418d5cd, 0xeb26a33e, 0xadc862c1,
    0xc3aca9d5, 0x78763c6c, 0x067f2d48, 0xad776264, 0x37dd62ab, 0xf0f6dafc, 0x86c1996e, 0xffb84295,
    0x7cd1c218, 0x6cbb7aca, 0x6e5b97f0, 0xb11381b1, 0x3a84bbb7, 0x32a6f1a2, 0x08505d57, 0x00ef4032,
    0xd35f1a2a, 0xc99dff28, 0x6633f5d2, 0x14f64cda, 0x61902273, 0x8cdcd79d, 0x1d7aeeb8, 0x2a046439,
    0x76a3161e, 0xe7f6cf12, 0x6c1cf41f, 0x677069a2, 0xd710cc5d, 0x010a1f38, 0x283799b2, 0xcffc4003,
    0x8e1c7654, 0xb564d4f0, 0x5b10495a, 0x2725c0e2, 0xcd67cfdb, 0x1761bc70, 0x4c375533, 0x4db4a0da,
    0xa5e7f5af, 0x00bb9c2b, 0x253a2f58, 0x2abf62fe, 0x9613af54, 0xd8f2d657, 0xa5a35ecf, 0x836a5545,
    0xac764934, 0x7ed7bb71, 0x97b43a73, 0x1d68ed85, 0x5925ee49, 0x8140a3aa, 0x42a73de7, 0xea6071ca,
    0xcfee20c2, 0xa1ed121b, 0xe33e3e73, 0x485f0bf6, 0x5c60f008, 0x19eb2f26, 0xadee6104, 0xd9b8f02f,
    0xdb72dc72, 0xeb75bd1f, 0x5186f74d, 0x72084b4f, 0x5ed43791, 0xc247652e, 0x9c606ae2, 0x9f36d5a4,
    0x8fe991ac, 0x6cb7d838, 0x88241cb2, 0xd2062f26, 0xdd4209cd, 0xe9229b5e, 0xcaac558d, 0xad4c83f5,
    0x9baeebd6, 0x797c5620, 0xde72e799, 0x72ffa82e, 0xd89092af, 0x2e5ddd28, 0x890c1764, 0x919dca8f,
    0xcbcbf3a5, 0x525a33ca, 0x13c20bb2, 0x624692b9, 0x6e3d6142, 0x541d0d3c, 0x2676b443, 0x1835d901,
    0x2842e3b7, 0x8f60a792, 0x616720bc, 0xfbce6782, 0xe08135b3, 0x3a83ce2d, 0xb96e05c6, 0xbd240a79,
    0x69d4411d, 0x683bd53a, 0x398549fc, 0x1a560af0, 0x153a58ef, 0xea229311, 0x6004d303, 0xafd48f11,
    0x84b8b5f4, 0x186b7ec4, 0x91660f55, 0xec70520f, 0x9f70f784, 0xbf01ab56, 0x6aad1c86, 0xd2443ca8,
    0x7df71965, 0xa4b3f1c1, 0xa9b85b14, 0xa9d16a67, 0xfc2526fd, 0xcbfe975a, 0x40506029, 0x5a7e9126,
    0xbee8c3ef, 0xc6f845e9, 0x5df5ba5e, 0x48ad1f95, 0x24330843, 0x1ff7aba4, 0x15607310, 0x44219aa6,
    0x170fa53e, 0xda63015a, 0xa34d77df, 0x8097d3b9, 0x3dc9996e, 0x07417044, 0x704c543e, 0x779d6fb8,
    0xde7d8fa4, 0x8d0fcf50, 0x3deff2bb, 0x63c08b90, 0xbcaea490, 0x38cd2a0a, 0x1e70f33e, 0x6cc95a33,
    0xb18bd65f, 0x3ba2d010, 0x221c347b, 0xa18bcc1e, 0xb2c3daa0, 0x529586b0, 0xc334962b, 0xfaa03bb0,
    0xc6f25d70, 0x3c8d6a00, 0xa0327bf6, 0xd1e0c36d, 0x6b127553, 0xd8870aab, 0xbbd96838, 0x456171c3,
    0xe1cc60b5, 0xf3246c95, 0x796c603a, 0xbe89688f, 0xee4f6a5a, 0xb79daa2e, 0x8a3e09c2, 0xc097fe39,
    0x9ee26682, 0x65a25ec9, 0x75f66921, 0xdc5b3371, 0xf89ea388, 0x395f7508, 0xf44bf532, 0xc8a0ee7a,
    0xf5de37d9, 0x9ac3f456, 0xfd56b894, 0x7d200922, 0x99602b3e, 0xe70f8719, 0x8629b6b7, 0xdf867e81,
    0x5ce0e8d6, 0xffbd1390, 0x9487cb7e, 0x8c1b3a77, 0x5845205a, 0xdf1c6ded, 0x37ffeff7, 0x8e5d93e8,
    0x3320283f, 0xfb1fc5db, 0xe6623e59, 0xcc8b74ec, 0x2693a27a, 0x35cc9fe7, 0x80c71050, 0xac7857e5,
    0x2db21490, 0x9cde5207, 0xf6ed27af, 0x01be06e5, 0x35ec8bd2, 0x874a43c2, 0x4573aee6, 0x0f8feb96,
    0x6006712a, 0x8ac615ac, 0xdba47a7f, 0x16e41055, 0xcdea6cc0, 0xe16e58b5, 0x25ed0826, 0xea689725,
    0xaaafeefb, 0xe4665ae6, 0x1d5e7c6d, 0x69ad5c49, 0x878787b5, 0x0b53a88b, 0x48792512, 0xcb52b6be,
    0xc4625e73, 0x06fa3bcd, 0xa2332960, 0x94ac137c, 0x5161d88e, 0x5ea49a30, 0x15274338, 0x98966c24,
    0x1a1f1fd3, 0xecfa6986, 0x3686bd91, 0xe8d465f5, 0x4b9f0981, 0xdcd77dd7, 0x80efef4c, 0x41545043,
    0x80c17bc9, 0x0650e2c9, 0xc3d77f3e, 0x07b4bbd8, 0xd78815a6, 0x569f4063, 0xf2c45889, 0xb844f57b,
    0x64ed3680, 0xfec3a5e6, 0x0f878307, 0x74b2fb59, 0x649deef1, 0x05f476f8, 0xca906f96, 0x8b6a1895,
    0xc77adbe7, 0x8556d9e9, 0x28487bb5, 0xb261e1e1, 0x31daefa4, 0x920eed7b, 0x33124e92, 0x35ea2d57,
    0xb559c9b2, 0x112ac50c, 0xa833880c, 0xe5435b3c, 0x80937b82, 0x75919939, 0xa69a25e4, 0x722c1775,
    0x258e6c52, 0x336df5cc, 0xa9820ed7, 0xa990e502, 0x8571c29c, 0x6ae483ac, 0xdfebf770, 0xeb8e6c72,
    0xa101889e, 0x0d9dc4f2, 0x767a86ce, 0x9bdc7773, 0xc581a943, 0xdb193cd9, 0x26e11eb4, 0x5ba4354f,
    0x9abb844f, 0xf992f169, 0x75518e87, 0xa4536100, 0xa9b530ed, 0xd8801d35, 0xb2f5a791, 0x66ce618e,
    0xd987acd3, 0x001cc27a, 0x2b7c8b1a, 0x0fb4adcb, 0x778e4f3a, 0xa66bea09, 0x282c019d, 0x6bf86c62,
    0xc36e889b, 0x96bf39c2, 0xd723fd1e, 0x792b12c0, 0xfd3bedc5, 0x8a633339, 0xcfee23ef, 0x89c7ccf4,
    0x0e3f4611, 0xafebe6bf, 0x36dfcd30, 0xc2685426, 0x792cfb94, 0x783bc8f6, 0x2ad54e79, 0xff9d05a9,
    0x61c1df9a, 0xd92f8bed, 0x263a49e8, 0xc2f6f45e, 0x867c4392, 0xfb9e5011, 0xe3c46650, 0xce5b6c0f,
    0x008b15f0, 0xbe728595, 0x2492db17, 0x166c70ec, 0xb9750c84, 0x79a38052, 0x181b74ff, 0x832119ce,
    0xa2d5fcb1, 0x9363e405, 0x1f8267d1, 0xe6ff7b17, 0x9d037148, 0x87e3ab62, 0x22ac1965, 0x4cfda2f2,
    0x99921e1e, 0x416ecf2a, 0x638d6c6a, 0x5cabac6b, 0x55722d3a, 0xba54ac7d, 0x8f43bd56, 0x8b7e8e7f,
    0x0847d181, 0x00d42c7a, 0xc075d12e, 0xea96e836, 0x098fc053, 0xa124ea5f, 0xb1d7198e, 0xb80420bd,
    0xa7ad3e28, 0x5ac277d7, 0xf3266877, 0x869a55ed, 0x04201221, 0x0fa82b6f, 0x8b011452, 0x4e5a6b4c,
    0x19cc8bb5, 0x954bcbef, 0x1a52d67f, 0x54acac2c, 0x50e0be80, 0xae84cdba, 0xf12dddfd, 0x414ebcf5,
    0x9178fadb, 0x845b64e9, 0xc3f31058, 0x4a74d242, 0x902c0738, 0x3c6c9a2b, 0x1edb5549, 0x0bfda52d,
    0xa220aa74, 0x4e47a41e, 0xf62cd32c, 0xcda48197, 0x208a6b8e, 0x8ac194f4, 0x2eed6182, 0xfdbc18fe,
    0x87b88f56, 0xd7d6070d, 0xae807024, 0x7950562c, 0x40887e2d, 0xeff57bc2, 0xd1532a14, 0x40871f3f,
    0x4def66b2, 0x14491954, 0xce53d3c9, 0x728bf65f, 0x5e0255b8, 0xf6f444ff, 0x31ad13c3, 0xd05b1108,
    0x8a86b3da, 0xed838857, 0xad3a2cf8, 0x8635f2d7, 0x25b55356, 0x026a33df, 0x39f9f567, 0x983bd2b9,
    0x7afc3e14, 0x78be9c2f, 0x12e47d37, 0x3b2d5ba5, 0x348bc883, 0xc8553ef2, 0xdd04029b, 0x947cfd76,
    0x5f586b23, 0x956b4924, 0xd73fe263, 0x0c65698c, 0x32c02a23, 0x1c1ffac6, 0x775d3e80, 0xe67688da,
    0xd25de644, 0x35adbd33, 0xb59078a6, 0xc804c2de, 0x933a4251, 0xb5f988f7, 0xd83d50a8, 0xb18d5957,
    0xd0aad98f, 0x254bcd5a, 0x9d95f52c, 0x73b6dca3, 0xb9aae7b4, 0x8dd4624d, 0x53b5d7d7, 0xb34fef88,
    0x987ca072, 0x32cd2eaa, 0x1d683173, 0xf4d27aee, 0x336c5dac, 0x7b36869c, 0x5302681c, 0x5792bdba,
    0x884a5a99, 0x616f610e, 0x6049245e, 0x2a4ffcd1, 0x2e723eb0, 0x8fe77f6c, 0xdad7c056, 0xc9f4a875,
]);

const SEED: Array4x8 = Array4x8::new([
    0x2d5cf89c, 0x46768a85, 0x0768f0d4, 0xa243fe28, 0x3fcee4d5, 0x37071d12, 0x675fd127, 0x9340000a,
]);

const KAT_MESSAGE: [u32; 16] = [
    0xc8f518d4, 0xf3aa1bd4, 0x6ed56c1c, 0x3c9e16fb, 0x800af504, 0xdb988435, 0x48c5f623, 0xee115f73,
    0xd4c62abc, 0x06d303b5, 0xd90d9a17, 0x5087290d, 0x16e60096, 0x44e2a5f2, 0xc41fed22, 0xe703fb78,
];

const KAT_PRIV_KEY_DIGEST: Array4x16 = Array4x16::new([
    0xa3eae8e3, 0x8ac986e1, 0xc4ccaee, 0x3e6b4782, 0xf8fe3932, 0x91e0b7a7, 0x75408072, 0xbb85b44,
    0xa174b457, 0x1d259780, 0xf826de94, 0x1d75fbca, 0x7f1741ed, 0x4b741f69, 0xd4d96eaa, 0x1a6645aa,
]);

const KAT_SIGNATURE_DIGEST: Array4x16 = Array4x16::new([
    0x58bad4e0, 0x6e57218f, 0x53248540, 0x27f1fe3d, 0x1da1ead8, 0x282ed21c, 0xedfa3c8f, 0x11be4e13,
    0x9bc9e4af, 0xaf19baa4, 0xfe7fe6c5, 0x87ad51ce, 0x125126b6, 0xab490691, 0xa588551a, 0xb3942cd6,
]);

#[derive(Default, Debug)]
pub struct Mldsa87Kat {}

impl Mldsa87Kat {
    /// This function executes the Known Answer Tests (aka KAT) for MLDSA87.
    ///
    /// # Arguments
    ///
    /// * `mldsa87` - MLDSA87 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, mldsa87: &mut Mldsa87, trng: &mut Trng) -> CaliptraResult<()> {
        self.kat_key_pair_gen_sign_and_verify(mldsa87, trng)
    }

    fn kat_key_pair_gen_sign_and_verify(
        &self,
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
    ) -> CaliptraResult<()> {
        let mut priv_key = Mldsa87PrivKey::default();
        let pub_key = mldsa87
            .key_pair(&Mldsa87Seed::Array4x8(&SEED), trng, Some(&mut priv_key))
            .map_err(|_| CaliptraError::KAT_MLDSA87_KEY_PAIR_GENERATE_FAILURE)?;

        // Compare SHA-512 hashes of the priv_key and signature to save on ROM space.
        let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
        let priv_key_digest = sha2
            .sha512_digest(priv_key.as_bytes())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

        if pub_key != KAT_PUB_KEY || priv_key_digest != KAT_PRIV_KEY_DIGEST {
            Err(CaliptraError::KAT_MLDSA87_KEY_PAIR_VERIFY_FAILURE)?;
        }

        let signature = mldsa87
            .sign(
                &Mldsa87Seed::Array4x8(&SEED),
                &KAT_PUB_KEY,
                &KAT_MESSAGE.into(),
                &Mldsa87SignRnd::default(),
                trng,
            )
            .map_err(|_| CaliptraError::KAT_MLDSA87_SIGNATURE_FAILURE)?;

        let signature_digest = sha2
            .sha512_digest(signature.as_bytes())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

        if signature_digest != KAT_SIGNATURE_DIGEST {
            Err(CaliptraError::KAT_MLDSA87_SIGNATURE_MISMATCH)?;
        }

        Ok(())
    }
}
