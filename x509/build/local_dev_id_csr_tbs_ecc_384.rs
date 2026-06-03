#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template with: cargo run -p caliptra-x509-gen

--"]
#[allow(clippy::needless_lifetimes)]
pub struct LocalDevIdCsrTbsEcc384Params<'a> {
    pub public_key: &'a [u8; 97usize],
    pub subject_sn: &'a [u8; 64usize],
    pub ueid: &'a [u8; 17usize],
}
impl LocalDevIdCsrTbsEcc384Params<'_> {
    pub const PUBLIC_KEY_LEN: usize = 97usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
    pub const UEID_LEN: usize = 17usize;
}
pub struct LocalDevIdCsrTbsEcc384 {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
impl LocalDevIdCsrTbsEcc384 {
    const PUBLIC_KEY_OFFSET: usize = 144usize;
    const SUBJECT_SN_OFFSET: usize = 57usize;
    const UEID_OFFSET: usize = 312usize;
    const PUBLIC_KEY_LEN: usize = 97usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    const UEID_LEN: usize = 17usize;
    pub const TBS_TEMPLATE_LEN: usize = 358usize;
    const COMPRESSED_TBS_TEMPLATE_BEFORE_KEY: [u8; 98usize] = [
        255u8, 48u8, 130u8, 1u8, 98u8, 2u8, 1u8, 0u8, 48u8, 255u8, 112u8, 49u8, 35u8, 48u8, 33u8,
        6u8, 3u8, 85u8, 255u8, 4u8, 3u8, 12u8, 26u8, 67u8, 97u8, 108u8, 105u8, 255u8, 112u8, 116u8,
        114u8, 97u8, 32u8, 50u8, 46u8, 49u8, 255u8, 32u8, 69u8, 99u8, 99u8, 51u8, 56u8, 52u8, 32u8,
        255u8, 76u8, 68u8, 101u8, 118u8, 73u8, 68u8, 49u8, 73u8, 123u8, 48u8, 71u8, 2u8, 81u8, 5u8,
        19u8, 64u8, 95u8, 0u8, 31u8, 248u8, 1u8, 63u8, 2u8, 95u8, 3u8, 118u8, 48u8, 118u8, 48u8,
        16u8, 6u8, 255u8, 7u8, 42u8, 134u8, 72u8, 206u8, 61u8, 2u8, 1u8, 255u8, 6u8, 5u8, 43u8,
        129u8, 4u8, 0u8, 34u8, 3u8, 3u8, 98u8, 0u8,
    ];
    const COMPRESSED_TBS_TEMPLATE_AFTER_KEY: [u8; 96usize] = [
        255u8, 160u8, 115u8, 48u8, 113u8, 6u8, 9u8, 42u8, 134u8, 255u8, 72u8, 134u8, 247u8, 13u8,
        1u8, 9u8, 14u8, 49u8, 255u8, 100u8, 48u8, 98u8, 48u8, 18u8, 6u8, 3u8, 85u8, 255u8, 29u8,
        19u8, 1u8, 1u8, 255u8, 4u8, 8u8, 48u8, 125u8, 6u8, 0u8, 112u8, 2u8, 1u8, 6u8, 48u8, 14u8,
        1u8, 65u8, 253u8, 15u8, 1u8, 65u8, 4u8, 3u8, 2u8, 2u8, 4u8, 48u8, 255u8, 31u8, 6u8, 6u8,
        103u8, 129u8, 5u8, 5u8, 4u8, 255u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8, 17u8, 95u8, 118u8,
        0u8, 29u8, 48u8, 27u8, 4u8, 81u8, 37u8, 4u8, 20u8, 4u8, 224u8, 45u8, 7u8, 2u8, 162u8,
        100u8, 7u8, 0u8, 149u8, 12u8,
    ];
    const TBS_TEMPLATE_BEFORE_KEY_LEN: usize = Self::PUBLIC_KEY_OFFSET;
    const TBS_TEMPLATE_AFTER_KEY_LEN: usize =
        Self::TBS_TEMPLATE_LEN - Self::PUBLIC_KEY_OFFSET - Self::PUBLIC_KEY_LEN;
    #[cfg(test)]
    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = {
        let mut result = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
        let before = [
            48u8, 130u8, 1u8, 98u8, 2u8, 1u8, 0u8, 48u8, 112u8, 49u8, 35u8, 48u8, 33u8, 6u8, 3u8,
            85u8, 4u8, 3u8, 12u8, 26u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8,
            50u8, 46u8, 49u8, 32u8, 69u8, 99u8, 99u8, 51u8, 56u8, 52u8, 32u8, 76u8, 68u8, 101u8,
            118u8, 73u8, 68u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 118u8, 48u8, 16u8, 6u8, 7u8, 42u8,
            134u8, 72u8, 206u8, 61u8, 2u8, 1u8, 6u8, 5u8, 43u8, 129u8, 4u8, 0u8, 34u8, 3u8, 98u8,
            0u8,
        ];
        let after = [
            160u8, 115u8, 48u8, 113u8, 6u8, 9u8, 42u8, 134u8, 72u8, 134u8, 247u8, 13u8, 1u8, 9u8,
            14u8, 49u8, 100u8, 48u8, 98u8, 48u8, 18u8, 6u8, 3u8, 85u8, 29u8, 19u8, 1u8, 1u8, 255u8,
            4u8, 8u8, 48u8, 6u8, 1u8, 1u8, 255u8, 2u8, 1u8, 6u8, 48u8, 14u8, 6u8, 3u8, 85u8, 29u8,
            15u8, 1u8, 1u8, 255u8, 4u8, 4u8, 3u8, 2u8, 2u8, 4u8, 48u8, 31u8, 6u8, 6u8, 103u8,
            129u8, 5u8, 5u8, 4u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8, 17u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8,
            27u8, 6u8, 3u8, 85u8, 29u8, 37u8, 4u8, 20u8, 48u8, 18u8, 6u8, 7u8, 103u8, 129u8, 5u8,
            5u8, 4u8, 100u8, 7u8, 6u8, 7u8, 103u8, 129u8, 5u8, 5u8, 4u8, 100u8, 12u8,
        ];
        let mut i = 0;
        while i < before.len() {
            result[i] = before[i];
            i += 1;
        }
        i = 0;
        while i < after.len() {
            result[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN + i] = after[i];
            i += 1;
        }
        result
    };
    pub fn new(params: &LocalDevIdCsrTbsEcc384Params) -> caliptra_error::CaliptraResult<Self> {
        let mut tbs = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
        let mut before_key = [0u8; Self::TBS_TEMPLATE_BEFORE_KEY_LEN];
        if !crate::lzss::decompress(&Self::COMPRESSED_TBS_TEMPLATE_BEFORE_KEY, &mut before_key) {
            return Err(caliptra_error::CaliptraError::X509_TEMPLATE_DECOMPRESSION_FAILED);
        }
        tbs[..Self::PUBLIC_KEY_OFFSET].copy_from_slice(&before_key);
        let mut after_key = [0u8; Self::TBS_TEMPLATE_AFTER_KEY_LEN];
        if !crate::lzss::decompress(&Self::COMPRESSED_TBS_TEMPLATE_AFTER_KEY, &mut after_key) {
            return Err(caliptra_error::CaliptraError::X509_TEMPLATE_DECOMPRESSION_FAILED);
        }
        tbs[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN..].copy_from_slice(&after_key);
        let mut template = Self { tbs };
        template.apply(params);
        Ok(template)
    }
    pub fn sign<Sig, Error>(
        &self,
        sign_fn: impl Fn(&[u8]) -> Result<Sig, Error>,
    ) -> Result<Sig, Error> {
        sign_fn(&self.tbs)
    }
    pub fn tbs(&self) -> &[u8] {
        &self.tbs
    }
    fn apply(&mut self, params: &LocalDevIdCsrTbsEcc384Params) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 358usize],
            val: &[u8; LEN],
        ) {
            buf[OFFSET..OFFSET + LEN].copy_from_slice(val);
        }
        apply_slice::<{ Self::PUBLIC_KEY_OFFSET }, { Self::PUBLIC_KEY_LEN }>(
            &mut self.tbs,
            params.public_key,
        );
        apply_slice::<{ Self::SUBJECT_SN_OFFSET }, { Self::SUBJECT_SN_LEN }>(
            &mut self.tbs,
            params.subject_sn,
        );
        apply_slice::<{ Self::UEID_OFFSET }, { Self::UEID_LEN }>(&mut self.tbs, params.ueid);
    }
}
#[cfg(test)]
mod lzss_tests {
    use super::*;
    #[test]
    fn test_template_decompression() {
        let mut before_key = [0u8; LocalDevIdCsrTbsEcc384::TBS_TEMPLATE_BEFORE_KEY_LEN];
        assert!(crate::lzss::decompress(
            &LocalDevIdCsrTbsEcc384::COMPRESSED_TBS_TEMPLATE_BEFORE_KEY,
            &mut before_key
        ));
        assert_eq!(
            before_key,
            LocalDevIdCsrTbsEcc384::TBS_TEMPLATE[..LocalDevIdCsrTbsEcc384::PUBLIC_KEY_OFFSET]
        );
        let mut after_key = [0u8; LocalDevIdCsrTbsEcc384::TBS_TEMPLATE_AFTER_KEY_LEN];
        assert!(crate::lzss::decompress(
            &LocalDevIdCsrTbsEcc384::COMPRESSED_TBS_TEMPLATE_AFTER_KEY,
            &mut after_key
        ));
        assert_eq!(
            after_key,
            LocalDevIdCsrTbsEcc384::TBS_TEMPLATE[LocalDevIdCsrTbsEcc384::PUBLIC_KEY_OFFSET
                + LocalDevIdCsrTbsEcc384::PUBLIC_KEY_LEN..]
        );
    }
}
