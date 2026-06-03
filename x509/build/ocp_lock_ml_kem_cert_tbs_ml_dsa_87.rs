#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template with: cargo run -p caliptra-x509-gen

--"]
#[allow(clippy::needless_lifetimes)]
pub struct OcpLockMlKemCertTbsMlDsa87Params<'a> {
    pub public_key: &'a [u8; 1568usize],
    pub subject_sn: &'a [u8; 64usize],
    pub issuer_sn: &'a [u8; 64usize],
    pub serial_number: &'a [u8; 20usize],
    pub subject_key_id: &'a [u8; 20usize],
    pub authority_key_id: &'a [u8; 20usize],
    pub not_before: &'a [u8; 15usize],
    pub not_after: &'a [u8; 15usize],
}
impl OcpLockMlKemCertTbsMlDsa87Params<'_> {
    pub const PUBLIC_KEY_LEN: usize = 1568usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
    pub const ISSUER_SN_LEN: usize = 64usize;
    pub const SERIAL_NUMBER_LEN: usize = 20usize;
    pub const SUBJECT_KEY_ID_LEN: usize = 20usize;
    pub const AUTHORITY_KEY_ID_LEN: usize = 20usize;
    pub const NOT_BEFORE_LEN: usize = 15usize;
    pub const NOT_AFTER_LEN: usize = 15usize;
}
pub struct OcpLockMlKemCertTbsMlDsa87 {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
impl OcpLockMlKemCertTbsMlDsa87 {
    const PUBLIC_KEY_OFFSET: usize = 344usize;
    const SUBJECT_SN_OFFSET: usize = 258usize;
    const ISSUER_SN_OFFSET: usize = 97usize;
    const SERIAL_NUMBER_OFFSET: usize = 11usize;
    const SUBJECT_KEY_ID_OFFSET: usize = 1983usize;
    const AUTHORITY_KEY_ID_OFFSET: usize = 2016usize;
    const NOT_BEFORE_OFFSET: usize = 165usize;
    const NOT_AFTER_OFFSET: usize = 182usize;
    const PUBLIC_KEY_LEN: usize = 1568usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    const ISSUER_SN_LEN: usize = 64usize;
    const SERIAL_NUMBER_LEN: usize = 20usize;
    const SUBJECT_KEY_ID_LEN: usize = 20usize;
    const AUTHORITY_KEY_ID_LEN: usize = 20usize;
    const NOT_BEFORE_LEN: usize = 15usize;
    const NOT_AFTER_LEN: usize = 15usize;
    pub const TBS_TEMPLATE_LEN: usize = 2036usize;
    const COMPRESSED_TBS_TEMPLATE_BEFORE_KEY: [u8; 181usize] = [
        255u8, 48u8, 130u8, 7u8, 240u8, 160u8, 3u8, 2u8, 1u8, 239u8, 2u8, 2u8, 20u8, 95u8, 0u8,
        31u8, 95u8, 48u8, 11u8, 255u8, 6u8, 9u8, 96u8, 134u8, 72u8, 1u8, 101u8, 3u8, 255u8, 4u8,
        3u8, 19u8, 48u8, 115u8, 49u8, 38u8, 48u8, 255u8, 36u8, 6u8, 3u8, 85u8, 4u8, 3u8, 12u8,
        29u8, 255u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 255u8, 32u8, 50u8, 46u8,
        49u8, 32u8, 77u8, 108u8, 68u8, 255u8, 115u8, 97u8, 56u8, 55u8, 32u8, 82u8, 116u8, 32u8,
        255u8, 65u8, 108u8, 105u8, 97u8, 115u8, 49u8, 73u8, 48u8, 29u8, 71u8, 2u8, 129u8, 5u8,
        19u8, 64u8, 5u8, 111u8, 6u8, 143u8, 7u8, 175u8, 206u8, 8u8, 40u8, 34u8, 24u8, 15u8, 9u8,
        172u8, 1u8, 30u8, 48u8, 123u8, 239u8, 49u8, 46u8, 48u8, 44u8, 9u8, 147u8, 37u8, 79u8, 67u8,
        255u8, 80u8, 32u8, 76u8, 79u8, 67u8, 75u8, 32u8, 72u8, 255u8, 80u8, 75u8, 69u8, 32u8, 69u8,
        110u8, 100u8, 111u8, 255u8, 114u8, 115u8, 101u8, 109u8, 101u8, 110u8, 116u8, 32u8, 255u8,
        77u8, 76u8, 45u8, 75u8, 69u8, 77u8, 32u8, 49u8, 7u8, 48u8, 50u8, 52u8, 10u8, 31u8, 15u8,
        239u8, 17u8, 15u8, 18u8, 47u8, 18u8, 49u8, 247u8, 130u8, 6u8, 50u8, 18u8, 120u8, 4u8, 3u8,
        3u8, 130u8, 7u8, 6u8, 33u8, 0u8,
    ];
    const COMPRESSED_TBS_TEMPLATE_AFTER_KEY: [u8; 92usize] = [
        255u8, 163u8, 122u8, 48u8, 120u8, 48u8, 15u8, 6u8, 3u8, 255u8, 85u8, 29u8, 19u8, 1u8, 1u8,
        255u8, 4u8, 5u8, 127u8, 48u8, 3u8, 2u8, 1u8, 0u8, 48u8, 14u8, 1u8, 17u8, 253u8, 15u8, 1u8,
        17u8, 4u8, 3u8, 2u8, 5u8, 32u8, 48u8, 255u8, 21u8, 6u8, 6u8, 103u8, 129u8, 5u8, 21u8, 1u8,
        255u8, 1u8, 4u8, 11u8, 48u8, 9u8, 2u8, 1u8, 66u8, 183u8, 2u8, 1u8, 2u8, 0u8, 48u8, 48u8,
        29u8, 3u8, 129u8, 14u8, 223u8, 4u8, 22u8, 4u8, 20u8, 95u8, 0u8, 31u8, 95u8, 48u8, 253u8,
        31u8, 5u8, 113u8, 35u8, 4u8, 24u8, 48u8, 22u8, 128u8, 0u8, 2u8, 31u8, 3u8, 32u8,
    ];
    const TBS_TEMPLATE_BEFORE_KEY_LEN: usize = Self::PUBLIC_KEY_OFFSET;
    const TBS_TEMPLATE_AFTER_KEY_LEN: usize =
        Self::TBS_TEMPLATE_LEN - Self::PUBLIC_KEY_OFFSET - Self::PUBLIC_KEY_LEN;
    #[cfg(test)]
    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = {
        let mut result = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
        let before = [
            48u8, 130u8, 7u8, 240u8, 160u8, 3u8, 2u8, 1u8, 2u8, 2u8, 20u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 48u8, 11u8, 6u8, 9u8, 96u8, 134u8, 72u8, 1u8, 101u8, 3u8, 4u8, 3u8, 19u8,
            48u8, 115u8, 49u8, 38u8, 48u8, 36u8, 6u8, 3u8, 85u8, 4u8, 3u8, 12u8, 29u8, 67u8, 97u8,
            108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8, 50u8, 46u8, 49u8, 32u8, 77u8, 108u8,
            68u8, 115u8, 97u8, 56u8, 55u8, 32u8, 82u8, 116u8, 32u8, 65u8, 108u8, 105u8, 97u8,
            115u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 34u8, 24u8, 15u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 24u8, 15u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8,
            123u8, 49u8, 46u8, 48u8, 44u8, 6u8, 3u8, 85u8, 4u8, 3u8, 12u8, 37u8, 79u8, 67u8, 80u8,
            32u8, 76u8, 79u8, 67u8, 75u8, 32u8, 72u8, 80u8, 75u8, 69u8, 32u8, 69u8, 110u8, 100u8,
            111u8, 114u8, 115u8, 101u8, 109u8, 101u8, 110u8, 116u8, 32u8, 77u8, 76u8, 45u8, 75u8,
            69u8, 77u8, 32u8, 49u8, 48u8, 50u8, 52u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8,
            5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 130u8, 6u8,
            50u8, 48u8, 11u8, 6u8, 9u8, 96u8, 134u8, 72u8, 1u8, 101u8, 3u8, 4u8, 4u8, 3u8, 3u8,
            130u8, 6u8, 33u8, 0u8,
        ];
        let after = [
            163u8, 122u8, 48u8, 120u8, 48u8, 15u8, 6u8, 3u8, 85u8, 29u8, 19u8, 1u8, 1u8, 255u8,
            4u8, 5u8, 48u8, 3u8, 2u8, 1u8, 0u8, 48u8, 14u8, 6u8, 3u8, 85u8, 29u8, 15u8, 1u8, 1u8,
            255u8, 4u8, 4u8, 3u8, 2u8, 5u8, 32u8, 48u8, 21u8, 6u8, 6u8, 103u8, 129u8, 5u8, 21u8,
            1u8, 1u8, 4u8, 11u8, 48u8, 9u8, 2u8, 1u8, 66u8, 2u8, 1u8, 2u8, 2u8, 1u8, 2u8, 48u8,
            29u8, 6u8, 3u8, 85u8, 29u8, 14u8, 4u8, 22u8, 4u8, 20u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 48u8, 31u8, 6u8, 3u8, 85u8, 29u8, 35u8, 4u8, 24u8, 48u8, 22u8, 128u8, 20u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
            95u8, 95u8, 95u8, 95u8, 95u8,
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
    pub fn new(params: &OcpLockMlKemCertTbsMlDsa87Params) -> caliptra_error::CaliptraResult<Self> {
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
    fn apply(&mut self, params: &OcpLockMlKemCertTbsMlDsa87Params) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 2036usize],
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
        apply_slice::<{ Self::ISSUER_SN_OFFSET }, { Self::ISSUER_SN_LEN }>(
            &mut self.tbs,
            params.issuer_sn,
        );
        apply_slice::<{ Self::SERIAL_NUMBER_OFFSET }, { Self::SERIAL_NUMBER_LEN }>(
            &mut self.tbs,
            params.serial_number,
        );
        apply_slice::<{ Self::SUBJECT_KEY_ID_OFFSET }, { Self::SUBJECT_KEY_ID_LEN }>(
            &mut self.tbs,
            params.subject_key_id,
        );
        apply_slice::<{ Self::AUTHORITY_KEY_ID_OFFSET }, { Self::AUTHORITY_KEY_ID_LEN }>(
            &mut self.tbs,
            params.authority_key_id,
        );
        apply_slice::<{ Self::NOT_BEFORE_OFFSET }, { Self::NOT_BEFORE_LEN }>(
            &mut self.tbs,
            params.not_before,
        );
        apply_slice::<{ Self::NOT_AFTER_OFFSET }, { Self::NOT_AFTER_LEN }>(
            &mut self.tbs,
            params.not_after,
        );
    }
}
#[cfg(test)]
mod lzss_tests {
    use super::*;
    #[test]
    fn test_template_decompression() {
        let mut before_key = [0u8; OcpLockMlKemCertTbsMlDsa87::TBS_TEMPLATE_BEFORE_KEY_LEN];
        assert!(crate::lzss::decompress(
            &OcpLockMlKemCertTbsMlDsa87::COMPRESSED_TBS_TEMPLATE_BEFORE_KEY,
            &mut before_key
        ));
        assert_eq!(
            before_key,
            OcpLockMlKemCertTbsMlDsa87::TBS_TEMPLATE
                [..OcpLockMlKemCertTbsMlDsa87::PUBLIC_KEY_OFFSET]
        );
        let mut after_key = [0u8; OcpLockMlKemCertTbsMlDsa87::TBS_TEMPLATE_AFTER_KEY_LEN];
        assert!(crate::lzss::decompress(
            &OcpLockMlKemCertTbsMlDsa87::COMPRESSED_TBS_TEMPLATE_AFTER_KEY,
            &mut after_key
        ));
        assert_eq!(
            after_key,
            OcpLockMlKemCertTbsMlDsa87::TBS_TEMPLATE[OcpLockMlKemCertTbsMlDsa87::PUBLIC_KEY_OFFSET
                + OcpLockMlKemCertTbsMlDsa87::PUBLIC_KEY_LEN..]
        );
    }
}
