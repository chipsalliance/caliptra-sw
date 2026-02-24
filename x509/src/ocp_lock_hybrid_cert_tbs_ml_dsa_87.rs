#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template by building caliptra-x509-build with the generate_templates flag.

--"]
#[allow(clippy::needless_lifetimes)]
pub struct OcpLockHybridCertTbsMlDsa87Params<'a> {
    pub public_key: &'a [u8; 1665usize],
    pub subject_sn: &'a [u8; 64usize],
    pub issuer_sn: &'a [u8; 64usize],
    pub serial_number: &'a [u8; 20usize],
    pub subject_key_id: &'a [u8; 20usize],
    pub authority_key_id: &'a [u8; 20usize],
    pub not_before: &'a [u8; 15usize],
    pub not_after: &'a [u8; 15usize],
}
impl OcpLockHybridCertTbsMlDsa87Params<'_> {
    pub const PUBLIC_KEY_LEN: usize = 1665usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
    pub const ISSUER_SN_LEN: usize = 64usize;
    pub const SERIAL_NUMBER_LEN: usize = 20usize;
    pub const SUBJECT_KEY_ID_LEN: usize = 20usize;
    pub const AUTHORITY_KEY_ID_LEN: usize = 20usize;
    pub const NOT_BEFORE_LEN: usize = 15usize;
    pub const NOT_AFTER_LEN: usize = 15usize;
}
pub struct OcpLockHybridCertTbsMlDsa87 {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
impl OcpLockHybridCertTbsMlDsa87 {
    const PUBLIC_KEY_OFFSET: usize = 354usize;
    const SUBJECT_SN_OFFSET: usize = 211usize;
    const ISSUER_SN_OFFSET: usize = 57usize;
    const SERIAL_NUMBER_OFFSET: usize = 11usize;
    const SUBJECT_KEY_ID_OFFSET: usize = 2090usize;
    const AUTHORITY_KEY_ID_OFFSET: usize = 2123usize;
    const NOT_BEFORE_OFFSET: usize = 165usize;
    const NOT_AFTER_OFFSET: usize = 182usize;
    const PUBLIC_KEY_LEN: usize = 1665usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    const ISSUER_SN_LEN: usize = 64usize;
    const SERIAL_NUMBER_LEN: usize = 20usize;
    const SUBJECT_KEY_ID_LEN: usize = 20usize;
    const AUTHORITY_KEY_ID_LEN: usize = 20usize;
    const NOT_BEFORE_LEN: usize = 15usize;
    const NOT_AFTER_LEN: usize = 15usize;
    pub const TBS_TEMPLATE_LEN: usize = 2143usize;
    const TBS_TEMPLATE_BEFORE_KEY: [u8; Self::PUBLIC_KEY_OFFSET] = [
        48u8, 130u8, 8u8, 91u8, 160u8, 3u8, 2u8, 1u8, 2u8, 2u8, 20u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        48u8, 11u8, 6u8, 9u8, 96u8, 134u8, 72u8, 1u8, 101u8, 3u8, 4u8, 3u8, 19u8, 48u8, 115u8,
        49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 49u8,
        38u8, 48u8, 36u8, 6u8, 3u8, 85u8, 4u8, 3u8, 12u8, 29u8, 67u8, 97u8, 108u8, 105u8, 112u8,
        116u8, 114u8, 97u8, 32u8, 50u8, 46u8, 49u8, 32u8, 77u8, 108u8, 68u8, 115u8, 97u8, 56u8,
        55u8, 32u8, 82u8, 116u8, 32u8, 65u8, 108u8, 105u8, 97u8, 115u8, 48u8, 34u8, 24u8, 15u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        24u8, 15u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 48u8, 129u8, 133u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8,
        64u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 49u8, 56u8, 48u8, 54u8, 6u8, 3u8, 85u8, 4u8, 3u8, 12u8, 47u8,
        79u8, 67u8, 80u8, 32u8, 76u8, 79u8, 67u8, 75u8, 32u8, 72u8, 80u8, 75u8, 69u8, 32u8, 69u8,
        110u8, 100u8, 111u8, 114u8, 115u8, 101u8, 109u8, 101u8, 110u8, 116u8, 32u8, 77u8, 76u8,
        45u8, 75u8, 69u8, 77u8, 45u8, 49u8, 48u8, 50u8, 52u8, 45u8, 69u8, 67u8, 68u8, 72u8, 45u8,
        80u8, 51u8, 56u8, 52u8, 48u8, 130u8, 6u8, 146u8, 48u8, 10u8, 6u8, 8u8, 43u8, 6u8, 1u8, 5u8,
        5u8, 7u8, 6u8, 63u8, 3u8, 130u8, 6u8, 130u8, 0u8,
    ];
    const TBS_TEMPLATE_AFTER_KEY_LEN: usize =
        Self::TBS_TEMPLATE_LEN - Self::PUBLIC_KEY_OFFSET - Self::PUBLIC_KEY_LEN;
    const TBS_TEMPLATE_AFTER_KEY: [u8; Self::TBS_TEMPLATE_AFTER_KEY_LEN] = [
        163u8, 122u8, 48u8, 120u8, 48u8, 15u8, 6u8, 3u8, 85u8, 29u8, 19u8, 1u8, 1u8, 255u8, 4u8,
        5u8, 48u8, 3u8, 2u8, 1u8, 0u8, 48u8, 14u8, 6u8, 3u8, 85u8, 29u8, 15u8, 1u8, 1u8, 255u8,
        4u8, 4u8, 3u8, 2u8, 5u8, 32u8, 48u8, 21u8, 6u8, 6u8, 103u8, 129u8, 5u8, 21u8, 1u8, 1u8,
        4u8, 11u8, 48u8, 9u8, 2u8, 1u8, 81u8, 2u8, 1u8, 2u8, 2u8, 1u8, 2u8, 48u8, 29u8, 6u8, 3u8,
        85u8, 29u8, 14u8, 4u8, 22u8, 4u8, 20u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 31u8, 6u8,
        3u8, 85u8, 29u8, 35u8, 4u8, 24u8, 48u8, 22u8, 128u8, 20u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
    ];
    #[cfg(test)]
    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = {
        let mut result = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
        let before = Self::TBS_TEMPLATE_BEFORE_KEY;
        let after = Self::TBS_TEMPLATE_AFTER_KEY;
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
    pub fn new(params: &OcpLockHybridCertTbsMlDsa87Params) -> Self {
        let mut tbs = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
        tbs[..Self::PUBLIC_KEY_OFFSET].copy_from_slice(&Self::TBS_TEMPLATE_BEFORE_KEY);
        tbs[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN..]
            .copy_from_slice(&Self::TBS_TEMPLATE_AFTER_KEY);
        let mut template = Self { tbs };
        template.apply(params);
        template
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
    fn apply(&mut self, params: &OcpLockHybridCertTbsMlDsa87Params) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 2143usize],
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
