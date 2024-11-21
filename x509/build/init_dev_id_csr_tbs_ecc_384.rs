#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template by building caliptra-x509-build with the generate-templates flag.

--"]
pub struct InitDevIdCsrTbsEcc384Params<'a> {
    pub ueid: &'a [u8; 17usize],
    pub public_key: &'a [u8; 97usize],
    pub subject_sn: &'a [u8; 64usize],
}
impl<'a> InitDevIdCsrTbsEcc384Params<'a> {
    pub const UEID_LEN: usize = 17usize;
    pub const PUBLIC_KEY_LEN: usize = 97usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
}
pub struct InitDevIdCsrTbsEcc384 {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
impl InitDevIdCsrTbsEcc384 {
    const UEID_OFFSET: usize = 305usize;
    const PUBLIC_KEY_OFFSET: usize = 137usize;
    const SUBJECT_SN_OFFSET: usize = 50usize;
    const UEID_LEN: usize = 17usize;
    const PUBLIC_KEY_LEN: usize = 97usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    pub const TBS_TEMPLATE_LEN: usize = 322usize;
    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = [
        48u8, 130u8, 1u8, 62u8, 2u8, 1u8, 0u8, 48u8, 105u8, 49u8, 28u8, 48u8, 26u8, 6u8, 3u8, 85u8,
        4u8, 3u8, 12u8, 19u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8, 49u8,
        46u8, 48u8, 32u8, 73u8, 68u8, 101u8, 118u8, 73u8, 68u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8,
        85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 118u8, 48u8, 16u8, 6u8, 7u8,
        42u8, 134u8, 72u8, 206u8, 61u8, 2u8, 1u8, 6u8, 5u8, 43u8, 129u8, 4u8, 0u8, 34u8, 3u8, 98u8,
        0u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 160u8, 86u8, 48u8, 84u8, 6u8, 9u8, 42u8,
        134u8, 72u8, 134u8, 247u8, 13u8, 1u8, 9u8, 14u8, 49u8, 71u8, 48u8, 69u8, 48u8, 18u8, 6u8,
        3u8, 85u8, 29u8, 19u8, 1u8, 1u8, 255u8, 4u8, 8u8, 48u8, 6u8, 1u8, 1u8, 255u8, 2u8, 1u8,
        5u8, 48u8, 14u8, 6u8, 3u8, 85u8, 29u8, 15u8, 1u8, 1u8, 255u8, 4u8, 4u8, 3u8, 2u8, 2u8, 4u8,
        48u8, 31u8, 6u8, 6u8, 103u8, 129u8, 5u8, 5u8, 4u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8, 17u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8,
    ];
    pub fn new(params: &InitDevIdCsrTbsEcc384Params) -> Self {
        let mut template = Self {
            tbs: Self::TBS_TEMPLATE,
        };
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
    fn apply(&mut self, params: &InitDevIdCsrTbsEcc384Params) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 322usize],
            val: &[u8; LEN],
        ) {
            buf[OFFSET..OFFSET + LEN].copy_from_slice(val);
        }
        apply_slice::<{ Self::UEID_OFFSET }, { Self::UEID_LEN }>(&mut self.tbs, params.ueid);
        apply_slice::<{ Self::PUBLIC_KEY_OFFSET }, { Self::PUBLIC_KEY_LEN }>(
            &mut self.tbs,
            params.public_key,
        );
        apply_slice::<{ Self::SUBJECT_SN_OFFSET }, { Self::SUBJECT_SN_LEN }>(
            &mut self.tbs,
            params.subject_sn,
        );
    }
}
