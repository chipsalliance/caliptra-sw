#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

--"]
// TODO generate when x509 libraries support MLDSA
#[allow(dead_code)]
pub struct InitDevIdCsrTbsMlDsa87Params<'a> {
    pub ueid: &'a [u8; 17usize],
    pub public_key: &'a [u8; 2592usize],
    pub subject_sn: &'a [u8; 64usize],
}

#[allow(dead_code)]
impl<'a> InitDevIdCsrTbsMlDsa87Params<'a> {
    pub const UEID_LEN: usize = 17usize;
    pub const PUBLIC_KEY_LEN: usize = 2592usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
}

#[allow(dead_code)]
pub struct InitDevIdCsrTbsMlDsa87 {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
#[allow(dead_code)]
impl InitDevIdCsrTbsMlDsa87 {
    const UEID_OFFSET: usize = 2801usize;
    const PUBLIC_KEY_OFFSET: usize = 138usize;
    const SUBJECT_SN_OFFSET: usize = 50usize;
    const UEID_LEN: usize = 17usize;
    const PUBLIC_KEY_LEN: usize = 2592usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    pub const TBS_TEMPLATE_LEN: usize = 2818usize;
    const TBS_TEMPLATE_PART_1: [u8; 138] = [
        48u8, 130u8, 1u8, 62u8, 2u8, 1u8, 0u8, 48u8, 105u8, 49u8, 28u8, 48u8, 26u8, 6u8, 3u8, 85u8,
        4u8, 3u8, 12u8, 19u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8, 49u8,
        46u8, 48u8, 32u8, 73u8, 68u8, 101u8, 118u8, 73u8, 68u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8,
        85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 118u8, 48u8, 16u8, 6u8, 7u8,
        42u8, 134u8, 72u8, 206u8, 61u8, 2u8, 1u8, 6u8, 5u8, 43u8, 129u8, 4u8, 0u8, 34u8, 4u8,
        130u8, 10u8, 32u8,
    ];

    const TBS_TEMPLATE_PART_2: [u8; 88] = [
        160u8, 86u8, 48u8, 84u8, 6u8, 9u8, 42u8, 134u8, 72u8, 134u8, 247u8, 13u8, 1u8, 9u8, 14u8,
        49u8, 71u8, 48u8, 69u8, 48u8, 18u8, 6u8, 3u8, 85u8, 29u8, 19u8, 1u8, 1u8, 255u8, 4u8, 8u8,
        48u8, 6u8, 1u8, 1u8, 255u8, 2u8, 1u8, 5u8, 48u8, 14u8, 6u8, 3u8, 85u8, 29u8, 15u8, 1u8,
        1u8, 255u8, 4u8, 4u8, 3u8, 2u8, 2u8, 4u8, 48u8, 31u8, 6u8, 6u8, 103u8, 129u8, 5u8, 5u8,
        4u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8, 17u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
    ];
    pub fn new(params: &InitDevIdCsrTbsMlDsa87Params) -> Self {
        let mut template = Self {
            tbs: [0; Self::TBS_TEMPLATE_LEN],
        };
        template.tbs[..Self::PUBLIC_KEY_OFFSET].copy_from_slice(&Self::TBS_TEMPLATE_PART_1);
        template.tbs[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN..]
            .copy_from_slice(&Self::TBS_TEMPLATE_PART_2);
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
    fn apply(&mut self, params: &InitDevIdCsrTbsMlDsa87Params) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 2818usize],
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
