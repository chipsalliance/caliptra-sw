#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template by building caliptra-x509-build with the generate-templates flag.

--"]
pub struct FmcAliasCertTbsParams<'a> {
    pub public_key: &'a [u8; 97usize],
    pub subject_sn: &'a [u8; 64usize],
    pub issuer_sn: &'a [u8; 64usize],
    pub tcb_info_device_info_hash: &'a [u8; 48usize],
    pub tcb_info_fmc_tci: &'a [u8; 48usize],
    pub serial_number: &'a [u8; 20usize],
    pub subject_key_id: &'a [u8; 20usize],
    pub authority_key_id: &'a [u8; 20usize],
    pub ueid: &'a [u8; 17usize],
    pub not_before: &'a [u8; 15usize],
    pub not_after: &'a [u8; 15usize],
    pub tcb_info_flags: &'a [u8; 4usize],
    pub tcb_info_fmc_svn: &'a [u8; 1usize],
    pub tcb_info_fmc_svn_fuses: &'a [u8; 1usize],
}
impl FmcAliasCertTbsParams<'_> {
    pub const PUBLIC_KEY_LEN: usize = 97usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
    pub const ISSUER_SN_LEN: usize = 64usize;
    pub const TCB_INFO_DEVICE_INFO_HASH_LEN: usize = 48usize;
    pub const TCB_INFO_FMC_TCI_LEN: usize = 48usize;
    pub const SERIAL_NUMBER_LEN: usize = 20usize;
    pub const SUBJECT_KEY_ID_LEN: usize = 20usize;
    pub const AUTHORITY_KEY_ID_LEN: usize = 20usize;
    pub const UEID_LEN: usize = 17usize;
    pub const NOT_BEFORE_LEN: usize = 15usize;
    pub const NOT_AFTER_LEN: usize = 15usize;
    pub const TCB_INFO_FLAGS_LEN: usize = 4usize;
    pub const TCB_INFO_FMC_SVN_LEN: usize = 1usize;
    pub const TCB_INFO_FMC_SVN_FUSES_LEN: usize = 1usize;
}
pub struct FmcAliasCertTbs {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
impl FmcAliasCertTbs {
    const PUBLIC_KEY_OFFSET: usize = 319usize;
    const SUBJECT_SN_OFFSET: usize = 232usize;
    const ISSUER_SN_OFFSET: usize = 86usize;
    const TCB_INFO_DEVICE_INFO_HASH_OFFSET: usize = 533usize;
    const TCB_INFO_FMC_TCI_OFFSET: usize = 631usize;
    const SERIAL_NUMBER_OFFSET: usize = 11usize;
    const SUBJECT_KEY_ID_OFFSET: usize = 700usize;
    const AUTHORITY_KEY_ID_OFFSET: usize = 733usize;
    const UEID_OFFSET: usize = 476usize;
    const NOT_BEFORE_OFFSET: usize = 154usize;
    const NOT_AFTER_OFFSET: usize = 171usize;
    const TCB_INFO_FLAGS_OFFSET: usize = 584usize;
    const TCB_INFO_FMC_SVN_OFFSET: usize = 613usize;
    const TCB_INFO_FMC_SVN_FUSES_OFFSET: usize = 515usize;
    const PUBLIC_KEY_LEN: usize = 97usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    const ISSUER_SN_LEN: usize = 64usize;
    const TCB_INFO_DEVICE_INFO_HASH_LEN: usize = 48usize;
    const TCB_INFO_FMC_TCI_LEN: usize = 48usize;
    const SERIAL_NUMBER_LEN: usize = 20usize;
    const SUBJECT_KEY_ID_LEN: usize = 20usize;
    const AUTHORITY_KEY_ID_LEN: usize = 20usize;
    const UEID_LEN: usize = 17usize;
    const NOT_BEFORE_LEN: usize = 15usize;
    const NOT_AFTER_LEN: usize = 15usize;
    const TCB_INFO_FLAGS_LEN: usize = 4usize;
    const TCB_INFO_FMC_SVN_LEN: usize = 1usize;
    const TCB_INFO_FMC_SVN_FUSES_LEN: usize = 1usize;
    pub const TBS_TEMPLATE_LEN: usize = 753usize;
    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = [
        48u8, 130u8, 2u8, 237u8, 160u8, 3u8, 2u8, 1u8, 2u8, 2u8, 20u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 48u8, 10u8, 6u8, 8u8, 42u8, 134u8, 72u8, 206u8, 61u8, 4u8, 3u8, 3u8, 48u8, 105u8,
        49u8, 28u8, 48u8, 26u8, 6u8, 3u8, 85u8, 4u8, 3u8, 12u8, 19u8, 67u8, 97u8, 108u8, 105u8,
        112u8, 116u8, 114u8, 97u8, 32u8, 49u8, 46u8, 48u8, 32u8, 76u8, 68u8, 101u8, 118u8, 73u8,
        68u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        48u8, 34u8, 24u8, 15u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 24u8, 15u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 108u8, 49u8, 31u8, 48u8, 29u8, 6u8, 3u8, 85u8,
        4u8, 3u8, 12u8, 22u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8, 49u8,
        46u8, 48u8, 32u8, 70u8, 77u8, 67u8, 32u8, 65u8, 108u8, 105u8, 97u8, 115u8, 49u8, 73u8,
        48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 118u8, 48u8,
        16u8, 6u8, 7u8, 42u8, 134u8, 72u8, 206u8, 61u8, 2u8, 1u8, 6u8, 5u8, 43u8, 129u8, 4u8, 0u8,
        34u8, 3u8, 98u8, 0u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 163u8, 130u8, 1u8, 77u8,
        48u8, 130u8, 1u8, 73u8, 48u8, 18u8, 6u8, 3u8, 85u8, 29u8, 19u8, 1u8, 1u8, 255u8, 4u8, 8u8,
        48u8, 6u8, 1u8, 1u8, 255u8, 2u8, 1u8, 3u8, 48u8, 14u8, 6u8, 3u8, 85u8, 29u8, 15u8, 1u8,
        1u8, 255u8, 4u8, 4u8, 3u8, 2u8, 2u8, 4u8, 48u8, 31u8, 6u8, 6u8, 103u8, 129u8, 5u8, 5u8,
        4u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8, 17u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 129u8, 193u8, 6u8, 6u8, 103u8,
        129u8, 5u8, 5u8, 4u8, 5u8, 4u8, 129u8, 182u8, 48u8, 129u8, 179u8, 48u8, 96u8, 131u8, 2u8,
        1u8, 95u8, 166u8, 63u8, 48u8, 61u8, 6u8, 9u8, 96u8, 134u8, 72u8, 1u8, 101u8, 3u8, 4u8, 2u8,
        2u8, 4u8, 48u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 135u8, 5u8, 0u8, 95u8, 95u8, 95u8, 95u8, 137u8, 11u8,
        68u8, 69u8, 86u8, 73u8, 67u8, 69u8, 95u8, 73u8, 78u8, 70u8, 79u8, 138u8, 5u8, 0u8, 208u8,
        0u8, 0u8, 1u8, 48u8, 79u8, 131u8, 2u8, 1u8, 95u8, 166u8, 63u8, 48u8, 61u8, 6u8, 9u8, 96u8,
        134u8, 72u8, 1u8, 101u8, 3u8, 4u8, 2u8, 2u8, 4u8, 48u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 137u8, 8u8, 70u8,
        77u8, 67u8, 95u8, 73u8, 78u8, 70u8, 79u8, 48u8, 29u8, 6u8, 3u8, 85u8, 29u8, 14u8, 4u8,
        22u8, 4u8, 20u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 48u8, 31u8, 6u8, 3u8, 85u8, 29u8, 35u8,
        4u8, 24u8, 48u8, 22u8, 128u8, 20u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
    ];
    pub fn new(params: &FmcAliasCertTbsParams) -> Self {
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
    fn apply(&mut self, params: &FmcAliasCertTbsParams) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 753usize],
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
        apply_slice::<
            { Self::TCB_INFO_DEVICE_INFO_HASH_OFFSET },
            { Self::TCB_INFO_DEVICE_INFO_HASH_LEN },
        >(&mut self.tbs, params.tcb_info_device_info_hash);
        apply_slice::<{ Self::TCB_INFO_FMC_TCI_OFFSET }, { Self::TCB_INFO_FMC_TCI_LEN }>(
            &mut self.tbs,
            params.tcb_info_fmc_tci,
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
        apply_slice::<{ Self::UEID_OFFSET }, { Self::UEID_LEN }>(&mut self.tbs, params.ueid);
        apply_slice::<{ Self::NOT_BEFORE_OFFSET }, { Self::NOT_BEFORE_LEN }>(
            &mut self.tbs,
            params.not_before,
        );
        apply_slice::<{ Self::NOT_AFTER_OFFSET }, { Self::NOT_AFTER_LEN }>(
            &mut self.tbs,
            params.not_after,
        );
        apply_slice::<{ Self::TCB_INFO_FLAGS_OFFSET }, { Self::TCB_INFO_FLAGS_LEN }>(
            &mut self.tbs,
            params.tcb_info_flags,
        );
        apply_slice::<{ Self::TCB_INFO_FMC_SVN_OFFSET }, { Self::TCB_INFO_FMC_SVN_LEN }>(
            &mut self.tbs,
            params.tcb_info_fmc_svn,
        );
        apply_slice::<{ Self::TCB_INFO_FMC_SVN_FUSES_OFFSET }, { Self::TCB_INFO_FMC_SVN_FUSES_LEN }>(
            &mut self.tbs,
            params.tcb_info_fmc_svn_fuses,
        );
    }
}
