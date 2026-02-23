#[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template with: cargo run -p caliptra-x509-gen

--"]
#[allow(clippy::needless_lifetimes)]
pub struct RtAliasCsrTbsEcc384Params<'a> {
    pub public_key: &'a [u8; 97usize],
    pub subject_sn: &'a [u8; 64usize],
    pub tcb_info_rt_tci: &'a [u8; 48usize],
    pub ueid: &'a [u8; 17usize],
    pub tcb_info_fw_svn: &'a [u8; 1usize],
}
impl RtAliasCsrTbsEcc384Params<'_> {
    pub const PUBLIC_KEY_LEN: usize = 97usize;
    pub const SUBJECT_SN_LEN: usize = 64usize;
    pub const TCB_INFO_RT_TCI_LEN: usize = 48usize;
    pub const UEID_LEN: usize = 17usize;
    pub const TCB_INFO_FW_SVN_LEN: usize = 1usize;
}
pub struct RtAliasCsrTbsEcc384 {
    tbs: [u8; Self::TBS_TEMPLATE_LEN],
}
impl RtAliasCsrTbsEcc384 {
    const PUBLIC_KEY_OFFSET: usize = 146usize;
    const SUBJECT_SN_OFFSET: usize = 59usize;
    const TCB_INFO_RT_TCI_OFFSET: usize = 390usize;
    const UEID_OFFSET: usize = 318usize;
    const TCB_INFO_FW_SVN_OFFSET: usize = 372usize;
    const PUBLIC_KEY_LEN: usize = 97usize;
    const SUBJECT_SN_LEN: usize = 64usize;
    const TCB_INFO_RT_TCI_LEN: usize = 48usize;
    const UEID_LEN: usize = 17usize;
    const TCB_INFO_FW_SVN_LEN: usize = 1usize;
    pub const TBS_TEMPLATE_LEN: usize = 469usize;
    const TBS_TEMPLATE_BEFORE_KEY: [u8; Self::PUBLIC_KEY_OFFSET] = [
        48u8, 130u8, 1u8, 209u8, 2u8, 1u8, 0u8, 48u8, 114u8, 49u8, 37u8, 48u8, 35u8, 6u8, 3u8,
        85u8, 4u8, 3u8, 12u8, 28u8, 67u8, 97u8, 108u8, 105u8, 112u8, 116u8, 114u8, 97u8, 32u8,
        50u8, 46u8, 49u8, 32u8, 69u8, 99u8, 99u8, 51u8, 56u8, 52u8, 32u8, 82u8, 116u8, 32u8, 65u8,
        108u8, 105u8, 97u8, 115u8, 49u8, 73u8, 48u8, 71u8, 6u8, 3u8, 85u8, 4u8, 5u8, 19u8, 64u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 48u8, 118u8, 48u8, 16u8, 6u8, 7u8, 42u8, 134u8, 72u8, 206u8, 61u8,
        2u8, 1u8, 6u8, 5u8, 43u8, 129u8, 4u8, 0u8, 34u8, 3u8, 98u8, 0u8,
    ];
    const TBS_TEMPLATE_AFTER_KEY_LEN: usize =
        Self::TBS_TEMPLATE_LEN - Self::PUBLIC_KEY_OFFSET - Self::PUBLIC_KEY_LEN;
    const TBS_TEMPLATE_AFTER_KEY: [u8; Self::TBS_TEMPLATE_AFTER_KEY_LEN] = [
        160u8, 129u8, 223u8, 48u8, 129u8, 220u8, 6u8, 9u8, 42u8, 134u8, 72u8, 134u8, 247u8, 13u8,
        1u8, 9u8, 14u8, 49u8, 129u8, 206u8, 48u8, 129u8, 203u8, 48u8, 18u8, 6u8, 3u8, 85u8, 29u8,
        19u8, 1u8, 1u8, 255u8, 4u8, 8u8, 48u8, 6u8, 1u8, 1u8, 255u8, 2u8, 1u8, 4u8, 48u8, 14u8,
        6u8, 3u8, 85u8, 29u8, 15u8, 1u8, 1u8, 255u8, 4u8, 4u8, 3u8, 2u8, 2u8, 132u8, 48u8, 31u8,
        6u8, 6u8, 103u8, 129u8, 5u8, 5u8, 4u8, 4u8, 4u8, 21u8, 48u8, 19u8, 4u8, 17u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        48u8, 18u8, 6u8, 3u8, 85u8, 29u8, 37u8, 4u8, 11u8, 48u8, 9u8, 6u8, 7u8, 103u8, 129u8, 5u8,
        5u8, 4u8, 100u8, 12u8, 48u8, 112u8, 6u8, 6u8, 103u8, 129u8, 5u8, 5u8, 4u8, 1u8, 4u8, 102u8,
        48u8, 100u8, 131u8, 2u8, 1u8, 95u8, 166u8, 63u8, 48u8, 61u8, 6u8, 9u8, 96u8, 134u8, 72u8,
        1u8, 101u8, 3u8, 4u8, 2u8, 2u8, 4u8, 48u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8,
        95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 95u8, 137u8, 29u8, 67u8, 65u8, 76u8,
        73u8, 80u8, 84u8, 82u8, 65u8, 95u8, 50u8, 95u8, 88u8, 95u8, 82u8, 84u8, 95u8, 70u8, 73u8,
        82u8, 77u8, 87u8, 65u8, 82u8, 69u8, 95u8, 73u8, 78u8, 70u8, 79u8,
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
    pub fn new(params: &RtAliasCsrTbsEcc384Params) -> Self {
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
    fn apply(&mut self, params: &RtAliasCsrTbsEcc384Params) {
        #[inline(always)]
        fn apply_slice<const OFFSET: usize, const LEN: usize>(
            buf: &mut [u8; 469usize],
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
        apply_slice::<{ Self::TCB_INFO_RT_TCI_OFFSET }, { Self::TCB_INFO_RT_TCI_LEN }>(
            &mut self.tbs,
            params.tcb_info_rt_tci,
        );
        apply_slice::<{ Self::UEID_OFFSET }, { Self::UEID_LEN }>(&mut self.tbs, params.ueid);
        apply_slice::<{ Self::TCB_INFO_FW_SVN_OFFSET }, { Self::TCB_INFO_FW_SVN_LEN }>(
            &mut self.tbs,
            params.tcb_info_fw_svn,
        );
    }
}
