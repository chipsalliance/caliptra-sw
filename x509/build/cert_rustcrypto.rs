use crate::tbs::{TbsParam, TbsTemplate};
use crate::x509::{AsymKey, FwidParam, KeyUsage, SigningAlgorithm};

/// Certificate Template Builder
pub struct CertTemplateBuilder<Algo: SigningAlgorithm> {
    algo: Algo,
    // Other fields...
}

impl<Algo: SigningAlgorithm> CertTemplateBuilder<Algo> {
    pub fn new() -> Self {
        unimplemented!()
    }

    pub fn add_basic_constraints_ext(mut self, ca: bool, path_len: u32) -> Self {
        unimplemented!()
    }

    pub fn add_key_usage_ext(mut self, usage: KeyUsage) -> Self {
        unimplemented!()
    }

    pub fn add_ueid_ext(mut self, ueid: &[u8]) -> Self {
        unimplemented!()
    }

    pub fn add_fmc_dice_tcb_info_ext(
        mut self,
        device_fwids: &[FwidParam],
        fmc_fwids: &[FwidParam],
    ) -> Self {
        unimplemented!()
    }

    pub fn add_rt_dice_tcb_info_ext(mut self, fwids: &[FwidParam]) -> Self {
        unimplemented!()
    }

    pub fn tbs_template(mut self, subject_cn: &str, issuer_cn: &str) -> TbsTemplate {
        unimplemented!()
    }
}
