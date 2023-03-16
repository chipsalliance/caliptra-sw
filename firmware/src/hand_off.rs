// Licensed under the Apache-2.0 license.

const FHT_MAGIC: u32 = 0x54484643;
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct HandoffParams {
    magic: u32,
    major: u16,
    minor: u16,
    mft_base_addr: u32,
    fips_base_addr: u32,
    rt_base_addr: u32,
    fmc_cdi_kv_idx: u8,
    fmc_priv_key_idx: u8,
    fmc_pub_key_idx: u8,
    fmc_cert_dv_idx: u8,
    rt_cdi_kv_idx: u8,
    rt_priv_key_kv_idx: u8,
    rt_pub_key_dv_idx: u8,
    rt_cert_dv_idx: u8,
    reserved: [u8; 20],
}

impl HandoffParams {
    pub fn is_valid(&self) -> bool {
        self.magic == FHT_MAGIC
    }
}

impl Default for HandoffParams {
    // TODO : replace placholder with actual values.
    fn default() -> Self {
        Self {
            magic: FHT_MAGIC,
            major: 0,
            minor: 0,
            mft_base_addr: 0,
            fips_base_addr: 0,
            fmc_cert_dv_idx: 0,
            fmc_cdi_kv_idx: 0,
            fmc_priv_key_idx: 0,
            fmc_pub_key_idx: 0,
            rt_base_addr: 0,
            rt_cdi_kv_idx: 0,
            rt_cert_dv_idx: 0,
            rt_priv_key_kv_idx: 0,
            rt_pub_key_dv_idx: 0,
            reserved: [u8; 0],
        }
    }
}
