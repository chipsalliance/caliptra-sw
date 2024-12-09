/*++

Licensed under the Apache-2.0 license.

File Name:

    idevid_csr_envelop.rs

Abstract:

    File contains the data structure for the Initial Device ID CSR Envelop.

--*/

use caliptra_drivers::{Ecc384IdevIdCsr, Mldsa87IdevIdCsr};
use caliptra_image_types::{SHA384_DIGEST_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE};
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

pub type Hmac384Tag = [u8; SHA384_DIGEST_BYTE_SIZE];
pub type Hmac512Tag = [u8; SHA512_DIGEST_BYTE_SIZE];

pub const IDEVID_CSR_ENVELOP_MARKER: u32 = 0x43_5352;

/// Calipatra IDEVID CSR Envelop
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Zeroize)]
pub struct InitDevIdCsrEnvelop {
    /// Marker
    pub marker: u32,

    /// Size of the CSR Envelop
    pub size: u32,

    /// ECC CSR
    pub ecc_csr: Ecc384IdevIdCsr,

    /// ECC CSR MAC
    pub ecc_csr_mac: Hmac384Tag,

    /// MLDSA CSR
    pub mldsa_csr: Mldsa87IdevIdCsr,

    /// MLDSA CSR MAC
    pub mldsa_csr_mac: Hmac512Tag,
}

impl Default for InitDevIdCsrEnvelop {
    fn default() -> Self {
        InitDevIdCsrEnvelop {
            marker: IDEVID_CSR_ENVELOP_MARKER,
            size: size_of::<InitDevIdCsrEnvelop>() as u32,
            ecc_csr: Ecc384IdevIdCsr::default(),
            ecc_csr_mac: [0u8; SHA384_DIGEST_BYTE_SIZE],
            mldsa_csr: Mldsa87IdevIdCsr::default(),
            mldsa_csr_mac: [0u8; SHA512_DIGEST_BYTE_SIZE],
        }
    }
}
