/*++

Licensed under the Apache-2.0 license.

File Name:

    sha_dma.rs

Abstract:

    File contains the SHA_DMA mailbox command.

--*/

use crate::{mutrefbytes, Drivers};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    CmHashAlgorithm, MailboxRespHeaderVarSize, ResponseVarSize, ShaDmaReq, ShaDmaResp,
};
use caliptra_drivers::{AesDmaMode, AxiAddr, CaliptraError, CaliptraResult, DmaRecovery};
use caliptra_image_types::{SHA384_DIGEST_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE};
use zerocopy::FromBytes;

/// Size of Caliptra's AXI subordinate aperture (2^`SOC_IFC_ADDR_W` in the RTL).
const CALIPTRA_AXI_APERTURE_SIZE: u64 = 1 << 19;

pub struct ShaDmaCmd;

impl ShaDmaCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        drivers.ensure_pl0()?;
        let cmd = ShaDmaReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        if cmd.flags != 0 {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }
        // SoC-AXI access to the SHA accelerator is only supported in subsystem mode.
        if !drivers.soc_ifc.subsystem_mode() {
            return Err(CaliptraError::RUNTIME_SHA_DMA_NOT_SUBSYSTEM_MODE);
        }
        let algorithm = CmHashAlgorithm::from(cmd.hash_algorithm);
        if !matches!(algorithm, CmHashAlgorithm::Sha384 | CmHashAlgorithm::Sha512) {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        let length = cmd.length;
        if !is_streamable_range(cmd.axi_addr_lo, length) {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }
        let source = AxiAddr {
            lo: cmd.axi_addr_lo,
            hi: cmd.axi_addr_hi,
        };
        let start = u64::from(source);
        let len = u64::from(length);
        let soc_ifc = &drivers.soc_ifc;
        if axi_range_overlaps(
            start,
            len,
            soc_ifc.caliptra_base_axi_addr(),
            CALIPTRA_AXI_APERTURE_SIZE,
        ) || axi_range_overlaps(
            start,
            len,
            soc_ifc.ocp_lock_get_key_release_addr(),
            u64::from(soc_ifc.ocp_lock_get_key_size()),
        ) {
            return Err(CaliptraError::RUNTIME_SHA_DMA_RANGE_NOT_ALLOWED);
        }

        let dma = DmaRecovery::new(
            soc_ifc.recovery_interface_base_addr().into(),
            soc_ifc.caliptra_base_axi_addr().into(),
            soc_ifc.mci_base_addr().into(),
            &drivers.dma,
        );
        let resp = mutrefbytes::<ShaDmaResp>(resp)?;
        resp.hdr = MailboxRespHeaderVarSize::default();
        if algorithm == CmHashAlgorithm::Sha384 {
            let digest = dma.sha384_image(
                &mut drivers.sha2_512_384_acc,
                source,
                length,
                AesDmaMode::None,
            )?;
            resp.hash[..SHA384_DIGEST_BYTE_SIZE]
                .copy_from_slice(&<[u8; SHA384_DIGEST_BYTE_SIZE]>::from(digest));
            resp.hdr.data_len = SHA384_DIGEST_BYTE_SIZE as u32;
        } else {
            let digest = dma.sha512_image(
                &mut drivers.sha2_512_384_acc,
                source,
                length,
                AesDmaMode::None,
            )?;
            resp.hash = digest.into();
            resp.hdr.data_len = SHA512_DIGEST_BYTE_SIZE as u32;
        }
        resp.partial_len()
    }
}

/// Returns whether `[lo, lo + length)` is non-empty, 4-byte aligned and inside one
/// 4 GiB-aligned block. The SHA accelerator never completes an empty stream, the DMA
/// hangs on an unaligned transfer, and it wraps at its address width.
fn is_streamable_range(lo: u32, length: u32) -> bool {
    length != 0 && (lo | length) & 3 == 0 && lo.checked_add(length - 1).is_some()
}

/// Returns whether `[start, start + len)` overlaps `[base, base + size)`.
fn axi_range_overlaps(start: u64, len: u64, base: u64, size: u64) -> bool {
    if len == 0 || size == 0 {
        return false;
    }
    let last = start.saturating_add(len - 1);
    let region_last = base.saturating_add(size - 1);
    start <= region_last && base <= last
}

#[cfg(test)]
mod tests {
    use super::{axi_range_overlaps, is_streamable_range};

    const BASE: u64 = 0x3000_0000;
    const SIZE: u64 = 0x8_0000;

    #[test]
    fn test_is_streamable_range() {
        assert!(is_streamable_range(0, 4));
        assert!(is_streamable_range(0xFFFF_F000, 0x1000));
        assert!(is_streamable_range(0xFFFF_FFFC, 4));
        assert!(!is_streamable_range(0, 0));
        assert!(!is_streamable_range(2, 4));
        assert!(!is_streamable_range(0, 6));
        assert!(!is_streamable_range(0xFFFF_F000, 0x1004));
        assert!(!is_streamable_range(0xFFFF_FFFC, 8));
    }

    #[test]
    fn test_axi_range_overlaps_edges() {
        assert!(!axi_range_overlaps(BASE - 8, 8, BASE, SIZE));
        assert!(!axi_range_overlaps(BASE + SIZE, 8, BASE, SIZE));
        assert!(axi_range_overlaps(BASE - 8, 9, BASE, SIZE));
        assert!(axi_range_overlaps(BASE + SIZE - 1, 8, BASE, SIZE));
        assert!(axi_range_overlaps(BASE - 4, SIZE + 8, BASE, SIZE));
        assert!(axi_range_overlaps(BASE + 0x2_1000, 4, BASE, SIZE));
    }

    #[test]
    fn test_axi_range_overlaps_empty() {
        assert!(!axi_range_overlaps(BASE, 8, BASE, 0));
        assert!(!axi_range_overlaps(BASE, 0, BASE, SIZE));
    }

    #[test]
    fn test_axi_range_overlaps_region_at_top() {
        let base = u64::MAX - 0xff;
        assert!(axi_range_overlaps(u64::MAX - 3, 4, base, 0x1000));
        assert!(!axi_range_overlaps(base - 4, 4, base, 0x1000));
    }
}
