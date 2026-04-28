/*++

Licensed under the Apache-2.0 license.

File Name:

    mrac_bus.rs

Abstract:

    Optional emulation of the VeeR EL2 MRAC (Memory Region Access Control)
    register for LSU (data) accesses. Wraps an inner Bus and enforces
    per-region access rules:

    - Side-effect regions: only naturally aligned access allowed.
    - Cacheable regions: reads are widened to 64-bit aligned double-word
      fetches (two word reads from the inner bus).

    IFU (instruction fetch) accesses are handled at the cpu side and bypass
    this wrapper -- see Cpu::read_instr.

    Ref: https://chipsalliance.github.io/Cores-VeeR-EL2/html/main/docs_rendered/html/memory-map.html#region-access-control-register-mrac

--*/

use std::cell::Cell;
use std::rc::Rc;
use std::sync::mpsc;

use crate::bus::{Bus, BusError};
use crate::event::Event;
use caliptra_emu_types::{RvAddr, RvData, RvSize};

/// Bus wrapper that enforces VeeR EL2 MRAC region access rules for LSU
/// (data load/store) accesses.
///
/// The 32-bit address space is split into 16 regions of 256MB each.
/// Each region has a 2-bit field in the MRAC CSR (0x7C0):
///   - bit Y*2:   cacheable
///   - bit Y*2+1: sideeffect
///
/// When `enabled` is false, all accesses pass through unchanged.
pub struct MracBus<TBus: Bus> {
    inner: TBus,
    mrac: Rc<Cell<u32>>,
    enabled: bool,
}

impl<TBus: Bus> MracBus<TBus> {
    pub fn new(inner: TBus, mrac: Rc<Cell<u32>>, enabled: bool) -> Self {
        Self {
            inner,
            mrac,
            enabled,
        }
    }

    /// Extract the 2-bit region field for a given address.
    ///
    /// The address space is split into 16 regions of 256 MB each. The high
    /// nibble of the address selects the region; each region has a 2-bit
    /// field at `mrac[region*2 +: 2]` where bit 0 = cacheable and bit 1 =
    /// sideeffect.
    fn region_bits(&self, addr: RvAddr) -> u32 {
        let region = (addr >> 28) & 0xF;
        (self.mrac.get() >> (region * 2)) & 0b11
    }

    /// True if the region containing `addr` has the sideeffect bit set
    /// (bit 1 of the region's 2-bit field).
    fn is_sideeffect(&self, addr: RvAddr) -> bool {
        self.region_bits(addr) & 0b10 != 0
    }

    /// True if the region containing `addr` has the cacheable bit set
    /// (bit 0 of the region's 2-bit field).
    fn is_cacheable(&self, addr: RvAddr) -> bool {
        self.region_bits(addr) & 0b01 != 0
    }

    /// Return a mutable reference to the inner bus.
    pub fn inner_mut(&mut self) -> &mut TBus {
        &mut self.inner
    }

    /// Return a reference to the inner bus.
    pub fn inner(&self) -> &TBus {
        &self.inner
    }

    /// Perform a "widened" read that emulates VeeR's 64-bit cache-line fill:
    /// the inner bus sees one or two aligned 8-byte fetches, and the
    /// requested `size` bytes at `addr` are extracted from the result.
    ///
    /// If `[addr, addr+size)` lies entirely within a single 8-byte aligned
    /// chunk, only one 8-byte fetch is issued. If it crosses the boundary
    /// (possible for unaligned half-word/word loads), two 8-byte fetches
    /// are issued and the result is stitched.
    fn read_widened(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        let size_bytes = match size {
            RvSize::Byte => 1usize,
            RvSize::HalfWord => 2,
            RvSize::Word => 4,
            _ => return Err(BusError::LoadAccessFault),
        };
        let aligned_addr = addr & !0x7;
        let byte_offset = (addr - aligned_addr) as usize;

        // wrapping_add is defensive against pathological MRAC settings near
        // the top of the u32 address space. Caliptra's cacheable region is
        // region 0 so this never wraps in practice, but it is cheaper than
        // a runtime overflow check.
        let lo0 = self.inner.read(RvSize::Word, aligned_addr)?;
        let hi0 = self
            .inner
            .read(RvSize::Word, aligned_addr.wrapping_add(4))?;
        let dword0: u64 = (lo0 as u64) | ((hi0 as u64) << 32);

        let combined: u128 = if byte_offset + size_bytes > 8 {
            // Access crosses the 8-byte boundary; fetch the next chunk too.
            let lo1 = self
                .inner
                .read(RvSize::Word, aligned_addr.wrapping_add(8))?;
            let hi1 = self
                .inner
                .read(RvSize::Word, aligned_addr.wrapping_add(12))?;
            let dword1: u64 = (lo1 as u64) | ((hi1 as u64) << 32);
            (dword0 as u128) | ((dword1 as u128) << 64)
        } else {
            dword0 as u128
        };

        let mask: u128 = match size {
            RvSize::Byte => 0xFF,
            RvSize::HalfWord => 0xFFFF,
            RvSize::Word => 0xFFFF_FFFF,
            _ => unreachable!(),
        };
        Ok(((combined >> (byte_offset * 8)) & mask) as u32)
    }
}

impl<TBus: Bus> Bus for MracBus<TBus> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if !self.enabled {
            return self.inner.read(size, addr);
        }

        if self.is_sideeffect(addr) {
            // LSU side-effect: reject misaligned access only.
            // Per RTL (lsu_addrcheck.sv): byte is always aligned,
            // halfword must be 2-byte aligned, word must be 4-byte aligned.
            let is_aligned = match size {
                RvSize::Byte => true,
                RvSize::HalfWord => (addr & 0x1) == 0,
                RvSize::Word => (addr & 0x3) == 0,
                _ => false,
            };
            if !is_aligned {
                return Err(BusError::LoadAddrMisaligned);
            }
            // Side-effect: exact-size pass-through (no widening)
            self.inner.read(size, addr)
        } else if self.is_cacheable(addr) {
            // LSU cacheable: widen to 64-bit aligned read(s)
            self.read_widened(size, addr)
        } else {
            // Neither side-effect nor cacheable: pass through
            self.inner.read(size, addr)
        }
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if !self.enabled {
            return self.inner.write(size, addr, val);
        }

        if self.is_sideeffect(addr) {
            // LSU side-effect: reject misaligned access only.
            let is_aligned = match size {
                RvSize::Byte => true,
                RvSize::HalfWord => (addr & 0x1) == 0,
                RvSize::Word => (addr & 0x3) == 0,
                _ => false,
            };
            if !is_aligned {
                return Err(BusError::StoreAddrMisaligned);
            }
        }

        // Cacheable/non-sideeffect writes pass through with original size
        self.inner.write(size, addr, val)
    }

    fn poll(&mut self) {
        self.inner.poll();
    }

    fn warm_reset(&mut self) {
        self.inner.warm_reset();
    }

    fn update_reset(&mut self) {
        self.inner.update_reset();
    }

    fn incoming_event(&mut self, event: Rc<Event>) {
        self.inner.incoming_event(event);
    }

    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.inner.register_outgoing_events(sender);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::testing::FakeBus;

    fn make_mrac_bus(mrac_val: u32, enabled: bool) -> MracBus<FakeBus> {
        let mrac = Rc::new(Cell::new(mrac_val));
        let fake = FakeBus::new();
        MracBus::new(fake, mrac, enabled)
    }

    #[test]
    fn test_disabled_passthrough() {
        let mut bus = make_mrac_bus(0xFFFF_FFFF, false);
        // Even with all regions side-effect, disabled should pass through
        assert!(bus.read(RvSize::Byte, 0x3003_0001).is_ok());
        assert!(bus.write(RvSize::Byte, 0x3003_0001, 0x42).is_ok());
    }

    #[test]
    fn test_sideeffect_word_aligned_ok() {
        // Region 3 (0x3xxx_xxxx): set sideeffect bit = bit 7 (region 3 * 2 + 1)
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert!(bus.read(RvSize::Word, 0x3003_0000).is_ok());
        assert!(bus.write(RvSize::Word, 0x3003_0000, 0x42).is_ok());
    }

    #[test]
    fn test_sideeffect_byte_aligned_ok() {
        // Per VeeR EL2 RTL: byte accesses are always naturally aligned,
        // so they always succeed in side-effect regions.
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert!(bus.read(RvSize::Byte, 0x3003_0001).is_ok());
        assert!(bus.write(RvSize::Byte, 0x3003_0001, 0x42).is_ok());
    }

    #[test]
    fn test_sideeffect_halfword_aligned_ok() {
        // Per VeeR EL2 RTL: 2-byte aligned halfword access succeeds.
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert!(bus.read(RvSize::HalfWord, 0x3003_0000).is_ok());
    }

    #[test]
    fn test_sideeffect_halfword_misaligned_rejected() {
        // Per VeeR EL2 RTL: misaligned halfword access is rejected.
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.read(RvSize::HalfWord, 0x3003_0001),
            Err(BusError::LoadAddrMisaligned)
        );
    }

    #[test]
    fn test_sideeffect_misaligned_word_rejected() {
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.read(RvSize::Word, 0x3003_0002),
            Err(BusError::LoadAddrMisaligned)
        );
    }

    #[test]
    fn test_cacheable_read_widens() {
        // Region 5 (0x5xxx_xxxx): set cacheable bit = bit 10 (region 5 * 2)
        let mrac_val = 1 << 10; // cacheable for region 5
        let mut bus = make_mrac_bus(mrac_val, true);
        // FakeBus returns Ok(0) by default, so widened read should succeed
        assert!(bus.read(RvSize::Byte, 0x5000_0001).is_ok());
        assert!(bus.read(RvSize::HalfWord, 0x5000_0002).is_ok());
        assert!(bus.read(RvSize::Word, 0x5000_0004).is_ok());
    }

    #[test]
    fn test_no_flags_passthrough() {
        // Region 2: no flags set
        let mut bus = make_mrac_bus(0, true);
        assert!(bus.read(RvSize::Byte, 0x2000_0001).is_ok());
        assert!(bus.write(RvSize::Byte, 0x2000_0001, 0x42).is_ok());
    }

    #[test]
    fn test_cacheable_widens_causes_spurious_lock() {
        // Demonstrates the problem: reading USER (offset 0x04) in a
        // cacheable region widens to 64-bit, causing a read at offset 0x00
        // (LOCK) which has side effects (acquires the lock).
        let mrac_val = 1 << 6; // cacheable for region 3
        let mut bus = make_mrac_bus(mrac_val, true);

        // Read USER at 0x3002_0004 -- should widen to 64-bit aligned read
        let _ = bus.read(RvSize::Word, 0x3002_0004);

        // The widened read should have issued two word reads starting at
        // the 64-bit aligned boundary (0x3002_0000)
        let log = bus.inner().log.take();
        assert!(
            log.contains("read(RvSize::Word, 0x30020000)"),
            "Cacheable read should widen to include LOCK addr 0x30020000, got: {log}"
        );
        assert!(
            log.contains("read(RvSize::Word, 0x30020004)"),
            "Cacheable read should also read USER addr 0x30020004, got: {log}"
        );
    }

    #[test]
    fn test_sideeffect_write_halfword_misaligned_rejected() {
        // Write-side counterpart of the read-side misalignment test:
        // RTL rejects misaligned stores into sideeffect regions with
        // StoreAddrMisaligned.
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.write(RvSize::HalfWord, 0x3003_0001, 0x42),
            Err(BusError::StoreAddrMisaligned)
        );
    }

    #[test]
    fn test_sideeffect_write_word_misaligned_rejected() {
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.write(RvSize::Word, 0x3003_0002, 0x42),
            Err(BusError::StoreAddrMisaligned)
        );
    }

    #[test]
    fn test_eleven_case_behaves_as_sideeffect() {
        // The CSR write path sanitizes the illegal 0b11 combination to
        // 0b10 (sideeffect-only). MracBus itself, however, may receive a
        // raw 0b11 if a caller writes the cell directly (e.g. tests, future
        // callers). Verify that runtime behavior in that case still matches
        // sideeffect semantics: misaligned LSU access is rejected and there
        // is no widening.
        let mrac_val = 0b11 << 6; // both bits set for region 3
        let mut bus = make_mrac_bus(mrac_val, true);
        assert_eq!(
            bus.read(RvSize::HalfWord, 0x3003_0001),
            Err(BusError::LoadAddrMisaligned)
        );
        // Aligned access goes through with no widening.
        let _ = bus.read(RvSize::Word, 0x3003_0004);
        let log = bus.inner().log.take();
        assert!(
            !log.contains("0x30030000"),
            "0b11 should behave as sideeffect (no widening to aligned dword), got: {log}"
        );
        assert!(
            log.contains("read(RvSize::Word, 0x30030004)"),
            "only the requested word should be read, got: {log}"
        );
    }

    #[test]
    fn test_sideeffect_prevents_spurious_lock() {
        // With side-effect correctly set for region 3, only the exact
        // register is read -- no widening, no spurious LOCK access.
        let mrac_val = 1 << 7; // sideeffect for region 3
        let mut bus = make_mrac_bus(mrac_val, true);

        let _ = bus.read(RvSize::Word, 0x3002_0004);

        let log = bus.inner().log.take();
        assert!(
            !log.contains("0x30020000"),
            "Side-effect read should not touch LOCK addr, got: {log}"
        );
        assert!(
            log.contains("read(RvSize::Word, 0x30020004)"),
            "Only USER addr should be read, got: {log}"
        );
    }

    #[test]
    fn test_cacheable_word_no_boundary_cross_single_dword() {
        // A 4-byte word at offset 0 inside an 8-byte aligned chunk lies
        // entirely within that chunk; only one 64-bit fetch is issued.
        let mrac_val = 1 << 10; // cacheable for region 5
        let mut bus = make_mrac_bus(mrac_val, true);
        let _ = bus.read(RvSize::Word, 0x5000_0000);
        let log = bus.inner().log.take();
        assert!(
            log.contains("read(RvSize::Word, 0x50000000)"),
            "lo word should be read, got: {log}"
        );
        assert!(
            log.contains("read(RvSize::Word, 0x50000004)"),
            "hi word should be read, got: {log}"
        );
        assert!(
            !log.contains("0x50000008"),
            "no second dword fetch expected (no boundary cross), got: {log}"
        );
    }

    #[test]
    fn test_cacheable_lsu_halfword_crossing_boundary_fetches_second_dword() {
        // A 2-byte halfword at offset 7 in an 8-byte chunk straddles into
        // the next chunk (byte 7 from chunk N, byte 0 from chunk N+1).
        let mrac_val = 1; // cacheable for region 0
        let mut bus = make_mrac_bus(mrac_val, true);
        let _ = bus.read(RvSize::HalfWord, 0x0000_0007);
        let log = bus.inner().log.take();
        for expect in [
            "read(RvSize::Word, 0x0)",
            "read(RvSize::Word, 0x4)",
            "read(RvSize::Word, 0x8)",
            "read(RvSize::Word, 0xc)",
        ] {
            assert!(
                log.contains(expect),
                "expected `{expect}` in halfword cross-boundary fetch log, got: {log}"
            );
        }
    }

    #[test]
    fn test_cacheable_write_does_not_widen() {
        // Per VeeR EL2 spec, the cacheable bit affects reads (cache-line
        // fill) but NOT writes. A byte write into a cacheable region must
        // pass through to the inner bus with the original size; it must
        // NOT be widened to a dword.
        let mrac_val = 1; // cacheable for region 0
        let mut bus = make_mrac_bus(mrac_val, true);
        bus.write(RvSize::Byte, 0x0000_0004, 0x42).unwrap();
        let log = bus.inner().log.take();
        assert!(
            log.contains("write(RvSize::Byte, 0x4, 0x42)"),
            "byte write should pass through unchanged, got: {log}"
        );
        assert!(
            !log.contains("0x0000_0000") && !log.contains("0x0)"),
            "no spurious read at aligned dword base, got: {log}"
        );
    }

    #[test]
    fn test_mrac_cell_change_takes_effect_immediately() {
        // Simulates the warm-reset path: the shared Rc<Cell<u32>> is
        // updated externally (e.g. by CsrFile::reset re-syncing the cell
        // to the post-reset CSR value of 0). MracBus must observe the new
        // value on the very next access, with no caching of region rules.
        let mrac = Rc::new(Cell::new(1u32)); // region 0 cacheable
        let mut bus = MracBus::new(FakeBus::new(), mrac.clone(), true);

        // First access: cacheable -> widened (two word reads)
        let _ = bus.read(RvSize::Word, 0x0000_0000);
        let log_before = bus.inner().log.take();
        assert!(
            log_before.contains("read(RvSize::Word, 0x0)")
                && log_before.contains("read(RvSize::Word, 0x4)"),
            "cacheable region should widen, got: {log_before}"
        );

        // Reset the cell to all-zero (passthrough) and re-issue the access.
        mrac.set(0);
        let _ = bus.read(RvSize::Word, 0x0000_0000);
        let log_after = bus.inner().log.take();
        assert!(
            log_after.contains("read(RvSize::Word, 0x0)") && !log_after.contains("0x4"),
            "after cell reset to 0, only the requested word should be read, got: {log_after}"
        );
    }

    #[test]
    fn test_cacheable_value_extracted_correctly_with_boundary_cross() {
        // Verify the stitched value is correct when reading across the
        // 8-byte boundary. Use a custom inner bus that returns address-keyed
        // data so we can assert the extracted value.
        struct AddrKeyedBus {
            // Word value at each aligned word address
            words: std::collections::HashMap<RvAddr, RvData>,
        }
        impl Bus for AddrKeyedBus {
            fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
                Ok(*self.words.get(&(addr & !0x3)).unwrap_or(&0))
            }
            fn write(&mut self, _: RvSize, _: RvAddr, _: RvData) -> Result<(), BusError> {
                Ok(())
            }
        }
        let mut words = std::collections::HashMap::new();
        // Aligned dword at 0x0: bytes 0..7 = AA BB CC DD EE FF 11 22
        words.insert(0x0, 0xDDCC_BBAA);
        words.insert(0x4, 0x2211_FFEE);
        // Aligned dword at 0x8: bytes 8..15 = 33 44 55 66 ...
        words.insert(0x8, 0x6655_4433);
        words.insert(0xC, 0x0);

        let mrac = Rc::new(Cell::new(1u32)); // cacheable for region 0
        let mut bus = MracBus::new(AddrKeyedBus { words }, mrac, true);

        // Halfword at 0x7 spans bytes [7,8] -> 22 33 -> 0x3322
        let result = bus.read(RvSize::HalfWord, 0x7).unwrap();
        assert_eq!(
            result, 0x3322,
            "boundary-crossing halfword at 0x7 should stitch correctly"
        );
    }
}
