// Licensed under the Apache-2.0 license

use caliptra_dpe_response_buffer::{ResponseBufError, ResponseBuffer};
use caliptra_drivers::memory_layout;

/// Streams bytes directly into mailbox SRAM via the memory-mapped window.
///
/// All writes are word-aligned internally via private helpers: word writes use
/// the fast direct-write path; unaligned bytes use read-modify-write of the
/// containing word.
pub struct MboxResponseWriter {
    pub base: usize,
}

impl MboxResponseWriter {
    const SIZE: usize = memory_layout::MBOX_SIZE as usize;

    // Note: Allow the creation of a mbox response buffer.  This is useful for unit tests, where
    // the mbox will not be instantiated.
    #[cfg(test)]
    fn new(base: usize) -> Self {
        Self { base }
    }

    // Create a default MboxResponseWriter utilizing the MBOX SRAM.
    pub fn from_mbox_base() -> Self {
        Self {
            base: memory_layout::MBOX_ORG as usize,
        }
    }

    /// Return a pointer to `MBOX_ORG + byte_offset` cast to `*mut u32`.
    ///
    /// Safety: `byte_offset` must be word-aligned.
    #[inline(always)]
    unsafe fn word_ptr(&self, byte_offset: usize) -> *mut u32 {
        (self.base + byte_offset) as *mut u32
    }

    /// Read the word at `byte_offset` (word-aligned) from SRAM.
    ///
    /// Safety: The `byte_offset` must be word aligned.
    #[inline(always)]
    unsafe fn read_word(&self, byte_offset: usize) -> u32 {
        // SAFETY: The caller guarantees the region is within mailbox SRAM.
        core::ptr::read_volatile(self.word_ptr(byte_offset))
    }

    /// Write `word` to `byte_offset` (word-aligned) in SRAM.
    ///
    /// Safety: The `byte_offset` must be word aligned.
    #[inline(always)]
    unsafe fn write_word(&self, byte_offset: usize, word: u32) {
        // SAFETY: The caller guarantees the region is within mailbox SRAM.
        core::ptr::write_volatile(self.word_ptr(byte_offset), word)
    }
}

impl ResponseBuffer for MboxResponseWriter {
    fn capacity(&self) -> usize {
        memory_layout::MBOX_SIZE as usize
    }

    /// Write `bytes` starting at `offset`.
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ResponseBufError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(ResponseBufError::Overflow)?;
        if end > Self::SIZE {
            return Err(ResponseBufError::Overflow);
        }

        let mut src = bytes;
        let mut pos = offset;

        // Leading unaligned bytes.
        let misalign = pos & 3;
        if misalign != 0 && !src.is_empty() {
            let leading = (4 - misalign).min(src.len());
            let word_off = pos & !3;

            // Safety: By the above word offset is 4 byte aligned, and thus the following are safe.
            unsafe {
                let mut word_bytes = self.read_word(word_off).to_le_bytes();
                word_bytes[misalign..misalign + leading].copy_from_slice(&src[..leading]);
                self.write_word(word_off, u32::from_le_bytes(word_bytes));
            }

            pos += leading;
            src = &src[leading..];
        }

        // Aligned interior words.
        let words = src.len() / 4;
        for chunk in src[..words * 4].chunks_exact(4) {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            // Safety: Since pos is word aligned at the start of the loop, and all chunks are on
            // the boundary this remains safe.
            unsafe { self.write_word(pos, w) };
            pos += 4;
        }
        src = &src[words * 4..];

        // Trailing partial word.
        for &b in src {
            let abs_b = pos;
            let word_off = abs_b & !3;
            let lane = abs_b & 3;
            unsafe {
                let mut word = self.read_word(word_off);
                word = (word & !(0xFF << (lane * 8))) | ((b as u32) << (lane * 8));
                self.write_word(word_off, word);
            }
            pos += 1;
        }

        Ok(())
    }

    /// Read back a range of already-written bytes.  The range is relative to
    /// the first byte written (offset 0 = `MBOX_ORG + self.base`).  Calls `f`
    /// one or more times: once per word boundary crossing to handle unaligned
    /// head and tail bytes.
    fn read_range(
        &self,
        range: core::ops::Range<usize>,
        f: &mut dyn FnMut(&[u8]) -> Result<(), ResponseBufError>,
    ) -> Result<(), ResponseBufError> {
        let mut pos = range.start;
        while pos < range.end {
            let word_offset = pos & !3;
            let byte_lane = pos & 3;
            let bytes_in_word = 4 - byte_lane;
            let remaining = range.end - pos;
            let chunk_len = bytes_in_word.min(remaining);

            // Safety: By word_offset construction it must be 4 byte aligned.
            let word = unsafe { self.read_word(word_offset) };
            let word_bytes = word.to_le_bytes();
            f(&word_bytes[byte_lane..byte_lane + chunk_len])?;

            pos += chunk_len;
        }
        Ok(())
    }

    /// Zero the entire backing region.
    fn clear(&mut self) -> Result<(), ResponseBufError> {
        // The MBOX SRAM is word aligned so this will clear the entire buffer.
        for i in 0..Self::SIZE / 4 {
            unsafe { self.write_word(i * 4, 0) };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};

    fn make_writer() -> (MboxResponseWriter, Vec<u8>) {
        let size = memory_layout::MBOX_SIZE as usize;
        let mut buf: Vec<u8> = vec![0; size];
        let base = buf.as_mut_ptr() as usize;
        // SAFETY: buf lives for the duration of the returned tuple; MboxResponseWriter
        // only accesses memory within MBOX_SIZE of base.
        let writer = MboxResponseWriter::new(base);
        (writer, buf)
    }

    fn collect(w: &MboxResponseWriter, range: core::ops::Range<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        w.read_range(range, &mut |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
        out
    }

    // Aligned full-word writes (the interior-word fast path).
    #[test]
    fn write_at_aligned() {
        let (mut w, _buf) = make_writer();
        w.write_at(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(collect(&w, 0..8), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    // Leading unaligned bytes that fit entirely within the remainder of one word.
    #[test]
    fn write_at_leading_within_word() {
        let (mut w, _buf) = make_writer();
        w.write_at(1, &[0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(collect(&w, 0..4), [0, 0xAA, 0xBB, 0xCC]);
    }

    // Leading unaligned (misalign=2) followed by aligned interior words.
    #[test]
    fn write_at_leading_then_aligned() {
        let (mut w, _buf) = make_writer();
        w.write_at(2, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap();
        assert_eq!(collect(&w, 0..12), [0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    // Aligned interior word followed by trailing partial-word bytes.
    #[test]
    fn write_at_trailing_partial() {
        let (mut w, _buf) = make_writer();
        w.write_at(0, &[1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(collect(&w, 0..8), [1, 2, 3, 4, 5, 6, 7, 0]);
    }

    // Leading unaligned (misalign=1) followed by aligned interior words.
    // Exercises the pos-advance path where leading != misalign.
    #[test]
    fn write_at_misalign1_then_aligned() {
        let (mut w, _buf) = make_writer();
        w.write_at(1, &[1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(collect(&w, 0..8), [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    // Leading unaligned (misalign=3) followed by aligned interior words.
    #[test]
    fn write_at_misalign3_then_aligned() {
        let (mut w, _buf) = make_writer();
        w.write_at(3, &[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(collect(&w, 0..8), [0, 0, 0, 1, 2, 3, 4, 5]);
    }

    // Overflow is rejected.
    #[test]
    fn write_at_overflow() {
        let (mut w, _buf) = make_writer();
        assert!(w
            .write_at(memory_layout::MBOX_SIZE as usize - 1, &[1, 2])
            .is_err());
    }

    // read_range with unaligned head and tail crossing a word boundary.
    #[test]
    fn read_range_unaligned() {
        let (mut w, _buf) = make_writer();
        w.write_at(0, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(collect(&w, 1..7), [2, 3, 4, 5, 6, 7]);
    }

    // clear zeroes previously-written data.
    #[test]
    fn clear_zeroes() {
        let (mut w, _buf) = make_writer();
        w.write_at(0, &[0xFF; 8]).unwrap();
        w.clear().unwrap();
        assert_eq!(collect(&w, 0..8), [0u8; 8]);
    }
}
