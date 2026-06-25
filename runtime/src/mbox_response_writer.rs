// Licensed under the Apache-2.0 license

use caliptra_dpe_response_buffer::{ResponseBufError, ResponseBuffer};
use caliptra_drivers::memory_layout;

/// Streams bytes directly into mailbox SRAM via the memory-mapped window.
///
/// All writes are word-aligned internally via private helpers: word writes use
/// the fast direct-write path; unaligned bytes use read-modify-write of the
/// containing word.
pub struct MboxResponseWriter {}

impl MboxResponseWriter {
    const BASE: usize = memory_layout::MBOX_ORG as usize;
    const SIZE: usize = memory_layout::MBOX_SIZE as usize;

    /// Return a pointer to `MBOX_ORG + byte_offset` cast to `*mut u32`.
    ///
    /// `byte_offset` must be word-aligned.
    #[inline(always)]
    fn word_ptr(&self, byte_offset: usize) -> *mut u32 {
        (Self::BASE + byte_offset) as *mut u32
    }

    /// Read the word at `byte_offset` (word-aligned) from SRAM.
    #[inline(always)]
    fn read_word(&self, byte_offset: usize) -> u32 {
        // SAFETY: The caller guarantees the region is within mailbox SRAM.
        unsafe { core::ptr::read_volatile(self.word_ptr(byte_offset)) }
    }

    /// Write `word` to `byte_offset` (word-aligned) in SRAM.
    #[inline(always)]
    fn write_word(&self, byte_offset: usize, word: u32) {
        // SAFETY: The caller guarantees the region is within mailbox SRAM.
        unsafe { core::ptr::write_volatile(self.word_ptr(byte_offset), word) }
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
            for &b in &src[..leading] {
                let abs_b = pos;
                let word_off = abs_b & !3;
                let lane = abs_b & 3;
                let mut word = self.read_word(word_off);
                word = (word & !(0xFF << (lane * 8))) | ((b as u32) << (lane * 8));
                self.write_word(word_off, word);
                pos += 1;
            }
            src = &src[leading..];
        }

        // Aligned interior words.
        let words = src.len() / 4;
        for chunk in src[..words * 4].chunks_exact(4) {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            self.write_word(pos, w);
            pos += 4;
        }
        src = &src[words * 4..];

        // Trailing partial word.
        for &b in src {
            let abs_b = pos;
            let word_off = abs_b & !3;
            let lane = abs_b & 3;
            let mut word = self.read_word(word_off);
            word = (word & !(0xFF << (lane * 8))) | ((b as u32) << (lane * 8));
            self.write_word(word_off, word);
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

            let word = self.read_word(word_offset);
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
            self.write_word(i * 4, 0);
        }
        Ok(())
    }
}
