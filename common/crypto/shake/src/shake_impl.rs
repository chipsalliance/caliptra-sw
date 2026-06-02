// Licensed under the Apache-2.0 license

use zerocopy::IntoBytes;

// Keccak phases.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeccakPhase {
    Absorb = 0,
    Squeeze = 1,
}

// Supported SHAKE configurations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ShakeConfig {
    Shake128 = 0,
    Shake256 = 1,
}

pub struct KeccakSt {
    state: [u64; 25],
    phase: KeccakPhase,
    rate_bytes: usize,
    absorb_offset: usize,
    squeeze_offset: usize,
}

// keccak_f implements the Keccak-1600 permutation as described at
// https://keccak.team/keccak_specs_summary.html. Each lane is represented as a
// 64-bit value and the 5×5 lanes are stored as an array in row-major order.
#[allow(unused_assignments)]
fn keccak_f(state: &mut [u64; 25]) {
    static ROUND_CONSTANTS: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    for round in &ROUND_CONSTANTS {
        // θ step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[y * 5 + x] ^= d;
            }
        }

        // ρ and π steps.
        let mut prev_value = state[1];

        macro_rules! pi_rho_step {
            ($index:expr, $rotation:expr) => {
                let value = prev_value.rotate_left($rotation);
                prev_value = state[$index];
                state[$index] = value;
            };
        }

        pi_rho_step!(10, 1);
        pi_rho_step!(7, 3);
        pi_rho_step!(11, 6);
        pi_rho_step!(17, 10);
        pi_rho_step!(18, 15);
        pi_rho_step!(3, 21);
        pi_rho_step!(5, 28);
        pi_rho_step!(16, 36);
        pi_rho_step!(8, 45);
        pi_rho_step!(21, 55);
        pi_rho_step!(24, 2);
        pi_rho_step!(4, 14);
        pi_rho_step!(15, 27);
        pi_rho_step!(23, 41);
        pi_rho_step!(19, 56);
        pi_rho_step!(13, 8);
        pi_rho_step!(12, 25);
        pi_rho_step!(2, 43);
        pi_rho_step!(20, 62);
        pi_rho_step!(14, 18);
        pi_rho_step!(22, 39);
        pi_rho_step!(9, 61);
        pi_rho_step!(6, 20);
        pi_rho_step!(1, 44);

        // χ step
        for y in 0..5 {
            let row_index = 5 * y;
            let orig_x0 = state[row_index];
            let orig_x1 = state[row_index + 1];
            state[row_index] ^= !orig_x1 & state[row_index + 2];
            state[row_index + 1] ^= !state[row_index + 2] & state[row_index + 3];
            state[row_index + 2] ^= !state[row_index + 3] & state[row_index + 4];
            state[row_index + 3] ^= !state[row_index + 4] & orig_x0;
            state[row_index + 4] ^= !orig_x0 & orig_x1;
        }

        // ι step
        state[0] ^= round;
    }
}

impl KeccakSt {
    pub fn new(config: ShakeConfig) -> Self {
        let capacity_bytes = match config {
            ShakeConfig::Shake128 => 256 / 8,
            ShakeConfig::Shake256 => 512 / 8,
        };

        KeccakSt {
            state: [0u64; 25],
            phase: KeccakPhase::Absorb,
            rate_bytes: 200 - capacity_bytes,
            absorb_offset: 0,
            squeeze_offset: 0,
        }
    }

    pub fn absorb(&mut self, mut in_slice: &[u8]) {
        let in_len = in_slice.len();
        let rate_bytes = self.rate_bytes;

        // Absorb partial block.
        if self.absorb_offset != 0 {
            let first_block_len = rate_bytes - self.absorb_offset;
            let todo = core::cmp::min(first_block_len, in_len);
            let absorb_offset = self.absorb_offset;
            // Skip+take iterator avoids the bounds-check panic that
            // `state.as_mut_bytes()[absorb_offset + i]` would emit.
            for (dst, in_byte) in self
                .state
                .as_mut_bytes()
                .iter_mut()
                .skip(absorb_offset)
                .take(todo)
                .zip(in_slice.iter())
            {
                *dst ^= *in_byte;
            }

            // This input didn't fill the block.
            if first_block_len > in_len {
                self.absorb_offset += in_len;
                return;
            }

            keccak_f(&mut self.state);
            // Statically Some: we just consumed `first_block_len` bytes that
            // were guaranteed to be present (else-branch above).
            in_slice = match in_slice.get(first_block_len..) {
                Some(rest) => rest,
                None => return,
            };
        }

        // Absorb full blocks. Use `split_at_checked` (stable 1.80) and
        // `as_chunks::<8>()` (stable 1.88) instead of slice ranges with
        // `try_into().unwrap()` so no panic landing pads are emitted.
        let rate_words = rate_bytes / 8;
        while in_slice.len() >= rate_bytes {
            let (block, rest) = match in_slice.split_at_checked(rate_bytes) {
                Some(p) => p,
                None => return,
            };
            let (words, _rem) = block.as_chunks::<8>();
            for (i, word_bytes) in words.iter().enumerate().take(rate_words) {
                if let Some(slot) = self.state.get_mut(i) {
                    *slot ^= u64::from_le_bytes(*word_bytes);
                }
            }
            keccak_f(&mut self.state);
            in_slice = rest;
        }

        // Absorb partial trailer.
        for (s, in_byte) in self.state.as_mut_bytes().iter_mut().zip(in_slice) {
            *s ^= *in_byte;
        }
        self.absorb_offset = in_slice.len();
    }

    fn finalize(&mut self) {
        let terminator = 0x1fu8;

        // Bounds-checked XORs of the two terminator bytes; both indices are
        // statically valid (`absorb_offset < rate_bytes <= 168 < 200` and
        // `rate_bytes - 1 < 200`), so the `if let Some` arms always run.
        let state_bytes = self.state.as_mut_bytes();
        if let Some(b) = state_bytes.get_mut(self.absorb_offset) {
            *b ^= terminator;
        }
        if self.rate_bytes > 0 {
            if let Some(b) = state_bytes.get_mut(self.rate_bytes - 1) {
                *b ^= 0x80;
            }
        }

        keccak_f(&mut self.state);
    }

    pub fn squeeze(&mut self, mut out_slice: &mut [u8]) {
        if self.phase == KeccakPhase::Absorb {
            self.finalize();
            self.phase = KeccakPhase::Squeeze;
        }

        while !out_slice.is_empty() {
            if self.squeeze_offset == self.rate_bytes {
                keccak_f(&mut self.state);
                self.squeeze_offset = 0;
            }

            let remaining = self.rate_bytes - self.squeeze_offset;
            let todo = core::cmp::min(out_slice.len(), remaining);

            // `split_at_mut_checked` / `get` avoid the panic landing pads
            // that `out_slice[..todo]` and `state[squeeze_offset..+todo]`
            // would otherwise leave behind. Both are always `Some` here.
            let (dst, rest) = match out_slice.split_at_mut_checked(todo) {
                Some(p) => p,
                None => return,
            };
            let state_bytes = self.state.as_bytes();
            let src = match state_bytes.get(self.squeeze_offset..self.squeeze_offset + todo) {
                Some(s) => s,
                None => return,
            };
            // Iterator copy: avoids `copy_from_slice`'s length-mismatch
            // panic landing pad. Both slices have the same length (`todo`).
            for (d, s) in dst.iter_mut().zip(src.iter()) {
                *d = *s;
            }

            out_slice = rest;
            self.squeeze_offset += todo;
        }
    }
}
