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
    config: ShakeConfig,
    state: [u64; 25],
    phase: KeccakPhase,
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
        KeccakSt {
            config,
            state: [0u64; 25],
            phase: KeccakPhase::Absorb,
            absorb_offset: 0,
            squeeze_offset: 0,
        }
    }

    fn rate(&self) -> usize {
        match self.config {
            ShakeConfig::Shake128 => 200 - (256 / 8),
            ShakeConfig::Shake256 => 200 - (512 / 8),
        }
    }

    pub fn absorb(&mut self, mut in_slice: &[u8]) {
        let in_len = in_slice.len();

        // Absorb partial block.
        if self.absorb_offset != 0 {
            let first_block_len = self.rate() - self.absorb_offset;
            let todo = core::cmp::min(first_block_len, in_len);
            let start = self.absorb_offset.min(self.state.as_bytes().len());
            for (s, b) in self.state.as_mut_bytes()[start..]
                .iter_mut()
                .zip(in_slice.iter().take(todo))
            {
                *s ^= b;
            }

            // This input didn't fill the block.
            if first_block_len > in_len {
                self.absorb_offset += in_len;
                return;
            }

            keccak_f(&mut self.state);
            in_slice = &in_slice[first_block_len..];
        }

        // Absorb full blocks.
        let state_words = self.state.len();
        let rate_words = self.rate() / 8;
        let rate = self.rate();
        while in_slice.len() >= rate {
            for (state_word, word_bytes) in self.state[..rate_words.min(state_words)]
                .iter_mut()
                .zip(in_slice.chunks_exact(8))
            {
                *state_word ^= u64::from_le_bytes([
                    word_bytes[0],
                    word_bytes[1],
                    word_bytes[2],
                    word_bytes[3],
                    word_bytes[4],
                    word_bytes[5],
                    word_bytes[6],
                    word_bytes[7],
                ]);
            }
            keccak_f(&mut self.state);
            in_slice = &in_slice[rate..];
        }

        // Absorb partial block.
        for (s, in_byte) in self.state.as_mut_bytes().iter_mut().zip(in_slice) {
            *s ^= *in_byte;
        }
        self.absorb_offset = in_slice.len();
    }

    fn finalize(&mut self) {
        let r = self.rate();
        let ao = self.absorb_offset.min(self.state.as_bytes().len() - 1);

        let state_bytes = self.state.as_mut_bytes();
        state_bytes[ao] ^= 0x1f;
        state_bytes[r - 1] ^= 0x80;

        keccak_f(&mut self.state);
    }

    pub fn squeeze(&mut self, mut out_slice: &mut [u8]) {
        if self.phase == KeccakPhase::Absorb {
            self.finalize();
            self.phase = KeccakPhase::Squeeze;
        }

        let rate = self.rate();

        while !out_slice.is_empty() {
            if self.squeeze_offset >= rate {
                keccak_f(&mut self.state);
                self.squeeze_offset = 0;
            }

            let squeeze_off = self.squeeze_offset.min(rate);
            let state_tail = &self.state.as_bytes()[squeeze_off..rate];
            let todo = out_slice.len().min(state_tail.len());
            let (dst, rest) = out_slice.split_at_mut(todo);
            dst.copy_from_slice(&state_tail[..todo]);
            out_slice = rest;
            self.squeeze_offset += todo;
        }
    }
}
