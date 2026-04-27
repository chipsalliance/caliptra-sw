// Licensed under the Apache-2.0 license

#![no_std]

use crate::shake_impl::{KeccakSt, ShakeConfig};

mod shake_impl;

pub struct Shake128(KeccakSt);

impl Shake128 {
    pub fn new() -> Self {
        Self(KeccakSt::new(ShakeConfig::Shake128))
    }
    pub fn absorb(&mut self, in_slice: &[u8]) {
        self.0.absorb(in_slice);
    }
    pub fn squeeze(&mut self, out_slice: &mut [u8]) {
        self.0.squeeze(out_slice);
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Shake256(KeccakSt);

impl Shake256 {
    pub fn new() -> Self {
        Self(KeccakSt::new(ShakeConfig::Shake256))
    }
    pub fn absorb(&mut self, in_slice: &[u8]) {
        self.0.absorb(in_slice);
    }
    pub fn squeeze(&mut self, out_slice: &mut [u8]) {
        self.0.squeeze(out_slice);
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}
