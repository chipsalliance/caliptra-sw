// Licensed under the Apache-2.0 license

use caliptra_drivers::{Array4x8, CaliptraResult, Sha256, Sha256DigestOp};

use sha2::digest::block_buffer::Block;
use sha2::digest::consts::U64;
use sha2::Digest;

const SHA256_BLOCK_BYTE_SIZE: usize = 64;

#[derive(Default)]
pub struct Sha256SoftwareDriver {}

pub struct Sha256DigestOpSw<'a> {
    driver: &'a mut Sha256SoftwareDriver,
    digest: sha2::Sha256,
}
impl<'a> Sha256DigestOp<'a> for Sha256DigestOpSw<'a> {
    fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        self.digest.update(data);
        Ok(())
    }
    fn finalize(self, digest: &mut Array4x8) -> CaliptraResult<()> {
        let result = self.digest.finalize();
        *digest = Array4x8::from(<[u8; 32]>::try_from(result.as_slice()).unwrap());
        Ok(())
    }
}

impl Sha256 for Sha256SoftwareDriver {
    type DigestOp<'a> = Sha256DigestOpSw<'a>;

    fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x8> {
        let result = sha2::Sha256::digest(buf);
        Ok(Array4x8::from(<[u8; 32]>::try_from(result).unwrap()))
    }

    fn digest_init(&mut self) -> CaliptraResult<Self::DigestOp<'_>> {
        Ok(Sha256DigestOpSw {
            driver: self,
            digest: sha2::Sha256::new(),
        })
    }
}

impl Sha256SoftwareDriver {
    pub fn new() -> Self {
        Self {}
    }
}
