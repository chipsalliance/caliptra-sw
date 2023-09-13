// Licensed under the Apache-2.0 license

use caliptra_drivers::{Array4x8, CaliptraResult, Sha256Alg, Sha256DigestOp};
use std::marker::PhantomData;

use sha2::Digest;

#[derive(Default)]
pub struct Sha256SoftwareDriver {}

pub struct Sha256DigestOpSw<'a> {
    driver: PhantomData<&'a mut Sha256SoftwareDriver>,
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

impl Sha256Alg for Sha256SoftwareDriver {
    type DigestOp<'a> = Sha256DigestOpSw<'a>;

    fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x8> {
        let result = sha2::Sha256::digest(buf);
        Ok(Array4x8::from(<[u8; 32]>::try_from(result).unwrap()))
    }

    fn digest_init(&mut self) -> CaliptraResult<Self::DigestOp<'_>> {
        Ok(Sha256DigestOpSw {
            driver: PhantomData::default(),
            digest: sha2::Sha256::new(),
        })
    }
}

impl Sha256SoftwareDriver {
    pub fn new() -> Self {
        Self {}
    }
}
