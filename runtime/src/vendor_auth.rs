/*++

Licensed under the Apache-2.0 license.

File Name:

    vendor_auth.rs

Abstract:

    Runtime handling for vendor-unique command authentication.

    Per-command challenge/response modeled on the production debug-unlock flow:
    - VENDOR_AUTH_HELLO mints a fresh one-time nonce (Caliptra RAM).
    - VENDOR_AUTH_CHALLENGE submits the vendor command-auth public keys and a
      hybrid (ECDSA-P384 + ML-DSA-87) signature over `cmd_id ‖ body_hash ‖ nonce`,
      which is verified against the anchor enrolled at SET_AUTH_MANIFEST
      (FwPersistentData::vendor_cmd_pk_hash, the Vendor Ext 0x0001 record).

--*/

use crate::mutrefbytes;
use caliptra_common::mailbox_api::{VendorAuthHelloResp, VENDOR_AUTH_NONCE_SIZE};
use caliptra_drivers::{CaliptraError, CaliptraResult, Trng};
use zerocopy::IntoBytes;

/// Runtime state for vendor-unique command authentication.
#[derive(Default)]
pub struct VendorAuth {
    /// The last minted one-time nonce, consumed on the next VENDOR_AUTH_CHALLENGE.
    last_challenge: Option<[u8; VENDOR_AUTH_NONCE_SIZE]>,
}

impl VendorAuth {
    pub fn new() -> Self {
        Self {
            last_challenge: None,
        }
    }

    /// Handle VENDOR_AUTH_HELLO: mint a fresh one-time nonce, store it, and return it.
    pub fn handle_hello(
        &mut self,
        trng: &mut Trng,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // TRNG generate() yields an Array4x12 (48 bytes).
        let nonce: [u8; VENDOR_AUTH_NONCE_SIZE] = trng
            .generate()?
            .as_bytes()
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        self.last_challenge = Some(nonce);

        let resp = mutrefbytes::<VendorAuthHelloResp>(resp)?;
        *resp = VendorAuthHelloResp {
            hdr: Default::default(),
            challenge: nonce,
        };
        Ok(core::mem::size_of::<VendorAuthHelloResp>())
    }

    /// Consume and return the outstanding nonce, if any (one-time use).
    pub fn take_challenge(&mut self) -> Option<[u8; VENDOR_AUTH_NONCE_SIZE]> {
        self.last_challenge.take()
    }
}
