/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_kat.rs

Abstract:

    File contains the Known Answer Test (KAT) for the CSRNG / CTR_DRBG-AES-256
    hardware engine, using a published NIST CAVP test vector.

    The DRBG is briefly placed into fully-deterministic mode (`flag0=true`)
    with a fixed seed, exercised against the NIST vector, and then restored
    to its production entropy-sourced state before this routine returns. It
    is therefore safe to invoke after the live `Trng` has been instantiated,
    e.g. as part of the boot-time KAT suite or an on-demand
    `FIPS_SELF_TEST` mailbox command.

--*/

use caliptra_drivers::{CaliptraError, CaliptraResult, Csrng, CsrngSeed, Trng};

// NIST CAVP CTR_DRBG-AES-256 known-answer vector
// =================================================================
// Source: NIST CAVP drbgvectors_no_reseed.zip / CTR_DRBG.rsp,
// section [AES-256 no df], PredictionResistance = False, EntropyInputLen
// = 384, NonceLen = 0, PersonalizationStringLen = 0, AdditionalInputLen
// = 0, ReturnedBitsLen = 512, COUNT = 0.
//
//   EntropyInput = df5d73fa a468649e dda33b5c ca79b0b0 5600419c cb7a879d
//                  dfec9db3 2ee494e5 531b51de 16a30f76 9262474c 73bec010
//   ReturnedBits = d1c07cd9 5af8a7f1 1012c84c e48bb8cb 87189e99 d40fccb1
//                  771c619b df82ab22 80b1dc2f 2581f391 64f7ac0c 510494b3
//                  a43c41b7 db17514c 87b107ae 793e01c5
//
// The CAVP test schema for this section issues Instantiate(EntropyInput),
// then Generate(512 bits) twice; the first Generate output is discarded
// (per the two consecutive `AdditionalInput = ` lines preceding
// `ReturnedBits`) and the second Generate output is the published
// ReturnedBits.

// `KAT_SEED` is `EntropyInput` repacked for the CSRNG `CMD_REQ` register.
// Per the OpenTitan CSRNG programmer's guide, additional-data bytes
// B1..Bn (NIST big-endian byte string, B1 most significant) are written
// as Word 1 = (Bn-3 Bn-2 Bn-1 Bn), ..., Word n/4 = (B1 B2 B3 B4): each
// 4-byte chunk packed big-endian, then the word order reversed.
const KAT_SEED: [u32; 12] = [
    0x73bec010, 0x9262474c, 0x16a30f76, 0x531b51de, 0x2ee494e5, 0xdfec9db3, 0xcb7a879d, 0x5600419c,
    0xca79b0b0, 0xdda33b5c, 0xa468649e, 0xdf5d73fa,
];

// `EXPECTED_OUTPUT` is `ReturnedBits` repacked in the order the CSRNG
// presents them on consecutive `GENBITS` reads. Per the OT programmer's
// guide, each 128-bit GENBITS block returns 4 words LSB-word first:
// for B1..B16 of a block, the four words are
// (B13 B14 B15 B16), (B9 B10 B11 B12), (B5 B6 B7 B8), (B1 B2 B3 B4).
// Block 1 of the byte string occupies words 0..3, block 2 words 4..7, etc.
const EXPECTED_OUTPUT: [u32; 16] = [
    0xe48bb8cb, 0x1012c84c, 0x5af8a7f1, 0xd1c07cd9, 0xdf82ab22, 0x771c619b, 0xd40fccb1, 0x87189e99,
    0x510494b3, 0x64f7ac0c, 0x2581f391, 0x80b1dc2f, 0x793e01c5, 0x87b107ae, 0xdb17514c, 0xa43c41b7,
];

#[derive(Default, Debug)]
pub struct CsrngKat {}

impl CsrngKat {
    /// Execute the CTR_DRBG-AES-256 known-answer test against the live CSRNG
    /// instance backing the supplied [`Trng`].
    ///
    /// On `Trng::External` (verilator / no-CSRNG configuration) and
    /// `Trng::MfgMode` (debug-only fake RNG) this is a no-op since there is
    /// no CSRNG hardware to validate.
    ///
    /// On `Trng::Internal` the routine:
    ///
    /// 1. Re-instantiates the DRBG with the deterministic [`KAT_SEED`]
    ///    (`flag0=true`, fully-deterministic mode).
    /// 2. Issues two 512-bit Generate commands; the first output is
    ///    discarded per NIST CAVP convention and the second is compared to
    ///    [`EXPECTED_OUTPUT`].
    /// 3. Always re-instantiates the DRBG from `EntropySrc` before
    ///    returning, so production randomness is restored even if the KAT
    ///    fails. The KAT failure (if any) is returned in preference to a
    ///    restore failure so the caller sees the more meaningful diagnostic.
    pub fn execute(&self, trng: &mut Trng) -> CaliptraResult<()> {
        match trng {
            Trng::Internal(csrng) => {
                let kat_result = self.run(csrng);
                let restore_result = csrng
                    .reinstantiate(CsrngSeed::EntropySrc)
                    .map_err(|_| CaliptraError::KAT_CSRNG_RESTORE_FAILURE);
                kat_result.and(restore_result)
            }
            _ => Ok(()),
        }
    }

    fn run(&self, csrng: &mut Csrng) -> CaliptraResult<()> {
        // Fault-injection hook: simulate a CSRNG generate failure inside the
        // KAT only. We cannot put this hook inside `Csrng::generate16` /
        // `Csrng::generate12` because the CSRNG is used for CFI counter
        // seeding before this KAT runs; injecting an error there would be
        // caught by `CfiCounter::reset` and surface as
        // `CfiPanicInfo::TrngError` instead of as the expected
        // `KAT_CSRNG_GENERATE_FAILURE`.
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            caliptra_drivers::FipsTestHook::error_if_hook_set(
                caliptra_drivers::FipsTestHook::CSRNG_GENERATE_FAILURE,
            )
            .map_err(|_| CaliptraError::KAT_CSRNG_GENERATE_FAILURE)?
        }

        csrng
            .reinstantiate(CsrngSeed::Constant(&KAT_SEED))
            .map_err(|_| CaliptraError::KAT_CSRNG_INSTANTIATE_FAILURE)?;

        // First Generate is discarded per the NIST CAVP CTR_DRBG validation
        // schema: the published `ReturnedBits` is the output of the second
        // Generate after Instantiate.
        let _discard = csrng
            .generate16()
            .map_err(|_| CaliptraError::KAT_CSRNG_GENERATE_FAILURE)?;

        let output = csrng
            .generate16()
            .map_err(|_| CaliptraError::KAT_CSRNG_GENERATE_FAILURE)?;

        if output != EXPECTED_OUTPUT {
            return Err(CaliptraError::KAT_CSRNG_DIGEST_MISMATCH);
        }

        Ok(())
    }
}
