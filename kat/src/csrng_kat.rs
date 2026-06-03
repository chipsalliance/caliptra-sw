/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_kat.rs

Abstract:

    File contains the Known Answer Test (KAT) for the CSRNG / CTR_DRBG-AES-256
    hardware engine, using published NIST CAVP test vectors.

    The DRBG is briefly placed into fully-deterministic mode (`flag0=true`)
    with a fixed seed, exercised against the NIST vectors, and then restored
    to its production entropy-sourced state before this routine returns. It
    is therefore safe to invoke after the live `Trng` has been instantiated,
    e.g. as part of the boot-time KAT suite or an on-demand
    `FIPS_SELF_TEST` mailbox command.

    FIPS 140-3 IG 10.3.A requires CAST coverage for SP 800-90A
    Instantiate, Generate, and Reseed. The no-reseed and reseed sweeps below
    use CAVP vectors to cover those functions.

--*/

use caliptra_drivers::{CaliptraError, CaliptraResult, Csrng, CsrngSeed, Trng};

// NIST CAVP CTR_DRBG-AES-256 known-answer vector (no reseed)
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

// NIST CAVP CTR_DRBG-AES-256 known-answer vector (reseed, PR=False)
// =================================================================
// Source: NIST CAVP drbgvectors_pr_false.zip / CTR_DRBG.rsp,
// section [AES-256 no df], PredictionResistance = False,
// EntropyInputLen = 384, NonceLen = 0, PersonalizationStringLen = 0,
// AdditionalInputLen = 0, ReturnedBitsLen = 512, COUNT = 0.
//
//   EntropyInput       = e4bc23c5 089a19d8 6f4119cb 3fa08c0a 4991e0a1
//                        def17e10 1e4c14d9 c323460a 7c2fb58e 0b086c6c
//                        57b55f56 cae25bad
//   EntropyInputReseed = fd85a836 bba85019 881e8c6b ad23c906 1adc7547
//                        7659acae a8e4a01d fe07a183 2dad1c13 6f59d70f
//                        8653a5dc 118663d6
//   ReturnedBits       = b2cb8905 c05e5950 ca318950 96be29ea 3d5a3b82
//                        b2694955 54eb80fe 07de43e1 93b9e7c3 ece73b80
//                        e062b1c1 f68202fb b1c52a04 0ea24788 64295282
//                        234aaada
//
// The CAVP test schema for this section issues:
//   Instantiate(EntropyInput) ->
//   Reseed(EntropyInputReseed) ->
//   Generate(512 bits, discarded) ->
//   Generate(512 bits, compared to ReturnedBits).
// All AdditionalInput, AdditionalInputReseed, PersonalizationString and
// Nonce fields are empty for this vector.

// Reseed vector values use the same CMD_REQ and GENBITS endianness rules
// documented above.
const KAT_RESEED_INIT_SEED: [u32; 12] = [
    0xcae25bad, 0x57b55f56, 0x0b086c6c, 0x7c2fb58e, 0xc323460a, 0x1e4c14d9, 0xdef17e10, 0x4991e0a1,
    0x3fa08c0a, 0x6f4119cb, 0x089a19d8, 0xe4bc23c5,
];

const KAT_RESEED_RESEED_SEED: [u32; 12] = [
    0x118663d6, 0x8653a5dc, 0x6f59d70f, 0x2dad1c13, 0xfe07a183, 0xa8e4a01d, 0x7659acae, 0x1adc7547,
    0xad23c906, 0x881e8c6b, 0xbba85019, 0xfd85a836,
];

const KAT_RESEED_EXPECTED_OUTPUT: [u32; 16] = [
    0x96be29ea, 0xca318950, 0xc05e5950, 0xb2cb8905, 0x07de43e1, 0x54eb80fe, 0xb2694955, 0x3d5a3b82,
    0xf68202fb, 0xe062b1c1, 0xece73b80, 0x93b9e7c3, 0x234aaada, 0x64295282, 0x0ea24788, 0xb1c52a04,
];

#[derive(Default, Debug)]
pub struct CsrngKat {}

impl CsrngKat {
    /// Execute the CTR_DRBG-AES-256 known-answer tests against the live CSRNG
    /// instance backing the supplied [`Trng`].
    ///
    /// On `Trng::External` (verilator / no-CSRNG configuration) and
    /// `Trng::MfgMode` (debug-only fake RNG) this is a no-op since there is
    /// no CSRNG hardware to validate.
    ///
    /// On `Trng::Internal`, both the no-reseed and reseed sweeps are run.
    ///
    /// The DRBG is always re-instantiated from `EntropySrc` before
    /// returning, so production randomness is restored even if a KAT
    /// fails. The KAT failure (if any) is returned in preference to a
    /// restore failure so the caller sees the more meaningful diagnostic.
    pub fn execute(&self, trng: &mut Trng) -> CaliptraResult<()> {
        match trng {
            Trng::Internal(csrng) => {
                let kat_result = self.run(csrng).and_then(|_| self.run_reseed(csrng));
                let restore_result = csrng
                    .reinstantiate(CsrngSeed::EntropySrc)
                    .map_err(|_| CaliptraError::KAT_CSRNG_RESTORE_FAILURE);
                kat_result.and(restore_result)
            }
            _ => Ok(()),
        }
    }

    fn run(&self, csrng: &mut Csrng) -> CaliptraResult<()> {
        // Keep this hook local to the KAT so earlier CSRNG users report
        // their own errors.
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

        // CAVP vectors compare the second Generate output.
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

    fn run_reseed(&self, csrng: &mut Csrng) -> CaliptraResult<()> {
        // Keep this hook local to the KAT so production reseed users are
        // unaffected.
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            caliptra_drivers::FipsTestHook::error_if_hook_set(
                caliptra_drivers::FipsTestHook::CSRNG_RESEED_FAILURE,
            )
            .map_err(|_| CaliptraError::KAT_CSRNG_RESEED_FAILURE)?
        }

        csrng
            .reinstantiate(CsrngSeed::Constant(&KAT_RESEED_INIT_SEED))
            .map_err(|_| CaliptraError::KAT_CSRNG_INSTANTIATE_FAILURE)?;

        csrng
            .reseed(CsrngSeed::Constant(&KAT_RESEED_RESEED_SEED))
            .map_err(|_| CaliptraError::KAT_CSRNG_RESEED_FAILURE)?;

        // CAVP vectors compare the second Generate output.
        let _discard = csrng
            .generate16()
            .map_err(|_| CaliptraError::KAT_CSRNG_GENERATE_FAILURE)?;

        let output = csrng
            .generate16()
            .map_err(|_| CaliptraError::KAT_CSRNG_GENERATE_FAILURE)?;

        if output != KAT_RESEED_EXPECTED_OUTPUT {
            return Err(CaliptraError::KAT_CSRNG_DIGEST_MISMATCH);
        }

        Ok(())
    }
}
