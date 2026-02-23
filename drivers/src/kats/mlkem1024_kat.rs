/*++

Licensed under the Apache-2.0 license.

File Name:

    mlkem1024_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for MLKEM1024 cryptography operations.
    Uses SHA-512 digests of outputs instead of full test vectors to save space.

--*/

use crate::{
    cprintln, Array4x16, CaliptraError, CaliptraResult, LEArray4x8, MlKem1024,
    MlKem1024MessageSource, MlKem1024Seeds, MlKem1024SharedKey, MlKem1024SharedKeyOut,
    Sha2_512_384,
};
use caliptra_registers::sha512::Sha512Reg;
use zerocopy::IntoBytes;

// Keygen seeds from NIST test vectors:
// https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json

const KEYGEN_SEED_Z: LEArray4x8 = LEArray4x8::new([
    0x6C4D060A, 0x73ABCE06, 0xA9FC9CE5, 0x250264FF, 0xEF6A325A, 0x78B69C1E, 0x9D9236BF, 0x589AE2AF,
]);

const KEYGEN_SEED_D: LEArray4x8 = LEArray4x8::new([
    0xC430532B, 0xFDFD3BF2, 0x50F0315C, 0x23383BBA, 0x03BF2453, 0x12FC7223, 0x89D04DD0, 0x59BDF020,
]);

const ENCAPS_M: LEArray4x8 = LEArray4x8::new([
    0x92CF9981, 0x2621E13C, 0x56080192, 0xF9CB119C, 0x443FF07C, 0x7DFA5CAF, 0x2A9B0E55, 0x821943C7,
]);

// SHA-512 digests of outputs, computed from the NIST keygen seeds above.
// Compare digests instead of full vectors to save space.
//
// These digests were verified using the RustCrypto `ml-kem` (v0.2) and `sha2`
// (v0.10) crates: keygen from (d, z), encaps with the derived EK and message m,
// and decaps with the derived DK all produce outputs whose SHA-512 hashes match
// the values below.

const KAT_EK_DIGEST: Array4x16 = Array4x16::new([
    0x230EE181, 0x103A4357, 0xDC8C770B, 0xE08BE4E8, 0xC32B8542, 0x301DD44F, 0x689597A2, 0xBA5B385E,
    0xF5D69597, 0x4CEC08D3, 0xFD884FDE, 0x0712DA7A, 0x50AAB225, 0xFFBEB282, 0x04539050, 0x0301D6F3,
]);

const KAT_DK_DIGEST: Array4x16 = Array4x16::new([
    0xB2F51D96, 0xA03B8F7E, 0xC5368330, 0x767591E9, 0x5BCC6883, 0x11E4DA68, 0xB5CDB2D3, 0x565ECB91,
    0x2DE3969B, 0xD7B16243, 0x74434ABE, 0xB329263B, 0x39A35D02, 0x7753ACD5, 0xCA0880E9, 0xBD2E3368,
]);

const KAT_CT_DIGEST: Array4x16 = Array4x16::new([
    0x857D17AC, 0x4D0A19C9, 0x2C8BB4EE, 0x8AD1E364, 0xDF8F7DD9, 0x707A9C97, 0x84EAA359, 0x53F11D80,
    0xA49D81A0, 0x111256DC, 0x3B992E4D, 0xADAFE862, 0xA4C8CB06, 0x55B67DD6, 0x384E504F, 0x8604B753,
]);

const KAT_SK_DIGEST: Array4x16 = Array4x16::new([
    0x8A0C1713, 0x45B885B9, 0xE11A7E63, 0x026178E8, 0x529282FA, 0xEFFA790F, 0xA5AB2B25, 0x88399494,
    0x51FD3214, 0xD686BB49, 0x76432EC1, 0x2B40DE7E, 0x4E68A595, 0x260B7E9E, 0x5B7A522B, 0x4D0F05AA,
]);

pub fn execute_mlkem1024_kat(mlkem: &mut MlKem1024) -> CaliptraResult<()> {
    cprintln!("[kat] MLKEM1024");
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };

    kat_keygen_encaps_decaps(mlkem, &mut sha2)?;
    Ok(())
}

fn kat_keygen_encaps_decaps(mlkem: &mut MlKem1024, sha2: &mut Sha2_512_384) -> CaliptraResult<()> {
    // Generate keypair from seeds
    let seeds = MlKem1024Seeds::Arrays(&KEYGEN_SEED_D, &KEYGEN_SEED_Z);
    let (ek, dk) = mlkem
        .key_pair(seeds)
        .map_err(|_| CaliptraError::KAT_MLKEM1024_KEY_PAIR_GENERATE_FAILURE)?;

    // Verify keygen outputs via SHA-512 digests
    let ek_digest = sha2
        .sha512_digest(ek.as_bytes())
        .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;
    let dk_digest = sha2
        .sha512_digest(dk.as_bytes())
        .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

    if ek_digest != KAT_EK_DIGEST || dk_digest != KAT_DK_DIGEST {
        Err(CaliptraError::KAT_MLKEM1024_KEY_PAIR_VERIFY_FAILURE)?;
    }

    // Encapsulate using the generated EK
    let mut shared_key_enc = MlKem1024SharedKey::default();
    let ciphertext = mlkem
        .encapsulate(
            &ek,
            MlKem1024MessageSource::Array(&ENCAPS_M),
            MlKem1024SharedKeyOut::Array(&mut shared_key_enc),
        )
        .map_err(|_| CaliptraError::KAT_MLKEM1024_ENCAPSULATE_FAILURE)?;

    // Verify encapsulation outputs via SHA-512 digests
    let ct_digest = sha2
        .sha512_digest(ciphertext.as_bytes())
        .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;
    let sk_enc_digest = sha2
        .sha512_digest(shared_key_enc.as_bytes())
        .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

    if ct_digest != KAT_CT_DIGEST {
        Err(CaliptraError::KAT_MLKEM1024_CIPHERTEXT_MISMATCH)?;
    }

    if sk_enc_digest != KAT_SK_DIGEST {
        Err(CaliptraError::KAT_MLKEM1024_SHARED_KEY_MISMATCH)?;
    }

    // Decapsulate and verify shared key matches
    let mut shared_key_dec = MlKem1024SharedKey::default();
    mlkem
        .decapsulate(
            &dk,
            &ciphertext,
            MlKem1024SharedKeyOut::Array(&mut shared_key_dec),
        )
        .map_err(|_| CaliptraError::KAT_MLKEM1024_DECAPSULATE_FAILURE)?;

    if shared_key_dec != shared_key_enc {
        Err(CaliptraError::KAT_MLKEM1024_SHARED_KEY_MISMATCH)?;
    }

    Ok(())
}
