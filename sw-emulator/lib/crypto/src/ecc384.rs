/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384.rs

Abstract:

    File contains implementation of Elliptic Curve Cryptography P-384 (ECC-384) Algorithm.

--*/

use p384::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::EncodedPoint;
use rfc6979::HmacDrbg;
use sha2::digest::generic_array::GenericArray;
use sha2::Sha384;

use crate::EndianessTransform;

/// ECC-384 coordinate size in bytes
pub const ECC_384_COORD_SIZE: usize = 48;

/// ECC-384 Coordinate
pub type Ecc384Scalar = [u8; ECC_384_COORD_SIZE];

/// ECC-384 Private Key
pub type Ecc384PrivKey = Ecc384Scalar;

/// ECC-384 Public Key
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384PubKey {
    /// X coordinate
    pub x: Ecc384Scalar,

    /// Y coordinate
    pub y: Ecc384Scalar,
}

impl Default for Ecc384PubKey {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            x: [0u8; ECC_384_COORD_SIZE],
            y: [0u8; ECC_384_COORD_SIZE],
        }
    }
}

impl From<EncodedPoint> for Ecc384PubKey {
    /// Converts to this type from the input type.
    fn from(point: EncodedPoint) -> Self {
        let mut pub_key = Self::default();
        pub_key.x.copy_from_slice(point.x().unwrap());
        pub_key.y.copy_from_slice(point.y().unwrap());
        pub_key
    }
}

impl From<&mut Ecc384PubKey> for EncodedPoint {
    /// Converts to this type from the input type.
    fn from(key: &mut Ecc384PubKey) -> Self {
        EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&key.x),
            GenericArray::from_slice(&key.y),
            false,
        )
    }
}

impl From<Ecc384PubKey> for EncodedPoint {
    /// Converts to this type from the input type.
    fn from(key: Ecc384PubKey) -> Self {
        EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&key.x),
            GenericArray::from_slice(&key.y),
            false,
        )
    }
}

/// ECC-384 Signature
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Ecc384Signature {
    /// Random point
    pub r: Ecc384Scalar,

    /// Proof
    pub s: Ecc384Scalar,
}

impl Default for Ecc384Signature {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            r: [0u8; ECC_384_COORD_SIZE],
            s: [0u8; ECC_384_COORD_SIZE],
        }
    }
}

impl From<Signature> for Ecc384Signature {
    /// Converts to this type from the input type.
    fn from(ecc_sig: Signature) -> Self {
        let mut sig = Self::default();
        sig.r.copy_from_slice(ecc_sig.r().to_bytes().as_slice());
        sig.s.copy_from_slice(ecc_sig.s().to_bytes().as_slice());
        sig
    }
}

impl From<&mut Ecc384Signature> for Signature {
    /// Converts to this type from the input type.
    fn from(signature: &mut Ecc384Signature) -> Self {
        Signature::from_scalars(
            GenericArray::clone_from_slice(&signature.r),
            GenericArray::clone_from_slice(&signature.s),
        )
        .unwrap()
    }
}

impl From<Ecc384Signature> for Signature {
    /// Converts to this type from the input type.
    fn from(signature: Ecc384Signature) -> Self {
        Signature::from_scalars(
            GenericArray::clone_from_slice(&signature.r),
            GenericArray::clone_from_slice(&signature.s),
        )
        .unwrap()
    }
}

pub enum Ecc384 {}

impl Ecc384 {
    /// Generate a deterministic ECC private & public key pair based on the ssed
    ///
    /// # Arguments
    ///
    /// * `Seed` - The seed used to derive the deterministic key
    ///
    /// # Result
    ///
    /// *  (Ecc384PrivKey, Ecc384PubKey) - Private & public key pair
    pub fn gen_key_pair(
        seed: &Ecc384Scalar,
        nonce: &Ecc384Scalar,
    ) -> (Ecc384PrivKey, Ecc384PubKey) {
        let mut priv_key = [0u8; ECC_384_COORD_SIZE];

        // Seed is received as a list of big-endian DWORDs. Changing them to little-endian.
        let mut seed_reversed = *seed;
        seed_reversed.to_little_endian();

        // Nonce is received as a list of big-endian DWORDs. Changing them to little-endian.
        let mut nonce_reversed = *nonce;
        nonce_reversed.to_little_endian();

        let mut drbg = HmacDrbg::<Sha384>::new(&seed_reversed, &nonce_reversed, &[]);
        drbg.fill_bytes(&mut priv_key);
        let signing_key = SigningKey::from_slice(&priv_key).unwrap();
        let verifying_key = signing_key.verifying_key();
        let ecc_point = verifying_key.to_encoded_point(false);

        let mut pub_key: Ecc384PubKey = ecc_point.into();

        // Changing the DWORD endianess of the private and public keys to big-endian.
        priv_key.to_big_endian();
        pub_key.x.to_big_endian();
        pub_key.y.to_big_endian();

        (priv_key, pub_key)
    }

    /// Sign the hash with specified private key
    ///
    /// # Arguments
    ///
    /// * `priv_key` - Private key
    /// * `hash` - Hash to sign
    ///
    /// # Result
    ///
    /// *  Ecc384Signature - Signature
    pub fn sign(priv_key: &Ecc384PrivKey, hash: &Ecc384Scalar) -> Ecc384Signature {
        // Private key and hash are received as a list of big-endian DWORDs. Changing them to little-endian.
        let mut priv_key_reversed = *priv_key;
        let mut hash_reversed = *hash;
        priv_key_reversed.to_little_endian();
        hash_reversed.to_little_endian();

        let signing_key = SigningKey::from_slice(&priv_key_reversed).unwrap();
        let ecc_sig: Signature = signing_key.sign_prehash(&hash_reversed).unwrap();

        let mut signature: Ecc384Signature = ecc_sig.into();

        // Changing the DWORD endianess of the signature to big-endian.
        signature.r.to_big_endian();
        signature.s.to_big_endian();
        signature
    }

    /// Verify the signature
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key
    /// * `hash` - Hash to sign
    /// * `signature` - Signature to verify
    ///
    /// # Result
    ///
    /// *  Ecc384Scalar - The 'r' value from signature verification calculation
    pub fn verify(
        pub_key: &Ecc384PubKey,
        hash: &Ecc384Scalar,
        signature: &Ecc384Signature,
    ) -> Ecc384Scalar {
        // Public key, hash and signature are received as a list of big-endian DWORDs. Changing them to little-endian.
        let mut pub_key_reversed = *pub_key;
        pub_key_reversed.x.to_little_endian();
        pub_key_reversed.y.to_little_endian();

        let mut hash_reversed = *hash;
        hash_reversed.to_little_endian();

        let mut signature_reversed = *signature;
        signature_reversed.r.to_little_endian();
        signature_reversed.s.to_little_endian();

        let verifying_key = VerifyingKey::from_encoded_point(&pub_key_reversed.into()).unwrap();
        let result =
            verifying_key.verify_prehash(&hash_reversed, &Signature::from(signature_reversed));
        if result.is_ok() {
            signature.r
        } else {
            // Note: We do not have access to the failed 'r'. Hence we reverse the original 'r'
            // value and flip the bits of each byte. This implementation should be good for
            // emulating the ECC-384 hardware
            let mut r = signature.r;
            r.iter_mut().for_each(|r| *r = !*r);
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV_KEY: [u8; 48] = [
        0xF2, 0x74, 0xF6, 0x9D, 0x16, 0x3B, 0x0C, 0x9F, 0x1F, 0xC3, 0xEB, 0xF4, 0x29, 0x2A, 0xD1,
        0xC4, 0xEB, 0x3C, 0xEC, 0x1C, 0x5A, 0x7D, 0xDE, 0x6F, 0x80, 0xC1, 0x42, 0x92, 0x93, 0x4C,
        0x20, 0x55, 0xE0, 0x87, 0x74, 0x8D, 0x0A, 0x16, 0x9C, 0x77, 0x24, 0x83, 0xAD, 0xEE, 0x5E,
        0xE7, 0x0E, 0x17,
    ];

    const PUB_KEY_X: [u8; 48] = [
        0xD7, 0x9C, 0x6D, 0x97, 0x2B, 0x34, 0xA1, 0xDF, 0xC9, 0x16, 0xA7, 0xB6, 0xE0, 0xA9, 0x9B,
        0x6B, 0x53, 0x87, 0xB3, 0x4D, 0xA2, 0x18, 0x76, 0x07, 0xC1, 0xAD, 0x0A, 0x4D, 0x1A, 0x8C,
        0x2E, 0x41, 0x72, 0xAB, 0x5F, 0xA5, 0xD9, 0xAB, 0x58, 0xFE, 0x45, 0xE4, 0x3F, 0x56, 0xBB,
        0xB6, 0x6B, 0xA4,
    ];

    const PUB_KEY_Y: [u8; 48] = [
        0x5A, 0x73, 0x63, 0x93, 0x2B, 0x06, 0xB4, 0xF2, 0x23, 0xBE, 0xF0, 0xB6, 0x0A, 0x63, 0x90,
        0x26, 0x51, 0x12, 0xDB, 0xBD, 0x0A, 0xAE, 0x67, 0xFE, 0xF2, 0x6B, 0x46, 0x5B, 0xE9, 0x35,
        0xB4, 0x8E, 0x45, 0x1E, 0x68, 0xD1, 0x6F, 0x11, 0x18, 0xF2, 0xB3, 0x2B, 0x4C, 0x28, 0x60,
        0x87, 0x49, 0xED,
    ];

    const SEED: [u8; 48] = [
        0x8F, 0xA8, 0x54, 0x1C, 0x82, 0xA3, 0x92, 0xCA, 0x74, 0xF2, 0x3E, 0xD1, 0xDB, 0xFD, 0x73,
        0x54, 0x1C, 0x59, 0x66, 0x39, 0x1B, 0x97, 0xEA, 0x73, 0xD7, 0x44, 0xB0, 0xE3, 0x4B, 0x9D,
        0xF5, 0x9E, 0xD0, 0x15, 0x80, 0x63, 0xE3, 0x9C, 0x09, 0xA5, 0xA0, 0x55, 0x37, 0x1E, 0xDF,
        0x7A, 0x54, 0x41,
    ];

    const NONCE: [u8; 48] = [
        0x1B, 0x7E, 0xC5, 0xE5, 0x48, 0xE8, 0xAA, 0xA9, 0x2E, 0xC7, 0x70, 0x97, 0xCA, 0x95, 0x51,
        0xC9, 0x78, 0x3C, 0xE6, 0x82, 0xCA, 0x18, 0xFB, 0x1E, 0xDB, 0xD9, 0xF1, 0xE5, 0x0B, 0xC3,
        0x82, 0xDB, 0x8A, 0xB3, 0x94, 0x96, 0xC8, 0xEE, 0x42, 0x3F, 0x8C, 0xA1, 0x05, 0xCB, 0xBA,
        0x7B, 0x65, 0x88,
    ];

    const SIGNATURE_R: [u8; 48] = [
        0x87, 0x1E, 0x6E, 0xA4, 0xDD, 0xC5, 0x43, 0x2C, 0xDD, 0xAA, 0x60, 0xFD, 0x7F, 0x05, 0x54,
        0x72, 0xD3, 0xC4, 0xDD, 0x41, 0xA5, 0xBF, 0xB2, 0x67, 0x09, 0xE8, 0x8C, 0x31, 0x1A, 0x97,
        0x09, 0x35, 0x99, 0xA7, 0xC8, 0xF5, 0x5B, 0x39, 0x74, 0xC1, 0x9E, 0x4F, 0x5A, 0x7B, 0xFC,
        0x1D, 0xD2, 0xAC,
    ];

    const MESSAGE: [u8; 48] = [
        0xC8, 0xF5, 0x18, 0xD4, 0xF3, 0xAA, 0x1B, 0xD4, 0x6E, 0xD5, 0x6C, 0x1C, 0x3C, 0x9E, 0x16,
        0xFB, 0x80, 0x0A, 0xF5, 0x04, 0xDB, 0x98, 0x84, 0x35, 0x48, 0xC5, 0xF6, 0x23, 0xEE, 0x11,
        0x5F, 0x73, 0xD4, 0xC6, 0x2A, 0xBC, 0x06, 0xD3, 0x03, 0xB5, 0xD9, 0x0D, 0x9A, 0x17, 0x50,
        0x87, 0x29, 0x0D,
    ];

    const SIGNATURE_S: [u8; 48] = [
        0x3E, 0x55, 0x52, 0xDE, 0x64, 0x03, 0x35, 0x0E, 0xE7, 0x0A, 0xD7, 0x4E, 0x4B, 0x85, 0x4D,
        0x2D, 0xC4, 0x12, 0x6B, 0xBF, 0x9C, 0x15, 0x3A, 0x5D, 0x7A, 0x07, 0xBD, 0x4B, 0x85, 0xD0,
        0x6E, 0x45, 0xF8, 0x50, 0x92, 0x0E, 0x89, 0x8F, 0xB7, 0xD3, 0x4F, 0x80, 0x79, 0x6D, 0xAE,
        0x29, 0x36, 0x5C,
    ];

    #[test]
    fn test_gen_key_pair() {
        let mut seed = SEED;
        seed.to_big_endian();
        let mut nonce = NONCE;
        nonce.to_big_endian();
        let (mut priv_key, mut pub_key) = Ecc384::gen_key_pair(&seed, &nonce);
        priv_key.to_little_endian();
        pub_key.x.to_little_endian();
        pub_key.y.to_little_endian();
        assert_eq!(priv_key, PRIV_KEY);
        assert_eq!(pub_key.x, PUB_KEY_X);
        assert_eq!(pub_key.y, PUB_KEY_Y);
    }

    #[test]
    fn test_sign() {
        let mut hash = MESSAGE;
        hash.to_big_endian();
        let mut priv_key = PRIV_KEY;
        priv_key.to_big_endian();

        let mut signature = Ecc384::sign(&priv_key, &hash);

        signature.r.to_little_endian();
        signature.s.to_little_endian();

        assert_eq!(signature.r, SIGNATURE_R);
        assert_eq!(signature.s, SIGNATURE_S);
    }

    #[test]
    fn test_verify() {
        let hash = [0u8; 48];
        let mut priv_key = PRIV_KEY;
        priv_key.to_big_endian();

        let mut signature = Ecc384::sign(&priv_key, &hash);

        let mut pub_key_x = PUB_KEY_X;
        let mut pub_key_y = PUB_KEY_Y;

        pub_key_x.to_big_endian();
        pub_key_y.to_big_endian();

        let pub_key = Ecc384PubKey {
            x: pub_key_x,
            y: pub_key_y,
        };
        let mut r = Ecc384::verify(&pub_key, &hash, &signature);
        r.to_little_endian();
        signature.r.to_little_endian();
        assert_eq!(r, signature.r)
    }

    #[test]
    fn test_verify_fail() {
        let hash = [0u8; 48];
        let mut priv_key = PRIV_KEY;
        priv_key.to_big_endian();

        let mut signature = Ecc384::sign(&priv_key, &hash);

        let mut pub_key_x = PUB_KEY_X;
        let mut pub_key_y = PUB_KEY_Y;

        pub_key_x.to_big_endian();
        pub_key_y.to_big_endian();

        let pub_key = Ecc384PubKey {
            x: pub_key_x,
            y: pub_key_y,
        };

        let hash = [0xFFu8; 48];
        let mut r = Ecc384::verify(&pub_key, &hash, &signature);

        r.to_little_endian();
        signature.r.to_little_endian();
        assert_ne!(r, signature.r)
    }
}
