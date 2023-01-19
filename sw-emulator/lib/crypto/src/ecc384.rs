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
        sig.r.copy_from_slice(ecc_sig.r().to_be_bytes().as_slice());
        sig.s.copy_from_slice(ecc_sig.s().to_be_bytes().as_slice());
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
    pub fn gen_key_pair(seed: &Ecc384Scalar) -> (Ecc384PrivKey, Ecc384PubKey) {
        let mut priv_key = [0u8; ECC_384_COORD_SIZE];

        // Seed is received as a list of big-endian DWORDs. Changing them to little-endian.
        // The received DOWRD list is also reversed from what is expected. Un-reversing the list.
        let mut seed_reversed = seed.clone();
        seed_reversed.reverse();

        let mut drbg = HmacDrbg::<Sha384>::new(&[], &[], &seed_reversed);
        drbg.fill_bytes(&mut priv_key);
        let signing_key = SigningKey::from_bytes(&priv_key).unwrap();
        let verifying_key = signing_key.verifying_key();
        let ecc_point = verifying_key.to_encoded_point(false);

        let mut pub_key: Ecc384PubKey = ecc_point.into();

        // Changing the DWORD endianess of the private and public keys to big-endian.
        // Also reversing the order of the DWORDs.
        priv_key.reverse();
        pub_key.x.reverse();
        pub_key.y.reverse();

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
        // The received DOWRD lists are also reversed from what is expected. Un-reversing the lists.
        let mut priv_key_reversed = priv_key.clone();
        let mut hash_reversed = hash.clone();
        priv_key_reversed.reverse();
        hash_reversed.reverse();

        let signing_key = SigningKey::from_bytes(&priv_key_reversed).unwrap();
        let ecc_sig = signing_key.sign_prehash(&hash_reversed).unwrap();

        let mut signature: Ecc384Signature = ecc_sig.into();

        // Changing the DWORD endianess of the signature to big-endian.
        // Also reversing the order of the DWORDs.
        signature.r.reverse();
        signature.s.reverse();
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
        // The received DOWRD lists are also reversed from what is expected. Un-reversing the lists.
        let mut pub_key_reversed = pub_key.clone();
        pub_key_reversed.x.reverse();
        pub_key_reversed.y.reverse();

        let mut hash_reversed = hash.clone();
        hash_reversed.reverse();

        let mut signature_reversed = signature.clone();
        signature_reversed.r.reverse();
        signature_reversed.s.reverse();

        let verifying_key = VerifyingKey::from_encoded_point(&pub_key_reversed.into()).unwrap();
        let result = verifying_key.verify_prehash(&hash_reversed, &signature_reversed.into());
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
        0xc9, 0x8, 0x58, 0x5a, 0x48, 0x6c, 0x3b, 0x3d, 0x8b, 0xbe, 0x50, 0xeb, 0x7d, 0x2e, 0xb8,
        0xa0, 0x3a, 0xa0, 0x4e, 0x3d, 0x8b, 0xde, 0x2c, 0x31, 0xa8, 0xa2, 0xa1, 0xe3, 0x34, 0x9d,
        0xc2, 0x1c, 0xbb, 0xe6, 0xc9, 0xa, 0xe2, 0xf7, 0x49, 0x12, 0x88, 0x84, 0xb6, 0x22, 0xbb,
        0x72, 0xb4, 0xc5,
    ];

    const PUB_KEY_X: [u8; 48] = [
        0x9, 0x82, 0x33, 0xca, 0x56, 0x7a, 0x3f, 0x14, 0xbe, 0x78, 0x49, 0x4, 0xc6, 0x92, 0x1d,
        0x43, 0x3b, 0x4f, 0x85, 0x3a, 0x52, 0x37, 0x42, 0xe4, 0xbc, 0x98, 0x76, 0x7e, 0x23, 0xca,
        0x3d, 0xa6, 0x65, 0x6b, 0xec, 0x46, 0xa7, 0xb1, 0x11, 0x9e, 0x63, 0xd2, 0x66, 0xca, 0x62,
        0x54, 0x97, 0x7f,
    ];

    const PUB_KEY_Y: [u8; 48] = [
        0x75, 0xd0, 0xb4, 0x1, 0xc8, 0xba, 0xc3, 0x9a, 0xc5, 0xfb, 0xf, 0x2b, 0x3b, 0x95, 0x37,
        0x2c, 0x41, 0xd9, 0xde, 0x40, 0x55, 0xfd, 0xdb, 0x6, 0xf7, 0x48, 0x49, 0x74, 0x8d, 0xa,
        0xed, 0x85, 0x9b, 0x65, 0x50, 0xca, 0x75, 0xc, 0x3c, 0xd1, 0x18, 0x51, 0xe0, 0x50, 0xbb,
        0x7d, 0x20, 0xb2,
    ];

    const SIGNATURE_R: [u8; 48] = [
        0x36, 0xf8, 0x50, 0x14, 0x6f, 0x40, 0x4, 0x43, 0x84, 0x8c, 0xae, 0x3, 0x57, 0x59, 0x10,
        0x32, 0xe6, 0xa3, 0x95, 0xde, 0x66, 0xe7, 0x26, 0x1a, 0x3, 0x80, 0x49, 0xfb, 0xee, 0x15,
        0xdb, 0x19, 0x5d, 0xbd, 0x97, 0x86, 0x94, 0x39, 0x29, 0x2a, 0x4f, 0x57, 0x92, 0xe4, 0x3a,
        0x12, 0x31, 0xb7,
    ];

    const SIGNATURE_S: [u8; 48] = [
        0xee, 0xea, 0x42, 0x94, 0x82, 0xfd, 0x8f, 0xa9, 0xd4, 0xd5, 0xf9, 0x60, 0xa0, 0x9e, 0xdf,
        0xa6, 0xc7, 0x65, 0xef, 0xe5, 0xff, 0x4c, 0x17, 0xa5, 0x12, 0xe6, 0x94, 0xfa, 0xcc, 0x45,
        0xd3, 0xf6, 0xfc, 0x3d, 0x3b, 0x5c, 0x62, 0x73, 0x9c, 0x1f, 0xb, 0x9f, 0xca, 0xe3, 0x26,
        0xf5, 0x4b, 0x43,
    ];

    #[test]
    fn test_gen_key_pair() {
        let mut seed = [0u8; 48];
        seed.reverse();
        let (mut priv_key, mut pub_key) = Ecc384::gen_key_pair(&seed);
        priv_key.reverse();
        pub_key.x.reverse();
        pub_key.y.reverse();
        assert_eq!(priv_key, PRIV_KEY);
        assert_eq!(pub_key.x, PUB_KEY_X);
        assert_eq!(pub_key.y, PUB_KEY_Y);
    }

    #[test]
    fn test_sign() {
        let hash = [0u8; 48];
        let mut priv_key = PRIV_KEY.clone();
        priv_key.reverse();

        let mut signature = Ecc384::sign(&priv_key, &hash);

        signature.r.reverse();
        signature.s.reverse();

        assert_eq!(signature.r, SIGNATURE_R);
        assert_eq!(signature.s, SIGNATURE_S);
    }

    #[test]
    fn test_verify() {
        let hash = [0u8; 48];
        let mut priv_key = PRIV_KEY.clone();
        priv_key.reverse();

        let mut signature = Ecc384::sign(&priv_key, &hash);

        let mut pub_key_x = PUB_KEY_X.clone();
        let mut pub_key_y = PUB_KEY_Y.clone();

        pub_key_x.reverse();
        pub_key_y.reverse();

        let pub_key = Ecc384PubKey {
            x: pub_key_x,
            y: pub_key_y,
        };
        let mut r = Ecc384::verify(&pub_key, &hash, &signature);
        r.reverse();
        signature.r.reverse();
        assert_eq!(r, signature.r)
    }

    #[test]
    fn test_verify_fail() {
        let hash = [0u8; 48];
        let mut priv_key = PRIV_KEY.clone();
        priv_key.reverse();

        let mut signature = Ecc384::sign(&priv_key, &hash);

        let mut pub_key_x = PUB_KEY_X.clone();
        let mut pub_key_y = PUB_KEY_Y.clone();

        pub_key_x.reverse();
        pub_key_y.reverse();

        let pub_key = Ecc384PubKey {
            x: pub_key_x,
            y: pub_key_y,
        };

        let hash = [0xFFu8; 48];
        let mut r = Ecc384::verify(&pub_key, &hash, &signature);

        r.reverse();
        signature.r.reverse();
        assert_ne!(r, signature.r)
    }
}
