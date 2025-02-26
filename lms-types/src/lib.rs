// Licensed under the Apache-2.0 license

// TODO not(fuzzing), attribute not found
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::Launder;
use core::mem::size_of;
#[cfg(feature = "std")]
use core::mem::size_of_val;
#[cfg(feature = "std")]
use serde::de::{self, Deserialize, Deserializer, Expected, MapAccess, Visitor};
use zerocopy::{
    BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian, Unaligned, U32,
};
use zeroize::Zeroize;

pub type LmsIdentifier = [u8; 16];

macro_rules! static_assert {
    ($expression:expr) => {
        const _: () = assert!($expression);
    };
}

#[repr(transparent)]
#[derive(
    IntoBytes,
    FromBytes,
    Copy,
    Clone,
    Debug,
    KnownLayout,
    Immutable,
    Unaligned,
    Default,
    PartialEq,
    Eq,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LmsAlgorithmType(pub U32<BigEndian>);
impl LmsAlgorithmType {
    #![allow(non_upper_case_globals)]

    pub const fn new(val: u32) -> Self {
        Self(U32::from_bytes(val.to_be_bytes()))
    }
    pub const LmsReserved: Self = Self::new(0);
    pub const LmsSha256N32H5: Self = Self::new(5);
    pub const LmsSha256N32H10: Self = Self::new(6);
    pub const LmsSha256N32H15: Self = Self::new(7);
    pub const LmsSha256N32H20: Self = Self::new(8);
    pub const LmsSha256N32H25: Self = Self::new(9);
    pub const LmsSha256N24H5: Self = Self::new(10);
    pub const LmsSha256N24H10: Self = Self::new(11);
    pub const LmsSha256N24H15: Self = Self::new(12);
    pub const LmsSha256N24H20: Self = Self::new(13);
    pub const LmsSha256N24H25: Self = Self::new(14);
}

// Manually implement serde::Deserialize. This has to be done manually because
// the zerocopy type `U32` does not support it and implementations of a trait
// have to be done in the crate the object is defined in. This is true for all
// of the other manual implementations in this file as well.
#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for LmsAlgorithmType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(LmsAlgorithmType::new(u32::deserialize(deserializer)?))
    }
}

#[repr(transparent)]
#[derive(
    IntoBytes,
    FromBytes,
    Debug,
    Immutable,
    KnownLayout,
    Unaligned,
    Default,
    PartialEq,
    Eq,
    Clone,
    Copy,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LmotsAlgorithmType(pub U32<BigEndian>);

impl LmotsAlgorithmType {
    #![allow(non_upper_case_globals)]

    pub const fn new(val: u32) -> Self {
        Self(U32::from_bytes(val.to_be_bytes()))
    }
    pub const LmotsReserved: Self = Self::new(0);
    pub const LmotsSha256N32W1: Self = Self::new(1);
    pub const LmotsSha256N32W2: Self = Self::new(2);
    pub const LmotsSha256N32W4: Self = Self::new(3);
    pub const LmotsSha256N32W8: Self = Self::new(4);
    pub const LmotsSha256N24W1: Self = Self::new(5);
    pub const LmotsSha256N24W2: Self = Self::new(6);
    pub const LmotsSha256N24W4: Self = Self::new(7);
    pub const LmotsSha256N24W8: Self = Self::new(8);
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for LmotsAlgorithmType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(LmotsAlgorithmType::new(u32::deserialize(deserializer)?))
    }
}

#[derive(Copy, Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(not(feature = "no-cfi"), derive(Launder))]
#[repr(C)]
pub struct LmsPublicKey<const N: usize> {
    pub tree_type: LmsAlgorithmType,
    pub otstype: LmotsAlgorithmType,
    pub id: [u8; 16],
    pub digest: [U32<LittleEndian>; N],
}

impl<const N: usize> Default for LmsPublicKey<N> {
    fn default() -> Self {
        Self {
            tree_type: Default::default(),
            otstype: Default::default(),
            id: Default::default(),
            digest: [Default::default(); N],
        }
    }
}
// Ensure there is no padding (required for IntoBytes safety)
static_assert!(
    size_of::<LmsPublicKey<1>>()
        == (size_of::<LmsAlgorithmType>()
            + size_of::<LmotsAlgorithmType>()
            + size_of::<[u8; 16]>()
            + size_of::<[U32<LittleEndian>; 1]>())
);

#[cfg(feature = "std")]
struct ExpectedDigestOrSeed<const N: usize>;

#[cfg(feature = "std")]
impl<const N: usize> Expected for ExpectedDigestOrSeed<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            formatter,
            "Expected an array of {} bytes",
            size_of::<[U32<LittleEndian>; N]>()
        )
    }
}

#[cfg(feature = "std")]
impl<'de, const N: usize> Deserialize<'de> for LmsPublicKey<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde_derive::Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            TreeType,
            Otstype,
            Id,
            Digest,
        }
        struct FieldVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for FieldVisitor<N> {
            type Value = LmsPublicKey<N>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str(format!("struct LmsPublicKey<{}>", N).as_str())
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut tree_type = None;
                let mut otstype = None;
                let mut id = None;
                let mut digest = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::TreeType => {
                            if tree_type.is_some() {
                                return Err(de::Error::duplicate_field("tree_type"));
                            }
                            tree_type = Some(map.next_value()?);
                        }
                        Field::Otstype => {
                            if otstype.is_some() {
                                return Err(de::Error::duplicate_field("otstype"));
                            }
                            otstype = Some(map.next_value()?);
                        }
                        Field::Id => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value()?);
                        }
                        Field::Digest => {
                            if digest.is_some() {
                                return Err(de::Error::duplicate_field("digest"));
                            }
                            let mut d = [Default::default(); N];
                            let digest_bytes: Vec<u8> = map.next_value()?;
                            if digest_bytes.len() != size_of_val(&d) {
                                return Err(de::Error::invalid_length(
                                    digest_bytes.len(),
                                    &ExpectedDigestOrSeed::<N>,
                                ));
                            }
                            d.as_mut_bytes().copy_from_slice(&digest_bytes);
                            digest = Some(d);
                        }
                    }
                }
                let tree_type = tree_type.ok_or_else(|| de::Error::missing_field("tree_type"))?;
                let otstype = otstype.ok_or_else(|| de::Error::missing_field("otstype"))?;
                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
                let digest = digest.ok_or_else(|| de::Error::missing_field("digest"))?;
                Ok(LmsPublicKey {
                    tree_type,
                    otstype,
                    id,
                    digest,
                })
            }
        }

        const FIELDS: &[&str] = &["tree_type", "otstype", "id", "digest"];
        deserializer.deserialize_struct("LmsPublicKey", FIELDS, FieldVisitor)
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Copy,
    Clone,
    Debug,
    IntoBytes,
    Immutable,
    KnownLayout,
    Unaligned,
    FromBytes,
    PartialEq,
    Eq,
    Zeroize,
)]
#[repr(C)]
pub struct LmotsSignature<const N: usize, const P: usize> {
    #[zeroize(skip)]
    pub ots_type: LmotsAlgorithmType,

    #[zeroize(skip)]
    pub nonce: [U32<LittleEndian>; N],

    #[zeroize(skip)]
    pub y: [[U32<LittleEndian>; N]; P],
}
impl<const N: usize, const P: usize> Default for LmotsSignature<N, P> {
    fn default() -> Self {
        Self {
            ots_type: Default::default(),
            nonce: [Default::default(); N],
            y: [[Default::default(); N]; P],
        }
    }
}
// Ensure there is no padding (required for IntoBytes safety)
static_assert!(
    size_of::<LmotsSignature<1, 1>>()
        == (size_of::<LmotsAlgorithmType>()
            + size_of::<[U32<LittleEndian>; 1]>()
            + size_of::<[[U32<LittleEndian>; 1]; 1]>())
);

#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(not(feature = "no-cfi"), derive(Launder))]
#[repr(C)]
pub struct LmsSignature<const N: usize, const P: usize, const H: usize> {
    pub q: U32<BigEndian>,

    pub ots: LmotsSignature<N, P>,

    pub tree_type: LmsAlgorithmType,

    pub tree_path: [[U32<LittleEndian>; N]; H],
}
impl<const N: usize, const P: usize, const H: usize> Default for LmsSignature<N, P, H> {
    fn default() -> Self {
        Self {
            q: Default::default(),
            ots: Default::default(),
            tree_type: Default::default(),
            tree_path: [[Default::default(); N]; H],
        }
    }
}
// Ensure there is no padding (required for IntoBytes safety)
static_assert!(
    size_of::<LmsSignature<1, 1, 1>>()
        == (size_of::<U32<BigEndian>>()
            + size_of::<LmotsSignature<1, 1>>()
            + size_of::<LmsAlgorithmType>()
            + size_of::<[[U32<LittleEndian>; 1]; 1]>())
);
// Derive doesn't support const generic arrays
// // unsafe impl<const N: usize, const P: usize, const H: usize> IntoBytes for LmsSignature<N, P, H> {
// //     fn only_derive_is_allowed_to_implement_this_trait() {}
// // }
// // unsafe impl<const N: usize, const P: usize, const H: usize> FromBytes for LmsSignature<N, P, H> {
// //     fn only_derive_is_allowed_to_implement_this_trait() {}
// // }
// impl<const N: usize, const P: usize, const H: usize> LmsSignature<N, P, H> {
//     pub fn ref_from_prefix(bytes: &[u8]) -> Option<&Self> {
//         if bytes.len() >= size_of::<Self>() {
//             Some(unsafe { &*(bytes.as_ptr() as *const Self) })
//         } else {
//             None
//         }
//     }
// }

// impl<const N: usize, const P: usize, const H: usize> LmsSignature<N, P, H> {
//     pub fn mut_ref_from_prefix(bytes: &mut [u8]) -> Option<&mut Self> {
//         {
//             if bytes.len() >= size_of::<Self>() {
//                 Some(unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) })
//             } else {
//                 None
//             }
//         }
//     }
// }

#[derive(Debug, Copy, Clone, IntoBytes, Immutable, KnownLayout, FromBytes, Eq, PartialEq)]
#[repr(C)]
pub struct LmsPrivateKey<const N: usize> {
    pub tree_type: LmsAlgorithmType,

    pub otstype: LmotsAlgorithmType,

    pub id: LmsIdentifier,

    pub seed: [U32<LittleEndian>; N],
}
impl<const N: usize> Default for LmsPrivateKey<N> {
    fn default() -> Self {
        Self {
            tree_type: Default::default(),
            otstype: Default::default(),
            id: Default::default(),
            seed: [Default::default(); N],
        }
    }
}
static_assert!(
    size_of::<LmsPrivateKey<1>>()
        == (size_of::<LmsAlgorithmType>()
            + size_of::<LmotsAlgorithmType>()
            + size_of::<LmsIdentifier>()
            + size_of::<[U32<LittleEndian>; 1]>())
);

#[cfg(feature = "std")]
impl<'de, const N: usize> Deserialize<'de> for LmsPrivateKey<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde_derive::Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            TreeType,
            Otstype,
            Id,
            Seed,
        }
        struct FieldVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for FieldVisitor<N> {
            type Value = LmsPrivateKey<N>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str(format!("struct LmsPrivateKey<{}>", N).as_str())
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut tree_type = None;
                let mut otstype = None;
                let mut id = None;
                let mut seed = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::TreeType => {
                            if tree_type.is_some() {
                                return Err(de::Error::duplicate_field("tree_type"));
                            }
                            tree_type = Some(map.next_value()?);
                        }
                        Field::Otstype => {
                            if otstype.is_some() {
                                return Err(de::Error::duplicate_field("otstype"));
                            }
                            otstype = Some(map.next_value()?);
                        }
                        Field::Id => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value()?);
                        }
                        Field::Seed => {
                            if seed.is_some() {
                                return Err(de::Error::duplicate_field("seed"));
                            }
                            let mut s = [Default::default(); N];
                            let seed_bytes: Vec<u8> = map.next_value()?;
                            if seed_bytes.len() != size_of_val(&s) {
                                return Err(de::Error::invalid_length(
                                    seed_bytes.len(),
                                    &ExpectedDigestOrSeed::<N>,
                                ));
                            }
                            s.as_mut_bytes().copy_from_slice(&seed_bytes);
                            seed = Some(s);
                        }
                    }
                }
                let tree_type = tree_type.ok_or_else(|| de::Error::missing_field("tree_type"))?;
                let otstype = otstype.ok_or_else(|| de::Error::missing_field("otstype"))?;
                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;
                let seed = seed.ok_or_else(|| de::Error::missing_field("seed"))?;
                Ok(LmsPrivateKey {
                    tree_type,
                    otstype,
                    id,
                    seed,
                })
            }
        }

        const FIELDS: &[&str] = &["tree_type", "otstype", "id", "seed"];
        deserializer.deserialize_struct("LmsPrivateKey", FIELDS, FieldVisitor)
    }
}

/// Converts a byte array to word arrays as used in the LMS types. Intended for
/// use at compile-time or in tests / host utilities; not optimized for use in
/// firmware at runtime.
pub const fn bytes_to_words_6(bytes: [u8; 24]) -> [U32<LittleEndian>; 6] {
    let mut result = [U32::ZERO; 6];
    let mut i = 0;
    while i < result.len() {
        result[i] = U32::from_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
        i += 1;
    }
    result
}

/// Converts a byte array to word arrays as used in the LMS types. Intended for
/// use at compile-time or in tests / host utilities; not optimized for use in
/// firmware at runtime.
pub const fn bytes_to_words_8(bytes: [u8; 32]) -> [U32<LittleEndian>; 8] {
    let mut result = [U32::ZERO; 8];
    let mut i = 0;
    while i < result.len() {
        result[i] = U32::from_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use zerocopy::{LittleEndian, U32};

    #[test]
    fn test_bytes_to_words_6() {
        assert_eq!(
            bytes_to_words_6([
                0x7e, 0x40, 0xc3, 0xed, 0x23, 0x13, 0x9f, 0x1b, 0xa0, 0xad, 0x31, 0x02, 0x4d, 0x15,
                0xe0, 0x39, 0xe8, 0x71, 0xd4, 0x79, 0xfc, 0x53, 0xca, 0xf0
            ]),
            [
                <U32<LittleEndian>>::from(0xedc3407e),
                0x1b9f1323.into(),
                0x0231ada0.into(),
                0x39e0154d.into(),
                0x79d471e8.into(),
                0xf0ca53fc.into()
            ]
        )
    }

    #[test]
    fn test_bytes_to_words_8() {
        assert_eq!(
            bytes_to_words_8([
                0x7e, 0x40, 0xc3, 0xed, 0x23, 0x13, 0x9f, 0x1b, 0xa0, 0xad, 0x31, 0x02, 0x4d, 0x15,
                0xe0, 0x39, 0xe8, 0x71, 0xd4, 0x79, 0xfc, 0x53, 0xca, 0xf0, 0x9a, 0x3c, 0x4b, 0xb8,
                0x1b, 0xde, 0x77, 0x9f
            ]),
            [
                <U32<LittleEndian>>::from(0xedc3407e),
                0x1b9f1323.into(),
                0x0231ada0.into(),
                0x39e0154d.into(),
                0x79d471e8.into(),
                0xf0ca53fc.into(),
                0xb84b3c9a.into(),
                0x9f77de1b.into()
            ]
        )
    }
}
