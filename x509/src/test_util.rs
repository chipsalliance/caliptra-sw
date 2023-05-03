/*++

Licensed under the Apache-2.0 license.

File Name:

    test_util.rs

Abstract:

    Test Utilities

--*/

#[cfg(all(test, target_family = "unix"))]
pub mod tests {

    use openssl::{
        bn::BigNumContext,
        ec::{EcGroup, EcKey, PointConversionForm},
        nid::Nid,
        pkey::{PKey, Private},
        sha::{Sha1, Sha256},
    };

    pub struct Ecc384AsymKey {
        priv_key: PKey<Private>,
        pub_key: Vec<u8>,
    }

    impl Ecc384AsymKey {
        pub fn priv_key(&self) -> &PKey<Private> {
            &self.priv_key
        }

        pub fn pub_key(&self) -> &[u8] {
            &self.pub_key
        }

        pub fn sha256(&self) -> [u8; 32] {
            let mut sha = Sha256::new();
            sha.update(self.pub_key());
            sha.finish()
        }

        pub fn sha1(&self) -> [u8; 20] {
            let mut sha = Sha1::new();
            sha.update(self.pub_key());
            sha.finish()
        }

        pub fn hex_str(&self) -> String {
            hex::encode(self.sha256()).to_uppercase()
        }
    }

    impl Default for Ecc384AsymKey {
        fn default() -> Self {
            let ecc_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
            let priv_key = EcKey::generate(&ecc_group).unwrap();
            let mut bn_ctx = BigNumContext::new().unwrap();
            let pub_key = priv_key
                .public_key()
                .to_bytes(&ecc_group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)
                .unwrap();
            Self {
                priv_key: PKey::from_ec_key(priv_key).unwrap(),
                pub_key,
            }
        }
    }
}
