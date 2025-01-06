/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use crate::cprintln;
use crate::rom_env::RomEnv;
use caliptra_common::{crypto::PubKey, x509};
use caliptra_drivers::*;
use core::mem::size_of;

/// Get Initial Device ID Cert Subject Key Identifier
///
/// # Arguments
///
/// * `env`     - ROM Environment
/// * `pub_key` - ECC or MLDSA Public Key
///
/// # Returns
///
/// `[u8; 20]` - X509 Subject Key Identifier
pub fn idev_subj_key_id(env: &mut RomEnv, pub_key: &PubKey) -> CaliptraResult<[u8; 20]> {
    let mut pub_key_bytes: [u8; size_of::<Mldsa87PubKey>()] = [0; size_of::<Mldsa87PubKey>()];
    let pub_key_size = x509::get_pubkey_bytes(pub_key, &mut pub_key_bytes);
    let data: &[u8] = &pub_key_bytes[..pub_key_size];

    let ecc_pub_key = matches!(pub_key, PubKey::Ecc(_));

    let digest: [u8; 20] = match env
        .soc_ifc
        .fuse_bank()
        .idev_id_x509_key_id_algo(ecc_pub_key)
    {
        X509KeyIdAlgo::Sha1 => {
            cprintln!("[idev] Sha1 KeyId Algorithm");
            let digest = env.sha1.digest(data);
            okref(&digest)?.into()
        }
        X509KeyIdAlgo::Sha256 => {
            cprintln!("[idev] Sha256 KeyId Algorithm");
            let digest = env.sha256.digest(data);
            let digest: [u8; 32] = okref(&digest)?.into();
            digest[..20].try_into().unwrap()
        }
        X509KeyIdAlgo::Sha384 => {
            cprintln!("[idev] Sha384 KeyId Algorithm");
            let digest = env.sha2_512_384.sha384_digest(data);
            let digest: [u8; 48] = okref(&digest)?.into();
            digest[..20].try_into().unwrap()
        }
        X509KeyIdAlgo::Sha512 => {
            cprintln!("[idev] Sha512 KeyId Algorithm");
            let digest = env.sha2_512_384.sha512_digest(data);
            let digest: [u8; 64] = okref(&digest)?.into();
            digest[..20].try_into().unwrap()
        }
        X509KeyIdAlgo::Fuse => {
            cprintln!("[idev] Fuse KeyId");
            env.soc_ifc.fuse_bank().subject_key_id(ecc_pub_key)
        }
    };

    Ok(digest)
}
