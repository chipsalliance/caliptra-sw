/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains crypto utilities needed to generate images.

--*/

use std::path::PathBuf;

use anyhow::{anyhow, Context};
use caliptra_drivers::{LmotsAlgorithmType,
    Lms, LmsAlgorithmType, LmsIdentifier, D_INTR, D_LEAF, D_MESG, D_PBLC};
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_image_types::*;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use openssl::sha::{Sha256, Sha384};

#[derive(Default)]
pub struct OsslCrypto {}

impl ImageGeneratorCrypto for OsslCrypto {
    /// Calculate SHA-384 Digest
    fn sha384_digest(&self, data: &[u8]) -> anyhow::Result<ImageDigest> {
        let mut engine = Sha384::new();
        engine.update(data);
        Ok(to_hw_format(&engine.finish()))
    }

    /// Calculate ECDSA-384 Signature
    fn ecdsa384_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageEccPrivKey,
        pub_key: &ImageEccPubKey,
    ) -> anyhow::Result<ImageEccSignature> {
        let priv_key: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(priv_key);
        let pub_key_x: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&pub_key.x);
        let pub_key_y: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(&pub_key.y);
        let digest: [u8; SHA384_DIGEST_BYTE_SIZE] = from_hw_format(digest);

        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let mut ctx = BigNumContext::new()?;

        let priv_key = BigNum::from_slice(&priv_key)?;
        let pub_key_x = BigNum::from_slice(&pub_key_x)?;
        let pub_key_y = BigNum::from_slice(&pub_key_y)?;

        let mut pub_key = EcPoint::new(&group)?;
        pub_key.set_affine_coordinates_gfp(&group, &pub_key_x, &pub_key_y, &mut ctx)?;

        let ec_key = EcKey::from_private_components(&group, &priv_key, &pub_key)?;
        let sig = EcdsaSig::sign(&digest, &ec_key)?;

        let r = sig.r().to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;
        let s = sig.s().to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

        let image_sig = ImageEccSignature {
            r: to_hw_format(&r),
            s: to_hw_format(&s),
        };
        Ok(image_sig)
    }

    fn lms_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageLmsPrivKey,
    ) -> anyhow::Result<ImageLmsSignature> {
        let message: [u8; ECC384_SCALAR_BYTE_SIZE] = from_hw_format(digest);
        let mut nonce = [0u8; SHA192_DIGEST_BYTE_SIZE];
        rand_bytes(&mut nonce).unwrap();
        sign_with_lms_key(
            priv_key,
            &message,
            &nonce,
            LmsAlgorithmType::LmsSha256N24H15,
            LmotsAlgorithmType::LmotsSha256N24W4,
            0,
        )
    }
}

/// Read ECC-384 Public Key from PEM file
pub fn ecc_pub_key_from_pem(path: &PathBuf) -> anyhow::Result<ImageEccPubKey> {
    let key_bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read public key PEM file {}", path.display()))?;
    let key = EcKey::public_key_from_pem(&key_bytes)?;
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;

    key.public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

    let x = x.to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;
    let y = y.to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

    let image_key = ImageEccPubKey {
        x: to_hw_format(&x),
        y: to_hw_format(&y),
    };
    Ok(image_key)
}

/// Read ECC-384 Private Key from PEM file
pub fn ecc_priv_key_from_pem(path: &PathBuf) -> anyhow::Result<ImageEccPrivKey> {
    let key_bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read public key PEM file {}", path.display()))?;

    let key = EcKey::private_key_from_pem(&key_bytes)?;

    let priv_key = key
        .private_key()
        .to_vec_padded(ECC384_SCALAR_BYTE_SIZE as i32)?;

    Ok(to_hw_format(&priv_key))
}

/// Convert the slice to hardware format
fn to_hw_format(value: &[u8]) -> [u32; ECC384_SCALAR_WORD_SIZE] {
    let arr = TryInto::<[u8; ECC384_SCALAR_BYTE_SIZE]>::try_into(value).unwrap();
    let mut result = [0u32; ECC384_SCALAR_WORD_SIZE];
    for i in 0..result.len() {
        result[i] = u32::from_be_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}

/// Convert the hardware format to byte array
fn from_hw_format(value: &[u32; ECC384_SCALAR_WORD_SIZE]) -> [u8; ECC384_SCALAR_BYTE_SIZE] {
    let mut result = [0u8; ECC384_SCALAR_BYTE_SIZE];
    for i in 0..value.len() {
        *<&mut [u8; 4]>::try_from(&mut result[i * 4..][..4]).unwrap() = value[i].to_be_bytes();
    }
    result
}

// https://www.rfc-editor.org/rfc/rfc8554.html#appendix-A
fn gen_x(id: &LmsIdentifier, q: u32, p: usize, seed: &[u8], x: &mut [u8]) {
    for i in 0..p {
        let offset = i * SHA192_DIGEST_BYTE_SIZE;
        let x_i = &mut x[offset..][..SHA192_DIGEST_BYTE_SIZE];
        let idx: [u8; 1] = [0xff];
        let i_str: [u8; 2] = (i as u16).to_be_bytes();
        let q_str: [u8; 4] = q.to_be_bytes();
        let mut hasher = Sha256::new();

        hasher.update(id);
        hasher.update(&q_str);
        hasher.update(&i_str);
        hasher.update(&idx);
        hasher.update(seed);
        x_i.clone_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);
    }
}

fn gen_k(id: &LmsIdentifier, q: u32, p: usize, w: u8, x: &[u8], k: &mut [u8]) {
    let mut y = vec![0u8; p * SHA192_DIGEST_BYTE_SIZE];
    for i in 0..p {
        let offset = i * SHA192_DIGEST_BYTE_SIZE;
        let tmp = &mut y[offset..][..SHA192_DIGEST_BYTE_SIZE];
        let x_i = &x[offset..][..SHA192_DIGEST_BYTE_SIZE];
        tmp.clone_from_slice(x_i);

        let i_str: [u8; 2] = (i as u16).to_be_bytes();
        let width: u16 = (1 << w) - 1;
        let chain_len: u8 = width as u8;
        for j in 0..chain_len {
            let j_str: [u8; 1] = [j];
            let mut hasher = Sha256::new();
            hasher.update(id);
            hasher.update(&q.to_be_bytes());
            hasher.update(&i_str);
            hasher.update(&j_str);
            hasher.update(tmp);
            tmp.clone_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(id);
    hasher.update(&q.to_be_bytes());
    hasher.update(&D_PBLC.to_be_bytes());
    hasher.update(&y[..]);
    k.clone_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);
}

fn generate_lmots_pubkey_helper(
    id: &LmsIdentifier,
    q: u32,
    p: usize,
    w: u8,
    seed: &[u8],
    k: &mut [u8],
) {
    let mut x = vec![0u8; p * SHA192_DIGEST_BYTE_SIZE];
    gen_x(id, q, p, seed, &mut x);
    gen_k(id, q, p, w, &x, k);
}

fn stack_top_mut(st: &mut Vec<u8>, st_index: usize) -> &mut [u8] {
    &mut st[st_index * SHA192_DIGEST_BYTE_SIZE..][..SHA192_DIGEST_BYTE_SIZE]
}

fn stack_top(st: &Vec<u8>, st_index: usize) -> &[u8] {
    &st[st_index * SHA192_DIGEST_BYTE_SIZE..][..SHA192_DIGEST_BYTE_SIZE]
}

// // https://datatracker.ietf.org/doc/html/rfc8554#appendix-C
fn generate_lms_pubkey_helper(
    id: &LmsIdentifier,
    ots_alg: LmotsAlgorithmType,
    tree_height: u8,
    seed: &[u8],
    q: Option<u32>,
    pub_key: &mut Option<ImageLmsPublicKey>,
    sig: &mut Option<ImageLmsSignature>,
) {
    let mut target_node: u32 = match pub_key {
        Some(_) => 1,
        None => (((1 << tree_height) as u32) + q.unwrap()) ^ 1,
    };
    let mut k = vec![0u8; SHA192_DIGEST_BYTE_SIZE];

    let mut level: usize = 0;
    let mut pub_key_stack = vec![0u8; SHA192_DIGEST_BYTE_SIZE * (tree_height as usize)];
    let mut stack_idx: usize = 0;
    let max_idx: u32 = 1 << tree_height;
    let alg_params = Lms::default().get_lmots_parameters(&ots_alg).unwrap();
    let p: usize = alg_params.p as usize;
    for i in 0..max_idx {
        generate_lmots_pubkey_helper(id, i, p, alg_params.w, seed, &mut k[..]);

        let mut r: u32 = i + (1 << tree_height);
        let mut r_str: [u8; 4] = r.to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(id);
        hasher.update(&r_str);
        hasher.update(&D_LEAF.to_be_bytes());
        hasher.update(&k[..]);
        k.clone_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);

        let mut j: u32 = i;
        let mut cur_node: u32 = (1 << tree_height) + i;
        while j % 2 == 1 {
            r = r >> 1;
            j = j >> 1;
            // pop left_side (i.e T[r]) from stack
            stack_idx -= 1;

            // Before mixing left and right nodes, check if left node is needed to be
            // filled in the signature path.
            if cur_node == target_node + 1 {
                if let Some(sig_val) = sig.as_mut() {
                    sig_val.tree_path[level].clone_from_slice(stack_top(&pub_key_stack, stack_idx));
                    level += 1;
                }
                target_node = (target_node >> 1) ^ 1;
            }

            // Before mixing left and right nodes, check if right node is needed to be
            // filled in the signature path.
            if cur_node == target_node {
                if let Some(sig_val) = sig.as_mut() {
                    sig_val.tree_path[level].clone_from_slice(&k[..]);
                    level += 1;
                }
                target_node = (target_node >> 1) ^ 1;
            }

            r_str = r.to_be_bytes();
            cur_node = cur_node >> 1;
            // temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
            hasher = Sha256::new();
            hasher.update(id);
            hasher.update(&r_str);
            hasher.update(&D_INTR.to_be_bytes());
            hasher.update(stack_top(&pub_key_stack, stack_idx));
            hasher.update(&k[..]);
            k.clone_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);
        }

        // push K onto the data stack
        stack_top_mut(&mut pub_key_stack, stack_idx).clone_from_slice(&k[..]);
        stack_idx += 1;
    }

    // Pop top from stack (should be 1) when requested for public key.
    if let Some(pub_key_val) = pub_key {
        stack_idx -= 1;
        pub_key_val
            .digest
            .clone_from_slice(stack_top(&pub_key_stack, stack_idx));
    }
}

// https://datatracker.ietf.org/doc/html/rfc8554#section-4.5
fn generate_ots_signature_helper(
    message: &[u8],
    ots_alg: LmotsAlgorithmType,
    id: &LmsIdentifier,
    seed: &[u8],
    rand: &[u8],
    q: u32,
) -> ImageLmOTSSignature {
    let alg_params = Lms::default().get_lmots_parameters(&ots_alg).unwrap();
    let mut sig: ImageLmOTSSignature = Default::default();
    sig.random.clone_from_slice(rand);
    let mut hasher = Sha256::new();
    hasher.update(id);
    hasher.update(&q.to_be_bytes());
    hasher.update(&D_MESG.to_be_bytes());
    hasher.update(rand);
    hasher.update(message);
    let mut q_arr = [0u8; SHA192_DIGEST_BYTE_SIZE];
    q_arr.clone_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);

    let mut checksum: u16 = 0;
    let width: usize = alg_params.w.into();
    let data_coeff: usize = (SHA192_DIGEST_BYTE_SIZE * 8) / width;
    let alg_p: usize = alg_params.p.into();
    let alg_chksum_max: u16 = (1 << alg_params.w) - 1;
    for i in 0..data_coeff {
        checksum += alg_chksum_max - (Lms::default().coefficient(&q_arr, i, width).unwrap() as u16);
    }

    let checksum_str: [u8; 2] = checksum.to_be_bytes();

    let mut x = vec![0u8; alg_p * SHA192_DIGEST_BYTE_SIZE];
    gen_x(id, q, alg_p, seed, &mut x);

    for i in 0..alg_p {
        let a: u8;
        if i < data_coeff {
            a = Lms::default().coefficient(&q_arr, i, width).unwrap();
        } else {
            a = Lms::default().coefficient(&checksum_str, i - data_coeff, width).unwrap();
        }

        let offset: usize = i * SHA192_DIGEST_BYTE_SIZE;
        let tmp: &mut [u8] = &mut x[offset..][..SHA192_DIGEST_BYTE_SIZE];
        let i_str: [u8; 2] = (i as u16).to_be_bytes();
        for j in 0..a {
            let j_str: [u8; 1] = [j];
            hasher = Sha256::new();
            hasher.update(id);
            hasher.update(&q.to_be_bytes());
            hasher.update(&i_str);
            hasher.update(&j_str);
            hasher.update(tmp);
            tmp.copy_from_slice(&hasher.finish()[..SHA192_DIGEST_BYTE_SIZE]);
        }
        let sig_val = &mut sig.sig[i];
        sig_val.clone_from_slice(tmp);
    }


    sig
}

fn generate_lms_pubkey(priv_key: &ImageLmsPrivKey) -> ImageLmsPublicKey {
    let mut pub_key = Some(ImageLmsPublicKey::default());
    pub_key.as_mut().map(|x| x.otstype = priv_key.otstype);
    pub_key.as_mut().map(|x| x.id = priv_key.id.clone());
    pub_key.as_mut().map(|x| x.tree_type = priv_key.tree_type);
    generate_lms_pubkey_helper(
        &priv_key.id,
        LmotsAlgorithmType::LmotsSha256N24W8,
        5u8,
        &priv_key.seed,
        None,
        &mut pub_key,
        &mut None,
    );
    pub_key.unwrap()
}

fn sign_with_lms_key(
    priv_key: &ImageLmsPrivKey,
    message: &[u8],
    nonce: &[u8],
    lms_alg_type: LmsAlgorithmType,
    ots_alg_type: LmotsAlgorithmType,
    q: u32,
) -> anyhow::Result<ImageLmsSignature> {
    let Ok((_, height)) = Lms::default().get_lms_parameters(&lms_alg_type) else {
         return Err(anyhow!("Error parsing lms parameters"));
    };
    if q >= (1 << height) {
        return Err(anyhow!("Invalid q"));
    }
    let ots_sig = generate_ots_signature_helper(
        message,
        ots_alg_type,
        &priv_key.id,
        &priv_key.seed,
        nonce,
        q
    );
    let mut sig = Some(ImageLmsSignature::default());
    sig.as_mut().map(|x| x.q = q);
    sig.as_mut().map(|x| x.ots_sig = ots_sig);

    generate_lms_pubkey_helper(
        &priv_key.id,
        ots_alg_type,
        height,
        &priv_key.seed,
        Some(q),
        &mut None,
        &mut sig,
    );
    Ok(sig.unwrap())
}

#[test]
fn test_print_lms_private_pub_key() {
    let mut priv_key: ImageLmsPrivKey = ImageLmsPrivKey::default();
    priv_key.tree_type = LmsAlgorithmType::LmsSha256N24H15 as u32;
    priv_key.otstype = LmotsAlgorithmType::LmotsSha256N24W4 as u32;
    for i in 0..4 {
        rand_bytes(&mut priv_key.id).unwrap();
        rand_bytes(&mut priv_key.seed).unwrap();
        let pub_key = generate_lms_pubkey(&priv_key);
        println!("pub const VENDOR_LMS_KEY{i}_PRIVATE: ImageLmsPrivKey = {priv_key:#04x?};");
        println!("pub const VENDOR_LMS_KEY{i}_PUBLIC: ImageLmsPublicKey = {pub_key:#04x?};");
    }
    for i in 0..1 {
        rand_bytes(&mut priv_key.id).unwrap();
        rand_bytes(&mut priv_key.seed).unwrap();
        let pub_key = generate_lms_pubkey(&priv_key);
        println!("pub const OWNER_LMS_KEY{i}_PRIVATE: ImageLmsPrivKey = {priv_key:#04x?};");
        println!("pub const OWNER_LMS_KEY{i}_PUBLIC: ImageLmsPublicKey = {pub_key:#04x?};");
    }
}

#[test]
fn test_lms() {
    let priv_key = ImageLmsPrivKey {
        tree_type: LmsAlgorithmType::LmsSha256N24H5 as u32,
        otstype: LmotsAlgorithmType::LmotsSha256N24W8 as u32,
        id: [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ],
        seed: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
    };
    let expected_pub_key = ImageLmsPublicKey {
        tree_type: LmsAlgorithmType::LmsSha256N24H5 as u32,
        otstype: LmotsAlgorithmType::LmotsSha256N24W8 as u32,
        id: priv_key.id.clone(),
        digest: [
            0x2c, 0x57, 0x14, 0x50, 0xae, 0xd9, 0x9c, 0xfb, 0x4f, 0x4a, 0xc2, 0x85, 0xda, 0x14,
            0x88, 0x27, 0x96, 0x61, 0x83, 0x14, 0x50, 0x8b, 0x12, 0xd2,
        ],
    };
    let pub_key = generate_lms_pubkey(&priv_key);
    assert_eq!(expected_pub_key, pub_key);
}

#[test]
fn test_lms_sig() {
    let priv_key = ImageLmsPrivKey {
        tree_type: LmsAlgorithmType::LmsSha256N24H5 as u32,
        otstype: LmotsAlgorithmType::LmotsSha256N24W8 as u32,
        id: [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ],
        seed: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
    };
    let expected_ots_sig: [[u8; 24]; 26] = [
        [
            0xe1, 0x3b, 0x9f, 0x08, 0x75, 0xf0, 0x93, 0x61, 0xdc, 0x77, 0xfc, 0xc4, 0x48, 0x1e,
            0xa4, 0x63, 0xc0, 0x73, 0x71, 0x62, 0x49, 0x71, 0x91, 0x93,
        ],
        [
            0x61, 0x4b, 0x83, 0x5b, 0x46, 0x94, 0xc0, 0x59, 0xf1, 0x2d, 0x3a, 0xed, 0xd3, 0x4f,
            0x3d, 0xb9, 0x3f, 0x35, 0x80, 0xfb, 0x88, 0x74, 0x3b, 0x8b,
        ],
        [
            0x3d, 0x06, 0x48, 0xc0, 0x53, 0x7b, 0x7a, 0x50, 0xe4, 0x33, 0xd7, 0xea, 0x9d, 0x66,
            0x72, 0xff, 0xfc, 0x5f, 0x42, 0x77, 0x0f, 0xea, 0xb4, 0xf9,
        ],
        [
            0x8e, 0xb3, 0xf3, 0xb2, 0x3f, 0xd2, 0x06, 0x1e, 0x4d, 0x0b, 0x38, 0xf8, 0x32, 0x86,
            0x0a, 0xe7, 0x66, 0x73, 0xad, 0x1a, 0x1a, 0x52, 0xa9, 0x00,
        ],
        [
            0x5d, 0xcf, 0x1b, 0xfb, 0x56, 0xfe, 0x16, 0xff, 0x72, 0x36, 0x27, 0x61, 0x2f, 0x9a,
            0x48, 0xf7, 0x90, 0xf3, 0xc4, 0x7a, 0x67, 0xf8, 0x70, 0xb8,
        ],
        [
            0x1e, 0x91, 0x9d, 0x99, 0x91, 0x9c, 0x8d, 0xb4, 0x81, 0x68, 0x83, 0x8c, 0xec, 0xe0,
            0xab, 0xfb, 0x68, 0x3d, 0xa4, 0x8b, 0x92, 0x09, 0x86, 0x8b,
        ],
        [
            0xe8, 0xec, 0x10, 0xc6, 0x3d, 0x8b, 0xf8, 0x0d, 0x36, 0x49, 0x8d, 0xfc, 0x20, 0x5d,
            0xc4, 0x5d, 0x0d, 0xd8, 0x70, 0x57, 0x2d, 0x6d, 0x8f, 0x1d,
        ],
        [
            0x90, 0x17, 0x7c, 0xf5, 0x13, 0x7b, 0x8b, 0xbf, 0x7b, 0xcb, 0x67, 0xa4, 0x6f, 0x86,
            0xf2, 0x6c, 0xfa, 0x5a, 0x44, 0xcb, 0xca, 0xa4, 0xe1, 0x8d,
        ],
        [
            0xa0, 0x99, 0xa9, 0x8b, 0x0b, 0x3f, 0x96, 0xd5, 0xac, 0x8a, 0xc3, 0x75, 0xd8, 0xda,
            0x2a, 0x7c, 0x24, 0x80, 0x04, 0xba, 0x11, 0xd7, 0xac, 0x77,
        ],
        [
            0x5b, 0x92, 0x18, 0x35, 0x9c, 0xdd, 0xab, 0x4c, 0xf8, 0xcc, 0xc6, 0xd5, 0x4c, 0xb7,
            0xe1, 0xb3, 0x5a, 0x36, 0xdd, 0xc9, 0x26, 0x5c, 0x08, 0x70,
        ],
        [
            0x63, 0xd2, 0xfc, 0x67, 0x42, 0xa7, 0x17, 0x78, 0x76, 0x47, 0x6a, 0x32, 0x4b, 0x03,
            0x29, 0x5b, 0xfe, 0xd9, 0x9f, 0x2e, 0xaf, 0x1f, 0x38, 0x97,
        ],
        [
            0x05, 0x83, 0xc1, 0xb2, 0xb6, 0x16, 0xaa, 0xd0, 0xf3, 0x1c, 0xd7, 0xa4, 0xb1, 0xbb,
            0x0a, 0x51, 0xe4, 0x77, 0xe9, 0x4a, 0x01, 0xbb, 0xb4, 0xd6,
        ],
        [
            0xf8, 0x86, 0x6e, 0x25, 0x28, 0xa1, 0x59, 0xdf, 0x3d, 0x6c, 0xe2, 0x44, 0xd2, 0xb6,
            0x51, 0x8d, 0x1f, 0x02, 0x12, 0x28, 0x5a, 0x3c, 0x2d, 0x4a,
        ],
        [
            0x92, 0x70, 0x54, 0xa1, 0xe1, 0x62, 0x0b, 0x5b, 0x02, 0xaa, 0xb0, 0xc8, 0xc1, 0x0e,
            0xd4, 0x8a, 0xe5, 0x18, 0xea, 0x73, 0xcb, 0xa8, 0x1f, 0xcf,
        ],
        [
            0xff, 0x88, 0xbf, 0xf4, 0x61, 0xda, 0xc5, 0x1e, 0x7a, 0xb4, 0xca, 0x75, 0xf4, 0x7a,
            0x62, 0x59, 0xd2, 0x48, 0x20, 0xb9, 0x99, 0x57, 0x92, 0xd1,
        ],
        [
            0x39, 0xf6, 0x1a, 0xe2, 0xa8, 0x18, 0x6a, 0xe4, 0xe3, 0xc9, 0xbf, 0xe0, 0xaf, 0x2c,
            0xc7, 0x17, 0xf4, 0x24, 0xf4, 0x1a, 0xa6, 0x7f, 0x03, 0xfa,
        ],
        [
            0xed, 0xb0, 0x66, 0x51, 0x15, 0xf2, 0x06, 0x7a, 0x46, 0x84, 0x3a, 0x4c, 0xbb, 0xd2,
            0x97, 0xd5, 0xe8, 0x3b, 0xc1, 0xaa, 0xfc, 0x18, 0xd1, 0xd0,
        ],
        [
            0x3b, 0x3d, 0x89, 0x4e, 0x85, 0x95, 0xa6, 0x52, 0x60, 0x73, 0xf0, 0x2a, 0xb0, 0xf0,
            0x8b, 0x99, 0xfd, 0x9e, 0xb2, 0x08, 0xb5, 0x9f, 0xf6, 0x31,
        ],
        [
            0x7e, 0x55, 0x45, 0xe6, 0xf9, 0xad, 0x5f, 0x9c, 0x18, 0x3a, 0xbd, 0x04, 0x3d, 0x5a,
            0xcd, 0x6e, 0xb2, 0xdd, 0x4d, 0xa3, 0xf0, 0x2d, 0xbc, 0x31,
        ],
        [
            0x67, 0xb4, 0x68, 0x72, 0x0a, 0x4b, 0x8b, 0x92, 0xdd, 0xfe, 0x79, 0x60, 0x99, 0x8b,
            0xb7, 0xa0, 0xec, 0xf2, 0xa2, 0x6a, 0x37, 0x59, 0x82, 0x99,
        ],
        [
            0x41, 0x3f, 0x7b, 0x2a, 0xec, 0xd3, 0x9a, 0x30, 0xce, 0xc5, 0x27, 0xb4, 0xd9, 0x71,
            0x0c, 0x44, 0x73, 0x63, 0x90, 0x22, 0x45, 0x1f, 0x50, 0xd0,
        ],
        [
            0x1c, 0x04, 0x57, 0x12, 0x5d, 0xa0, 0xfa, 0x44, 0x29, 0xc0, 0x7d, 0xad, 0x85, 0x9c,
            0x84, 0x6c, 0xbb, 0xd9, 0x3a, 0xb5, 0xb9, 0x1b, 0x01, 0xbc,
        ],
        [
            0x77, 0x0b, 0x08, 0x9c, 0xfe, 0xde, 0x6f, 0x65, 0x1e, 0x86, 0xdd, 0x7c, 0x15, 0x98,
            0x9c, 0x8b, 0x53, 0x21, 0xde, 0xa9, 0xca, 0x60, 0x8c, 0x71,
        ],
        [
            0xfd, 0x86, 0x23, 0x23, 0x07, 0x2b, 0x82, 0x7c, 0xee, 0x7a, 0x7e, 0x28, 0xe4, 0xe2,
            0xb9, 0x99, 0x64, 0x72, 0x33, 0xc3, 0x45, 0x69, 0x44, 0xbb,
        ],
        [
            0x7a, 0xef, 0x91, 0x87, 0xc9, 0x6b, 0x3f, 0x5b, 0x79, 0xfb, 0x98, 0xbc, 0x76, 0xc3,
            0x57, 0x4d, 0xd0, 0x6f, 0x0e, 0x95, 0x68, 0x5e, 0x5b, 0x3a,
        ],
        [
            0xef, 0x3a, 0x54, 0xc4, 0x15, 0x5f, 0xe3, 0xad, 0x81, 0x77, 0x49, 0x62, 0x9c, 0x30,
            0xad, 0xbe, 0x89, 0x7c, 0x4f, 0x44, 0x54, 0xc8, 0x6c, 0x49,
        ],
    ];
    let message: [u8; 28] = [
        0x54, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f,
        0x72, 0x20, 0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x2d, 0x31, 0x39, 0x32, 0x0a,
    ];
    let nonce = [
        0x0b, 0x50, 0x40, 0xa1, 0x8c, 0x1b, 0x5c, 0xab, 0xcb, 0xc8, 0x5b, 0x04, 0x74, 0x02, 0xec,
        0x62, 0x94, 0xa3, 0x0d, 0xd8, 0xda, 0x8f, 0xc3, 0xda,
    ];
    let expected_tree_path = [
        [
            0xe9, 0xca, 0x10, 0xea, 0xa8, 0x11, 0xb2, 0x2a, 0xe0, 0x7f, 0xb1, 0x95, 0xe3, 0x59,
            0x0a, 0x33, 0x4e, 0xa6, 0x42, 0x09, 0x94, 0x2f, 0xba, 0xe3,
        ],
        [
            0x38, 0xd1, 0x9f, 0x15, 0x21, 0x82, 0xc8, 0x07, 0xd3, 0xc4, 0x0b, 0x18, 0x9d, 0x3f,
            0xcb, 0xea, 0x94, 0x2f, 0x44, 0x68, 0x24, 0x39, 0xb1, 0x91,
        ],
        [
            0x33, 0x2d, 0x33, 0xae, 0x0b, 0x76, 0x1a, 0x2a, 0x8f, 0x98, 0x4b, 0x56, 0xb2, 0xac,
            0x2f, 0xd4, 0xab, 0x08, 0x22, 0x3a, 0x69, 0xed, 0x1f, 0x77,
        ],
        [
            0x19, 0xc7, 0xaa, 0x7e, 0x9e, 0xee, 0x96, 0x50, 0x4b, 0x0e, 0x60, 0xc6, 0xbb, 0x5c,
            0x94, 0x2d, 0x69, 0x5f, 0x04, 0x93, 0xeb, 0x25, 0xf8, 0x0a,
        ],
        [
            0x58, 0x71, 0xcf, 0xfd, 0x13, 0x1d, 0x0e, 0x04, 0xff, 0xe5, 0x06, 0x5b, 0xc7, 0x87,
            0x5e, 0x82, 0xd3, 0x4b, 0x40, 0xb6, 0x9d, 0xd9, 0xf3, 0xc1,
        ],
    ];
    let sig = sign_with_lms_key(
        &priv_key,
        &message,
        &nonce,
        LmsAlgorithmType::LmsSha256N24H5,
        LmotsAlgorithmType::LmotsSha256N24W8,
        5,
    )
    .unwrap();
    let mut expected_sig = ImageLmsSignature::default();
    expected_sig.q = 5;

    expected_sig.ots_sig.random = nonce.clone();
    for i in 0..26 {
        expected_sig.ots_sig.sig[i].clone_from_slice(&expected_ots_sig[i]);
    }
    for i in 0..5 {
        expected_sig.tree_path[i].clone_from_slice(&expected_tree_path[i]);
    }
    assert_eq!(sig, expected_sig);
}
