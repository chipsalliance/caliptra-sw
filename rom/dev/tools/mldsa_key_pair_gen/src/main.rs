/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains app for generating MLDSA key pairs from FIPS204 library.

--*/

use fips204::ml_dsa_87::try_keygen_with_rng;
use fips204::traits::SerDes;
use rand::prelude::*;
use rand::rngs::StdRng;
use std::fs::{self, File};
use std::io::Write;

fn write_to_file(filename: &str, bytes: &[u8]) {
    let mut w = File::create(filename).unwrap();
    w.write_all(bytes).unwrap();
}

fn main() {
    let mut seed_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed_bytes);

    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    for i in 0..5 {
        let (pk, sk) = try_keygen_with_rng(&mut seeded_rng).unwrap();
        let pk = pk.into_bytes();
        let sk = sk.into_bytes();

        let dir = "../mldsa_keys";
        fs::create_dir_all(dir).unwrap();

        let mut pub_file = format!("{}/vnd-mldsa-pub-key-{}.bin", dir, i);
        let mut priv_file = format!("{}/vnd-mldsa-priv-key-{}.bin", dir, i);

        if i == 4 {
            pub_file = format!("{}/own-mldsa-pub-key.bin", dir);
            priv_file = format!("{}/own-mldsa-priv-key.bin", dir);
        }

        // Write the keys in the library format.
        // For MLDSA, library format is same as hardware format.
        write_to_file(&pub_file, &pk);
        write_to_file(&priv_file, &sk);
    }
}
