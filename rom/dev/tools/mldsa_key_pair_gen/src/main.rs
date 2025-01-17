use fips204::ml_dsa_87::try_keygen_with_rng;
use fips204::traits::SerDes;
use rand::prelude::*;
use rand::rngs::StdRng;
use std::fs::{self, File};
use std::io::Write;

fn write_as_dword(filename: &str, bytes: &[u8]) {
    let mut w = File::create(filename).unwrap();
    for chunk in bytes.chunks(4) {
        let dword = u32::from_be_bytes(chunk.try_into().unwrap());
        w.write_all(&dword.to_be_bytes()).unwrap();
    }
}

fn main() {
    let mut seed_bytes = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed_bytes);

    let mut seeded_rng = StdRng::from_seed(seed_bytes);

    for i in 0..5 {
        let (pk, sk) = try_keygen_with_rng(&mut seeded_rng).unwrap();
        let mut pk = pk.into_bytes();
        let mut sk = sk.into_bytes();
        pk.reverse();
        sk.reverse();

        let dir = "mldsa_keys";
        fs::create_dir_all(dir).unwrap();

        let mut pub_file = format!("{}/vnd-mldsa-pub-key-{}.bin", dir, i);
        let mut priv_file = format!("{}/vnd-mldsa-priv-key-{}.bin", dir, i);

        if i == 4 {
            pub_file = format!("{}/own-mldsa-pub-key.bin", dir);
            priv_file = format!("{}/own-mldsa-priv-key.bin", dir);
        }

        write_as_dword(&pub_file, &pk);
        write_as_dword(&priv_file, &sk);
    }
}
