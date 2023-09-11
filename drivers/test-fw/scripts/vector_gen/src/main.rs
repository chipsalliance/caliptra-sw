/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    Driver for test vector generators.

--*/

mod hmac384_kdf_vector_gen;
mod hmac384_vector_gen;

use crate::hmac384_kdf_vector_gen::Hmac384KdfVector;
use crate::hmac384_vector_gen::Hmac384Vector;

fn hex_arr(bytes: &[u8]) -> String {
    format!(
        "[{}]",
        bytes
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<String>>()
            .join(", ")
    )
}

fn main() {
    let vec_d8: Hmac384Vector = hmac384_vector_gen::gen_vector(8);
    println!("hmac384 data_len=8");
    println!("  let seed = {};", hex_arr(&vec_d8.seed));
    println!("  let data = {};", hex_arr(&vec_d8.data));
    println!("  let out_pub_x = {};", hex_arr(&vec_d8.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_d8.out_pub_y));
    println!();

    let vec_d28: Hmac384Vector = hmac384_vector_gen::gen_vector(28);
    println!("hmac384 data_len=28");
    println!("  let seed = {};", hex_arr(&vec_d28.seed));
    println!("  let data = {};", hex_arr(&vec_d28.data));
    println!("  let out_pub_x = {};", hex_arr(&vec_d28.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_d28.out_pub_y));
    println!();

    let vec_d48: Hmac384Vector = hmac384_vector_gen::gen_vector(48);
    println!("hmac384 data_len=48");
    println!("  let seed = {};", hex_arr(&vec_d48.seed));
    println!("  let data = {};", hex_arr(&vec_d48.data));
    println!("  let out_pub_x = {};", hex_arr(&vec_d48.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_d48.out_pub_y));
    println!();

    let vec_kdf_c48: Hmac384KdfVector = hmac384_kdf_vector_gen::gen_vector(4, 48);
    println!("hmac384_kdf context_len=48");
    println!("  let key_0 = {};", hex_arr(&vec_kdf_c48.key_0));
    println!("  let msg_0 = {};", hex_arr(&vec_kdf_c48.msg_0));
    println!("  let label = {};", hex_arr(&vec_kdf_c48.label));
    println!("  let context = {};", hex_arr(&vec_kdf_c48.context));
    println!("  let out_pub_x = {};", hex_arr(&vec_kdf_c48.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_kdf_c48.out_pub_y));
    println!();

    let vec_kdf_c0: Hmac384KdfVector = hmac384_kdf_vector_gen::gen_vector(4, 0);
    println!("hmac384_kdf context_len=0");
    println!("  let key_0 = {};", hex_arr(&vec_kdf_c0.key_0));
    println!("  let msg_0 = {};", hex_arr(&vec_kdf_c0.msg_0));
    println!("  let label = {};", hex_arr(&vec_kdf_c0.label));
    println!("  let out_pub_x = {};", hex_arr(&vec_kdf_c0.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_kdf_c0.out_pub_y));
    println!();
}
