/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    Driver for test vector generators.

--*/

use crate::hmac384_kdf_vector_gen::{gen_vector, Hmac384KdfVector};

mod hmac384_kdf_vector_gen;

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
    let vec_c48: Hmac384KdfVector = gen_vector(4, 48);

    println!("hmac384_kdf context_len=48");
    println!("  let key_0 = {};", hex_arr(&vec_c48.key_0));
    println!("  let msg_0 = {};", hex_arr(&vec_c48.msg_0));
    println!("  let label = {};", hex_arr(&vec_c48.label));
    println!("  let context = {};", hex_arr(&vec_c48.context));
    println!("  let out_pub_x = {};", hex_arr(&vec_c48.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_c48.out_pub_y));
    println!();

    let vec_c0: Hmac384KdfVector = gen_vector(4, 0);

    println!("hmac384_kdf context_len=0");
    println!("  let key_0 = {};", hex_arr(&vec_c0.key_0));
    println!("  let msg_0 = {};", hex_arr(&vec_c0.msg_0));
    println!("  let label = {};", hex_arr(&vec_c0.label));
    println!("  let out_pub_x = {};", hex_arr(&vec_c0.out_pub_x));
    println!("  let out_pub_y = {};", hex_arr(&vec_c0.out_pub_y));
    println!();
}
