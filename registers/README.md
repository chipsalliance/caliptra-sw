The caliptra-registers crate contains register definitions for the caliptra
hardware peripherals, generated from the RDL files in the rtl-caliptra repo.

To update the register definitions from the rtl-repo repo, run the following
(this example assumes https://github.com/Project-Caliptra/rtl-caliptra has been
cloned to ~/git/rtl-caliptra) 

```
~/git/fw-caliptra-lib/registers$ cargo run --release --manifest-path bin/generator/Cargo.toml -- ../../rtl-caliptra src/
   Compiling caliptra_registers_generator (~/git/fw-caliptra-lib/registers/bin/generator)
     Running `~/git/fw-caliptra-lib/target/release/caliptra_registers_generator ../../rtl-caliptra src/`
Writing to "src/doe.rs"
Writing to "src/ecc.rs"
Writing to "src/hmac.rs"
Writing to "src/kv.rs"
Writing to "src/sha512.rs"
Writing to "src/sha256.rs"
Writing to "src/mbox.rs"
Writing to "src/soc_ifc.rs"
```