The caliptra-registers crate contains register definitions for the caliptra
hardware peripherals, generated from the RDL files in the rtl-caliptra repo.

To update the register definitions (and RTL submodule) to the latest version of caliptra-rtl:

```console
~/git/caliptra-sw$ git submodule update --init  # If you haven't already populated the submodule
~/git/caliptra-sw$ (cd hw-latest/caliptra-rtl/ && git checkout main && git pull --rebase)
~/git/caliptra-sw$ registers/update.sh
   Compiling caliptra_registers_generator (~/git/caliptra-sw/registers/bin/generator)
     Running `~/git/caliptra-sw/target/release/caliptra_registers_generator ../../rtl-caliptra src/`
Writing to "src/doe.rs"
Writing to "src/ecc.rs"
Writing to "src/hmac.rs"
Writing to "src/kv.rs"
Writing to "src/sha512.rs"
Writing to "src/sha256.rs"
Writing to "src/mbox.rs"
Writing to "src/soc_ifc.rs"

~/git/caliptra-sw$ git commit -a -m "Updated hw-latest/caliptra-rtl to $(cd hw-latest/caliptra-rtl && git rev-parse HEAD)"
```
