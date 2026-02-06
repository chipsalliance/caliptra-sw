// Licensed under the Apache-2.0 license

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-env=OPENOCD_SYSFSGPIO_ADAPTER_CFG={manifest_dir}/../hw/fpga/openocd_sysfsgpio_adapter.cfg");
    println!("cargo:rustc-env=OPENOCD_TAP_CFG={manifest_dir}/../hw/fpga/openocd_ss.cfg");
}
