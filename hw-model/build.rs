// Licensed under the Apache-2.0 license

fn main() {
    println!(
        "cargo:rustc-env=OPENOCD_SYSFSGPIO_ADAPTER_CFG=../../../hw/fpga/openocd_sysfsgpio_adapter.cfg"
    );
    println!("cargo:rustc-env=OPENOCD_TAP_CFG=../../../hw/fpga/openocd_ss.cfg");
}
