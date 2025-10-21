/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra Drivers.

--*/

fn main() {
    let features = std::env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(|s| s.to_lowercase()))
        .collect::<Vec<_>>();

    let fpga_subsystem = features.contains(&"fpga_subsystem".to_string());
    let emu_subsystem = features.contains(&"emu_subsystem".to_string());
    let fpga_realtime = features.contains(&"fpga_realtime".to_string());
    let verilator = features.contains(&"verilator".to_string());
    let emu_core = !(fpga_subsystem || emu_subsystem || fpga_realtime || verilator);

    let modes = [
        fpga_realtime,
        fpga_subsystem,
        verilator,
        emu_subsystem,
        emu_core,
    ];
    assert_eq!(modes.iter().filter(|&&b| b).count(), 1);

    println!("cargo::rustc-check-cfg=cfg(has_subsystem)");
    println!("cargo::rustc-check-cfg=cfg(is_fpga)");
    if fpga_subsystem || emu_subsystem {
        println!("cargo::rustc-cfg=has_subsystem");
    }
    if fpga_realtime || fpga_subsystem {
        println!("cargo::rustc-cfg=is_fpga");
    }
}
