/*++

Licensed under the Apache-2.0 license.

File Name:

    hand_off.rs

    Implements handoff behavior of FMC :
        - Retrieves FHT table from fixed address in DCCM.
        - Transfers control to the runtime firmware.
++*/

use crate::fmc_env::FmcEnv;
use caliptra_common::{cprintln, FirmwareHandoffTable};
use caliptra_drivers::WarmResetEntry4;

#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("transfer_control.S"));

const ICCM_ORG: u32 = 0x40000000;
const ICCM_SIZE: u32 = 128 << 10;

struct MemoryRegion {
    start: u32,
    size: u32,
}

impl MemoryRegion {
    fn validate_address(&self, phys_addr: u32) -> bool {
        phys_addr >= self.start && phys_addr <= self.start + self.size
    }
}

const ICCM: MemoryRegion = MemoryRegion {
    start: ICCM_ORG,
    size: ICCM_SIZE,
};

pub struct HandOff {
    fht: FirmwareHandoffTable,
}

pub fn dump_fht(fht: &FirmwareHandoffTable) {
    cprintln!("[fmc] FHT Marker: 0x{:08X}", fht.fht_marker);
    cprintln!("[fmc] FHT Major Version: 0x{:04X}", fht.fht_major_ver);
    cprintln!("[fmc] FHT Minor Version: 0x{:04X}", fht.fht_minor_ver);
    cprintln!("[fmc] FHT Manifest Addr: 0x{:08X}", fht.manifest_load_addr);
    cprintln!("[fmc] FHT FMC CDI KV KeyID: {}", fht.fmc_cdi_kv_idx);
    cprintln!(
        "[fmc] FHT FMC PrivKey KV KeyID: {}",
        fht.fmc_priv_key_kv_idx
    );
    cprintln!(
        "[fmc] FHT RT Load Address: 0x{:08x}",
        fht.rt_fw_entry_point_idx
    );
    cprintln!(
        "[fmc] FHT RT Entry Point: 0x{:08x}",
        fht.rt_fw_load_addr_idx
    );
}

impl HandOff {
    pub fn from_previous() -> Option<HandOff> {
        if let Some(fht) = FirmwareHandoffTable::try_load() {
            dump_fht(&fht);
            let me = Self { fht };
            return Some(me);
        }
        None
    }

    pub fn to_rt(&self, env: &FmcEnv) -> ! {
        // Function is defined in start.S
        extern "C" {
            fn transfer_control(entry: u32) -> !;
        }
        let rt_entry = self.rt_entry_point(env);
        cprintln!("[exit] Launching RT @ 0x{:08X}", rt_entry);

        if !ICCM.validate_address(rt_entry) {
            crate::report_error(0xdead);
        }
        // Exit FMC and jump to speicified entry point
        unsafe { transfer_control(rt_entry) }
    }

    fn rt_entry_point(&self, env: &FmcEnv) -> u32 {
        env.data_vault().map(|d| {
            d.read_warm_reset_entry4(
                WarmResetEntry4::try_from(self.fht.rt_fw_entry_point_idx)
                    .unwrap_or_else(|_| crate::report_error(0xdead)),
            )
        })
    }
}
