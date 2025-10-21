/*++

Licensed under the Apache-2.0 license.

File Name:

    mci.rs

Abstract:

    File contains implementation of MCI

--*/

use std::{cell::RefCell, rc::Rc, sync::mpsc};

use bitfield::size_of;
use caliptra_emu_bus::{Bus, BusError, Device, Event, EventData};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use sha2::{Digest, Sha384};

const SS_MANUF_DBG_UNLOCK_FUSE_SIZE: usize = 48;
const SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES: usize = 8;

const NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK: u32 = 0x2;

#[derive(Bus)]
pub struct MciRegs {
    pub event_sender: Option<mpsc::Sender<Event>>,

    #[register(offset = 0x0)]
    pub hw_capabilities: u32,
    #[register(offset = 0x4)]
    pub fw_capabilities: u32,
    #[register(offset = 0x8)]
    pub cap_lock: u32,
    #[register(offset = 0xc)]
    pub hw_rev_id: u32,
    #[register_array(offset = 0x10)]
    pub fw_rev_id: [u32; 2],
    #[register(offset = 0x18)]
    pub hw_config0: u32,
    #[register(offset = 0x1c)]
    pub hw_config1: u32,
    #[register(offset = 0x20)]
    pub mcu_ifu_axi_user: u32,
    #[register(offset = 0x24)]
    pub mcu_lsu_axi_user: u32,
    #[register(offset = 0x28)]
    pub mcu_sram_config_axi_user: u32,
    #[register(offset = 0x2c)]
    pub mci_soc_config_axi_user: u32,
    #[register(offset = 0x30)]
    pub flow_status: u32,
    #[register(offset = 0x34)]
    pub hw_flow_status: u32,
    #[register(offset = 0x38)]
    pub reset_reason: u32,
    #[register(offset = 0x3c)]
    pub reset_status: u32,
    #[register(offset = 0x40)]
    pub security_state: u32,
    #[register(offset = 0x50)]
    pub hw_error_fatal: u32,
    #[register(offset = 0x54)]
    pub agg_error_fatal: u32,
    #[register(offset = 0x58)]
    pub hw_error_non_fatal: u32,
    #[register(offset = 0x5c)]
    pub agg_error_non_fatal: u32,
    #[register(offset = 0x60)]
    pub fw_error_fatal: u32,
    #[register(offset = 0x64)]
    pub fw_error_non_fatal: u32,
    #[register(offset = 0x68)]
    pub hw_error_enc: u32,
    #[register(offset = 0x6c)]
    pub fw_error_enc: u32,
    #[register_array(offset = 0x70)]
    pub fw_extended_error_info: [u32; 8],
    #[register(offset = 0x90)]
    pub internal_hw_error_fatal_mask: u32,
    #[register(offset = 0x94)]
    pub internal_hw_error_non_fatal_mask: u32,
    #[register(offset = 0x98)]
    pub internal_agg_error_fatal_mask: u32,
    #[register(offset = 0x9c)]
    pub internal_agg_error_non_fatal_mask: u32,
    #[register(offset = 0xa0)]
    pub internal_fw_error_fatal_mask: u32,
    #[register(offset = 0xa4)]
    pub internal_fw_error_non_fatal_mask: u32,
    #[register(offset = 0xb0)]
    pub wdt_timer1_en: u32,
    #[register(offset = 0xb4)]
    pub wdt_timer1_ctrl: u32,
    #[register_array(offset = 0xb8)]
    pub wdt_timer1_timeout_period: [u32; 2],
    #[register(offset = 0xc0)]
    pub wdt_timer2_en: u32,
    #[register(offset = 0xc4)]
    pub wdt_timer2_ctrl: u32,
    #[register_array(offset = 0xc8)]
    pub wdt_timer2_timeout_period: [u32; 2],
    #[register(offset = 0xd0)]
    pub wdt_status: u32,
    #[register_array(offset = 0xd4)]
    pub wdt_cfg: [u32; 2],
    #[register(offset = 0xe0)]
    pub mcu_timer_config: u32,
    #[register(offset = 0xe4)]
    pub mcu_rv_mtime_l: u32,
    #[register(offset = 0xe8)]
    pub mcu_rv_mtime_h: u32,
    #[register(offset = 0xec)]
    pub mcu_rv_mtimecmp_l: u32,
    #[register(offset = 0xf0)]
    pub mcu_rv_mtimecmp_h: u32,
    #[register(offset = 0x100)]
    pub reset_request: u32,
    #[register(offset = 0x104)]
    pub mci_bootfsm_go: u32,
    #[register(offset = 0x108)]
    pub cptra_boot_go: u32,
    #[register(offset = 0x10c)]
    pub fw_sram_exec_region_size: u32,
    #[register(offset = 0x110)]
    pub mcu_nmi_vector: u32,
    #[register(offset = 0x114)]
    pub mcu_reset_vector: u32,
    #[register_array(offset = 0x180)]
    pub mbox0_valid_axi_user: [u32; 5],
    #[register_array(offset = 0x1a0)]
    pub mbox0_axi_user_lock: [u32; 5],
    #[register_array(offset = 0x1c0)]
    pub mbox1_valid_axi_user: [u32; 5],
    #[register_array(offset = 0x1e0)]
    pub mbox1_axi_user_lock: [u32; 5],
    #[register_array(offset = 0x300)]
    pub soc_dft_en: [u32; 2],
    #[register_array(offset = 0x308)]
    pub soc_hw_debug_en: [u32; 2],
    #[register_array(offset = 0x310)]
    pub soc_prod_debug_state: [u32; 2],
    #[register(offset = 0x318)]
    pub fc_fips_zerozation: u32,
    #[register_array(offset = 0x400)]
    pub generic_input_wires: [u32; 2],
    #[register_array(offset = 0x408)]
    pub generic_output_wires: [u32; 2],
    #[register(offset = 0x410)]
    pub debug_in: u32,
    #[register(offset = 0x414)]
    pub debug_out: u32,
    #[register(offset = 0x418)]
    pub ss_debug_intent: u32,
    #[register(offset = 0x440)]
    pub ss_config_done_sticky: u32,
    #[register(offset = 0x444)]
    pub ss_config_done: u32,
    #[register_array(offset = 0x480)]
    pub prod_debug_unlock_pk_hash_reg: [u32; 96],
    #[register_array(offset = 0xa00)]
    fuses: [u32; SS_MANUF_DBG_UNLOCK_FUSE_SIZE / size_of::<u32>()
        * SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES],
    #[register(offset = 0x1000)]
    pub intr_block_rf_global_intr_en_r: u32,
    #[register(offset = 0x1004)]
    pub intr_block_rf_error0_intr_en_r: u32,
    #[register(offset = 0x1008)]
    pub intr_block_rf_error1_intr_en_r: u32,
    #[register(offset = 0x100c)]
    pub intr_block_rf_notif0_intr_en_r: u32,
    #[register(offset = 0x1010)]
    pub intr_block_rf_notif1_intr_en_r: u32,
    #[register(offset = 0x1014)]
    pub intr_block_rf_error_global_intr_r: u32,
    #[register(offset = 0x1018)]
    pub intr_block_rf_notif_global_intr_r: u32,
    #[register(offset = 0x101c)]
    pub intr_block_rf_error0_internal_intr_r: u32,
    #[register(offset = 0x1020)]
    pub intr_block_rf_error1_internal_intr_r: u32,
    #[register(offset = 0x1024)]
    pub intr_block_rf_notif0_internal_intr_r: u32,
    #[register(offset = 0x1028)]
    pub intr_block_rf_notif1_internal_intr_r: u32,
    #[register(offset = 0x102c)]
    pub intr_block_rf_error0_intr_trig_r: u32,
    #[register(offset = 0x1030)]
    pub intr_block_rf_error1_intr_trig_r: u32,
    #[register(offset = 0x1034, write_fn = on_write_intr_block_rf_notif0_intr_trig_r)]
    pub intr_block_rf_notif0_intr_trig_r: u32,
    #[register(offset = 0x1038)]
    pub intr_block_rf_notif1_intr_trig_r: u32,
    #[register(offset = 0x1100)]
    pub intr_block_rf_error_internal_intr_count_r: u32,
    #[register(offset = 0x1104)]
    pub intr_block_rf_error_mbox0_ecc_unc_intr_count_r: u32,
    #[register(offset = 0x1108)]
    pub intr_block_rf_error_mbox1_ecc_unc_intr_count_r: u32,
    #[register(offset = 0x110c)]
    pub intr_block_rf_error_mcu_sram_dmi_axi_collision_intr_count_r: u32,
    #[register(offset = 0x1110)]
    pub intr_block_rf_error_wdt_timer1_timeout_intr_count_r: u32,
    #[register(offset = 0x1114)]
    pub intr_block_rf_error_wdt_timer2_timeout_intr_count_r: u32,
    #[register(offset = 0x1118)]
    pub intr_block_rf_error_agg_error_fatal0_intr_count_r: u32,
    #[register(offset = 0x111c)]
    pub intr_block_rf_error_agg_error_fatal1_intr_count_r: u32,
    #[register(offset = 0x1120)]
    pub intr_block_rf_error_agg_error_fatal2_intr_count_r: u32,
    #[register(offset = 0x1124)]
    pub intr_block_rf_error_agg_error_fatal3_intr_count_r: u32,
    #[register(offset = 0x1128)]
    pub intr_block_rf_error_agg_error_fatal4_intr_count_r: u32,
    #[register(offset = 0x112c)]
    pub intr_block_rf_error_agg_error_fatal5_intr_count_r: u32,
    #[register(offset = 0x1130)]
    pub intr_block_rf_error_agg_error_fatal6_intr_count_r: u32,
    #[register(offset = 0x1134)]
    pub intr_block_rf_error_agg_error_fatal7_intr_count_r: u32,
    #[register(offset = 0x1138)]
    pub intr_block_rf_error_agg_error_fatal8_intr_count_r: u32,
    #[register(offset = 0x113c)]
    pub intr_block_rf_error_agg_error_fatal9_intr_count_r: u32,
    #[register(offset = 0x1140)]
    pub intr_block_rf_error_agg_error_fatal10_intr_count_r: u32,
    #[register(offset = 0x1144)]
    pub intr_block_rf_error_agg_error_fatal11_intr_count_r: u32,
    #[register(offset = 0x1148)]
    pub intr_block_rf_error_agg_error_fatal12_intr_count_r: u32,
    #[register(offset = 0x114c)]
    pub intr_block_rf_error_agg_error_fatal13_intr_count_r: u32,
    #[register(offset = 0x1150)]
    pub intr_block_rf_error_agg_error_fatal14_intr_count_r: u32,
    #[register(offset = 0x1154)]
    pub intr_block_rf_error_agg_error_fatal15_intr_count_r: u32,
    #[register(offset = 0x1158)]
    pub intr_block_rf_error_agg_error_fatal16_intr_count_r: u32,
    #[register(offset = 0x115c)]
    pub intr_block_rf_error_agg_error_fatal17_intr_count_r: u32,
    #[register(offset = 0x1160)]
    pub intr_block_rf_error_agg_error_fatal18_intr_count_r: u32,
    #[register(offset = 0x1164)]
    pub intr_block_rf_error_agg_error_fatal19_intr_count_r: u32,
    #[register(offset = 0x1168)]
    pub intr_block_rf_error_agg_error_fatal20_intr_count_r: u32,
    #[register(offset = 0x116c)]
    pub intr_block_rf_error_agg_error_fatal21_intr_count_r: u32,
    #[register(offset = 0x1170)]
    pub intr_block_rf_error_agg_error_fatal22_intr_count_r: u32,
    #[register(offset = 0x1174)]
    pub intr_block_rf_error_agg_error_fatal23_intr_count_r: u32,
    #[register(offset = 0x1178)]
    pub intr_block_rf_error_agg_error_fatal24_intr_count_r: u32,
    #[register(offset = 0x117c)]
    pub intr_block_rf_error_agg_error_fatal25_intr_count_r: u32,
    #[register(offset = 0x1180)]
    pub intr_block_rf_error_agg_error_fatal26_intr_count_r: u32,
    #[register(offset = 0x1184)]
    pub intr_block_rf_error_agg_error_fatal27_intr_count_r: u32,
    #[register(offset = 0x1188)]
    pub intr_block_rf_error_agg_error_fatal28_intr_count_r: u32,
    #[register(offset = 0x118c)]
    pub intr_block_rf_error_agg_error_fatal29_intr_count_r: u32,
    #[register(offset = 0x1190)]
    pub intr_block_rf_error_agg_error_fatal30_intr_count_r: u32,
    #[register(offset = 0x1194)]
    pub intr_block_rf_error_agg_error_fatal31_intr_count_r: u32,
}

impl MciRegs {
    pub const SS_MANUF_DBG_UNLOCK_FUSE_OFFSET: usize = 0xa00;
    pub const SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES: usize = SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES;

    pub fn new(key_pairs: Vec<(&[u8; 96], &[u8; 2592])>) -> Self {
        Self {
            event_sender: None,

            hw_capabilities: 0,
            fw_capabilities: 0,
            cap_lock: 0,
            hw_rev_id: 0,
            fw_rev_id: [0; 2],
            hw_config0: 0,
            hw_config1: 0,
            mcu_ifu_axi_user: 0,
            mcu_lsu_axi_user: 0,
            mcu_sram_config_axi_user: 0,
            mci_soc_config_axi_user: 0,
            flow_status: 0,
            hw_flow_status: 0,
            reset_reason: 0,
            reset_status: 0x2, // MCU on reset
            security_state: 0,
            hw_error_fatal: 0,
            agg_error_fatal: 0,
            hw_error_non_fatal: 0,
            agg_error_non_fatal: 0,
            fw_error_fatal: 0,
            fw_error_non_fatal: 0,
            hw_error_enc: 0,
            fw_error_enc: 0,
            fw_extended_error_info: [0; 8],
            internal_hw_error_fatal_mask: 0,
            internal_hw_error_non_fatal_mask: 0,
            internal_agg_error_fatal_mask: 0,
            internal_agg_error_non_fatal_mask: 0,
            internal_fw_error_fatal_mask: 0,
            internal_fw_error_non_fatal_mask: 0,
            wdt_timer1_en: 0,
            wdt_timer1_ctrl: 0,
            wdt_timer1_timeout_period: [0xffff_ffff; 2],
            wdt_timer2_en: 0,
            wdt_timer2_ctrl: 0,
            wdt_timer2_timeout_period: [0xffff_ffff; 2],
            wdt_status: 0,
            wdt_cfg: [0; 2],
            mcu_timer_config: 0,
            mcu_rv_mtime_l: 0,
            mcu_rv_mtime_h: 0,
            mcu_rv_mtimecmp_l: 0,
            mcu_rv_mtimecmp_h: 0,
            reset_request: 0,
            mci_bootfsm_go: 0,
            cptra_boot_go: 0,
            fw_sram_exec_region_size: 0,
            mcu_nmi_vector: 0,
            mcu_reset_vector: 0,
            mbox0_valid_axi_user: [0; 5],
            mbox0_axi_user_lock: [0; 5],
            mbox1_valid_axi_user: [0; 5],
            mbox1_axi_user_lock: [0; 5],
            soc_dft_en: [0; 2],
            soc_hw_debug_en: [0; 2],
            soc_prod_debug_state: [0; 2],
            fc_fips_zerozation: 0,
            generic_input_wires: [0; 2],
            generic_output_wires: [0; 2],
            debug_in: 0,
            debug_out: 0,
            ss_debug_intent: 0,
            ss_config_done_sticky: 0,
            ss_config_done: 0,
            prod_debug_unlock_pk_hash_reg: [0; 96],
            fuses: {
                let mut fuses = [0; SS_MANUF_DBG_UNLOCK_FUSE_SIZE / size_of::<u32>()
                    * SS_MANUF_DBG_UNLOCK_NUMBER_OF_FUSES];
                key_pairs.iter().enumerate().for_each(|(i, (ecc, mldsa))| {
                    // Create a single hasher for the concatenated keys
                    let mut hasher = Sha384::new();
                    hasher.update(ecc);
                    hasher.update(mldsa);
                    let hash = hasher.finalize();

                    // Copy hash into fuses array (64 bytes / 16 u32s)
                    let base_idx = i * (SS_MANUF_DBG_UNLOCK_FUSE_SIZE / size_of::<u32>());
                    hash.chunks(4).enumerate().for_each(|(j, chunk)| {
                        // Program the hash in hardware format i.e. little endian.
                        let value = u32::from_be_bytes(chunk.try_into().unwrap());
                        fuses[base_idx + j] = value;
                    });
                });
                fuses
            },
            intr_block_rf_global_intr_en_r: 0,
            intr_block_rf_error0_intr_en_r: 0,
            intr_block_rf_error1_intr_en_r: 0,
            intr_block_rf_notif0_intr_en_r: 0,
            intr_block_rf_notif1_intr_en_r: 0,
            intr_block_rf_error_global_intr_r: 0,
            intr_block_rf_notif_global_intr_r: 0,
            intr_block_rf_error0_internal_intr_r: 0,
            intr_block_rf_error1_internal_intr_r: 0,
            intr_block_rf_notif0_internal_intr_r: 0,
            intr_block_rf_notif1_internal_intr_r: 0,
            intr_block_rf_error0_intr_trig_r: 0,
            intr_block_rf_error1_intr_trig_r: 0,
            intr_block_rf_notif0_intr_trig_r: 0,
            intr_block_rf_notif1_intr_trig_r: 0,
            intr_block_rf_error_internal_intr_count_r: 0,
            intr_block_rf_error_mbox0_ecc_unc_intr_count_r: 0,
            intr_block_rf_error_mbox1_ecc_unc_intr_count_r: 0,
            intr_block_rf_error_mcu_sram_dmi_axi_collision_intr_count_r: 0,
            intr_block_rf_error_wdt_timer1_timeout_intr_count_r: 0,
            intr_block_rf_error_wdt_timer2_timeout_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal0_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal1_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal2_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal3_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal4_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal5_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal6_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal7_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal8_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal9_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal10_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal11_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal12_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal13_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal14_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal15_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal16_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal17_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal18_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal19_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal20_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal21_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal22_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal23_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal24_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal25_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal26_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal27_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal28_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal29_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal30_intr_count_r: 0,
            intr_block_rf_error_agg_error_fatal31_intr_count_r: 0,
        }
    }
    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        println!("[MCI] Registering outgoing events");
        self.event_sender = Some(sender);
    }
    fn cptra_request_mcu_reset(&mut self) {
        self.intr_block_rf_notif0_internal_intr_r |= NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK;
        if let Some(sender) = &self.event_sender {
            sender
                .send(Event::new(
                    Device::CaliptraCore,
                    Device::MCU,
                    EventData::MciInterrupt { asserted: true },
                ))
                .unwrap();
        }
    }
    fn on_write_intr_block_rf_notif0_intr_trig_r(
        &mut self,
        _size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        if val & NOTIF_CPTRA_MCU_RESET_REQ_STS_MASK != 0 {
            self.cptra_request_mcu_reset();
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Mci {
    pub regs: Rc<RefCell<MciRegs>>,
}

impl Mci {
    /// Create a new instance of SHA-512 Accelerator
    pub fn new(key_pairs: Vec<(&[u8; 96], &[u8; 2592])>) -> Self {
        Self {
            regs: Rc::new(RefCell::new(MciRegs::new(key_pairs))),
        }
    }
    pub fn cptra_request_mcu_reset(&self) {
        self.regs.borrow_mut().cptra_request_mcu_reset();
    }
}

impl Bus for Mci {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.regs.borrow_mut().read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        self.regs.borrow_mut().write(size, addr, val)
    }

    fn poll(&mut self) {
        self.regs.borrow_mut().poll();
    }

    fn warm_reset(&mut self) {
        self.regs.borrow_mut().warm_reset();
    }

    fn update_reset(&mut self) {
        self.regs.borrow_mut().update_reset();
    }
    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        println!("[MCI] Registering outgoing events");
        self.regs
            .borrow_mut()
            .register_outgoing_events(sender.clone());
    }
}
