// Licensed under the Apache-2.0 license.

#![allow(dead_code)]

use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};
use tock_registers::{register_bitfields, register_structs};

register_bitfields! {
    u32,
    pub Control [
        CptraPwrgood OFFSET(0) NUMBITS(1) [],
        CptraSsRstB OFFSET(1) NUMBITS(1) [],
        CptraObfUdsSeedVld OFFSET(2) NUMBITS(1) [],
        CptraObfFieldEntropyVld OFFSET(3) NUMBITS(1) [],
        RsvdDbgLocked OFFSET(4) NUMBITS(1) [],
        RsvdDeviceLifecycle OFFSET(5) NUMBITS(2) [],
        BootfsmBrkpoint OFFSET(7) NUMBITS(1) [],
        ScanMode OFFSET(8) NUMBITS(1) [],

        SsDebugIntent OFFSET(16) NUMBITS(1) [],
        I3cAxiUserIdFiltering OFFSET(17) NUMBITS(1) [],
        OcpLockEn OFFSET(18) NUMBITS(1) [],
        LcAllowRmaOrScrapOnPpd OFFSET(19) NUMBITS(1) [],
        FipsZeroizationPpd OFFSET(20) NUMBITS(1) [],
        AxiReset OFFSET(31) NUMBITS(1) [],
    ],
    pub MciError [
        MciErrorFatal OFFSET(0) NUMBITS(1) [],
        MciErrorNonFatal OFFSET(1) NUMBITS(1) [],
    ],
    pub McuConfig [
        McuNoRomConfig OFFSET(0) NUMBITS(1) [],
        CptraSsMciBootSeqBrkpointI OFFSET(1) NUMBITS(1) [],
        CptraSsLcAllowRmaOnPpdI OFFSET(2) NUMBITS(1) [],
        CptraSsLcCtrlScanRstNiI OFFSET(3) NUMBITS(1) [],
        CptraSsLcEsclateScrapState0I OFFSET(4) NUMBITS(1) [],
        CptraSsLcEsclateScrapState1I OFFSET(5) NUMBITS(1) [],
    ],
    pub Status [
        CptraErrorFatal OFFSET(0) NUMBITS(1) [],
        CptraErrorNonFatal OFFSET(1) NUMBITS(1) [],
        ReadyForFuses OFFSET(2) NUMBITS(1) [],
        ReadyForFwPush OFFSET(3) NUMBITS(1) [],
        ReadyForRuntime OFFSET(4) NUMBITS(1) [],
        MailboxDataAvail OFFSET(5) NUMBITS(1) [],
        MailboxFlowDone OFFSET(6) NUMBITS(1) [],
    ],
    pub FifoStatus [
        Empty OFFSET(0) NUMBITS(1) [],
        Full OFFSET(1) NUMBITS(1) [],
    ],
    pub ItrngFifoStatus [
        Empty OFFSET(0) NUMBITS(1) [],
        Full OFFSET(1) NUMBITS(1) [],
        Reset OFFSET(2) NUMBITS(1) [],
    ],
    pub FifoData [
        NextChar OFFSET(0) NUMBITS(8) [],
        CharValid OFFSET(8) NUMBITS(1) [],
    ],
    pub FlashControl [
        START OFFSET(0) NUMBITS(1) [],
        OP OFFSET(1) NUMBITS(2) [],
    ],
    pub FlashOpStatus [
        DONE OFFSET(0) NUMBITS(1) [],
        ERR OFFSET(1) NUMBITS(3) [],
    ],
    pub FlashCtrlRegwen [
        EN OFFSET(0) NUMBITS(1) [],
    ],
}

register_structs! {
    pub FifoRegs {
        (0x0 => pub log_fifo_data: ReadOnly<u32, FifoData::Register>),
        (0x4 => pub log_fifo_status: ReadOnly<u32, FifoStatus::Register>),
        (0x8 => pub itrng_fifo_data: ReadWrite<u32>),
        (0xc => pub itrng_fifo_status: ReadWrite<u32, ItrngFifoStatus::Register>),
        (0x10 => pub dbg_fifo_data_pop: ReadOnly<u32, FifoData::Register>),
        (0x14 => pub dbg_fifo_data_push: WriteOnly<u32, FifoData::Register>),
        (0x18 => pub dbg_fifo_status: ReadOnly<u32, FifoStatus::Register>),
        (0x1c => @END),
    },
    pub FlashCtrlRegs {
        (0x00 => pub fl_interrupt_state: ReadWrite<u32>),
        (0x04 => pub fl_interrupt_enable: ReadWrite<u32>),
        (0x08 => pub page_size: ReadWrite<u32>),
        (0x0c => pub page_num: ReadWrite<u32>),
        (0x10 => pub page_addr: ReadWrite<u32>),
        (0x14 => pub fl_control: ReadWrite<u32, FlashControl::Register>),
        (0x18 => pub op_status: ReadWrite<u32, FlashOpStatus::Register>),
        (0x1c => pub ctrl_regwen: ReadWrite<u32, FlashCtrlRegwen::Register>),
        (0x20 => pub flash_size: ReadWrite<u32>),
        (0x24 => _reserved0),
        (0x100 => pub buffer: [ReadWrite<u32>; 64]),
        (0x200 => @END),
    },
    pub WrapperRegs {
        (0x0 => pub fpga_magic: ReadOnly<u32>),
        (0x4 => pub fpga_version: ReadOnly<u32>),
        (0x8 => pub control: ReadWrite<u32, Control::Register>),
        (0xc => pub status: ReadOnly<u32, Status::Register>),
        (0x10 => pub arm_user: ReadWrite<u32>),
        (0x14 => pub itrng_divisor: ReadWrite<u32>),
        (0x18 => pub cycle_count: ReadOnly<u32>),
        (0x1c => _reserved0),
        (0x30 => pub generic_input_wires: [ReadWrite<u32>; 2]),
        (0x38 => pub generic_output_wires: [ReadOnly<u32>; 2]),
        (0x40 => pub cptra_obf_key: [ReadWrite<u32>; 8]),
        (0x60 => pub cptra_csr_hmac_key: [ReadWrite<u32>; 16]),
        (0xa0 => pub cptra_obf_uds_seed: [ReadWrite<u32>; 16]),
        (0xe0 => pub cptra_obf_field_entropy: [ReadWrite<u32>; 8]),
        (0x100 => pub lsu_user: ReadWrite<u32>),
        (0x104 => pub ifu_user: ReadWrite<u32>),
        (0x108 => pub dma_axi_user: ReadWrite<u32>),
        (0x10c => pub soc_config_user: ReadWrite<u32>),
        (0x110 => pub sram_config_user: ReadWrite<u32>),
        (0x114 => pub mcu_reset_vector: ReadWrite<u32>),
        (0x118 => pub mci_error: ReadOnly<u32, MciError::Register>),
        (0x11c => pub mcu_config: ReadWrite<u32, McuConfig::Register>),
        (0x120 => pub uds_seed_base_addr: ReadWrite<u32>),
        (0x124 => pub prod_debug_unlock_auth_pk_hash_reg_bank_offset: ReadWrite<u32>),
        (0x128 => pub num_of_prod_debug_unlock_auth_pk_hashes: ReadWrite<u32>),
        (0x12c => pub mci_generic_input_wires: [ReadWrite<u32>; 2]),
        (0x134 => pub mci_generic_output_wires: [ReadOnly<u32>; 2]),
        (0x13c => pub ss_key_release_base_addr: ReadOnly<u32>),
        (0x140 => pub ss_key_release_key_size: ReadOnly<u32>),
        (0x144 => pub ss_external_staging_area_base_addr: ReadOnly<u32>),
        (0x148 => pub cptra_ss_mcu_ext_int: ReadWrite<u32>),
        (0x14c => pub cptr_ss_raw_unlock_token_hash: [ReadWrite<u32>; 4]),
        (0x15c => _reserved1),
        (0x200 => pub ocp_lock_key_release_reg: [ReadWrite<u32>; 16]),
        (0x240 => @END),
    }
}
