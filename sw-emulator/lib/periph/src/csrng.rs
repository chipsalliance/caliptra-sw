// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{BusError, ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use caliptra_registers::entropy_src::regs::{
    AdaptpHiThresholdsReadVal, AdaptpLoThresholdsReadVal, ConfReadVal, RepcntThresholdsReadVal,
};
use sha3::{Digest, Sha3_384};
use std::mem;

mod health_test;
use health_test::HealthTester;

mod ctr_drbg;
use ctr_drbg::{Block, CtrDrbg, Instantiate, Seed};

type Word = u32;

const BITS_PER_NIBBLE: usize = 4;
const WORD_SIZE_BYTES: usize = mem::size_of::<Word>();

#[derive(Bus)]
pub struct Csrng {
    // CSRNG registers
    #[register(offset = 0x14)]
    ctrl: u32,

    #[register(offset = 0x18, write_fn = cmd_req_write)]
    cmd_req: WriteOnlyRegister<u32>,

    #[register(offset = 0x1c)]
    sw_cmd_sts: ReadOnlyRegister<u32>,

    #[register(offset = 0x20, read_fn = genbits_vld_read)]
    genbits_vld: ReadOnlyRegister<u32>,

    #[register(offset = 0x24, read_fn = genbits_read)]
    genbits: ReadOnlyRegister<u32>,

    #[register(offset = 0x38)]
    err_code: ReadOnlyRegister<u32>,

    // Entropy Source registers
    #[register(offset = 0x1020, write_fn = module_enable_write)]
    module_enable: u32,

    #[register(offset = 0x1024)]
    conf: u32,

    #[register(offset = 0x1030)]
    health_test_windows: ReadOnlyRegister<u32>,

    #[register(offset = 0x1034, write_fn = repcnt_thresholds_write)]
    repcnt_thresholds: u32,

    #[register(offset = 0x103c, write_fn = adaptp_hi_thresholds_write)]
    adaptp_hi_thresholds: u32,

    #[register(offset = 0x1040, write_fn = adaptp_lo_thresholds_write)]
    adaptp_lo_thresholds: u32,

    #[register(offset = 0x10a4, read_fn = alert_summary_fail_counts_read)]
    alert_summary_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x10a8, read_fn = alert_fail_counts_read)]
    alert_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x10e0, read_fn = main_sm_state_read)]
    main_sm_state: ReadOnlyRegister<u32>,

    cmd_req_state: CmdReqState,
    seed: Vec<u32>,
    ctr_drbg: CtrDrbg,
    words: Words,
    health_tester: HealthTester,
}

impl Csrng {
    pub fn new(itrng_nibbles: Box<dyn Iterator<Item = u8>>) -> Self {
        Self {
            // These reset values come from register definitions
            ctrl: 0x999,
            cmd_req: WriteOnlyRegister::new(0),
            sw_cmd_sts: ReadOnlyRegister::new(0b01),
            genbits_vld: ReadOnlyRegister::new(0b01),
            genbits: ReadOnlyRegister::new(0),
            err_code: ReadOnlyRegister::new(0),
            module_enable: 0x9,
            conf: 0x909099,
            health_test_windows: ReadOnlyRegister::new(0x600200),
            repcnt_thresholds: 0xffffffff,
            adaptp_hi_thresholds: 0xffffffff,
            adaptp_lo_thresholds: 0,
            alert_summary_fail_counts: ReadOnlyRegister::new(0),
            alert_fail_counts: ReadOnlyRegister::new(0),
            main_sm_state: ReadOnlyRegister::new(0x2c), // StartupHTStart, entropy_src_main_sm_pkg.sv

            cmd_req_state: CmdReqState::ExpectNewCommand,
            seed: vec![],
            ctr_drbg: CtrDrbg::new(),
            words: Words::default(),
            health_tester: HealthTester::new(itrng_nibbles),
        }
    }

    fn cmd_req_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // Since the CMD_REQ register can be used to initiate new commands or
        // supply words to an existing command, we need to track which "state"
        // we're in for this register and branch accordingly.
        match self.cmd_req_state {
            CmdReqState::ExpectNewCommand => self.process_new_cmd(data),

            CmdReqState::ExpectSeedWords { num_words } => {
                self.seed.push(data);
                if self.seed.len() == num_words {
                    self.ctr_drbg.instantiate(Instantiate::Words(&self.seed));
                    self.seed.clear();
                    self.cmd_req_state = CmdReqState::ExpectNewCommand;
                }
            }
        }
        Ok(())
    }

    fn genbits_vld_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        if self.words.is_empty() {
            // Check if the CTR_DRBG has any bits for us.
            if let Some(block) = self.ctr_drbg.pop_block() {
                self.words = Words::new(block);
                Ok(0b01)
            } else {
                Ok(0b00)
            }
        } else {
            Ok(0b01)
        }
    }

    fn genbits_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        Ok(self.words.next().unwrap_or(0xCAFE_F00D))
    }

    fn module_enable_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        self.module_enable = data;

        if data == MultiBitBool::False as u32 {
            return Ok(());
        }

        if ConfReadVal::from(self.conf).fips_enable() == MultiBitBool::False as u32 {
            unimplemented!("emulation of non-FIPS mode");
        }

        self.health_tester.test_boot_window();

        Ok(())
    }

    fn repcnt_thresholds_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        self.health_tester
            .repcnt
            .set_threshold(RepcntThresholdsReadVal::from(data));
        Ok(())
    }

    fn adaptp_hi_thresholds_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        self.health_tester
            .adaptp
            .set_hi_threshold(AdaptpHiThresholdsReadVal::from(data));
        Ok(())
    }

    fn adaptp_lo_thresholds_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        self.health_tester
            .adaptp
            .set_lo_threshold(AdaptpLoThresholdsReadVal::from(data));
        Ok(())
    }

    fn alert_summary_fail_counts_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        let failures = self.health_tester.failures();
        self.alert_summary_fail_counts = ReadOnlyRegister::new(failures);
        Ok(failures)
    }

    fn alert_fail_counts_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        // Don't have a `AlertFailCountsWriteVal` from ureg, so let's  pack counts manually.
        let adapt_lo = self.health_tester.adaptp.lo_failures().min(0xf) & 0xf;
        let adapt_hi = self.health_tester.adaptp.hi_failures().min(0xf) & 0xf;
        let repcnt = self.health_tester.repcnt.failures().min(0xf) & 0xf;
        let fail_counts = (adapt_lo << 12) | (adapt_hi << 8) | (repcnt << 4);

        self.alert_fail_counts = ReadOnlyRegister::new(fail_counts);
        Ok(fail_counts)
    }

    fn main_sm_state_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        // https://opentitan.org/book/hw/ip/entropy_src/doc/theory_of_operation.html#main-state-machine-diagram
        // https://github.com/chipsalliance/caliptra-rtl/blob/main/src/entropy_src/rtl/entropy_src_main_sm_pkg.sv
        const ALERT_HANG: u32 = 0x15c;
        const CONT_HT_RUNNING: u32 = 0x1a2;

        let state = if self.health_tester.failures() > 0 {
            ALERT_HANG
        } else {
            CONT_HT_RUNNING
        };

        self.main_sm_state = ReadOnlyRegister::new(state);
        Ok(state)
    }

    fn process_new_cmd(&mut self, data: RvData) {
        const INSTANTIATE: u32 = 1;
        const GENERATE: u32 = 3;
        const UNINSTANTIATE: u32 = 5;

        let acmd = data & 0xf;
        let clen = (data >> 4) & 0xf;
        let flag0 = (data >> 8) & 0xf;
        let glen = (data >> 12) & 0x1fff;

        match acmd {
            INSTANTIATE => {
                const FALSE: u32 = MultiBitBool::False as u32;
                const TRUE: u32 = MultiBitBool::True as u32;

                // https://opentitan.org/book/hw/ip/csrng/doc/theory_of_operation.html#command-description
                match [flag0, clen] {
                    [FALSE, 0] => {
                        // Seed from entropy_src.
                        let seed = get_conditioned_seed(&mut self.health_tester);
                        self.ctr_drbg.instantiate(Instantiate::Bytes(&seed));
                    }

                    [FALSE, _] => unimplemented!("seed: entropy_src XOR constant"),

                    [TRUE, 0] => {
                        // Zero seed.
                        self.ctr_drbg.instantiate(Instantiate::default());
                    }

                    [TRUE, _] => {
                        self.cmd_req_state = CmdReqState::ExpectSeedWords {
                            num_words: clen as usize,
                        };
                    }

                    _ => unreachable!("invalid INSTANTIATE state: flag0={flag0}, clen={clen}"),
                }
            }

            GENERATE => {
                self.ctr_drbg.generate(glen as usize);
            }

            UNINSTANTIATE => {
                self.ctr_drbg.uninstantiate();
            }

            _ => {
                unimplemented!("CSRNG cmd: {acmd}");
            }
        }
    }
}

fn get_conditioned_seed(mut itrng_nibbles: impl Iterator<Item = u8>) -> Seed {
    // Replicate the logic in caliptra-rtl/src/entropy_src/rtl/entropy_src_core.sv.
    let mut hasher = Sha3_384::new();

    for _ in 0..64 {
        // Update the hasher in 64-bit packed entropy blocks.
        const NUM_NIBBLES: usize = 8 * mem::size_of::<u64>() / BITS_PER_NIBBLE;

        let packed_entropy = (0..NUM_NIBBLES).fold(0, |packed, i| {
            let nibble = itrng_nibbles
                .next()
                .expect("itrng iterator should provide at least 1024 nibbles in FIPS mode");
            packed | u64::from(nibble) << (i * BITS_PER_NIBBLE)
        });
        hasher.update(packed_entropy.to_le_bytes());
    }

    let mut digest = hasher.finalize();
    digest.as_mut_slice().reverse();
    digest
        .as_slice()
        .try_into()
        .expect("SHA3-384 should generate a 384 bit seed from raw entropy nibbles")
}

#[derive(Default)]
struct Words {
    block: Block,
    cursor: usize,
}

impl Words {
    pub fn new(block: Block) -> Self {
        Self {
            block,
            cursor: block.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Iterator for Words {
    type Item = Word;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == 0 {
            None
        } else {
            // We have to return, in reverse order, the words within this block.
            // Reverse order because of https://opentitan.org/book/hw/ip/csrng/doc/programmers_guide.html#endianness-and-known-answer-tests
            let start = self.cursor - WORD_SIZE_BYTES;
            let end = self.cursor;

            let word = &self.block[start..end];
            let word = word.try_into().expect("byte slice to 4-byte array");
            let word = u32::from_be_bytes(word);

            self.cursor = start;
            Some(word)
        }
    }
}

impl ExactSizeIterator for Words {
    fn len(&self) -> usize {
        self.cursor / WORD_SIZE_BYTES
    }
}

enum CmdReqState {
    ExpectNewCommand,
    ExpectSeedWords { num_words: usize },
}

#[repr(u32)]
enum MultiBitBool {
    False = 9,
    True = 6,
}
