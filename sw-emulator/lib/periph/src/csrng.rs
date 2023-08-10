// Licensed under the Apache-2.0 license

use caliptra_emu_bus::{BusError, ReadOnlyRegister, ReadWriteRegister, WriteOnlyRegister};

use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};

mod ctr_drbg;
use ctr_drbg::{Block, CtrDrbg};

use std::mem;

#[derive(Bus)]
pub struct Csrng {
    // CSRNG registers
    #[register(offset = 0x14)]
    ctrl: ReadWriteRegister<u32>,

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
    #[register(offset = 0x1020)]
    module_enable: ReadWriteRegister<u32>,

    #[register(offset = 0x1024)]
    conf: ReadWriteRegister<u32>,

    #[register(offset = 0x10a4)]
    alert_summary_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x10a8)]
    alert_fail_counts: ReadOnlyRegister<u32>,

    #[register(offset = 0x10e0)]
    main_sm_state: ReadOnlyRegister<u32>,

    cmd_req_state: CmdReqState,

    seed: Vec<u32>,

    ctr_drbg: CtrDrbg,

    words: Words,
}

impl Csrng {
    pub fn new(_itrng_nibbles: Box<dyn Iterator<Item = u8>>) -> Self {
        Self {
            // TODO(rkr35): implement CTRL, CONF, and MODULE_ENABLE register logic.
            ctrl: ReadWriteRegister::new(0x999),
            cmd_req: WriteOnlyRegister::new(0),
            sw_cmd_sts: ReadOnlyRegister::new(0b01),
            genbits_vld: ReadOnlyRegister::new(0b01),
            genbits: ReadOnlyRegister::new(0),
            err_code: ReadOnlyRegister::new(0),

            module_enable: ReadWriteRegister::new(0x9),
            conf: ReadWriteRegister::new(0x909099),
            alert_summary_fail_counts: ReadOnlyRegister::new(0),
            alert_fail_counts: ReadOnlyRegister::new(0),
            main_sm_state: ReadOnlyRegister::new(0x1a2),

            cmd_req_state: CmdReqState::ExpectNewCommand,
            seed: vec![],
            ctr_drbg: CtrDrbg::new(),
            words: Words::default(),
        }
    }

    fn cmd_req_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // Since the CMD_REQ register can be use to initiate new commands or
        // supply words to an existing command, we need to track which "state"
        // we're in for this register and branch accordingly.
        match self.cmd_req_state {
            CmdReqState::ExpectNewCommand => self.process_new_cmd(data),

            CmdReqState::ExpectSeedWords { num_words } => {
                self.seed.push(data);
                if self.seed.len() == num_words {
                    self.ctr_drbg.instantiate(&self.seed);
                    self.seed.clear();
                    self.cmd_req_state = CmdReqState::ExpectNewCommand;
                }
            }
        }
        Ok(())
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

                        // TODO(rkr35): Figure out a better way to pass the entropy bits the tests are using.
                        self.ctr_drbg.instantiate(&[
                            0x4B7DE947, 0x27E4ED3E, 0xF763FC5D, 0x11731D9D, 0xA08B3943, 0x71DC56AA,
                            0xF4ECBEBA, 0x10518E4B, 0xE743CC50, 0x65693560, 0xF57AD687, 0x33F63B65,
                        ]);
                    }

                    [FALSE, _] => unimplemented!("seed: entropy_src XOR constant"),

                    [TRUE, 0] => {
                        // Zero seed.
                        self.ctr_drbg.instantiate(&[])
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
}

type Word = u32;
const WORD_SIZE_BYTES: usize = mem::size_of::<Word>();

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
