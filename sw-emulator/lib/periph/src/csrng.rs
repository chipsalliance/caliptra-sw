// Licensed under the Apache-2.0 license

use crate::entropy_combiner::CombinerLink;
use crate::entropy_src::{ConditionedSeed, SharedEntropySrc};
use crate::helpers::{bytes_from_words_be, MultiBitBool};
use caliptra_emu_bus::{BusError, ReadOnlyRegister, WriteOnlyRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use std::{mem, rc::Rc};
use tock_registers::interfaces::Readable;

mod ctr_drbg;
pub(crate) use ctr_drbg::Seed;
use ctr_drbg::{Block, CtrDrbg, Instantiate, SEED_LEN_BYTES};

type Word = u32;
const WORD_SIZE_BYTES: usize = mem::size_of::<Word>();

#[derive(Clone)]
struct EntropyInputs {
    es0: SharedEntropySrc,
    topology: EntropyTopology,
}

#[derive(Clone)]
enum EntropyTopology {
    Single,
    Dual {
        es1: SharedEntropySrc,
        combiner: Rc<CombinerLink>,
    },
}

#[derive(Clone, Copy)]
enum SeedCommand {
    Instantiate,
    Reseed,
}

struct PendingSeed {
    command: SeedCommand,
    combiner_zeroize_epoch: u64,
    source_seeds: [Option<ConditionedSeed>; 2],
}

#[derive(Bus)]
#[warm_reset_fn(warm_reset)]
pub struct Csrng {
    // CSRNG registers
    #[register(offset = 0x14, write_fn = ctrl_write)]
    ctrl: u32,

    #[register(offset = 0x18, write_fn = cmd_req_write)]
    cmd_req: WriteOnlyRegister<u32>,

    #[register(offset = 0x1C, write_fn = reseed_interval_write)]
    reseed_interval: u32,

    // SW app instance counter (NumApps=3, instance 2 is what the driver reads).
    #[register(offset = 0x28, read_fn = reseed_counter_read)]
    reseed_counter_2: ReadOnlyRegister<u32>,

    #[register(offset = 0x2c, read_fn = read_command_status)]
    sw_cmd_sts: ReadOnlyRegister<u32>,

    #[register(offset = 0x30, read_fn = genbits_vld_read)]
    genbits_vld: ReadOnlyRegister<u32>,

    #[register(offset = 0x34, read_fn = genbits_read)]
    genbits: ReadOnlyRegister<u32>,

    // MAIN_SM_STATE is Idle except while waiting for a dual entropy seed.
    #[register(offset = 0x5c, read_fn = read_csrng_state)]
    main_sm_state_csrng: ReadOnlyRegister<u32>,

    #[register(offset = 0x54)]
    err_code: ReadOnlyRegister<u32>,

    cmd_req_state: CmdReqState,
    seed: Vec<u32>,
    update: Vec<u32>,
    ctr_drbg: CtrDrbg,
    words: Words,
    entropy: EntropyInputs,
    pending_seed: Option<PendingSeed>,
    output_fips: bool,
}

impl Csrng {
    pub(crate) fn new(es0: SharedEntropySrc) -> Self {
        Self::with_entropy(EntropyInputs {
            es0,
            topology: EntropyTopology::Single,
        })
    }

    fn with_entropy(entropy: EntropyInputs) -> Self {
        Self {
            // These reset values come from register definitions
            ctrl: 0x999,
            cmd_req: WriteOnlyRegister::new(0),
            reseed_interval: 0xffffffff,
            reseed_counter_2: ReadOnlyRegister::new(0),
            sw_cmd_sts: ReadOnlyRegister::new(0b110), // cmd_rdy=1, cmd_ack=1, cmd_sts=0
            genbits_vld: ReadOnlyRegister::new(0b01),
            genbits: ReadOnlyRegister::new(0),
            main_sm_state_csrng: ReadOnlyRegister::new(0x4e), // MainSmIdle (csrng_pkg.sv)
            err_code: ReadOnlyRegister::new(0),
            cmd_req_state: CmdReqState::NewCommand,
            seed: vec![],
            update: vec![],
            ctr_drbg: CtrDrbg::new(),
            words: Words::default(),
            entropy,
            pending_seed: None,
            output_fips: false,
        }
    }

    pub(crate) fn enable_dual(&mut self, es1: SharedEntropySrc, combiner: Rc<CombinerLink>) {
        self.entropy.topology = EntropyTopology::Dual { es1, combiner };
    }

    fn warm_reset(&mut self) {
        // The root bus resets the sources separately. Retain only the wiring.
        *self = Self::with_entropy(self.entropy.clone());
    }

    fn read_csrng_state(&mut self, _: RvSize) -> Result<RvData, BusError> {
        self.progress_dual_request();
        Ok(
            match self.pending_seed.as_ref().map(|request| request.command) {
                Some(SeedCommand::Instantiate) => 0xc1, // MainSmInstantPrep
                Some(SeedCommand::Reseed) => 0xdd,      // MainSmReseedPrep
                None => 0x4e,                           // MainSmIdle
            },
        )
    }

    fn read_command_status(&mut self, _: RvSize) -> Result<RvData, BusError> {
        self.progress_dual_request();
        Ok(self.sw_cmd_sts.reg.get())
    }

    fn cmd_req_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // Since the CMD_REQ register can be used to initiate new commands or
        // supply words to an existing command, we need to track which "state"
        // we're in for this register and branch accordingly.
        self.progress_dual_request();
        if self.pending_seed.is_some() {
            return Ok(());
        }
        match self.cmd_req_state {
            CmdReqState::NewCommand => self.process_new_cmd(data),

            CmdReqState::SeedWords { num_words } => {
                self.seed.push(data);
                if self.seed.len() == num_words {
                    self.ctr_drbg.instantiate(Instantiate::Words(&self.seed));
                    self.seed.clear();
                    self.cmd_req_state = CmdReqState::NewCommand;
                }
            }

            CmdReqState::ReseedWords { num_words } => {
                self.seed.push(data);
                if self.seed.len() == num_words {
                    self.ctr_drbg.reseed(Instantiate::Words(&self.seed));
                    self.seed.clear();
                    self.cmd_req_state = CmdReqState::NewCommand;
                }
            }

            CmdReqState::UpdateWords { num_words } => {
                self.update.push(data);
                if self.update.len() == num_words {
                    let seed32: [u32; SEED_LEN_BYTES / 4] =
                        self.update.as_slice().try_into().unwrap();
                    let seed = bytes_from_words_be(&seed32);
                    self.ctr_drbg.update(seed);
                    self.update.clear();
                    self.cmd_req_state = CmdReqState::NewCommand;
                }
            }
        }
        Ok(())
    }

    /// CTRL write handler. Disabling CSRNG clears the DRBG instance and any
    /// partially received command, as in the RTL.
    fn ctrl_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        const ENABLE_MASK: u32 = 0xf;
        if data & ENABLE_MASK != MultiBitBool::True as u32 {
            self.ctr_drbg = CtrDrbg::new();
            self.ctr_drbg.set_reseed_interval(self.reseed_interval);
            self.words = Words::default();
            self.cmd_req_state = CmdReqState::NewCommand;
            self.seed.clear();
            self.update.clear();
            self.output_fips = false;
            self.pending_seed = None;
        }
        self.ctrl = data;
        Ok(())
    }

    fn reseed_interval_write(&mut self, _: RvSize, data: RvData) -> Result<(), BusError> {
        // ES0's SW_REGUPD also protects CSRNG's reseed interval.
        if self.entropy.es0.borrow().configuration_locked() {
            return Ok(());
        }
        self.reseed_interval = data;

        self.ctr_drbg.set_reseed_interval(data);
        Ok(())
    }

    /// Read handler for RESEED_COUNTER_2 (SW app instance; NumApps=3).
    fn reseed_counter_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        Ok(self.ctr_drbg.reseed_counter())
    }

    fn genbits_vld_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        if self.words.is_empty() {
            // Check if the CTR_DRBG has any bits for us.
            if let Some(block) = self.ctr_drbg.pop_block() {
                self.words = Words::new(block);
                Ok(1 | (u32::from(self.output_fips) << 1))
            } else {
                Ok(0b00)
            }
        } else {
            Ok(1 | (u32::from(self.output_fips) << 1))
        }
    }

    fn genbits_read(&mut self, _: RvSize) -> Result<RvData, BusError> {
        Ok(self.words.next().unwrap_or(0xCAFE_F00D))
    }

    fn progress_dual_request(&mut self) {
        let (Some(request), EntropyTopology::Dual { es1, combiner }) =
            (&mut self.pending_seed, &self.entropy.topology)
        else {
            return;
        };
        let zeroize_epoch = combiner.zeroize_epoch();
        if request.combiner_zeroize_epoch != zeroize_epoch {
            // RTL clears in-flight seed storage, but retains the request while waiting.
            request.combiner_zeroize_epoch = zeroize_epoch;
            request.source_seeds = [None; 2];
        }
        if combiner.has_error() {
            return;
        }
        for (seed, source) in request
            .source_seeds
            .iter_mut()
            .zip([&self.entropy.es0, es1])
        {
            if seed.is_none() {
                *seed = source.borrow_mut().take_seed();
            }
        }
        let [Some(es0), Some(es1)] = request.source_seeds else {
            return;
        };
        let seed = combiner.combine(es0, es1);
        let command = request.command;
        self.apply_entropy_seed(command, seed);
        self.pending_seed = None;
        self.sw_cmd_sts = ReadOnlyRegister::new(0b110);
    }

    fn request_entropy_seed(&mut self, command: SeedCommand) {
        match &self.entropy.topology {
            EntropyTopology::Single => {
                let seed =
                    self.entropy
                        .es0
                        .borrow_mut()
                        .take_seed()
                        .unwrap_or_else(|| match command {
                            SeedCommand::Instantiate => {
                                panic!("iTRNG iterator ended while conditioning")
                            }
                            SeedCommand::Reseed => panic!("iTRNG iterator ended while reseeding"),
                        });
                self.apply_entropy_seed(command, seed);
                if matches!(command, SeedCommand::Instantiate) {
                    self.entropy.es0.borrow_mut().complete_boot_instantiate();
                }
            }
            EntropyTopology::Dual { combiner, .. } => {
                self.pending_seed = Some(PendingSeed {
                    command,
                    combiner_zeroize_epoch: combiner.zeroize_epoch(),
                    source_seeds: [None; 2],
                });
                self.sw_cmd_sts = ReadOnlyRegister::new(0b010);
                self.progress_dual_request();
            }
        }
    }

    fn apply_entropy_seed(&mut self, command: SeedCommand, seed: ConditionedSeed) {
        self.output_fips = seed.fips;
        let bytes = seed.into_csrng_bytes();
        match command {
            SeedCommand::Instantiate => self.ctr_drbg.instantiate(Instantiate::Bytes(&bytes)),
            SeedCommand::Reseed => self.ctr_drbg.reseed(Instantiate::Bytes(&bytes)),
        }
    }

    fn process_new_cmd(&mut self, data: RvData) {
        const INSTANTIATE: u32 = 1;
        const RESEED: u32 = 2;
        const GENERATE: u32 = 3;
        const UPDATE: u32 = 4;
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
                    [FALSE, 0] => self.request_entropy_seed(SeedCommand::Instantiate),

                    [FALSE, _] => unimplemented!("seed: entropy_src XOR constant"),

                    [TRUE, 0] => {
                        self.output_fips = false;
                        // Zero seed.
                        self.ctr_drbg.instantiate(Instantiate::default());
                    }

                    [TRUE, _] => {
                        self.output_fips = false;
                        self.cmd_req_state = CmdReqState::SeedWords {
                            num_words: clen as usize,
                        };
                    }

                    _ => unreachable!("invalid INSTANTIATE state: flag0={flag0}, clen={clen}"),
                }
            }

            RESEED => {
                const FALSE: u32 = MultiBitBool::False as u32;
                const TRUE: u32 = MultiBitBool::True as u32;

                // Mirror INSTANTIATE flag handling for RESEED.
                match [flag0, clen] {
                    [FALSE, 0] => self.request_entropy_seed(SeedCommand::Reseed),

                    [FALSE, _] => unimplemented!("reseed: entropy_src XOR constant"),

                    [TRUE, 0] => {
                        self.ctr_drbg.reseed(Instantiate::default());
                    }

                    [TRUE, _] => {
                        self.cmd_req_state = CmdReqState::ReseedWords {
                            num_words: clen as usize,
                        };
                    }

                    _ => unreachable!("invalid RESEED state: flag0={flag0}, clen={clen}"),
                }
            }

            GENERATE => {
                self.ctr_drbg.generate(glen as usize);
            }

            UNINSTANTIATE => {
                self.output_fips = false;
                self.ctr_drbg.uninstantiate();
            }

            UPDATE => {
                self.cmd_req_state = CmdReqState::UpdateWords {
                    num_words: SEED_LEN_BYTES / 4,
                };
            }

            _ => {
                unimplemented!("CSRNG cmd: {acmd}");
            }
        }
    }
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
    NewCommand,
    SeedWords { num_words: usize },
    ReseedWords { num_words: usize },
    UpdateWords { num_words: usize },
}
