// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with caliptra-rtl repo at 6664611ac8437c944453a8158aa44402af2e57b3
//
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
#[derive(Clone, Copy)]
pub struct RegisterBlock<TMmio: ureg::Mmio + core::borrow::Borrow<TMmio> = ureg::RealMmio> {
    ptr: *mut u32,
    mmio: TMmio,
}
impl RegisterBlock<ureg::RealMmio> {
    pub fn hmac_reg() -> Self {
        unsafe { Self::new(0x10010000 as *mut u32) }
    }
}
impl<TMmio: ureg::Mmio + core::default::Default> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    pub unsafe fn new(ptr: *mut u32) -> Self {
        Self {
            ptr,
            mmio: core::default::Default::default(),
        }
    }
}
impl<TMmio: ureg::Mmio> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    pub unsafe fn new_with_mmio(ptr: *mut u32, mmio: TMmio) -> Self {
        Self { ptr, mmio }
    }
    /// Two 32-bit read-only registers repereseting of the name
    /// of HMAC384 component. These registers are located at
    /// HMAC384_base_address + 0x0000_0000 and 0x0000_0004 addresses.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn name(&self) -> ureg::Array<2, ureg::RegRef<crate::hmac::meta::Name, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Two 32-bit read-only registers repereseting of the version
    /// of HMAC384 component. These registers are located at
    /// HMAC384_base_address + 0x0000_0008 and 0x0000_000C addresses.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn version(&self) -> ureg::Array<2, ureg::RegRef<crate::hmac::meta::Version, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(8 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// One 3-bit register including the following flags:
    /// bit #0: INIT : Trigs the HMAC384 core to start the
    ///                processing for the key and the first padded
    ///                message block.
    /// bit #1: NEXT: ​Trigs the HMAC384 core to start the
    ///                processing for the remining padded message block.
    /// bit #3: Zeroize all internal registers after HMAC process, to avoid SCA leakage.
    /// This register is located at HMAC384_base_address + 0x0000_0010
    /// After each software write, hardware will erase the register.
    ///
    /// Read value: [`hmac::regs::CtrlReadVal`]; Write value: [`hmac::regs::CtrlWriteVal`]
    pub fn ctrl(&self) -> ureg::RegRef<crate::hmac::meta::Ctrl, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x10 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// One 2-bit register including the following flags:
    /// bit #0: READY : ​Indicates if the core is ready to take
    ///                a control command and process the block.  
    /// bit #1: Valid: ​Indicates if the process is done and the
    ///                results stored in TAG registers are valid.
    /// This register is located at HMAC384_base_address + 0x0000_0018.
    ///
    /// Read value: [`hmac::regs::StatusReadVal`]; Write value: [`hmac::regs::StatusWriteVal`]
    pub fn status(&self) -> ureg::RegRef<crate::hmac::meta::Status, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x18 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// 12 32-bit registers storing the 384-bit key.
    /// These registers are located at HMAC384_base_address +
    /// 0x0000_0040 to 0x0000_006C in big-endian representation.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn key(&self) -> ureg::Array<12, ureg::RegRef<crate::hmac::meta::Key, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x40 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// 32 32-bit registers storing the 1024-bit padded input.
    /// These registers are located at HMAC384_base_address +
    /// 0x0000_0080 to 0x0000_00FC in big-endian representation.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn block(&self) -> ureg::Array<32, ureg::RegRef<crate::hmac::meta::Block, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x80 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// 12 32-bit registers storing the 384-bit digest output.
    /// These registers are located at HMAC384_base_address +
    /// 0x0000_0100 to 0x0000_012C in big-endian representation.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn tag(&self) -> ureg::Array<12, ureg::RegRef<crate::hmac::meta::Tag, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x100 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// 5 32-bit registers storing the 160-bit lfsr seed input.
    /// These registers are located at HMAC384_base_address +
    /// 0x0000_0130 to 0x0000_0140 in big-endian representation.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    pub fn lfsr_seed(&self) -> ureg::Array<5, ureg::RegRef<crate::hmac::meta::LfsrSeed, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x130 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls the Key Vault read access for this engine
    ///
    /// Read value: [`regs::KvReadCtrlRegReadVal`]; Write value: [`regs::KvReadCtrlRegWriteVal`]
    pub fn kv_rd_key_ctrl(&self) -> ureg::RegRef<crate::hmac::meta::KvRdKeyCtrl, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x600 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Reports the Key Vault flow status for this engine
    ///
    /// Read value: [`regs::KvStatusRegReadVal`]; Write value: [`regs::KvStatusRegWriteVal`]
    pub fn kv_rd_key_status(&self) -> ureg::RegRef<crate::hmac::meta::KvRdKeyStatus, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x604 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls the Key Vault read access for this engine
    ///
    /// Read value: [`regs::KvReadCtrlRegReadVal`]; Write value: [`regs::KvReadCtrlRegWriteVal`]
    pub fn kv_rd_block_ctrl(&self) -> ureg::RegRef<crate::hmac::meta::KvRdBlockCtrl, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x608 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Reports the Key Vault flow status for this engine
    ///
    /// Read value: [`regs::KvStatusRegReadVal`]; Write value: [`regs::KvStatusRegWriteVal`]
    pub fn kv_rd_block_status(&self) -> ureg::RegRef<crate::hmac::meta::KvRdBlockStatus, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x60c / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Controls the Key Vault write access for this engine
    ///
    /// Read value: [`regs::KvWriteCtrlRegReadVal`]; Write value: [`regs::KvWriteCtrlRegWriteVal`]
    pub fn kv_wr_ctrl(&self) -> ureg::RegRef<crate::hmac::meta::KvWrCtrl, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x610 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Reports the Key Vault flow status for this engine
    ///
    /// Read value: [`regs::KvStatusRegReadVal`]; Write value: [`regs::KvStatusRegWriteVal`]
    pub fn kv_wr_status(&self) -> ureg::RegRef<crate::hmac::meta::KvWrStatus, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x614 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
}
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct CtrlWriteVal(u32);
    impl CtrlWriteVal {
        /// Control init command bit
        #[inline(always)]
        pub fn init(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Control next command bit
        #[inline(always)]
        pub fn next(self, val: bool) -> Self {
            Self((self.0 & !(1 << 1)) | (u32::from(val) << 1))
        }
        /// Zeroize all internal registers
        #[inline(always)]
        pub fn zeroize(self, val: bool) -> Self {
            Self((self.0 & !(1 << 2)) | (u32::from(val) << 2))
        }
    }
    impl From<u32> for CtrlWriteVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<CtrlWriteVal> for u32 {
        fn from(val: CtrlWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct StatusReadVal(u32);
    impl StatusReadVal {
        /// Status ready bit
        #[inline(always)]
        pub fn ready(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Status valid bit
        #[inline(always)]
        pub fn valid(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
    }
    impl From<u32> for StatusReadVal {
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<StatusReadVal> for u32 {
        fn from(val: StatusReadVal) -> u32 {
            val.0
        }
    }
}
pub mod enums {
    //! Enumerations used by some register fields.
    #[derive(Clone, Copy, Eq, PartialEq)]
    #[repr(u32)]
    pub enum KvErrorE {
        Success = 0,
        KvReadFail = 1,
        KvWriteFail = 2,
        Reserved3 = 3,
        Reserved4 = 4,
        Reserved5 = 5,
        Reserved6 = 6,
        Reserved7 = 7,
        Reserved8 = 8,
        Reserved9 = 9,
        Reserved10 = 10,
        Reserved11 = 11,
        Reserved12 = 12,
        Reserved13 = 13,
        Reserved14 = 14,
        Reserved15 = 15,
        Reserved16 = 16,
        Reserved17 = 17,
        Reserved18 = 18,
        Reserved19 = 19,
        Reserved20 = 20,
        Reserved21 = 21,
        Reserved22 = 22,
        Reserved23 = 23,
        Reserved24 = 24,
        Reserved25 = 25,
        Reserved26 = 26,
        Reserved27 = 27,
        Reserved28 = 28,
        Reserved29 = 29,
        Reserved30 = 30,
        Reserved31 = 31,
        Reserved32 = 32,
        Reserved33 = 33,
        Reserved34 = 34,
        Reserved35 = 35,
        Reserved36 = 36,
        Reserved37 = 37,
        Reserved38 = 38,
        Reserved39 = 39,
        Reserved40 = 40,
        Reserved41 = 41,
        Reserved42 = 42,
        Reserved43 = 43,
        Reserved44 = 44,
        Reserved45 = 45,
        Reserved46 = 46,
        Reserved47 = 47,
        Reserved48 = 48,
        Reserved49 = 49,
        Reserved50 = 50,
        Reserved51 = 51,
        Reserved52 = 52,
        Reserved53 = 53,
        Reserved54 = 54,
        Reserved55 = 55,
        Reserved56 = 56,
        Reserved57 = 57,
        Reserved58 = 58,
        Reserved59 = 59,
        Reserved60 = 60,
        Reserved61 = 61,
        Reserved62 = 62,
        Reserved63 = 63,
        Reserved64 = 64,
        Reserved65 = 65,
        Reserved66 = 66,
        Reserved67 = 67,
        Reserved68 = 68,
        Reserved69 = 69,
        Reserved70 = 70,
        Reserved71 = 71,
        Reserved72 = 72,
        Reserved73 = 73,
        Reserved74 = 74,
        Reserved75 = 75,
        Reserved76 = 76,
        Reserved77 = 77,
        Reserved78 = 78,
        Reserved79 = 79,
        Reserved80 = 80,
        Reserved81 = 81,
        Reserved82 = 82,
        Reserved83 = 83,
        Reserved84 = 84,
        Reserved85 = 85,
        Reserved86 = 86,
        Reserved87 = 87,
        Reserved88 = 88,
        Reserved89 = 89,
        Reserved90 = 90,
        Reserved91 = 91,
        Reserved92 = 92,
        Reserved93 = 93,
        Reserved94 = 94,
        Reserved95 = 95,
        Reserved96 = 96,
        Reserved97 = 97,
        Reserved98 = 98,
        Reserved99 = 99,
        Reserved100 = 100,
        Reserved101 = 101,
        Reserved102 = 102,
        Reserved103 = 103,
        Reserved104 = 104,
        Reserved105 = 105,
        Reserved106 = 106,
        Reserved107 = 107,
        Reserved108 = 108,
        Reserved109 = 109,
        Reserved110 = 110,
        Reserved111 = 111,
        Reserved112 = 112,
        Reserved113 = 113,
        Reserved114 = 114,
        Reserved115 = 115,
        Reserved116 = 116,
        Reserved117 = 117,
        Reserved118 = 118,
        Reserved119 = 119,
        Reserved120 = 120,
        Reserved121 = 121,
        Reserved122 = 122,
        Reserved123 = 123,
        Reserved124 = 124,
        Reserved125 = 125,
        Reserved126 = 126,
        Reserved127 = 127,
        Reserved128 = 128,
        Reserved129 = 129,
        Reserved130 = 130,
        Reserved131 = 131,
        Reserved132 = 132,
        Reserved133 = 133,
        Reserved134 = 134,
        Reserved135 = 135,
        Reserved136 = 136,
        Reserved137 = 137,
        Reserved138 = 138,
        Reserved139 = 139,
        Reserved140 = 140,
        Reserved141 = 141,
        Reserved142 = 142,
        Reserved143 = 143,
        Reserved144 = 144,
        Reserved145 = 145,
        Reserved146 = 146,
        Reserved147 = 147,
        Reserved148 = 148,
        Reserved149 = 149,
        Reserved150 = 150,
        Reserved151 = 151,
        Reserved152 = 152,
        Reserved153 = 153,
        Reserved154 = 154,
        Reserved155 = 155,
        Reserved156 = 156,
        Reserved157 = 157,
        Reserved158 = 158,
        Reserved159 = 159,
        Reserved160 = 160,
        Reserved161 = 161,
        Reserved162 = 162,
        Reserved163 = 163,
        Reserved164 = 164,
        Reserved165 = 165,
        Reserved166 = 166,
        Reserved167 = 167,
        Reserved168 = 168,
        Reserved169 = 169,
        Reserved170 = 170,
        Reserved171 = 171,
        Reserved172 = 172,
        Reserved173 = 173,
        Reserved174 = 174,
        Reserved175 = 175,
        Reserved176 = 176,
        Reserved177 = 177,
        Reserved178 = 178,
        Reserved179 = 179,
        Reserved180 = 180,
        Reserved181 = 181,
        Reserved182 = 182,
        Reserved183 = 183,
        Reserved184 = 184,
        Reserved185 = 185,
        Reserved186 = 186,
        Reserved187 = 187,
        Reserved188 = 188,
        Reserved189 = 189,
        Reserved190 = 190,
        Reserved191 = 191,
        Reserved192 = 192,
        Reserved193 = 193,
        Reserved194 = 194,
        Reserved195 = 195,
        Reserved196 = 196,
        Reserved197 = 197,
        Reserved198 = 198,
        Reserved199 = 199,
        Reserved200 = 200,
        Reserved201 = 201,
        Reserved202 = 202,
        Reserved203 = 203,
        Reserved204 = 204,
        Reserved205 = 205,
        Reserved206 = 206,
        Reserved207 = 207,
        Reserved208 = 208,
        Reserved209 = 209,
        Reserved210 = 210,
        Reserved211 = 211,
        Reserved212 = 212,
        Reserved213 = 213,
        Reserved214 = 214,
        Reserved215 = 215,
        Reserved216 = 216,
        Reserved217 = 217,
        Reserved218 = 218,
        Reserved219 = 219,
        Reserved220 = 220,
        Reserved221 = 221,
        Reserved222 = 222,
        Reserved223 = 223,
        Reserved224 = 224,
        Reserved225 = 225,
        Reserved226 = 226,
        Reserved227 = 227,
        Reserved228 = 228,
        Reserved229 = 229,
        Reserved230 = 230,
        Reserved231 = 231,
        Reserved232 = 232,
        Reserved233 = 233,
        Reserved234 = 234,
        Reserved235 = 235,
        Reserved236 = 236,
        Reserved237 = 237,
        Reserved238 = 238,
        Reserved239 = 239,
        Reserved240 = 240,
        Reserved241 = 241,
        Reserved242 = 242,
        Reserved243 = 243,
        Reserved244 = 244,
        Reserved245 = 245,
        Reserved246 = 246,
        Reserved247 = 247,
        Reserved248 = 248,
        Reserved249 = 249,
        Reserved250 = 250,
        Reserved251 = 251,
        Reserved252 = 252,
        Reserved253 = 253,
        Reserved254 = 254,
        Reserved255 = 255,
    }
    impl KvErrorE {
        #[inline(always)]
        pub fn success(&self) -> bool {
            *self == Self::Success
        }
        #[inline(always)]
        pub fn kv_read_fail(&self) -> bool {
            *self == Self::KvReadFail
        }
        #[inline(always)]
        pub fn kv_write_fail(&self) -> bool {
            *self == Self::KvWriteFail
        }
    }
    impl TryFrom<u32> for KvErrorE {
        type Error = ();
        #[inline(always)]
        fn try_from(val: u32) -> Result<KvErrorE, ()> {
            match val {
                0 => Ok(Self::Success),
                1 => Ok(Self::KvReadFail),
                2 => Ok(Self::KvWriteFail),
                3 => Ok(Self::Reserved3),
                4 => Ok(Self::Reserved4),
                5 => Ok(Self::Reserved5),
                6 => Ok(Self::Reserved6),
                7 => Ok(Self::Reserved7),
                8 => Ok(Self::Reserved8),
                9 => Ok(Self::Reserved9),
                10 => Ok(Self::Reserved10),
                11 => Ok(Self::Reserved11),
                12 => Ok(Self::Reserved12),
                13 => Ok(Self::Reserved13),
                14 => Ok(Self::Reserved14),
                15 => Ok(Self::Reserved15),
                16 => Ok(Self::Reserved16),
                17 => Ok(Self::Reserved17),
                18 => Ok(Self::Reserved18),
                19 => Ok(Self::Reserved19),
                20 => Ok(Self::Reserved20),
                21 => Ok(Self::Reserved21),
                22 => Ok(Self::Reserved22),
                23 => Ok(Self::Reserved23),
                24 => Ok(Self::Reserved24),
                25 => Ok(Self::Reserved25),
                26 => Ok(Self::Reserved26),
                27 => Ok(Self::Reserved27),
                28 => Ok(Self::Reserved28),
                29 => Ok(Self::Reserved29),
                30 => Ok(Self::Reserved30),
                31 => Ok(Self::Reserved31),
                32 => Ok(Self::Reserved32),
                33 => Ok(Self::Reserved33),
                34 => Ok(Self::Reserved34),
                35 => Ok(Self::Reserved35),
                36 => Ok(Self::Reserved36),
                37 => Ok(Self::Reserved37),
                38 => Ok(Self::Reserved38),
                39 => Ok(Self::Reserved39),
                40 => Ok(Self::Reserved40),
                41 => Ok(Self::Reserved41),
                42 => Ok(Self::Reserved42),
                43 => Ok(Self::Reserved43),
                44 => Ok(Self::Reserved44),
                45 => Ok(Self::Reserved45),
                46 => Ok(Self::Reserved46),
                47 => Ok(Self::Reserved47),
                48 => Ok(Self::Reserved48),
                49 => Ok(Self::Reserved49),
                50 => Ok(Self::Reserved50),
                51 => Ok(Self::Reserved51),
                52 => Ok(Self::Reserved52),
                53 => Ok(Self::Reserved53),
                54 => Ok(Self::Reserved54),
                55 => Ok(Self::Reserved55),
                56 => Ok(Self::Reserved56),
                57 => Ok(Self::Reserved57),
                58 => Ok(Self::Reserved58),
                59 => Ok(Self::Reserved59),
                60 => Ok(Self::Reserved60),
                61 => Ok(Self::Reserved61),
                62 => Ok(Self::Reserved62),
                63 => Ok(Self::Reserved63),
                64 => Ok(Self::Reserved64),
                65 => Ok(Self::Reserved65),
                66 => Ok(Self::Reserved66),
                67 => Ok(Self::Reserved67),
                68 => Ok(Self::Reserved68),
                69 => Ok(Self::Reserved69),
                70 => Ok(Self::Reserved70),
                71 => Ok(Self::Reserved71),
                72 => Ok(Self::Reserved72),
                73 => Ok(Self::Reserved73),
                74 => Ok(Self::Reserved74),
                75 => Ok(Self::Reserved75),
                76 => Ok(Self::Reserved76),
                77 => Ok(Self::Reserved77),
                78 => Ok(Self::Reserved78),
                79 => Ok(Self::Reserved79),
                80 => Ok(Self::Reserved80),
                81 => Ok(Self::Reserved81),
                82 => Ok(Self::Reserved82),
                83 => Ok(Self::Reserved83),
                84 => Ok(Self::Reserved84),
                85 => Ok(Self::Reserved85),
                86 => Ok(Self::Reserved86),
                87 => Ok(Self::Reserved87),
                88 => Ok(Self::Reserved88),
                89 => Ok(Self::Reserved89),
                90 => Ok(Self::Reserved90),
                91 => Ok(Self::Reserved91),
                92 => Ok(Self::Reserved92),
                93 => Ok(Self::Reserved93),
                94 => Ok(Self::Reserved94),
                95 => Ok(Self::Reserved95),
                96 => Ok(Self::Reserved96),
                97 => Ok(Self::Reserved97),
                98 => Ok(Self::Reserved98),
                99 => Ok(Self::Reserved99),
                100 => Ok(Self::Reserved100),
                101 => Ok(Self::Reserved101),
                102 => Ok(Self::Reserved102),
                103 => Ok(Self::Reserved103),
                104 => Ok(Self::Reserved104),
                105 => Ok(Self::Reserved105),
                106 => Ok(Self::Reserved106),
                107 => Ok(Self::Reserved107),
                108 => Ok(Self::Reserved108),
                109 => Ok(Self::Reserved109),
                110 => Ok(Self::Reserved110),
                111 => Ok(Self::Reserved111),
                112 => Ok(Self::Reserved112),
                113 => Ok(Self::Reserved113),
                114 => Ok(Self::Reserved114),
                115 => Ok(Self::Reserved115),
                116 => Ok(Self::Reserved116),
                117 => Ok(Self::Reserved117),
                118 => Ok(Self::Reserved118),
                119 => Ok(Self::Reserved119),
                120 => Ok(Self::Reserved120),
                121 => Ok(Self::Reserved121),
                122 => Ok(Self::Reserved122),
                123 => Ok(Self::Reserved123),
                124 => Ok(Self::Reserved124),
                125 => Ok(Self::Reserved125),
                126 => Ok(Self::Reserved126),
                127 => Ok(Self::Reserved127),
                128 => Ok(Self::Reserved128),
                129 => Ok(Self::Reserved129),
                130 => Ok(Self::Reserved130),
                131 => Ok(Self::Reserved131),
                132 => Ok(Self::Reserved132),
                133 => Ok(Self::Reserved133),
                134 => Ok(Self::Reserved134),
                135 => Ok(Self::Reserved135),
                136 => Ok(Self::Reserved136),
                137 => Ok(Self::Reserved137),
                138 => Ok(Self::Reserved138),
                139 => Ok(Self::Reserved139),
                140 => Ok(Self::Reserved140),
                141 => Ok(Self::Reserved141),
                142 => Ok(Self::Reserved142),
                143 => Ok(Self::Reserved143),
                144 => Ok(Self::Reserved144),
                145 => Ok(Self::Reserved145),
                146 => Ok(Self::Reserved146),
                147 => Ok(Self::Reserved147),
                148 => Ok(Self::Reserved148),
                149 => Ok(Self::Reserved149),
                150 => Ok(Self::Reserved150),
                151 => Ok(Self::Reserved151),
                152 => Ok(Self::Reserved152),
                153 => Ok(Self::Reserved153),
                154 => Ok(Self::Reserved154),
                155 => Ok(Self::Reserved155),
                156 => Ok(Self::Reserved156),
                157 => Ok(Self::Reserved157),
                158 => Ok(Self::Reserved158),
                159 => Ok(Self::Reserved159),
                160 => Ok(Self::Reserved160),
                161 => Ok(Self::Reserved161),
                162 => Ok(Self::Reserved162),
                163 => Ok(Self::Reserved163),
                164 => Ok(Self::Reserved164),
                165 => Ok(Self::Reserved165),
                166 => Ok(Self::Reserved166),
                167 => Ok(Self::Reserved167),
                168 => Ok(Self::Reserved168),
                169 => Ok(Self::Reserved169),
                170 => Ok(Self::Reserved170),
                171 => Ok(Self::Reserved171),
                172 => Ok(Self::Reserved172),
                173 => Ok(Self::Reserved173),
                174 => Ok(Self::Reserved174),
                175 => Ok(Self::Reserved175),
                176 => Ok(Self::Reserved176),
                177 => Ok(Self::Reserved177),
                178 => Ok(Self::Reserved178),
                179 => Ok(Self::Reserved179),
                180 => Ok(Self::Reserved180),
                181 => Ok(Self::Reserved181),
                182 => Ok(Self::Reserved182),
                183 => Ok(Self::Reserved183),
                184 => Ok(Self::Reserved184),
                185 => Ok(Self::Reserved185),
                186 => Ok(Self::Reserved186),
                187 => Ok(Self::Reserved187),
                188 => Ok(Self::Reserved188),
                189 => Ok(Self::Reserved189),
                190 => Ok(Self::Reserved190),
                191 => Ok(Self::Reserved191),
                192 => Ok(Self::Reserved192),
                193 => Ok(Self::Reserved193),
                194 => Ok(Self::Reserved194),
                195 => Ok(Self::Reserved195),
                196 => Ok(Self::Reserved196),
                197 => Ok(Self::Reserved197),
                198 => Ok(Self::Reserved198),
                199 => Ok(Self::Reserved199),
                200 => Ok(Self::Reserved200),
                201 => Ok(Self::Reserved201),
                202 => Ok(Self::Reserved202),
                203 => Ok(Self::Reserved203),
                204 => Ok(Self::Reserved204),
                205 => Ok(Self::Reserved205),
                206 => Ok(Self::Reserved206),
                207 => Ok(Self::Reserved207),
                208 => Ok(Self::Reserved208),
                209 => Ok(Self::Reserved209),
                210 => Ok(Self::Reserved210),
                211 => Ok(Self::Reserved211),
                212 => Ok(Self::Reserved212),
                213 => Ok(Self::Reserved213),
                214 => Ok(Self::Reserved214),
                215 => Ok(Self::Reserved215),
                216 => Ok(Self::Reserved216),
                217 => Ok(Self::Reserved217),
                218 => Ok(Self::Reserved218),
                219 => Ok(Self::Reserved219),
                220 => Ok(Self::Reserved220),
                221 => Ok(Self::Reserved221),
                222 => Ok(Self::Reserved222),
                223 => Ok(Self::Reserved223),
                224 => Ok(Self::Reserved224),
                225 => Ok(Self::Reserved225),
                226 => Ok(Self::Reserved226),
                227 => Ok(Self::Reserved227),
                228 => Ok(Self::Reserved228),
                229 => Ok(Self::Reserved229),
                230 => Ok(Self::Reserved230),
                231 => Ok(Self::Reserved231),
                232 => Ok(Self::Reserved232),
                233 => Ok(Self::Reserved233),
                234 => Ok(Self::Reserved234),
                235 => Ok(Self::Reserved235),
                236 => Ok(Self::Reserved236),
                237 => Ok(Self::Reserved237),
                238 => Ok(Self::Reserved238),
                239 => Ok(Self::Reserved239),
                240 => Ok(Self::Reserved240),
                241 => Ok(Self::Reserved241),
                242 => Ok(Self::Reserved242),
                243 => Ok(Self::Reserved243),
                244 => Ok(Self::Reserved244),
                245 => Ok(Self::Reserved245),
                246 => Ok(Self::Reserved246),
                247 => Ok(Self::Reserved247),
                248 => Ok(Self::Reserved248),
                249 => Ok(Self::Reserved249),
                250 => Ok(Self::Reserved250),
                251 => Ok(Self::Reserved251),
                252 => Ok(Self::Reserved252),
                253 => Ok(Self::Reserved253),
                254 => Ok(Self::Reserved254),
                255 => Ok(Self::Reserved255),
                _ => Err(()),
            }
        }
    }
    impl From<KvErrorE> for u32 {
        fn from(val: KvErrorE) -> Self {
            val as u32
        }
    }
    pub mod selector {
        pub struct KvErrorESelector();
        impl KvErrorESelector {
            #[inline(always)]
            pub fn success(&self) -> super::KvErrorE {
                super::KvErrorE::Success
            }
            #[inline(always)]
            pub fn kv_read_fail(&self) -> super::KvErrorE {
                super::KvErrorE::KvReadFail
            }
            #[inline(always)]
            pub fn kv_write_fail(&self) -> super::KvErrorE {
                super::KvErrorE::KvWriteFail
            }
        }
    }
}
pub mod meta {
    //! Additional metadata needed by ureg.
    pub type Name = ureg::ReadOnlyReg32<u32>;
    pub type Version = ureg::ReadOnlyReg32<u32>;
    pub type Ctrl = ureg::WriteOnlyReg32<0, crate::hmac::regs::CtrlWriteVal>;
    pub type Status = ureg::ReadOnlyReg32<crate::hmac::regs::StatusReadVal>;
    pub type Key = ureg::WriteOnlyReg32<0, u32>;
    pub type Block = ureg::WriteOnlyReg32<0, u32>;
    pub type Tag = ureg::ReadOnlyReg32<u32>;
    pub type LfsrSeed = ureg::WriteOnlyReg32<0x3cabffb0, u32>;
    pub type KvRdKeyCtrl = ureg::ReadWriteReg32<
        0,
        crate::regs::KvReadCtrlRegReadVal,
        crate::regs::KvReadCtrlRegWriteVal,
    >;
    pub type KvRdKeyStatus = ureg::ReadOnlyReg32<crate::regs::KvStatusRegReadVal>;
    pub type KvRdBlockCtrl = ureg::ReadWriteReg32<
        0,
        crate::regs::KvReadCtrlRegReadVal,
        crate::regs::KvReadCtrlRegWriteVal,
    >;
    pub type KvRdBlockStatus = ureg::ReadOnlyReg32<crate::regs::KvStatusRegReadVal>;
    pub type KvWrCtrl = ureg::ReadWriteReg32<
        0,
        crate::regs::KvWriteCtrlRegReadVal,
        crate::regs::KvWriteCtrlRegWriteVal,
    >;
    pub type KvWrStatus = ureg::ReadOnlyReg32<crate::regs::KvStatusRegReadVal>;
}
