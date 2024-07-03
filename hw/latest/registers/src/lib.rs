// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with caliptra-rtl repo at dea4ee4d3e13ffd16455e16dc6ead226e640a457
//
#![no_std]
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct KvReadCtrlRegReadVal(u32);
    impl KvReadCtrlRegReadVal {
        /// Indicates that the read data is to come from the key vault.
        /// Setting this bit to 1 initiates copying of data from the key vault.
        #[inline(always)]
        pub fn read_en(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Key Vault entry to retrieve the read data from for the engine
        #[inline(always)]
        pub fn read_entry(&self) -> u32 {
            (self.0 >> 1) & 0x1f
        }
        /// Requested entry is a PCR. This is used only for SHA to hash extend, it's NOP in all other engines
        #[inline(always)]
        pub fn pcr_hash_extend(&self) -> bool {
            ((self.0 >> 6) & 1) != 0
        }
        /// Reserved field
        #[inline(always)]
        pub fn rsvd(&self) -> u32 {
            (self.0 >> 7) & 0x1ffffff
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> KvReadCtrlRegWriteVal {
            KvReadCtrlRegWriteVal(self.0)
        }
    }
    impl From<u32> for KvReadCtrlRegReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvReadCtrlRegReadVal> for u32 {
        #[inline(always)]
        fn from(val: KvReadCtrlRegReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct KvReadCtrlRegWriteVal(u32);
    impl KvReadCtrlRegWriteVal {
        /// Indicates that the read data is to come from the key vault.
        /// Setting this bit to 1 initiates copying of data from the key vault.
        #[inline(always)]
        pub fn read_en(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Key Vault entry to retrieve the read data from for the engine
        #[inline(always)]
        pub fn read_entry(self, val: u32) -> Self {
            Self((self.0 & !(0x1f << 1)) | ((val & 0x1f) << 1))
        }
        /// Requested entry is a PCR. This is used only for SHA to hash extend, it's NOP in all other engines
        #[inline(always)]
        pub fn pcr_hash_extend(self, val: bool) -> Self {
            Self((self.0 & !(1 << 6)) | (u32::from(val) << 6))
        }
        /// Reserved field
        #[inline(always)]
        pub fn rsvd(self, val: u32) -> Self {
            Self((self.0 & !(0x1ffffff << 7)) | ((val & 0x1ffffff) << 7))
        }
    }
    impl From<u32> for KvReadCtrlRegWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvReadCtrlRegWriteVal> for u32 {
        #[inline(always)]
        fn from(val: KvReadCtrlRegWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct KvStatusRegReadVal(u32);
    impl KvStatusRegReadVal {
        /// Key Vault control is ready for use
        #[inline(always)]
        pub fn ready(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Key Vault flow is done
        #[inline(always)]
        pub fn valid(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
        /// Indicates the error status of a key vault flow
        #[inline(always)]
        pub fn error(&self) -> super::enums::KvErrorE {
            super::enums::KvErrorE::try_from((self.0 >> 2) & 0xff).unwrap()
        }
    }
    impl From<u32> for KvStatusRegReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvStatusRegReadVal> for u32 {
        #[inline(always)]
        fn from(val: KvStatusRegReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct KvWriteCtrlRegReadVal(u32);
    impl KvWriteCtrlRegReadVal {
        /// Indicates that the result is to be stored in the key vault.
        /// Setting this bit to 1 will copy the result to the keyvault when it is ready.
        #[inline(always)]
        pub fn write_en(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Key Vault entry to store the result
        #[inline(always)]
        pub fn write_entry(&self) -> u32 {
            (self.0 >> 1) & 0x1f
        }
        /// HMAC KEY is a valid destination
        #[inline(always)]
        pub fn hmac_key_dest_valid(&self) -> bool {
            ((self.0 >> 6) & 1) != 0
        }
        /// HMAC BLOCK is a valid destination
        #[inline(always)]
        pub fn hmac_block_dest_valid(&self) -> bool {
            ((self.0 >> 7) & 1) != 0
        }
        /// Reserved field. No SHA key vault interface
        #[inline(always)]
        pub fn sha_block_dest_valid(&self) -> bool {
            ((self.0 >> 8) & 1) != 0
        }
        /// ECC PKEY is a valid destination
        #[inline(always)]
        pub fn ecc_pkey_dest_valid(&self) -> bool {
            ((self.0 >> 9) & 1) != 0
        }
        /// ECC SEED is a valid destination
        #[inline(always)]
        pub fn ecc_seed_dest_valid(&self) -> bool {
            ((self.0 >> 10) & 1) != 0
        }
        /// Reserved field
        #[inline(always)]
        pub fn rsvd(&self) -> u32 {
            (self.0 >> 11) & 0x1fffff
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> KvWriteCtrlRegWriteVal {
            KvWriteCtrlRegWriteVal(self.0)
        }
    }
    impl From<u32> for KvWriteCtrlRegReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvWriteCtrlRegReadVal> for u32 {
        #[inline(always)]
        fn from(val: KvWriteCtrlRegReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct KvWriteCtrlRegWriteVal(u32);
    impl KvWriteCtrlRegWriteVal {
        /// Indicates that the result is to be stored in the key vault.
        /// Setting this bit to 1 will copy the result to the keyvault when it is ready.
        #[inline(always)]
        pub fn write_en(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// Key Vault entry to store the result
        #[inline(always)]
        pub fn write_entry(self, val: u32) -> Self {
            Self((self.0 & !(0x1f << 1)) | ((val & 0x1f) << 1))
        }
        /// HMAC KEY is a valid destination
        #[inline(always)]
        pub fn hmac_key_dest_valid(self, val: bool) -> Self {
            Self((self.0 & !(1 << 6)) | (u32::from(val) << 6))
        }
        /// HMAC BLOCK is a valid destination
        #[inline(always)]
        pub fn hmac_block_dest_valid(self, val: bool) -> Self {
            Self((self.0 & !(1 << 7)) | (u32::from(val) << 7))
        }
        /// Reserved field. No SHA key vault interface
        #[inline(always)]
        pub fn sha_block_dest_valid(self, val: bool) -> Self {
            Self((self.0 & !(1 << 8)) | (u32::from(val) << 8))
        }
        /// ECC PKEY is a valid destination
        #[inline(always)]
        pub fn ecc_pkey_dest_valid(self, val: bool) -> Self {
            Self((self.0 & !(1 << 9)) | (u32::from(val) << 9))
        }
        /// ECC SEED is a valid destination
        #[inline(always)]
        pub fn ecc_seed_dest_valid(self, val: bool) -> Self {
            Self((self.0 & !(1 << 10)) | (u32::from(val) << 10))
        }
        /// Reserved field
        #[inline(always)]
        pub fn rsvd(self, val: u32) -> Self {
            Self((self.0 & !(0x1fffff << 11)) | ((val & 0x1fffff) << 11))
        }
    }
    impl From<u32> for KvWriteCtrlRegWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<KvWriteCtrlRegWriteVal> for u32 {
        #[inline(always)]
        fn from(val: KvWriteCtrlRegWriteVal) -> u32 {
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
            if val < 0x100 {
                Ok(unsafe { core::mem::transmute(val) })
            } else {
                Err(())
            }
        }
    }
    impl From<KvErrorE> for u32 {
        fn from(val: KvErrorE) -> Self {
            val as u32
        }
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    #[repr(u32)]
    pub enum PvErrorE {
        Success = 0,
        PvReadFail = 1,
        PvWriteFail = 2,
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
    impl PvErrorE {
        #[inline(always)]
        pub fn success(&self) -> bool {
            *self == Self::Success
        }
        #[inline(always)]
        pub fn pv_read_fail(&self) -> bool {
            *self == Self::PvReadFail
        }
        #[inline(always)]
        pub fn pv_write_fail(&self) -> bool {
            *self == Self::PvWriteFail
        }
    }
    impl TryFrom<u32> for PvErrorE {
        type Error = ();
        #[inline(always)]
        fn try_from(val: u32) -> Result<PvErrorE, ()> {
            if val < 0x100 {
                Ok(unsafe { core::mem::transmute(val) })
            } else {
                Err(())
            }
        }
    }
    impl From<PvErrorE> for u32 {
        fn from(val: PvErrorE) -> Self {
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
        pub struct PvErrorESelector();
        impl PvErrorESelector {
            #[inline(always)]
            pub fn success(&self) -> super::PvErrorE {
                super::PvErrorE::Success
            }
            #[inline(always)]
            pub fn pv_read_fail(&self) -> super::PvErrorE {
                super::PvErrorE::PvReadFail
            }
            #[inline(always)]
            pub fn pv_write_fail(&self) -> super::PvErrorE {
                super::PvErrorE::PvWriteFail
            }
        }
    }
}
pub mod meta {
    //! Additional metadata needed by ureg.
}
pub mod csrng;
pub mod doe;
pub mod dv;
pub mod ecc;
pub mod el2_pic_ctrl;
pub mod entropy_src;
pub mod hmac;
pub mod kv;
pub mod mbox;
pub mod pv;
pub mod sha256;
pub mod sha512;
pub mod sha512_acc;
pub mod soc_ifc;
pub mod soc_ifc_trng;
pub mod spi_host;
pub mod uart;
