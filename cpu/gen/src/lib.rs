// Licensed under the Apache-2.0 license
use caliptra_common::memory_layout::*;
pub fn gen_memory_x(iccm_org: u32, iccm_size: u32) -> String {
    format!(
        r#"
        ICCM_ORG  		 = 0x{iccm_org:08X};
        DCCM_ORG  		 = 0x{DCCM_ORG:08X};
        DATA_ORG  		 = 0x{DATA_ORG:08X};
        STACK_ORG 		 = 0x{STACK_ORG:08X};
        ESTACK_ORG  	 = 0x{ESTACK_ORG:08X};
        NSTACK_ORG       = 0x{NSTACK_ORG:08X};
        LDEVID_TBS_ORG   = 0x{LDEVID_TBS_ORG:08X};;
        FMCALIAS_TBS_ORG = 0x{FMCALIAS_TBS_ORG:08X};;
        RTALIAS_TBS_ORG  = 0x{RTALIAS_TBS_ORG:08X};

        CFI_STATE_ORG = 0x{CFI_STATE_ORG:08X};

        LDEVID_TBS_SIZE   = 0x{LDEVID_TBS_SIZE:08X};
        FMCALIAS_TBS_SIZE = 0x{FMCALIAS_TBS_SIZE:08X};
        RTALIAS_TBS_SIZE  = 0x{RTALIAS_TBS_SIZE:08X};

        ICCM_SIZE   = 0x{iccm_size:08X};
        DCCM_SIZE   = 0x{DCCM_SIZE:08X};
        DATA_SIZE   = 0x{DATA_SIZE:08X};
        STACK_SIZE  = 0x{STACK_SIZE:08X};
        ESTACK_SIZE = 0x{ESTACK_SIZE:08X};
        NSTACK_SIZE = 0x{NSTACK_SIZE:08X};


        MEMORY
        {{
            ICCM 		 (rx) : ORIGIN = ICCM_ORG, 		   LENGTH = ICCM_SIZE
            RTALIAS_TBS  (rw) : ORIGIN = RTALIAS_TBS_ORG,  LENGTH = RTALIAS_TBS_SIZE
            DATA         (rw) : ORIGIN = DATA_ORG,         LENGTH = DATA_SIZE
            STACK	     (rw) : ORIGIN = STACK_ORG,  	   LENGTH = STACK_SIZE
            ESTACK 		 (rw) : ORIGIN = ESTACK_ORG,       LENGTH = ESTACK_SIZE
            NSTACK       (rw) : ORIGIN = NSTACK_ORG,       LENGTH = NSTACK_SIZE
        }}
        REGION_ALIAS("REGION_TEXT", ICCM);
        REGION_ALIAS("REGION_RODATA", ICCM);
        REGION_ALIAS("REGION_DATA", DATA);
        REGION_ALIAS("REGION_BSS", DATA);
        REGION_ALIAS("REGION_STACK", STACK);
        REGION_ALIAS("REGION_ESTACK", ESTACK);
        REGION_ALIAS("REGION_NSTACK", NSTACK);"#
    )
}
