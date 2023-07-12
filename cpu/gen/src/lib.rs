// Licensed under the Apache-2.0 license
use caliptra_common::memory_layout::{FMCALIAS_TBS_ORG, LDEVID_TBS_ORG};
pub fn gen_memory_x(iccm_org: u32, iccm_size: u32) -> String {
    format!(
        r#"
        ICCM_ORG  		 = 0x{:08X};
        DCCM_ORG  		 = 0x50000000;
        DATA_ORG  		 = 0x50004400;
        STACK_ORG 		 = 0x5001C000;
        ESTACK_ORG  	 = 0x5001F800;
        NSTACK_ORG       = 0x5001FC00;
        LDEVID_TBS_ORG   = 0x{:08X};;
        FMCALIAS_TBS_ORG = 0x{:08X};;
        RTALIAS_TBS_ORG  = 0x50004000;
        
        LDEVID_TBS_SIZE   = 1K;
        FMCALIAS_TBS_SIZE = 1K;
        RTALIAS_TBS_SIZE  = 1K;
              
        ICCM_SIZE   = 0x{:08X};
        DCCM_SIZE   = 128K;
        DATA_SIZE   = 95K;
        STACK_SIZE  = 14K;
        ESTACK_SIZE = 1K;
        NSTACK_SIZE = 1K;
        
        
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
        REGION_ALIAS("REGION_NSTACK", NSTACK);"#,
        iccm_org, LDEVID_TBS_ORG, FMCALIAS_TBS_ORG, iccm_size,
    )
}
