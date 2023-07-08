/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Build script for Caliptra ROM Test FMC.

--*/

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(not(feature = "std"))] {
            use std::env;
            use std::fs;
            use std::path::PathBuf;

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            fs::write(
                out_dir.join("memory.x"),
                r#"
                ROM_ORG   	     = 0x00000000;
                META_ORG  		 = ROM_SIZE;
                ICCM_ORG  		 = 0x40000000;
                DCCM_ORG  		 = 0x50000000;
                FHT_ORG   		 = 0x50002800;
                DATA_ORG  		 = 0x50004400;
                STACK_ORG 		 = 0x5001C000;
                ESTACK_ORG  	 = 0x5001F800;
                NSTACK_ORG       = 0x5001FC00;
                LDEVID_TBS_ORG   = 0x50003000;
                FMCALIAS_TBS_ORG = 0x50003400;
                PCR_LOG_ORG      = 0x50003800;
                FUSE_LOG_ORG     = 0x50003C00;
                RTALIAS_TBS_ORG  = 0x50004000;
                
                LDEVID_TBS_SIZE   = 1K;
                FMCALIAS_TBS_SIZE = 1K;
                RTALIAS_TBS_SIZE  = 1K;
                PCR_LOG_SIZE      = 1K;
                FUSE_LOG_SIZE     = 1K;
                
                
                
                ROM_SIZE    = 32K;
                MBOX_SIZE   = 128K;
                ICCM_SIZE   = 128K;
                DCCM_SIZE   = 128K;
                MAN1_SIZE   = 5K;
                MAN2_SIZE   = 5K;
                FHT_SIZE    = 2K;
                DATA_SIZE   = 95K;
                STACK_SIZE  = 14K;
                ESTACK_SIZE = 1K;
                NSTACK_SIZE = 1K;
                
                
                MEMORY
                {
                    ROM  		 (rx) : ORIGIN = ROM_ORG,  		   LENGTH = ROM_SIZE
                    META 		 (r)  : ORIGIN = META_ORG, 		   LENGTH = META_SIZE
                    ICCM 		 (rx) : ORIGIN = ICCM_ORG, 		   LENGTH = ICCM_SIZE
                    FHT  		 (rw) : ORIGIN = FHT_ORG,  		   LENGTH = FHT_SIZE
                    LDEVID_TBS   (rw) : ORIGIN = LDEVID_TBS_ORG,   LENGTH = LDEVID_TBS_SIZE
                    FMCALIAS_TBS (rw) : ORIGIN = FMCALIAS_TBS_ORG, LENGTH = FMCALIAS_TBS_SIZE
                    PCR_LOG      (rw) : ORIGIN = PCR_LOG_ORG,      LENGTH = PCR_LOG_SIZE
                    FUSE_LOG     (rw) : ORIGIN = FUSE_LOG_ORG,     LENGTH = FUSE_LOG_SIZE
                    RTALIAS_TBS  (rw) : ORIGIN = RTALIAS_TBS_ORG,  LENGTH = RTALIAS_TBS_SIZE
                    DATA         (rw) : ORIGIN = DATA_ORG,         LENGTH = DATA_SIZE
                    STACK	     (rw) : ORIGIN = STACK_ORG,  	   LENGTH = STACK_SIZE
                    ESTACK 		 (rw) : ORIGIN = ESTACK_ORG,       LENGTH = ESTACK_SIZE
                    NSTACK       (rw) : ORIGIN = NSTACK_ORG,       LENGTH = NSTACK_SIZE
                } 
                REGION_ALIAS("REGION_TEXT", ICCM);     
                REGION_ALIAS("REGION_RODATA", ICCM);  
                REGION_ALIAS("REGION_DATA", DATA);     
                REGION_ALIAS("REGION_BSS", DATA);      
                REGION_ALIAS("REGION_STACK", STACK);     
                REGION_ALIAS("REGION_ESTACK", ESTACK);     
                REGION_ALIAS("REGION_NSTACK", NSTACK);"#.as_bytes()).expect("Unable to generate memory.x");;     


            println!("cargo:rustc-link-search={}", out_dir.display());

            println!("cargo:rerun-if-changed=memory.x");
            println!("cargo:rustc-link-arg=-Tmemory.x");

            println!("cargo:rustc-link-arg=-Tlink.x");
            println!("cargo:rerun-if-changed=build.rs");
        }
    }
}
