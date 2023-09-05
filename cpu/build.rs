// Licensed under the Apache-2.0 license

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Put the linker script somewhere the linker can find it.
    fs::write(
        out_dir.join("link.x"),
        r#"SECTIONS 
    {
        .text : ALIGN(4)
        {
            _stext = .;
    
            KEEP(*(.init .init.*));
            *(.text .text.*);
            KEEP(*(.vectors))
    
            . = ALIGN(4);
            _etext = .;
        } > REGION_TEXT
    
        .rodata : ALIGN(4)
        {
            _srodata = .;
            
            *(.srodata .srodata.*);
            *(.rodata .rodata.*);
    
            . = ALIGN(4);
            _erodata = .;
        } > REGION_RODATA
    
        .data : AT (_erodata) ALIGN(4) 
        {
            _sidata = LOADADDR(.data);
            _sdata = .;
            
            /* Must be called __global_pointer$ for linker relaxations to work. */
            PROVIDE(__global_pointer$ = . + 0x800);
       
            *(.sdata .sdata.* .sdata2 .sdata2.*);
            *(.data .data.*);
            
            . = ALIGN(4);
            _edata = .;
        } > REGION_DATA 
    
     
        .bss (NOLOAD) : ALIGN(4) 
        {
            _sbss = .;
    
            *(.bss*)
            *(.sbss*)
            *(COMMON)
            . = ALIGN(4);
            
            _ebss = .;
        } > REGION_BSS
    
        .stack (NOLOAD): ALIGN(4)
        {
            _estack = .;
            
            . = . + STACK_SIZE;
    
            . = ALIGN(4);
            _sstack = .;
        } > REGION_STACK
    
        .estack (NOLOAD): ALIGN(4)
        {
            _eestack = .;
            
            . = . + ESTACK_SIZE;
    
            . = ALIGN(4);
            _sestack = .;
        } > REGION_ESTACK
    
        .nstack (NOLOAD): ALIGN(4)
        {
            _enstack = .;
            
            . = . + NSTACK_SIZE;
    
            . = ALIGN(4);
            _snstack = .;
        } > REGION_NSTACK
    
    
        .got (INFO) :
        {
            KEEP(*(.got .got.*));
        }
    
        .eh_frame (INFO) : 
        { 
            KEEP(*(.eh_frame))
        }
        
        .eh_frame_hdr (INFO) :
        {
            *(.eh_frame_hdr) 
        }
    }
    
    _bss_len  = SIZEOF(.bss);
    _data_len = SIZEOF(.data);
    
    ASSERT(SIZEOF(.got) == 0, ".got section detected");
    ASSERT(SIZEOF(.data) == 0, ".data section detected");
    ASSERT(SIZEOF(.bss) == 0, ".bss section detected");
    ASSERT(SIZEOF(.stack) == STACK_SIZE, ".stack section overflow");
    ASSERT(SIZEOF(.estack) == ESTACK_SIZE, ".estack section overflow");
    ASSERT(SIZEOF(.nstack) == NSTACK_SIZE, ".nstack section overflow");"#
            .as_bytes(),
    )
    .unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());
}
