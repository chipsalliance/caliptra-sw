/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains linker script for Caliptra Library Tests

--*/


ENTRY(_start)
OUTPUT_ARCH( "riscv" )

MEMORY
{
  ROM   (rx) : ORIGIN = 0x00000000, LENGTH = 48K
  ICCM_CTL (rwx) : ORIGIN = 0x7FF0, LENGTH = 8
  DCCM_CTL (rwx) : ORIGIN = 0x7FF8, LENGTH = 8
  ICCM (rwx) : ORIGIN = 0x40000000, LENGTH = 128K
  DCCM (rwx) : ORIGIN = 0x50000000, LENGTH = 128K
  DATA (rw) : ORIGIN  = 0x50004800, LENGTH = 94K
}

STACK_SIZE = 0x8000;

SECTIONS
{
    .text :
    {
        *(.text.init )
        *(.text*)
        *(.rodata*)
    } > ROM

    ROM_DATA = .;

    .data : AT(ROM_DATA)
    {
        . = ALIGN(4);
        *(.data*);
        *(.sdata*);
        KEEP(*(.eh_frame))
        . = ALIGN(4);
        PROVIDE( __global_pointer$ = . + 0x800 );
        . = ALIGN(4);
    } > DATA

    .iccm.ctl : { LONG(0x40000000); LONG(0x40020000) } > ICCM_CTL    

    .data.ctl : { LONG(0x50000000); LONG(0x50020000) } > DCCM_CTL
    
    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
    } > DATA

    .stack (NOLOAD):
    {
        . = ALIGN(4);
        . = . + STACK_SIZE;
        . = ALIGN(4);
        PROVIDE(STACK_START = . );
    } > DATA

    _end = . ;
}

BSS_START = ADDR(.bss);
BSS_END = BSS_START + SIZEOF(.bss);
DATA_START = ADDR(.data);
DATA_END = DATA_START + SIZEOF(.data);
ROM_DATA_START = LOADADDR(.data);
