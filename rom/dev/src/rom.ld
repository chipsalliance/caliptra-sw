/*++

Licensed under the Apache-2.0 license.

File Name:

	rom.ld

Abstract:

	ROM Linker Script

--*/

OUTPUT_ARCH(riscv)
OUTPUT_FORMAT("elf32-littleriscv", "elf32-littleriscv", "elf32-littleriscv")
ENTRY(_start)

ROM_ORG          = 0x00000000;
ICCM_ORG         = 0x40000000;
DCCM_ORG         = 0x50000000;
/* Avoid overlap with other long-lived DCCM structures */
DATA_ORG         = 0x50004400;
STACK_ORG        = 0x5001C000;
ESTACK_ORG       = 0x5001F800;
NSTACK_ORG       = 0x5001FC00;

/* Workaround https://github.com/llvm/llvm-project/issues/62423
 * by allowing lld to exceed the ROM size before relaxation optimizations are
 * applied. To prevent legitimate overflows, caliptra_builder::elf2rom() will
 * ensure that the sections fit within the true 32k ROM size.
 */
ROM_RELAXATION_PADDING = 4k;
ROM_SIZE          = 32K;
ICCM_SIZE         = 128K;
DCCM_SIZE         = 128K;
DATA_SIZE         = 95K;
STACK_SIZE        = 14K;
ESTACK_SIZE       = 1K;
NSTACK_SIZE       = 1K;

MEMORY
{
	ROM          (rx) : ORIGIN = ROM_ORG,          LENGTH = ROM_SIZE + ROM_RELAXATION_PADDING
	ICCM         (rx) : ORIGIN = ICCM_ORG,         LENGTH = ICCM_SIZE
	DATA         (rw) : ORIGIN = DATA_ORG,         LENGTH = DATA_SIZE
	STACK        (rw) : ORIGIN = STACK_ORG,        LENGTH = STACK_SIZE
	ESTACK       (rw) : ORIGIN = ESTACK_ORG,       LENGTH = ESTACK_SIZE
	NSTACK       (rw) : ORIGIN = NSTACK_ORG,       LENGTH = NSTACK_SIZE
} 

SECTIONS 
{
	.text : ALIGN(4)
	{
        _stext = .;

		KEEP(*(.init .init.*));
        *(.text .text.*);
        KEEP(*(.vectors))

    	. = ALIGN(4);
        _etext = .;
  	} > ROM

	.rodata : ALIGN(4)
	{
        _srodata = .;
		
		  *(.srodata .srodata.*);
    	*(.rodata .rodata.*);

    	. = ALIGN(4);
        _erodata = .;
	} > ROM

	.data : ALIGN(4)
	{
		  _sidata = LOADADDR(.data);
	    _sdata = .;
		
	    /* Must be called __global_pointer$ for linker relaxations to work. */
	    PROVIDE(__global_pointer$ = . + 0x800);
   
		*(.sdata .sdata.* .sdata2 .sdata2.*);
	    *(.data .data.*);
	    
		. = ALIGN(4);
	    _edata = .;
	} > DATA AT> ROM

	.bss (NOLOAD) : ALIGN(4) 
    {
		_sbss = .;

        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
		
		_ebss = .;
    } > DATA

    .stack (NOLOAD): ALIGN(4)
    {
    	_estack = .;
		
        . = . + STACK_SIZE;

        . = ALIGN(4);
    	_sstack = .;
    } > STACK

	.estack (NOLOAD): ALIGN(4)
    {
    	_eestack = .;
		
        . = . + ESTACK_SIZE;

        . = ALIGN(4);
    	_sestack = .;
    } > ESTACK

    .nstack (NOLOAD): ALIGN(4)
    {
    	_enstack = .;
		
        . = . + NSTACK_SIZE;

        . = ALIGN(4);
    	_snstack = .;
    } > NSTACK

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

/*
_bss_len  = SIZEOF(.bss);
_data_len = SIZEOF(.data);
*/

ASSERT(SIZEOF(.got) == 0, ".got section detected in ROM");
ASSERT(SIZEOF(.data) == 0, ".data section detected in ROM");
ASSERT(SIZEOF(.bss) == 0, ".bss section detected in ROM");
ASSERT(SIZEOF(.stack) == STACK_SIZE, ".stack section overflow");
ASSERT(SIZEOF(.estack) == ESTACK_SIZE, ".estack section overflow");
ASSERT(SIZEOF(.nstack) == NSTACK_SIZE, ".nstack section overflow");

