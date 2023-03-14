OUTPUT_ARCH(riscv)
OUTPUT_FORMAT("elf32-littleriscv", "elf32-littleriscv", "elf32-littleriscv")
ENTRY(_start)

SECTIONS 
{
	.text : ALIGN(4)
	{
        _stext = .;

		KEEP(*(.init .init.*));
        *(.text .text.*);
        KEEP(*(.vectors))
    	. = ALIGN(4);
		*(.trap);
		*(.trap.rust);
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

ASSERT(SIZEOF(.got) == 0, ".got section detected in fmc");