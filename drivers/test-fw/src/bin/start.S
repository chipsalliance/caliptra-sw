/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains startup code for Caliptra Library Tests

--*/

.section .text.init
.global _start
_start:

.option push
.option norelax
    la gp, __global_pointer$
.option pop

    # Initialize the stack pointer
    la sp, STACK_START
    
    # Setup trap handler
    la t0, trap_vec
    csrw MTVEC, t0

    # Copy BSS
    la t0, BSS_START
    la t1, BSS_END
copy_bss:
    bge t0, t1, end_copy_bss
    sw x0, 0(t0)
    addi t0, t0, 4
    j copy_bss
end_copy_bss:
    
    # Copy data
    la t0, ROM_DATA_START
    la t1, DATA_START
    la t2, DATA_END
copy_data:
    bge t1, t2, end_copy_data
    lw t3, 0(t0)
    sw t3, 0(t1)
    addi t0, t0, 4
    addi t1, t1, 4
    j copy_data
end_copy_data:
    
    # Set side-effects in MRAC
    li x1, 0xaaaaaaaa
    csrw 0x7c0, x1

    # call main entry point
    call main
    
    # exit the emulator with success
    la t0, EMU_CTRL_EXIT
    li t1, 0xFF
    sw t1, 0(t0)
1:
    j 1b

trap_vec:
    # exit the emulator with error
    la t0, EMU_CTRL_EXIT
    li t1, 0x01
    sw t1, 0(t0)
1:
    j 1b

.section .data
.equ  EMU_CTRL_EXIT, 0x300300C8
