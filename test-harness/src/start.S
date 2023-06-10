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

.equ CPTRA_FW_ERROR_NON_FATAL, 0x3003000c
.equ CPTRA_FW_EXTENDED_ERROR_INFO, 0x30030018
.equ CPTRA_INTERNAL_NMI_VECTOR, 0x3003062c

.equ CPTRA_ERROR_EXCEPTION, 0x03000002
.equ CPTRA_ERROR_NMI, 0x03000003

.option push
.option norelax
    la gp, __global_pointer$
.option pop

    # Initialize the stack pointer
    la sp, STACK_START
    
    # Setup trap handler
    la t0, trap_vec
    csrw MTVEC, t0

    # Setup NMI handler
    li t0, CPTRA_INTERNAL_NMI_VECTOR
    la t1, nmi_vec
    sw t1, 0(t0)

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
    
    # Setup MRAC
    # ---------------------------------------------
    # | Region       | Side Effect |  Cacheable   |      
    # ---------------------------------------------
    # | 0x0000_0000  |    0        |      1       |  
    # | 0x4000_0000  |    0        |      0       |  
    # | 0x5000_0000  |    0        |      0       |  
    # | Others       |    1        |      0       |  
    # ---------------------------------------------
    li x1, 0xAAAAA0A9
    csrw 0x7c0, x1

    # call main entry point
    call main
    
    # exit the emulator with success
    la t0, EMU_CTRL_EXIT
    li t1, 0xFF
    sw t1, 0(t0)
1:
    j 1b

.align 2
nmi_vec:
    li t0, CPTRA_FW_ERROR_NON_FATAL
    li t1, CPTRA_ERROR_NMI
    sw t1, 0(t0)
    j exception_common

.align 2
trap_vec:
    li t0, CPTRA_FW_ERROR_NON_FATAL
    li t1, CPTRA_ERROR_EXCEPTION
    sw t1, 0(t0)

exception_common:
    li t0, CPTRA_FW_EXTENDED_ERROR_INFO
    sw sp, 0(t0)

    csrr t1, mepc
    sw t1, 4(t0)

    csrr t1, mcause
    sw t1, 8(t0)

    // MSCAUSE = 0x7FF
    csrr t1, 0x7ff
    sw t1, 12(t0)

    csrr t1, mstatus
    sw t1, 16(t0)

    csrr t1, mtval
    sw t1, 20(t0)

    # exit the emulator with error
    la t0, EMU_CTRL_EXIT
    li t1, 0x01
    sw t1, 0(t0)
1:
    j 1b

    nop
    nop
    nop
    nop

.section .data
.equ  EMU_CTRL_EXIT, 0x300300C8
