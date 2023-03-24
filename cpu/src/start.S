/*++

Licensed under the Apache-2.0 license.

File Name:

    start.S

Abstract:

    File contains startup code for Caliptra.

Environment:

    ROM
   
--*/

#define MRAC 0x7C0

.section .init, "ax"
.global _start
_start:
   .cfi_startproc
   .cfi_undefined ra

   // Disable interrupts and clear pending interrupts
   csrw mie, 0
   csrw mip, 0

   // Clear all registers
   li x1,  0; li x2,  0; li x3,  0; li x4,  0;
   li x5,  0; li x6,  0; li x7,  0; li x8,  0;
   li x9,  0; li x10, 0; li x11, 0; li x12, 0;
   li x13, 0; li x14, 0; li x15, 0; li x16, 0;
   li x17, 0; li x18, 0; li x19, 0; li x20, 0;
   li x21, 0; li x22, 0; li x23, 0; li x24, 0;
   li x25, 0; li x26, 0; li x27, 0; li x28, 0;
   li x29, 0; li x30, 0; li x31, 0;

   // Setup the global pointer to enable linker relaxation.
   // Linker relaxation enables generation of relative jump
   // instruction on function calls and jumps. The relative
   // jumps have a tigher encoding than absolute jumps hence
   // reducing code memory usage.
   .option push
   .option norelax
      la gp, __global_pointer$
   .option pop

    // Setup stack pointer   
    la sp, _sstack

    // TODO: Initialize ICCM & DCCM on cold boot to
    // all zeros. This is needed to intialize the ECC
    // in ICCM & DCCM.

    // TODO: Setup Exception Vector
    la t0, _trap_handler
    csrw mtvec, t0    

    // Setup NMI Vector
    // Load address of NMI handler
    la t0, _nmi_handler
    // Load address of MMIO NMI vector register
    // CLP_SOC_IFC_REG_INTERNAL_NMI_VECTOR = 0x3003062c
    li t1, 0x3003062c
    // Store address of NMI handler in MMIO NMI vector register
    sw t0, 0x0(t1)    

    
    // Copy Data Section    
    la a0, _sdata        // dest
    la a1, _sidata       // src
    la a2, _data_len     // len 
    call _copy_mem32
    
    // Zero BSS Section    
    la a0, _sbss         // dest
    la a1, _bss_len      // len 
    call _zero_mem32

    tail entry_point

    .cfi_endproc 

.section .init.text, "ax"
.align 2
_zero_mem32:
    .cfi_startproc
    li t0, 4
1:    
    beqz a1, 1f
    sw x0, 0(a0) 
    addi a0, a0, 4
    sub a1, a1, t0
    j 1b
1:
    ret
    .cfi_endproc

.section .init.text, "ax"
.align 2
_copy_mem32:
    .cfi_startproc
    li t0, 4
1:  
    beqz a2, 1f
    lw t1, 0(a1)
    sw t1, 0(a0)
    addi a0, a0, 4
    addi a1, a1, 4
    sub a2, a2, t0
    j 1b
1:
    ret   
    .cfi_endproc

