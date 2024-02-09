
.section .init.text, "ax"
.align 2
_ext_intr_handler:
    // Clear MPIE: ensures that interrupts are disabled again after mret
    csrw mscratch, t0
    li t0, 0x80
    csrc mstatus, t0
    csrr t0, mscratch

    // Return back to event loop
    mret

// meivt must point at an address in DCCM
.section .data
// meivt must be 1024-byte aligned
.balign 1024
_ext_intr_vector:
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler

    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler

    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler

    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler
    .word _ext_intr_handler

