.section .init.text, "ax"
.align 2
.global transfer_control
transfer_control:
    .cfi_startproc
    jr a0
1:
    j 1b
    .cfi_endproc
