// Licensed under the Apache-2.0 license

/*++

Copyright (c) 2020. RISC-V International. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation and/or
   other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

--*/
#ifndef _MODEL_TEST_H
#define _MODEL_TEST_H

#if XLEN == 64
  #define ALIGNMENT 3
#else
  #define ALIGNMENT 2
#endif

#define RVMODEL_DATA_SECTION \
        .pushsection .tohost,"aw",@progbits; \
        .align 8; .global tohost; tohost: .dword 0; \
        .align 8; .global fromhost; fromhost: .dword 0; \
        .popsection;  \
        .align 8; .pushsection .regstate,"aw",@progbits; .global begin_regstate; begin_regstate:  \
        .word 128; \
        .align 8; .global end_regstate; end_regstate: .popsection \
        .word 4;

#define RVMODEL_HALT \
  addi x1, x1, 4; \
  li x1, 1; \
  write_tohost: \
    sw x1, tohost, t5; \
  self_loop:  j self_loop;

#define RVMODEL_BOOT

#define RVMODEL_DATA_BEGIN  \
  .align 4;  .pushsection .sig,"aw",@progbits; .global begin_signature; begin_signature:

#define RVMODEL_DATA_END \
  .align 4; .global end_signature; end_signature: .popsection \
  RVMODEL_DATA_SECTION \

#define RVMODEL_IO_INIT
#define RVMODEL_IO_WRITE_STR(_R, _STR)
#define RVMODEL_IO_CHECK()
#define RVMODEL_IO_ASSERT_GPR_EQ(_S, _R, _I)
#define RVMODEL_IO_ASSERT_SFPR_EQ(_F, _R, _I)
#define RVMODEL_IO_ASSERT_DFPR_EQ(_D, _R, _I)

#define RVMODEL_SET_MSW_INT \
 li t1, 1; \
 li t2, 0x2000000;  \
 sw t1, 0(t2);

#define RVMODEL_CLEAR_MSW_INT \
 li t2, 0x2000000; \
 sw x0, 0(t2);

#define RVMODEL_CLEAR_MTIMER_INT

#define RVMODEL_CLEAR_MEXT_INT

#endif // _MODEL_TEST_H