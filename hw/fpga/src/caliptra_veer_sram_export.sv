// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import el2_pkg::*;
module caliptra_veer_sram_export #(
    `include "el2_param.vh"
) (
    el2_mem_if.veer_sram_sink el2_mem_export
);


//////////////////////////////////////////////////////
// DCCM
//
if (pt.DCCM_ENABLE == 1) begin: Gen_dccm_enable
`define EL2_LOCAL_DCCM_RAM_TEST_PORTS    .TEST1   (1'b0   ), \
                                         .RME     (1'b0   ), \
                                         .RM      (4'b0000), \
                                         .LS      (1'b0   ), \
                                         .DS      (1'b0   ), \
                                         .SD      (1'b0   ), \
                                         .TEST_RNM(1'b0   ), \
                                         .BC1     (1'b0   ), \
                                         .BC2     (1'b0   ), \

localparam DCCM_INDEX_DEPTH = ((pt.DCCM_SIZE)*1024)/((pt.DCCM_BYTE_WIDTH)*(pt.DCCM_NUM_BANKS));  // Depth of memory bank
// 8 Banks, 16KB each (2048 x 72)
for (genvar i=0; i<pt.DCCM_NUM_BANKS; i++) begin: dccm_loop
`ifdef VERILATOR

        el2_ram #(DCCM_INDEX_DEPTH,39)  ram (
                                  // Primary ports
                                  .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                  .CLK (el2_mem_export.clk                                            ),
                                  .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                  .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                  .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                  .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                  .ROP (                                                              ),
                                  // These are used by SoC
                                  `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                  .*
                                  );
`else

      if (DCCM_INDEX_DEPTH == 32768) begin : dccm
         ram_32768x39  dccm_bank (
                                  // Primary ports
                                  .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                  .CLK (el2_mem_export.clk                                            ),
                                  .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                  .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                  .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                  .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                  .ROP (                                                              ),
                                  // These are used by SoC
                                  `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                  .*
                                  );
      end
      else if (DCCM_INDEX_DEPTH == 16384) begin : dccm
         ram_16384x39  dccm_bank (
                                  // Primary ports
                                  .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                  .CLK (el2_mem_export.clk                                            ),
                                  .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                  .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                  .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                  .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                  .ROP (                                                              ),
                                  // These are used by SoC
                                  `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                  .*
                                  );
      end
      else if (DCCM_INDEX_DEPTH == 8192) begin : dccm
         ram_8192x39  dccm_bank (
                                 // Primary ports
                                 .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                 .CLK (el2_mem_export.clk                                            ),
                                 .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                 .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                 .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                 .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                 .ROP (                                                              ),
                                 // These are used by SoC
                                 `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                 .*
                                 );
      end
      else if (DCCM_INDEX_DEPTH == 4096) begin : dccm
         ram_4096x39  dccm_bank (
                                 // Primary ports
                                 .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                 .CLK (el2_mem_export.clk                                            ),
                                 .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                 .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                 .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                 .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                 .ROP (                                                              ),
                                 // These are used by SoC
                                 `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                 .*
                                 );
      end
      else if (DCCM_INDEX_DEPTH == 3072) begin : dccm
         ram_3072x39  dccm_bank (
                                 // Primary ports
                                 .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                 .CLK (el2_mem_export.clk                                            ),
                                 .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                 .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                 .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                 .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                 .ROP (                                                              ),
                                 // These are used by SoC
                                 `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                 .*
                                 );
      end
      else if (DCCM_INDEX_DEPTH == 2048) begin : dccm
         ram_2048x39  dccm_bank (
                                 // Primary ports
                                 .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                 .CLK (el2_mem_export.clk                                            ),
                                 .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                 .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                 .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                 .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                 .ROP (                                                              ),
                                 // These are used by SoC
                                 `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                 .*
                                 );
      end
      else if (DCCM_INDEX_DEPTH == 1024) begin : dccm
         ram_1024x39  dccm_bank (
                                 // Primary ports
                                 .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                 .CLK (el2_mem_export.clk                                            ),
                                 .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                 .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                 .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                 .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                 .ROP (                                                              ),
                                 // These are used by SoC
                                 `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                 .*
                                 );
      end
      else if (DCCM_INDEX_DEPTH == 512) begin : dccm
         ram_512x39  dccm_bank (
                                // Primary ports
                                .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                .CLK (el2_mem_export.clk                                            ),
                                .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                .ROP (                                                              ),
                                // These are used by SoC
                                `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                .*
                                );
      end
      else if (DCCM_INDEX_DEPTH == 256) begin : dccm
         ram_256x39  dccm_bank (
                                // Primary ports
                                .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                .CLK (el2_mem_export.clk                                            ),
                                .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                .ROP (                                                              ),
                                // These are used by SoC
                                `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                .*
                                );
      end
      else if (DCCM_INDEX_DEPTH == 128) begin : dccm
         ram_128x39  dccm_bank (
                                // Primary ports
                                .ME  (el2_mem_export.dccm_clken[i]                                  ),
                                .CLK (el2_mem_export.clk                                            ),
                                .WE  (el2_mem_export.dccm_wren_bank[i]                              ),
                                .ADR (el2_mem_export.dccm_addr_bank[i]                              ),
                                .D   ({el2_mem_export.dccm_wr_ecc_bank[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_DATA_WIDTH-1:0]}),
                                .Q   ({el2_mem_export.dccm_bank_ecc[i][pt.DCCM_ECC_WIDTH-1:0],el2_mem_export.dccm_bank_dout[i][pt.DCCM_DATA_WIDTH-1:0]}     ),
                                .ROP (                                                              ),
                                // These are used by SoC
                                `EL2_LOCAL_DCCM_RAM_TEST_PORTS
                                .*
                                );
      end
`endif
end : dccm_loop
end :Gen_dccm_enable


//////////////////////////////////////////////////////
// ICCM
//
if (pt.ICCM_ENABLE) begin : Gen_iccm_enable
for (genvar i=0; i<pt.ICCM_NUM_BANKS; i++) begin: iccm_loop
 `ifdef VERILATOR

    el2_ram #(.depth(1<<pt.ICCM_INDEX_BITS), .width(39)) iccm_bank (
                                     // Primary ports
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .CLK (el2_mem_export.clk                       ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
 `else

     if (pt.ICCM_INDEX_BITS == 6 ) begin : iccm
               ram_64x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm

   else if (pt.ICCM_INDEX_BITS == 7 ) begin : iccm
               ram_128x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm

     else if (pt.ICCM_INDEX_BITS == 8 ) begin : iccm
               ram_256x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else if (pt.ICCM_INDEX_BITS == 9 ) begin : iccm
               ram_512x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else if (pt.ICCM_INDEX_BITS == 10 ) begin : iccm
               ram_1024x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else if (pt.ICCM_INDEX_BITS == 11 ) begin : iccm
               ram_2048x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else if (pt.ICCM_INDEX_BITS == 12 ) begin : iccm
               ram_4096x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else if (pt.ICCM_INDEX_BITS == 13 ) begin : iccm
               ram_8192x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else if (pt.ICCM_INDEX_BITS == 14 ) begin : iccm
               ram_16384x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
     else begin : iccm
               ram_32768x39 iccm_bank (
                                     // Primary ports
                                     .CLK (el2_mem_export.clk                       ),
                                     .ME  (el2_mem_export.iccm_clken[i]             ),
                                     .WE  (el2_mem_export.iccm_wren_bank[i]         ),
                                     .ADR (el2_mem_export.iccm_addr_bank[i]         ),
                                     .D   ({el2_mem_export.iccm_bank_wr_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_wr_data[i][31:0]}),
                                     .Q   ({el2_mem_export.iccm_bank_ecc[i][pt.ICCM_ECC_WIDTH-1:0],el2_mem_export.iccm_bank_dout[i][31:0]}   ),
                                     .ROP (                                         ),
                                     // These are used by SoC
                                     .TEST1   (1'b0   ),
                                     .RME     (1'b0   ),
                                     .RM      (4'b0000),
                                     .LS      (1'b0   ),
                                     .DS      (1'b0   ),
                                     .SD      (1'b0   ) ,
                                     .TEST_RNM(1'b0   ),
                                     .BC1     (1'b0   ),
                                     .BC2     (1'b0   )

                                      );
     end // block: iccm
`endif
end : iccm_loop
end : Gen_iccm_enable


endmodule
