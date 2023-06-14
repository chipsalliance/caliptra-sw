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
`include "el2_pdef.vh"
import el2_pkg::*;
module caliptra_veer_sram_export #(
    parameter el2_param_t pt = '{
	BHT_ADDR_HI            : 8'h09         ,
	BHT_ADDR_LO            : 6'h02         ,
	BHT_ARRAY_DEPTH        : 15'h0100       ,
	BHT_GHR_HASH_1         : 5'h00         ,
	BHT_GHR_SIZE           : 8'h08         ,
	BHT_SIZE               : 16'h0200       ,
	BITMANIP_ZBA           : 5'h01         ,
	BITMANIP_ZBB           : 5'h01         ,
	BITMANIP_ZBC           : 5'h01         ,
	BITMANIP_ZBE           : 5'h00         ,
	BITMANIP_ZBF           : 5'h00         ,
	BITMANIP_ZBP           : 5'h00         ,
	BITMANIP_ZBR           : 5'h00         ,
	BITMANIP_ZBS           : 5'h01         ,
	BTB_ADDR_HI            : 9'h009        ,
	BTB_ADDR_LO            : 6'h02         ,
	BTB_ARRAY_DEPTH        : 13'h0100       ,
	BTB_BTAG_FOLD          : 5'h00         ,
	BTB_BTAG_SIZE          : 9'h005        ,
	BTB_ENABLE             : 5'h01         ,
	BTB_FOLD2_INDEX_HASH   : 5'h00         ,
	BTB_FULLYA             : 5'h00         ,
	BTB_INDEX1_HI          : 9'h009        ,
	BTB_INDEX1_LO          : 9'h002        ,
	BTB_INDEX2_HI          : 9'h011        ,
	BTB_INDEX2_LO          : 9'h00A        ,
	BTB_INDEX3_HI          : 9'h019        ,
	BTB_INDEX3_LO          : 9'h012        ,
	BTB_SIZE               : 14'h0200       ,
	BTB_TOFFSET_SIZE       : 9'h00C        ,
	BUILD_AHB_LITE         : 5'h01         ,
	BUILD_AXI4             : 4'h0          ,
	BUILD_AXI_NATIVE       : 5'h01         ,
	BUS_PRTY_DEFAULT       : 6'h03         ,
	DATA_ACCESS_ADDR0      : 36'h000000000  ,
	DATA_ACCESS_ADDR1      : 36'h000000000  ,
	DATA_ACCESS_ADDR2      : 36'h000000000  ,
	DATA_ACCESS_ADDR3      : 36'h000000000  ,
	DATA_ACCESS_ADDR4      : 36'h000000000  ,
	DATA_ACCESS_ADDR5      : 36'h000000000  ,
	DATA_ACCESS_ADDR6      : 36'h000000000  ,
	DATA_ACCESS_ADDR7      : 36'h000000000  ,
	DATA_ACCESS_ENABLE0    : 5'h00         ,
	DATA_ACCESS_ENABLE1    : 5'h00         ,
	DATA_ACCESS_ENABLE2    : 5'h00         ,
	DATA_ACCESS_ENABLE3    : 5'h00         ,
	DATA_ACCESS_ENABLE4    : 5'h00         ,
	DATA_ACCESS_ENABLE5    : 5'h00         ,
	DATA_ACCESS_ENABLE6    : 5'h00         ,
	DATA_ACCESS_ENABLE7    : 5'h00         ,
	DATA_ACCESS_MASK0      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK1      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK2      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK3      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK4      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK5      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK6      : 36'h0FFFFFFFF  ,
	DATA_ACCESS_MASK7      : 36'h0FFFFFFFF  ,
	DCCM_BANK_BITS         : 7'h02         ,
	DCCM_BITS              : 9'h011        ,
	DCCM_BYTE_WIDTH        : 7'h04         ,
	DCCM_DATA_WIDTH        : 10'h020        ,
	DCCM_ECC_WIDTH         : 7'h07         ,
	DCCM_ENABLE            : 5'h01         ,
	DCCM_FDATA_WIDTH       : 10'h027        ,
	DCCM_INDEX_BITS        : 8'h0D         ,
	DCCM_NUM_BANKS         : 9'h004        ,
	DCCM_REGION            : 8'h05         ,
	DCCM_SADR              : 36'h050000000  ,
	DCCM_SIZE              : 14'h0080       ,
	DCCM_WIDTH_BITS        : 6'h02         ,
	DIV_BIT                : 7'h04         ,
	DIV_NEW                : 5'h01         ,
	DMA_BUF_DEPTH          : 7'h05         ,
	DMA_BUS_ID             : 9'h001        ,
	DMA_BUS_PRTY           : 6'h02         ,
	DMA_BUS_TAG            : 8'h01         ,
	FAST_INTERRUPT_REDIRECT : 5'h01         ,
	ICACHE_2BANKS          : 5'h01         ,
	ICACHE_BANK_BITS       : 7'h01         ,
	ICACHE_BANK_HI         : 7'h03         ,
	ICACHE_BANK_LO         : 6'h03         ,
	ICACHE_BANK_WIDTH      : 8'h08         ,
	ICACHE_BANKS_WAY       : 7'h02         ,
	ICACHE_BEAT_ADDR_HI    : 8'h05         ,
	ICACHE_BEAT_BITS       : 8'h03         ,
	ICACHE_BYPASS_ENABLE   : 5'h01         ,
	ICACHE_DATA_DEPTH      : 18'h00200      ,
	ICACHE_DATA_INDEX_LO   : 7'h04         ,
	ICACHE_DATA_WIDTH      : 11'h040        ,
	ICACHE_ECC             : 5'h01         ,
	ICACHE_ENABLE          : 5'h00         ,
	ICACHE_FDATA_WIDTH     : 11'h047        ,
	ICACHE_INDEX_HI        : 9'h00C        ,
	ICACHE_LN_SZ           : 11'h040        ,
	ICACHE_NUM_BEATS       : 8'h08         ,
	ICACHE_NUM_BYPASS      : 8'h02         ,
	ICACHE_NUM_BYPASS_WIDTH : 8'h02         ,
	ICACHE_NUM_WAYS        : 7'h02         ,
	ICACHE_ONLY            : 5'h00         ,
	ICACHE_SCND_LAST       : 8'h06         ,
	ICACHE_SIZE            : 13'h0010       ,
	ICACHE_STATUS_BITS     : 7'h01         ,
	ICACHE_TAG_BYPASS_ENABLE : 5'h01         ,
	ICACHE_TAG_DEPTH       : 17'h00080      ,
	ICACHE_TAG_INDEX_LO    : 7'h06         ,
	ICACHE_TAG_LO          : 9'h00D        ,
	ICACHE_TAG_NUM_BYPASS  : 8'h02         ,
	ICACHE_TAG_NUM_BYPASS_WIDTH : 8'h02         ,
	ICACHE_WAYPACK         : 5'h01         ,
	ICCM_BANK_BITS         : 7'h02         ,
	ICCM_BANK_HI           : 9'h003        ,
	ICCM_BANK_INDEX_LO     : 9'h004        ,
	ICCM_BITS              : 9'h011        ,
	ICCM_ENABLE            : 5'h01         ,
	ICCM_ICACHE            : 5'h00         ,
	ICCM_INDEX_BITS        : 8'h0D         ,
	ICCM_NUM_BANKS         : 9'h004        ,
	ICCM_ONLY              : 5'h01         ,
	ICCM_REGION            : 8'h04         ,
	ICCM_SADR              : 36'h040000000  ,
	ICCM_SIZE              : 14'h0080       ,
	IFU_BUS_ID             : 5'h01         ,
	IFU_BUS_PRTY           : 6'h02         ,
	IFU_BUS_TAG            : 8'h03         ,
	INST_ACCESS_ADDR0      : 36'h000000000  ,
	INST_ACCESS_ADDR1      : 36'h000000000  ,
	INST_ACCESS_ADDR2      : 36'h000000000  ,
	INST_ACCESS_ADDR3      : 36'h000000000  ,
	INST_ACCESS_ADDR4      : 36'h000000000  ,
	INST_ACCESS_ADDR5      : 36'h000000000  ,
	INST_ACCESS_ADDR6      : 36'h000000000  ,
	INST_ACCESS_ADDR7      : 36'h000000000  ,
	INST_ACCESS_ENABLE0    : 5'h00         ,
	INST_ACCESS_ENABLE1    : 5'h00         ,
	INST_ACCESS_ENABLE2    : 5'h00         ,
	INST_ACCESS_ENABLE3    : 5'h00         ,
	INST_ACCESS_ENABLE4    : 5'h00         ,
	INST_ACCESS_ENABLE5    : 5'h00         ,
	INST_ACCESS_ENABLE6    : 5'h00         ,
	INST_ACCESS_ENABLE7    : 5'h00         ,
	INST_ACCESS_MASK0      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK1      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK2      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK3      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK4      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK5      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK6      : 36'h0FFFFFFFF  ,
	INST_ACCESS_MASK7      : 36'h0FFFFFFFF  ,
	LOAD_TO_USE_PLUS1      : 5'h00         ,
	LSU2DMA                : 5'h00         ,
	LSU_BUS_ID             : 5'h01         ,
	LSU_BUS_PRTY           : 6'h02         ,
	LSU_BUS_TAG            : 8'h03         ,
	LSU_NUM_NBLOAD         : 9'h004        ,
	LSU_NUM_NBLOAD_WIDTH   : 7'h02         ,
	LSU_SB_BITS            : 9'h011        ,
	LSU_STBUF_DEPTH        : 8'h04         ,
	NO_ICCM_NO_ICACHE      : 5'h00         ,
	PIC_2CYCLE             : 5'h00         ,
	PIC_BASE_ADDR          : 36'h060000000  ,
	PIC_BITS               : 9'h00F        ,
	PIC_INT_WORDS          : 8'h01         ,
	PIC_REGION             : 8'h06         ,
	PIC_SIZE               : 13'h0020       ,
	PIC_TOTAL_INT          : 12'h01F        ,
	PIC_TOTAL_INT_PLUS1    : 13'h0020       ,
	RET_STACK_SIZE         : 8'h08         ,
	SB_BUS_ID              : 5'h01         ,
	SB_BUS_PRTY            : 6'h02         ,
	SB_BUS_TAG             : 8'h01         ,
	TIMER_LEGAL_EN         : 5'h01
}

) (
    el2_mem_if.top el2_mem_export
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
                                  .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                  .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                  .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                  .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                  .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                  .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                 .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                 .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                 .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                 .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                 .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                 .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                 .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                 .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                 .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                 .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                .D   (el2_mem_export.dccm_wr_data_bank[i][pt.DCCM_FDATA_WIDTH-1:0]  ),
                                .Q   (el2_mem_export.dccm_bank_dout[i][pt.DCCM_FDATA_WIDTH-1:0]     ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
                                     .D   (el2_mem_export.iccm_bank_wr_data[i][38:0]),
                                     .Q   (el2_mem_export.iccm_bank_dout[i][38:0]   ),
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
