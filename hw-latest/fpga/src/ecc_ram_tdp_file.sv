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
//======================================================================
//
// ecc_ram_tdp_file.sv
// --------
// ECC Data Memory to store intermediate results from point multiplication.
//
//
//======================================================================

module ecc_ram_tdp_file #(
    parameter ADDR_WIDTH = 10,
    parameter DATA_WIDTH = 32
    )
    (      
    input  wire                      clk,
    input  wire                      reset_n,
    input  wire                      zeroize, // TODO: FPGA doesn't handle zeroize
    
    input  wire                      ena,
    input  wire                      wea,
    input  wire  [ADDR_WIDTH-1 : 0]  addra,
    input  wire  [DATA_WIDTH-1 : 0]  dina,
    output logic [DATA_WIDTH-1 : 0]  douta,

    input  wire                      enb,
    input  wire                      web,
    input  wire  [ADDR_WIDTH-1 : 0]  addrb,
    input  wire  [DATA_WIDTH-1 : 0]  dinb,
    output logic [DATA_WIDTH-1 : 0]  doutb
    );

    localparam ADDR_LENGTH = 2**ADDR_WIDTH;

    (* ram_style = "block" *)
    reg [DATA_WIDTH-1:0] ram[ADDR_LENGTH];


    always @(posedge clk) begin
        if (ena & wea) begin
            ram[addra] <= dina;
        end
        if (ena & ~wea) begin
            douta <= ram[addra];
        end
    end

    always @(posedge clk) begin
        if (enb & web) begin
            ram[addrb] <= dinb;
        end
        if (enb & ~web) begin
            doutb <= ram[addrb];
        end
    end

endmodule