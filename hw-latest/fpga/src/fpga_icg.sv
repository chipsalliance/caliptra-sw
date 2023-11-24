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

// Caliptra ICG that disables clock gating
module fpga_fake_icg (
    input logic clk,
    input logic en,
    output clk_cg
);
    // No clock gating
    assign clk_cg = clk;

endmodule

// Caliptra ICG that uses gated clock conversion for clock gating
module fpga_real_icg (
    (* gated_clock = "yes" *) input logic clk,
    input logic en,
    output clk_cg
);
    logic en_lat;

    always @(negedge clk) begin
        en_lat <= en;
    end

    // Gate clk
    assign clk_cg = clk && en_lat;

endmodule

// VEER ICG that uses gated clock conversion for clock gating
module fpga_rv_clkhdr
  (
   (* gated_clock = "yes" *) input logic CK,
   input logic SE, EN,
   output Q
   );
   logic  enable;
   assign enable = EN | SE;
   logic  en_ff;

   always @(negedge CK) begin
      en_ff <= enable;
   end

   assign Q = CK & en_ff;

endmodule
