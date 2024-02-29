// From https://github.com/SystemRDL/PeakRDL-regblock/blob/683fc4d0acc8c4733ca7f53803347eb99667441e/hdl-src/axi4lite_intf.sv
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

interface axi4lite_intf #(
    parameter DATA_WIDTH = 64,
    parameter ADDR_WIDTH = 32
);
    logic AWREADY;
    logic AWVALID;
    logic [ADDR_WIDTH-1:0] AWADDR;
    logic [2:0] AWPROT;

    logic WREADY;
    logic WVALID;
    logic [DATA_WIDTH-1:0] WDATA;
    logic [DATA_WIDTH/8-1:0] WSTRB;

    logic BREADY;
    logic BVALID;
    logic [1:0] BRESP;

    logic ARREADY;
    logic ARVALID;
    logic [ADDR_WIDTH-1:0] ARADDR;
    logic [2:0] ARPROT;

    logic RREADY;
    logic RVALID;
    logic [DATA_WIDTH-1:0] RDATA;
    logic [1:0] RRESP;

    modport master (
        input AWREADY,
        output AWVALID,
        output AWADDR,
        output AWPROT,

        input WREADY,
        output WVALID,
        output WDATA,
        output WSTRB,

        output BREADY,
        input BVALID,
        input BRESP,

        input ARREADY,
        output ARVALID,
        output ARADDR,
        output ARPROT,

        output RREADY,
        input RVALID,
        input RDATA,
        input RRESP
    );

    modport slave (
        output AWREADY,
        input AWVALID,
        input AWADDR,
        input AWPROT,

        output WREADY,
        input WVALID,
        input WDATA,
        input WSTRB,

        input BREADY,
        output BVALID,
        output BRESP,

        output ARREADY,
        input ARVALID,
        input ARADDR,
        input ARPROT,

        input RREADY,
        output RVALID,
        output RDATA,
        output RRESP
    );
endinterface