// FPGA replacement for KV with a configurable depth to use less resources

`define KV_DEPTH 8

module kv_reg (
        input wire clk,
        input wire rst,

        input wire s_cpuif_req,
        input wire s_cpuif_req_is_wr,
        input wire [11:0] s_cpuif_addr,
        input wire [31:0] s_cpuif_wr_data,
        input wire [31:0] s_cpuif_wr_biten,
        output wire s_cpuif_req_stall_wr,
        output wire s_cpuif_req_stall_rd,
        output wire s_cpuif_rd_ack,
        output wire s_cpuif_rd_err,
        output wire [31:0] s_cpuif_rd_data,
        output wire s_cpuif_wr_ack,
        output wire s_cpuif_wr_err,

        input kv_reg_pkg::kv_reg__in_t hwif_in,
        output kv_reg_pkg::kv_reg__out_t hwif_out
    );

    //--------------------------------------------------------------------------
    // CPU Bus interface logic
    //--------------------------------------------------------------------------
    logic cpuif_req;
    logic cpuif_req_is_wr;
    logic [11:0] cpuif_addr;
    logic [31:0] cpuif_wr_data;
    logic [31:0] cpuif_wr_biten;
    logic cpuif_req_stall_wr;
    logic cpuif_req_stall_rd;

    logic cpuif_rd_ack;
    logic cpuif_rd_err;
    logic [31:0] cpuif_rd_data;

    logic cpuif_wr_ack;
    logic cpuif_wr_err;

    assign cpuif_req = s_cpuif_req;
    assign cpuif_req_is_wr = s_cpuif_req_is_wr;
    assign cpuif_addr = s_cpuif_addr;
    assign cpuif_wr_data = s_cpuif_wr_data;
    assign cpuif_wr_biten = s_cpuif_wr_biten;
    assign s_cpuif_req_stall_wr = cpuif_req_stall_wr;
    assign s_cpuif_req_stall_rd = cpuif_req_stall_rd;
    assign s_cpuif_rd_ack = cpuif_rd_ack;
    assign s_cpuif_rd_err = cpuif_rd_err;
    assign s_cpuif_rd_data = cpuif_rd_data;
    assign s_cpuif_wr_ack = cpuif_wr_ack;
    assign s_cpuif_wr_err = cpuif_wr_err;

    logic cpuif_req_masked;

    // Read & write latencies are balanced. Stalls not required
    assign cpuif_req_stall_rd = '0;
    assign cpuif_req_stall_wr = '0;
    assign cpuif_req_masked = cpuif_req;

    //--------------------------------------------------------------------------
    // Address Decode
    //--------------------------------------------------------------------------
    typedef struct packed{
        logic [`KV_DEPTH-1:0]KEY_CTRL;
        logic [`KV_DEPTH-1:0][12-1:0]KEY_ENTRY;
        logic CLEAR_SECRETS;
    } decoded_reg_strb_t;
    decoded_reg_strb_t decoded_reg_strb;
    logic decoded_req;
    logic decoded_req_is_wr;
    logic [31:0] decoded_wr_data;
    logic [31:0] decoded_wr_biten;

    always_comb begin
        for(int i0=0; i0<`KV_DEPTH; i0++) begin
            decoded_reg_strb.KEY_CTRL[i0] = cpuif_req_masked & (cpuif_addr == 'h0 + i0*'h4);
        end
        for(int i0=0; i0<`KV_DEPTH; i0++) begin
            for(int i1=0; i1<12; i1++) begin
                decoded_reg_strb.KEY_ENTRY[i0][i1] = cpuif_req_masked & (cpuif_addr == 'h600 + i0*'h30 + i1*'h4);
            end
        end
        decoded_reg_strb.CLEAR_SECRETS = cpuif_req_masked & (cpuif_addr == 'hc00);
    end

    // Pass down signals to next stage
    assign decoded_req = cpuif_req_masked;
    assign decoded_req_is_wr = cpuif_req_is_wr;
    assign decoded_wr_data = cpuif_wr_data;
    assign decoded_wr_biten = cpuif_wr_biten;


    // Writes are always granted with no error response
    assign cpuif_wr_ack = decoded_req & decoded_req_is_wr;
    assign cpuif_wr_err = '0;
    //--------------------------------------------------------------------------
    // Field logic
    //--------------------------------------------------------------------------
    typedef struct packed{
        struct packed{
            struct packed{
                logic next;
                logic load_next;
            } lock_wr;
            struct packed{
                logic next;
                logic load_next;
            } lock_use;
            struct packed{
                logic next;
                logic load_next;
            } clear;
            struct packed{
                logic next;
                logic load_next;
            } rsvd0;
            struct packed{
                logic [4:0] next;
                logic load_next;
            } rsvd1;
            struct packed{
                logic [7:0] next;
                logic load_next;
            } dest_valid;
            struct packed{
                logic [3:0] next;
                logic load_next;
            } last_dword;
        } [`KV_DEPTH-1:0]KEY_CTRL;
        struct packed{
            struct packed{
                logic [31:0] next;
                logic load_next;
            } data;
        } [`KV_DEPTH-1:0][12-1:0]KEY_ENTRY;
        struct packed{
            struct packed{
                logic next;
                logic load_next;
            } wr_debug_values;
            struct packed{
                logic next;
                logic load_next;
            } sel_debug_value;
        } CLEAR_SECRETS;
    } field_combo_t;
    field_combo_t field_combo;

    typedef struct packed{
        struct packed{
            struct packed{
                logic value;
            } lock_wr;
            struct packed{
                logic value;
            } lock_use;
            struct packed{
                logic value;
            } clear;
            struct packed{
                logic value;
            } rsvd0;
            struct packed{
                logic [4:0] value;
            } rsvd1;
            struct packed{
                logic [7:0] value;
            } dest_valid;
            struct packed{
                logic [3:0] value;
            } last_dword;
        } [`KV_DEPTH-1:0]KEY_CTRL;
        struct packed{
            struct packed{
                logic [31:0] value;
            } data;
        } [`KV_DEPTH-1:0][12-1:0]KEY_ENTRY;
        struct packed{
            struct packed{
                logic value;
            } wr_debug_values;
            struct packed{
                logic value;
            } sel_debug_value;
        } CLEAR_SECRETS;
    } field_storage_t;
    field_storage_t field_storage;

    for(genvar i0=0; i0<`KV_DEPTH; i0++) begin
        // Field: kv_reg.KEY_CTRL[].lock_wr
        always_comb begin
            automatic logic [0:0] next_c = field_storage.KEY_CTRL[i0].lock_wr.value;
            automatic logic load_next_c = '0;
            if(decoded_reg_strb.KEY_CTRL[i0] && decoded_req_is_wr && !(hwif_in.KEY_CTRL[i0].lock_wr.swwel)) begin // SW write
                next_c = (field_storage.KEY_CTRL[i0].lock_wr.value & ~decoded_wr_biten[0:0]) | (decoded_wr_data[0:0] & decoded_wr_biten[0:0]);
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].lock_wr.next = next_c;
            field_combo.KEY_CTRL[i0].lock_wr.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.core_only_rst_b) begin
            if(~hwif_in.core_only_rst_b) begin
                field_storage.KEY_CTRL[i0].lock_wr.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].lock_wr.load_next) begin
                field_storage.KEY_CTRL[i0].lock_wr.value <= field_combo.KEY_CTRL[i0].lock_wr.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].lock_wr.value = field_storage.KEY_CTRL[i0].lock_wr.value;
        // Field: kv_reg.KEY_CTRL[].lock_use
        always_comb begin
            automatic logic [0:0] next_c = field_storage.KEY_CTRL[i0].lock_use.value;
            automatic logic load_next_c = '0;
            if(decoded_reg_strb.KEY_CTRL[i0] && decoded_req_is_wr && !(hwif_in.KEY_CTRL[i0].lock_use.swwel)) begin // SW write
                next_c = (field_storage.KEY_CTRL[i0].lock_use.value & ~decoded_wr_biten[1:1]) | (decoded_wr_data[1:1] & decoded_wr_biten[1:1]);
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].lock_use.next = next_c;
            field_combo.KEY_CTRL[i0].lock_use.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.core_only_rst_b) begin
            if(~hwif_in.core_only_rst_b) begin
                field_storage.KEY_CTRL[i0].lock_use.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].lock_use.load_next) begin
                field_storage.KEY_CTRL[i0].lock_use.value <= field_combo.KEY_CTRL[i0].lock_use.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].lock_use.value = field_storage.KEY_CTRL[i0].lock_use.value;
        // Field: kv_reg.KEY_CTRL[].clear
        always_comb begin
            automatic logic [0:0] next_c = field_storage.KEY_CTRL[i0].clear.value;
            automatic logic load_next_c = '0;
            if(decoded_reg_strb.KEY_CTRL[i0] && decoded_req_is_wr) begin // SW write
                next_c = (field_storage.KEY_CTRL[i0].clear.value & ~decoded_wr_biten[2:2]) | (decoded_wr_data[2:2] & decoded_wr_biten[2:2]);
                load_next_c = '1;
            end else if(1) begin // singlepulse clears back to 0
                next_c = '0;
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].clear.next = next_c;
            field_combo.KEY_CTRL[i0].clear.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.reset_b) begin
            if(~hwif_in.reset_b) begin
                field_storage.KEY_CTRL[i0].clear.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].clear.load_next) begin
                field_storage.KEY_CTRL[i0].clear.value <= field_combo.KEY_CTRL[i0].clear.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].clear.value = field_storage.KEY_CTRL[i0].clear.value;
        // Field: kv_reg.KEY_CTRL[].rsvd0
        always_comb begin
            automatic logic [0:0] next_c = field_storage.KEY_CTRL[i0].rsvd0.value;
            automatic logic load_next_c = '0;
            if(decoded_reg_strb.KEY_CTRL[i0] && decoded_req_is_wr) begin // SW write
                next_c = (field_storage.KEY_CTRL[i0].rsvd0.value & ~decoded_wr_biten[3:3]) | (decoded_wr_data[3:3] & decoded_wr_biten[3:3]);
                load_next_c = '1;
            end else if(hwif_in.KEY_CTRL[i0].rsvd0.hwclr) begin // HW Clear
                next_c = '0;
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].rsvd0.next = next_c;
            field_combo.KEY_CTRL[i0].rsvd0.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.reset_b) begin
            if(~hwif_in.reset_b) begin
                field_storage.KEY_CTRL[i0].rsvd0.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].rsvd0.load_next) begin
                field_storage.KEY_CTRL[i0].rsvd0.value <= field_combo.KEY_CTRL[i0].rsvd0.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].rsvd0.value = field_storage.KEY_CTRL[i0].rsvd0.value;
        // Field: kv_reg.KEY_CTRL[].rsvd1
        always_comb begin
            automatic logic [4:0] next_c = field_storage.KEY_CTRL[i0].rsvd1.value;
            automatic logic load_next_c = '0;
            if(decoded_reg_strb.KEY_CTRL[i0] && decoded_req_is_wr) begin // SW write
                next_c = (field_storage.KEY_CTRL[i0].rsvd1.value & ~decoded_wr_biten[8:4]) | (decoded_wr_data[8:4] & decoded_wr_biten[8:4]);
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].rsvd1.next = next_c;
            field_combo.KEY_CTRL[i0].rsvd1.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.reset_b) begin
            if(~hwif_in.reset_b) begin
                field_storage.KEY_CTRL[i0].rsvd1.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].rsvd1.load_next) begin
                field_storage.KEY_CTRL[i0].rsvd1.value <= field_combo.KEY_CTRL[i0].rsvd1.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].rsvd1.value = field_storage.KEY_CTRL[i0].rsvd1.value;
        // Field: kv_reg.KEY_CTRL[].dest_valid
        always_comb begin
            automatic logic [7:0] next_c = field_storage.KEY_CTRL[i0].dest_valid.value;
            automatic logic load_next_c = '0;
            if(hwif_in.KEY_CTRL[i0].dest_valid.we) begin // HW Write - we
                next_c = hwif_in.KEY_CTRL[i0].dest_valid.next;
                load_next_c = '1;
            end else if(hwif_in.KEY_CTRL[i0].dest_valid.hwclr) begin // HW Clear
                next_c = '0;
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].dest_valid.next = next_c;
            field_combo.KEY_CTRL[i0].dest_valid.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.hard_reset_b) begin
            if(~hwif_in.hard_reset_b) begin
                field_storage.KEY_CTRL[i0].dest_valid.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].dest_valid.load_next) begin
                field_storage.KEY_CTRL[i0].dest_valid.value <= field_combo.KEY_CTRL[i0].dest_valid.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].dest_valid.value = field_storage.KEY_CTRL[i0].dest_valid.value;
        // Field: kv_reg.KEY_CTRL[].last_dword
        always_comb begin
            automatic logic [3:0] next_c = field_storage.KEY_CTRL[i0].last_dword.value;
            automatic logic load_next_c = '0;
            if(hwif_in.KEY_CTRL[i0].last_dword.we) begin // HW Write - we
                next_c = hwif_in.KEY_CTRL[i0].last_dword.next;
                load_next_c = '1;
            end else if(hwif_in.KEY_CTRL[i0].last_dword.hwclr) begin // HW Clear
                next_c = '0;
                load_next_c = '1;
            end
            field_combo.KEY_CTRL[i0].last_dword.next = next_c;
            field_combo.KEY_CTRL[i0].last_dword.load_next = load_next_c;
        end
        always_ff @(posedge clk or negedge hwif_in.hard_reset_b) begin
            if(~hwif_in.hard_reset_b) begin
                field_storage.KEY_CTRL[i0].last_dword.value <= 'h0;
            end else if(field_combo.KEY_CTRL[i0].last_dword.load_next) begin
                field_storage.KEY_CTRL[i0].last_dword.value <= field_combo.KEY_CTRL[i0].last_dword.next;
            end
        end
        assign hwif_out.KEY_CTRL[i0].last_dword.value = field_storage.KEY_CTRL[i0].last_dword.value;
    end
    for(genvar i0=0; i0<`KV_DEPTH; i0++) begin
        for(genvar i1=0; i1<12; i1++) begin
            // Field: kv_reg.KEY_ENTRY[][].data
            always_comb begin
                automatic logic [31:0] next_c = field_storage.KEY_ENTRY[i0][i1].data.value;
                automatic logic load_next_c = '0;
                if(decoded_reg_strb.KEY_ENTRY[i0][i1] && decoded_req_is_wr && !(hwif_in.KEY_ENTRY[i0][i1].data.swwel)) begin // SW write
                    next_c = (field_storage.KEY_ENTRY[i0][i1].data.value & ~decoded_wr_biten[31:0]) | (decoded_wr_data[31:0] & decoded_wr_biten[31:0]);
                    load_next_c = '1;
                end else if(hwif_in.KEY_ENTRY[i0][i1].data.we) begin // HW Write - we
                    next_c = hwif_in.KEY_ENTRY[i0][i1].data.next;
                    load_next_c = '1;
                end else if(hwif_in.KEY_ENTRY[i0][i1].data.hwclr) begin // HW Clear
                    next_c = '0;
                    load_next_c = '1;
                end
                field_combo.KEY_ENTRY[i0][i1].data.next = next_c;
                field_combo.KEY_ENTRY[i0][i1].data.load_next = load_next_c;
            end
            always_ff @(posedge clk or negedge hwif_in.hard_reset_b) begin
                if(~hwif_in.hard_reset_b) begin
                    field_storage.KEY_ENTRY[i0][i1].data.value <= 'h0;
                end else if(field_combo.KEY_ENTRY[i0][i1].data.load_next) begin
                    field_storage.KEY_ENTRY[i0][i1].data.value <= field_combo.KEY_ENTRY[i0][i1].data.next;
                end
            end
            assign hwif_out.KEY_ENTRY[i0][i1].data.value = field_storage.KEY_ENTRY[i0][i1].data.value;
        end
    end
    // Field: kv_reg.CLEAR_SECRETS.wr_debug_values
    always_comb begin
        automatic logic [0:0] next_c = field_storage.CLEAR_SECRETS.wr_debug_values.value;
        automatic logic load_next_c = '0;
        if(decoded_reg_strb.CLEAR_SECRETS && decoded_req_is_wr) begin // SW write
            next_c = (field_storage.CLEAR_SECRETS.wr_debug_values.value & ~decoded_wr_biten[0:0]) | (decoded_wr_data[0:0] & decoded_wr_biten[0:0]);
            load_next_c = '1;
        end else if(1) begin // singlepulse clears back to 0
            next_c = '0;
            load_next_c = '1;
        end
        field_combo.CLEAR_SECRETS.wr_debug_values.next = next_c;
        field_combo.CLEAR_SECRETS.wr_debug_values.load_next = load_next_c;
    end
    always_ff @(posedge clk or negedge hwif_in.reset_b) begin
        if(~hwif_in.reset_b) begin
            field_storage.CLEAR_SECRETS.wr_debug_values.value <= 'h0;
        end else if(field_combo.CLEAR_SECRETS.wr_debug_values.load_next) begin
            field_storage.CLEAR_SECRETS.wr_debug_values.value <= field_combo.CLEAR_SECRETS.wr_debug_values.next;
        end
    end
    assign hwif_out.CLEAR_SECRETS.wr_debug_values.value = field_storage.CLEAR_SECRETS.wr_debug_values.value;
    // Field: kv_reg.CLEAR_SECRETS.sel_debug_value
    always_comb begin
        automatic logic [0:0] next_c = field_storage.CLEAR_SECRETS.sel_debug_value.value;
        automatic logic load_next_c = '0;
        if(decoded_reg_strb.CLEAR_SECRETS && decoded_req_is_wr) begin // SW write
            next_c = (field_storage.CLEAR_SECRETS.sel_debug_value.value & ~decoded_wr_biten[1:1]) | (decoded_wr_data[1:1] & decoded_wr_biten[1:1]);
            load_next_c = '1;
        end
        field_combo.CLEAR_SECRETS.sel_debug_value.next = next_c;
        field_combo.CLEAR_SECRETS.sel_debug_value.load_next = load_next_c;
    end
    always_ff @(posedge clk or negedge hwif_in.reset_b) begin
        if(~hwif_in.reset_b) begin
            field_storage.CLEAR_SECRETS.sel_debug_value.value <= 'h0;
        end else if(field_combo.CLEAR_SECRETS.sel_debug_value.load_next) begin
            field_storage.CLEAR_SECRETS.sel_debug_value.value <= field_combo.CLEAR_SECRETS.sel_debug_value.next;
        end
    end
    assign hwif_out.CLEAR_SECRETS.sel_debug_value.value = field_storage.CLEAR_SECRETS.sel_debug_value.value;
    //--------------------------------------------------------------------------
    // Readback
    //--------------------------------------------------------------------------
    logic readback_err;
    logic readback_done;
    logic [31:0] readback_data;
    
    // Assign readback values to a flattened array
    logic [`KV_DEPTH:0][31:0] readback_array;
    for(genvar i0=0; i0<`KV_DEPTH; i0++) begin
        assign readback_array[i0*1 + 0][0:0] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].lock_wr.value : '0;
        assign readback_array[i0*1 + 0][1:1] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].lock_use.value : '0;
        assign readback_array[i0*1 + 0][2:2] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].clear.value : '0;
        assign readback_array[i0*1 + 0][3:3] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].rsvd0.value : '0;
        assign readback_array[i0*1 + 0][8:4] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].rsvd1.value : '0;
        assign readback_array[i0*1 + 0][16:9] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].dest_valid.value : '0;
        assign readback_array[i0*1 + 0][20:17] = (decoded_reg_strb.KEY_CTRL[i0] && !decoded_req_is_wr) ? field_storage.KEY_CTRL[i0].last_dword.value : '0;
        assign readback_array[i0*1 + 0][31:21] = '0;
    end
    assign readback_array[`KV_DEPTH][0:0] = (decoded_reg_strb.CLEAR_SECRETS && !decoded_req_is_wr) ? field_storage.CLEAR_SECRETS.wr_debug_values.value : '0;
    assign readback_array[`KV_DEPTH][1:1] = (decoded_reg_strb.CLEAR_SECRETS && !decoded_req_is_wr) ? field_storage.CLEAR_SECRETS.sel_debug_value.value : '0;
    assign readback_array[`KV_DEPTH][31:2] = '0;


    // Reduce the array
    always_comb begin
        automatic logic [31:0] readback_data_var;
        readback_done = decoded_req & ~decoded_req_is_wr;
        readback_err = '0;
        readback_data_var = '0;
        for(int i=0; i<(`KV_DEPTH+1); i++) readback_data_var |= readback_array[i];
        readback_data = readback_data_var;
    end

    assign cpuif_rd_ack = readback_done;
    assign cpuif_rd_data = readback_data;
    assign cpuif_rd_err = readback_err;
endmodule