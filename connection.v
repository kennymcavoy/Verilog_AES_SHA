module connections (

    input wire  clk,
    
    input wire [159:0] sha_key,

    input wire ready,
    input wire [127:0] aes_result,
    input wire result_valid,

    output wire reset_n,
    output wire init,
    output wire next,
    output wire [511:0] block

);

wire [511:0] aes_data_sha;
reg [511:0] aes_data;

task data_correct;
    begin
        // aes_data = 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
        aes_data [511:384] = aes_result [127:0];
        aes_data [383:8] = 376h'8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
        aes_data [7:0] = h'80
    end
endtask


aes_core aes_inst (
    .ready (ready),
    .result (aes_result),
    .result_valid (result_valid)
);

sha1_core sha1_inst(
    .reset_n (reset_n),
    .init (init),
    .next (next),
    .block (block)
);

