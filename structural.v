module aes_sha_structural(

    // Clock and reset.
    input wire           clk,
    input wire           aes_reset_n,
    input wire           sha_reset_n,
    input wire []         aes_data,
    input wire []          aes_key,

    output wire [127:0]         aes_output,
    output wire [159:0]        sha_hash

);

//----------------------------------------------------------------
// AES Registers
//----------------------------------------------------------------

  reg aes_init_reg;
  reg aes_init_new;

  reg aes_next_reg;
  reg aes_next_new;

  reg aes_encdec_reg;
  reg aes_keylen_reg;
  reg aes_config_we;

  reg [31 : 0] aes_block_reg [0 : 3];
  reg          aes_block_we;

  reg [31 : 0] aes_key_reg [0 : 7];
  reg          aes_key_we;

  reg [127 : 0] aes_result_reg;
  reg           aes_valid_reg;
  reg           aes_ready_reg;

//----------------------------------------------------------------
// SHA Registers
//----------------------------------------------------------------

  reg sha_init_reg;
  reg sha_init_new;

  reg sha_next_reg;
  reg sha_next_new;

//----------------------------------------------------------------
// AES Wires
//----------------------------------------------------------------

  wire           aes_core_encdec;
  wire           aes_core_init;
  wire           aes_core_next;
  wire           aes_core_ready;
  wire [255 : 0] aes_core_key;
  wire           aes_core_keylen;
  wire [127 : 0] aes_core_block;
  wire [127 : 0] aes_core_result;
  wire           aes_core_valid;


//----------------------------------------------------------------
// SHA Wires
//----------------------------------------------------------------

  wire           sha_core_ready;
  wire [511 : 0] sha_core_block;
  wire [159 : 0] sha_core_digest;
  wire           sha_core_digest_valid;

  reg [31 : 0]   sha_tmp_read_data; // maybe?
  reg            sha_tmp_error; // maybe?

//----------------------------------------------------------------
// AES Instance
//----------------------------------------------------------------

  aes_core core_aes(
                .clk(clk), // input
                .reset_n(aes_reset_n), // reset_n

                .encdec(aes_core_encdec), // input
                .init(aes_core_init), // input
                .next(aes_core_next), // input
                .ready(aes_core_ready), // output

                .key(aes_core_key), // input
                .keylen(aes_core_keylen), // input

                .block(aes_core_block), // input
                .result(aes_core_result), // output
                .result_valid(aes_core_valid) // output
                );

//----------------------------------------------------------------
// SHA Instance
//----------------------------------------------------------------

sha1_core core_sha(
                 .clk(clk), // input
                 .reset_n(sha_reset_n), // input

                 .init(sha_init_reg), // input
                 .next(sha_next_reg), // input

                 .ready(sha_core_ready), // output

                 .block(sha_core_block), // input

                 .digest(sha_core_digest), // output
                 .digest_valid(sha_core_digest_valid) // output
                );


//----------------------------------------------------------------
// AES Control
//----------------------------------------------------------------

  always @ (posedge clk or negedge aes_reset_n)
    begin : aes_reg_update
      integer i;

      if (!aes_reset_n)
        begin
          for (i = 0 ; i < 4 ; i = i + 1)
            aes_block_reg[i] <= 32'h0;

          for (i = 0 ; i < 8 ; i = i + 1)
            aes_key_reg[i] <= 32'h0;

          aes_init_reg   <= 1'b0;
          aes_next_reg   <= 1'b0;
          aes_encdec_reg <= 1'b0;
          aes_keylen_reg <= 1'b0;

          aes_result_reg <= 128'h0;
          aes_valid_reg  <= 1'b0;
          aes_ready_reg  <= 1'b0;
        end
      else
        begin
          aes_ready_reg  <= core_ready;
          aes_valid_reg  <= core_valid;
          aes_result_reg <= core_result;
          aes_init_reg   <= init_new;
          aes_next_reg   <= next_new;

        //   if (config_we)                                         UNKNOWN
        //     begin
        //       encdec_reg <= write_data[CTRL_ENCDEC_BIT];
        //       keylen_reg <= write_data[CTRL_KEYLEN_BIT];
        //     end

        //   if (key_we)
        //     key_reg[address[2 : 0]] <= write_data;

        //   if (block_we)
        //     block_reg[address[1 : 0]] <= write_data;
        end
    end // reg_update


//----------------------------------------------------------------
// SHA Control
//----------------------------------------------------------------

  always @ (posedge clk or negedge sha_reset_n)
    begin : sha_reg_update
      integer i;

      if (!sha_reset_n)
        begin
          sha_init_reg         <= 0;
          sha_next_reg         <= 0;
          sha_ready_reg        <= 0;
          sha_digest_reg       <= 160'h0;
          sha_digest_valid_reg <= 0;

          for (i = 0 ; i < 16 ; i = i + 1)
            sha_block_reg[i] <= 32'h0;
        end
      else
        begin
          sha_ready_reg        <= core_ready;
          sha_digest_valid_reg <= sha_core_digest_valid;
          sha_init_reg         <= init_new;
          sha_next_reg         <= next_new;

        //   if (block_we)                                 UNKNOWN
        //     block_reg[address[3 : 0]] <= write_data; 

          if (sha_core_digest_valid)
            sha_digest_reg <= core_digest;
        end
    end // reg_update



task sha_test(
                         input [511 : 0] block,
                         input [159 : 0] expected);
   begin
     $display("*** TC %0d single block test case started.");
     tc_ctr = tc_ctr + 1;

     tb_block = block;
     tb_init = 1;
     #(CLK_PERIOD);
     tb_init = 0;
     wait_ready();


     if (tb_digest == expected)
       begin
         $display("*** TC %0d successful.");
         $display("");
       end
     else
       begin
         $display("*** ERROR: TC %0d NOT successful.");
         $display("Expected: 0x%040x", expected);
         $display("Got:      0x%040x", tb_digest);
         $display("");

         error_ctr = error_ctr + 1;
       end
   end
  endtask // sha_test

  task aes_test(
                                  input           encdec,
                                  input [255 : 0] key,
                                  input           key_length,
                                  input [127 : 0] block,
                                  input [127 : 0] expected);
   begin
     $display("*** TC %0d ECB mode test started.");
     tc_ctr = tc_ctr + 1;

     // Init the cipher with the given key and length.
     tb_key = key;
     tb_keylen = key_length;
     tb_init = 1;
     #(2 * CLK_PERIOD);
     tb_init = 0;
     wait_ready();

     $display("Key expansion done");
     $display("");

     dump_keys();


     // Perform encipher och decipher operation on the block.
     tb_encdec = encdec;
     tb_block = block;
     tb_next = 1;
     #(2 * CLK_PERIOD);
     tb_next = 0;
     wait_ready();

     if (tb_result == expected)
       begin
         $display("*** TC %0d successful.");
         $display("");
       end
     else
       begin
         $display("*** ERROR: TC %0d NOT successful.");
         $display("Expected: 0x%032x", expected);
         $display("Got:      0x%032x", tb_result);
         $display("");

         error_ctr = error_ctr + 1;
       end
   end
  endtask // aes_test









endmodule




// AES IO
    // input wire            clk,
    // input wire            reset_n,

    // input wire            encdec,
    // input wire            init,
    // input wire            next,
    
    // input wire [255 : 0]  key,
    // input wire            keylen,
    // input wire [127 : 0]  block,

    // output wire           ready,
    // output wire [127 : 0] result,
    // output wire           result_valid


// SHA IO
    //  input wire            clk,
    //  input wire            reset_n,

    //  input wire            init,
    //  input wire            next,

    //  input wire [511 : 0]  block,


    //  output wire           ready,
    //  output wire [159 : 0] digest,
    //  output wire           digest_valid