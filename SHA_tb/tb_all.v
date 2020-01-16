module tb_all();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG = 0;

  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD = CLK_HALF_PERIOD * 2;


  //----------------------------------------------------------------
  // SHA declarations.
  //----------------------------------------------------------------
  reg [31 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;

  reg            tb_clk;
  reg            tb_reset_n;
  reg            tb_init;
  reg            tb_next;
  reg [511 : 0]  tb_block;
  wire           tb_ready;
  wire [159 : 0] tb_digest;
  wire           tb_digest_valid;

  //----------------------------------------------------------------
  // AES declarations.
  //----------------------------------------------------------------

reg [15:0] hex_in;               // hexadecimal input
reg [3:0] public_key;            // public key
wire [15:0] hex_out;             // hexadecimal output
wire [3:0] private_keyrec;       // Private key
wire [3:0] encrypt_data;         // Encrypted data

  //----------------------------------------------------------------
  // All declarations.
  //----------------------------------------------------------------

wire [511:0] encrpyted_data // Encrpyted Data
wire [159:0] sha_key // SHA Key
wire [] aes_key // AES Key
wire [511:0] data_out // data
wire [159:0] sha_out // SHA out
wire [1:0] verify // Verification bit



  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  sha1_core dut(
                   .clk(tb_clk),
                   .reset_n(tb_reset_n),

                   .init(tb_init),
                   .next(tb_next),

                   .block(tb_block),

                   .ready(tb_ready),

                   .digest(tb_digest),
                   .digest_valid(tb_digest_valid)
                 );

  always
    begin : clk_gen
      #CLK_HALF_PERIOD tb_clk = !tb_clk;
    end // clk_gen

  //----------------------------------------------------------------
  // sys_monitor
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      #(CLK_PERIOD);
      if (DEBUG)
        begin
          dump_dut_state();
        end
    end

  task dump_dut_state;
    begin
      $display("State of DUT");
      $display("------------");
      $display("Inputs and outputs:");
      $display("init   = 0x%01x, next  = 0x%01x",
               dut.init, dut.next);
      $display("block  = 0x%0128x", dut.block);

      $display("ready  = 0x%01x, valid = 0x%01x",
               dut.ready, dut.digest_valid);
      $display("digest = 0x%040x", dut.digest);
      $display("H0_reg = 0x%08x, H1_reg = 0x%08x, H2_reg = 0x%08x, H3_reg = 0x%08x, H4_reg = 0x%08x",
               dut.H0_reg, dut.H1_reg, dut.H2_reg, dut.H3_reg, dut.H4_reg);
      $display("");

      $display("Control signals and counter:");
      $display("sha1_ctrl_reg = 0x%01x", dut.sha1_ctrl_reg);
      $display("digest_init   = 0x%01x, digest_update = 0x%01x",
               dut.digest_init, dut.digest_update);
      $display("state_init    = 0x%01x, state_update  = 0x%01x",
               dut.state_init, dut.state_update);
      $display("first_block   = 0x%01x, ready_flag    = 0x%01x, w_init        = 0x%01x",
               dut.first_block, dut.ready_flag, dut.w_init);
      $display("round_ctr_inc = 0x%01x, round_ctr_rst = 0x%01x, round_ctr_reg = 0x%02x",
               dut.round_ctr_inc, dut.round_ctr_rst, dut.round_ctr_reg);
      $display("");

      $display("State registers:");
      $display("a_reg = 0x%08x, b_reg = 0x%08x, c_reg = 0x%08x, d_reg = 0x%08x, e_reg = 0x%08x",
               dut.a_reg, dut.b_reg, dut.c_reg, dut.d_reg,  dut.e_reg);
      $display("a_new = 0x%08x, b_new = 0x%08x, c_new = 0x%08x, d_new = 0x%08x, e_new = 0x%08x",
               dut.a_new, dut.b_new, dut.c_new, dut.d_new, dut.e_new);
      $display("");

      $display("State update values:");
      $display("f = 0x%08x, k = 0x%08x, t = 0x%08x, w = 0x%08x,",
               dut.state_logic.f, dut.state_logic.k, dut.state_logic.t, dut.w);
      $display("");
    end
  endtask // dump_dut_state

  //----------------------------------------------------------------
  // reset_dut()
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("*** Toggle reset.");
      tb_reset_n = 0;
      #(4 * CLK_HALF_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut

  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim;
    begin
      error_ctr = 0;
      tc_ctr = 0;

      tb_clk = 0;
      tb_reset_n = 1;

      tb_init = 0;
      tb_next = 0;
      tb_block = 512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000;
    end
  endtask // init_dut

    //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result;
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("*** %02d test cases did not complete successfully.", error_ctr);
        end
    end
  endtask // display_test_result


  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready;
    begin
      while (!tb_ready)
        begin
          #(CLK_PERIOD);

        end
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // single_block_test
  //
  // Test a message of at most one block.
  //----------------------------------------------------------------
  task single_block_test(input [7 : 0]   tc_number,
                         input [511 : 0] block,
                         input [159 : 0] expected);
   begin
     $display("*** TC %0d single block test case started.", tc_number);
     tc_ctr = tc_ctr + 1;

     tb_block = block;
     tb_init = 1;
     #(CLK_PERIOD);
     tb_init = 0;
     wait_ready();


     if (tb_digest == expected)
       begin
         $display("*** TC %0d successful.", tc_number);
         $display("");
       end
     else
       begin
         $display("*** ERROR: TC %0d NOT successful.", tc_number);
         $display("Expected: 0x%040x", expected);
         $display("Got:      0x%040x", tb_digest);
         $display("");

         error_ctr = error_ctr + 1;
       end
   end
  endtask // single_block_test

  //----------------------------------------------------------------
  // sha1_core_test
  // The main test functionality.
  //
  // Test cases taken from:
  // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
  //----------------------------------------------------------------
  initial
    begin : sha1_core_test
      reg [511 : 0] tc1_2;
      reg [159 : 0] res1_2;

      $display("   -- Testbench for sha1 core started --");

      init_sim();
      dump_dut_state();
      reset_dut();
      dump_dut_state();

      // TC1: Single block message: "55len".
      tc1_2 = 512'h746865717569636B62726F776E666F786A756D70736F7665727468656C617A79646F67746865717569636B62726F776E666F786A756D708000000000000001B8;
      res1_2 = 160'h58141f4f10dda66ff7efdf84217399e5ab6b963b;
      single_block_test(1, tc1_2, res1_2);

      display_test_result();
      $display("*** Simulation done.");
      $finish;
    end // sha1_core_test
endmodule // tb_sha1_core