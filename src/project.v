/*
 * Copyright (c) 2024 Your Name
 * SPDX-License-Identifier: Apache-2.0
 */

`default_nettype none

module tt_um_kingslanding_tiny_ascon_top (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // always 1 when the design is powered, so you can ignore it
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

  // Internal wire for ASCON byte output — needed so we can mux it below
  wire [7:0] w_byte_out;

  // ASCON wrapper instance
  ascon_wrap u_ascon_wrap (
      .clk        (clk),
      .rst        (~rst_n),
      .en         (uio_in[6]),
      .phase_valid(uio_in[0]),
      .encrypt_en (uio_in[1]),
      .ad_en      (uio_in[2]),
      .bdi_type   (uio_in[4:3]),
      .last_byte  (uio_in[5]),
      .byte_in    (ui_in),
      .byte_out   (w_byte_out),
      .phase_ready(uio_out[6])
  );

  reg [7:0] opt_cnt;
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) opt_cnt <= 8'd0;
    else opt_cnt <= opt_cnt + (ui_in ^ uio_in ^ {7'b0, ena});
  end

  assign uo_out       = ena ? w_byte_out : opt_cnt;
  assign uio_out[7]   = 1'b0;
  assign uio_out[5:0] = 6'b000000;
  assign uio_oe       = 8'b0100_0000;

endmodule
