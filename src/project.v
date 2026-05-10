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

  // ASCON wrapper instance
  ascon_wrap u_ascon_wrap (
    .clk            (clk),
    .rst            (~rst_n),
    .en             (uio_in[6]),
    .phase_valid    (uio_in[0]),
    .encrypt_en     (uio_in[1]),
    .ad_en          (uio_in[2]),
    .bdi_type       (uio_in[4:3]),
    .last_byte      (uio_in[5]),
    .byte_in        (ui_in),
    .byte_out       (uo_out),
    .phase_ready    (uio_out[6])
  );

  assign uio_oe = 8'b0100_0000; 

  // List all unused inputs to prevent warnings
  wire _unused_ok = &{ena, uio_out[7],uio_out[5:0],uio_oe};

endmodule
