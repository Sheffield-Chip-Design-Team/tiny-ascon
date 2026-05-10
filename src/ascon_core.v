module ascon_core (
    input wire         clk,
    input wire         rst,
    input wire         decrypt,          // 0=encrypt, 1=decrypt
    input wire [127:0] key,
    input wire [127:0] bdi,
    input wire [ 15:0] bdi_valid_bytes,
    input wire [  3:0] core_op,          // Operation code from FSM

    input  wire [319:0] perm_state_out,
    output wire [319:0] state_to_perm,

    output wire [127:0] bdo,
    output wire         auth
);
  // Operation codes (must match top module)
  // localparam OP_IDLE = 4'd0;  // Handled by default case
  localparam OP_LD_KEY = 4'd1;
  localparam OP_LD_NPUB = 4'd2;
  localparam OP_INIT = 4'd3;
  localparam OP_PERM_WB = 4'd4;
  localparam OP_KADD2 = 4'd5;
  localparam OP_ABS_AD = 4'd6;
  localparam OP_ABS_MSG = 4'd7;
  localparam OP_PAD_AD = 4'd8;
  localparam OP_PAD_MSG = 4'd9;
  localparam OP_DOM_SEP = 4'd10;
  localparam OP_KADD3 = 4'd11;
  localparam OP_KADD4 = 4'd12;
  localparam OP_LD_TAG = 4'd13;
  localparam [63:0] IV_AEAD128 = 64'h00001000808c0001;

  reg [127:0] key_reg;
  reg [127:0] npub_reg;
  reg [319:0] state_reg;
  reg [127:0] bdo_reg;  // Register for output data
  reg         auth_reg;  // Authentication result

  // Padding function for encryption (inserts 0x01 after last valid byte)
  function [127:0] pad;
    input [127:0] in;
    input [15:0] val;
    integer i;
    begin
      // First byte
      pad[7:0] = val[0] ? in[7:0] : 8'd0;
      // Remaining bytes
      for (i = 1; i < 16; i = i + 1) begin
        pad[i*8+:8] = val[i] ? in[i*8+:8] : (val[i-1] ? 8'd1 : 8'd0);
      end
    end
  endfunction

  // Padding function for decryption state update
  // in1 = recovered plaintext bytes, in2 = current state bytes (rate part)
  function [127:0] pad2;
    input [127:0] in1;
    input [127:0] in2;
    input [15:0] val;
    integer i;
    begin
      pad2[7:0] = val[0] ? in1[7:0] : in2[7:0];
      for (i = 1; i < 16; i = i + 1) begin
        pad2[i*8+:8] = val[i] ? in1[i*8+:8] : (val[i-1] ? (in2[i*8+:8] ^ 8'd1) : in2[i*8+:8]);
      end
    end
  endfunction

  // 128-bit bus is little-endian byte packed:
  // bits [63:0] are first 8 bytes, bits [127:64] are next 8 bytes.
  wire [ 63:0] kh = key_reg[63:0];
  wire [ 63:0] kl = key_reg[127:64];
  wire [ 63:0] nh = npub_reg[63:0];
  wire [ 63:0] nl = npub_reg[127:64];

  wire [127:0] bdi_padded = pad(bdi, bdi_valid_bytes);
  wire [ 63:0] bdi_h = bdi_padded[63:0];
  wire [ 63:0] bdi_l = bdi_padded[127:64];

  wire [127:0] rate_state_bus = {state_reg[255:192], state_reg[319:256]};
  wire [127:0] dec_state_bus = pad2(bdi, rate_state_bus, bdi_valid_bytes);
  wire [127:0] enc_msg_bdo = {state_reg[255:192] ^ bdi_l, state_reg[319:256] ^ bdi_h};
  wire [127:0] dec_msg_bdo = rate_state_bus ^ dec_state_bus;

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      key_reg   <= 128'd0;
      npub_reg  <= 128'd0;
      state_reg <= 320'd0;
      bdo_reg   <= 128'd0;
      auth_reg  <= 1'b0;
    end else begin
      case (core_op)
        OP_LD_KEY: begin
          key_reg <= key;
        end

        OP_LD_NPUB: begin
          npub_reg <= bdi;
        end

        OP_INIT: begin
          state_reg <= {IV_AEAD128, kh, kl, nh, nl};
        end

        OP_PERM_WB: begin
          state_reg <= perm_state_out;
        end

        OP_KADD2: begin
          // XOR key into S3,S4 after initialization
          state_reg[127:0] <= state_reg[127:0] ^ {kh, kl};
        end

        OP_ABS_AD: begin
          // Absorb AD into rate (S0||S1) with padding
          state_reg[319:192] <= state_reg[319:192] ^ {bdi_h, bdi_l};
        end

        OP_ABS_MSG: begin
          if (decrypt) begin
            // Decryption: plaintext = state[rate] XOR ciphertext, absorb ciphertext
            state_reg[319:192] <= {dec_state_bus[63:0], dec_state_bus[127:64]};
          end else begin
            // Encryption: state[rate] ^= plaintext → ciphertext, output ciphertext
            state_reg[319:192] <= state_reg[319:192] ^ {bdi_h, bdi_l};
          end
        end

        OP_PAD_AD: begin
          // Explicit padding when no AD data (XOR 0x01 into first rate byte)
          state_reg[263:256] <= state_reg[263:256] ^ 8'h01;
        end

        OP_PAD_MSG: begin
          // Explicit padding when no MSG data (XOR 0x01 into first rate byte)
          state_reg[263:256] <= state_reg[263:256] ^ 8'h01;
        end

        OP_DOM_SEP: begin
          // Domain separation: flip MSB of S4
          state_reg[63] <= state_reg[63] ^ 1'b1;
        end

        OP_KADD3: begin
          // XOR key into S2,S3 before finalization
          state_reg[191:64] <= state_reg[191:64] ^ {kh, kl};
        end

        OP_KADD4: begin
          // XOR key into S3,S4 for tag extraction
          state_reg[127:0] <= state_reg[127:0] ^ {kh, kl};
          // Compute tag and prepare output
          bdo_reg <= {state_reg[63:0] ^ kl, state_reg[127:64] ^ kh};
        end

        OP_LD_TAG: begin
          // Compare received tag with computed tag (stored in bdo_reg from KADD4)
          auth_reg <= (bdi == bdo_reg);
        end

        default: begin
          // OP_IDLE - do nothing
        end
      endcase
    end
  end

  assign state_to_perm = state_reg;
  assign bdo           = (core_op == OP_ABS_MSG) ? (decrypt ? dec_msg_bdo : enc_msg_bdo) : bdo_reg;
  assign auth          = auth_reg;

endmodule
