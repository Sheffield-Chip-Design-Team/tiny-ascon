// Ascon Permutation Module
// Performs sequential permutation rounds (one round per clock cycle)

module ascon_permutation (
    input  wire         clk,
    input  wire         rst,
    input  wire         start,
    input  wire [  3:0] rounds,
    input  wire [319:0] ascon_state_in,
    output reg  [319:0] ascon_state_out,
    output reg          done
);

  // State lanes (5 x 64-bit)
  reg [63:0] x0, x1, x2, x3, x4;

  // Round counter
  reg [3:0] round_cnt;

  // FSM states
  localparam IDLE = 1'b0;
  localparam BUSY = 1'b1;
  reg state;

  // Intermediate wires for one permutation round
  wire [63:0] x0_aff1, x1_aff1, x2_aff1, x3_aff1, x4_aff1;
  wire [63:0] x0_chi, x1_chi, x2_chi, x3_chi, x4_chi;
  wire [63:0] x0_aff2, x1_aff2, x2_aff2, x3_aff2, x4_aff2;
  wire [63:0] x0_next, x1_next, x2_next, x3_next, x4_next;

  // Round constant calculation
  wire [3:0] t = 4'd12 - round_cnt;

  // ==========================================================================
  // LAYER 1: First Affine Layer (Constant Addition + Pre-mixing)
  // ==========================================================================
  assign x0_aff1 = x0 ^ x4;
  assign x1_aff1 = x1;
  assign x2_aff1 = x2 ^ x1 ^ {56'd0, (4'd15 - t), t};  // Round constant
  assign x3_aff1 = x3;
  assign x4_aff1 = x4 ^ x3;

  // ==========================================================================
  // LAYER 2: Chi/S-box Layer (Non-linear)
  // ==========================================================================
  assign x0_chi  = x0_aff1 ^ ((~x1_aff1) & x2_aff1);
  assign x1_chi  = x1_aff1 ^ ((~x2_aff1) & x3_aff1);
  assign x2_chi  = x2_aff1 ^ ((~x3_aff1) & x4_aff1);
  assign x3_chi  = x3_aff1 ^ ((~x4_aff1) & x0_aff1);
  assign x4_chi  = x4_aff1 ^ ((~x0_aff1) & x1_aff1);

  // ==========================================================================
  // LAYER 3: Second Affine Layer (Post-S-box Mixing)
  // ==========================================================================
  assign x0_aff2 = x0_chi ^ x4_chi;
  assign x1_aff2 = x1_chi ^ x0_chi;
  assign x2_aff2 = ~x2_chi;
  assign x3_aff2 = x3_chi ^ x2_chi;
  assign x4_aff2 = x4_chi;

  // ==========================================================================
  // LAYER 4: Linear Diffusion Layer
  // ==========================================================================
  // Rotation amounts: x0(19,28), x1(61,39), x2(1,6), x3(10,17), x4(7,41)
  assign x0_next = x0_aff2 ^ {x0_aff2[18:0], x0_aff2[63:19]} ^ {x0_aff2[27:0], x0_aff2[63:28]};
  assign x1_next = x1_aff2 ^ {x1_aff2[60:0], x1_aff2[63:61]} ^ {x1_aff2[38:0], x1_aff2[63:39]};
  assign x2_next = x2_aff2 ^ {x2_aff2[0:0], x2_aff2[63:1]} ^ {x2_aff2[5:0], x2_aff2[63:6]};
  assign x3_next = x3_aff2 ^ {x3_aff2[9:0], x3_aff2[63:10]} ^ {x3_aff2[16:0], x3_aff2[63:17]};
  assign x4_next = x4_aff2 ^ {x4_aff2[6:0], x4_aff2[63:7]} ^ {x4_aff2[40:0], x4_aff2[63:41]};

  // ==========================================================================
  // Sequential Control Logic with Reset
  // ==========================================================================
  always @(posedge clk or posedge rst) begin
    if (rst) begin
      state <= IDLE;
      done <= 1'b0;
      x0 <= 64'd0;
      x1 <= 64'd0;
      x2 <= 64'd0;
      x3 <= 64'd0;
      x4 <= 64'd0;
      round_cnt <= 4'd0;
      ascon_state_out <= 320'd0;
    end else begin
      case (state)
        IDLE: begin
          if (start) begin
            // Load input state
            x0 <= ascon_state_in[319:256];
            x1 <= ascon_state_in[255:192];
            x2 <= ascon_state_in[191:128];
            x3 <= ascon_state_in[127:64];
            x4 <= ascon_state_in[63:0];
            round_cnt <= rounds;
            state <= BUSY;
            done <= 1'b0;
          end else begin
            done <= 1'b0;
          end
        end

        BUSY: begin
          if (round_cnt > 0) begin
            // Apply one permutation round
            x0 <= x0_next;
            x1 <= x1_next;
            x2 <= x2_next;
            x3 <= x3_next;
            x4 <= x4_next;
            round_cnt <= round_cnt - 1;
          end else begin
            // Done - output result
            ascon_state_out <= {x0, x1, x2, x3, x4};
            done <= 1'b1;
            state <= IDLE;
          end
        end
      endcase
    end
  end

endmodule
