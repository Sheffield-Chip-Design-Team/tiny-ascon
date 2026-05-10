// ========== FSM (Finite State Machine) States ==========
// Hardware sequencing for Ascon-AEAD128.

module ascon_top (
    // ========== Clock and Reset ==========
    input wire clk,
    input wire rst,

    // ========== Mode Selection ==========
    input wire decrypt,  // 0=encrypt, 1=decrypt

    // ========== Key Input Port ==========
    input wire [127:0] key,
    input wire key_valid,
    output reg key_ready,

    // ========== Block Data Input (BDI) ==========
    input wire [127:0] bdi,
    input wire [15:0] bdi_valid,
    input wire [1:0] bdi_type,
    input wire bdi_eot,  // End of type signal
    input wire bdi_eoi,  // End of Input signal
    output reg bdi_ready,

    // ========== Block Data Output (BDO) ==========
    input wire bdo_ready,
    output wire [127:0] bdo,
    output reg bdo_valid,
    output reg [1:0] bdo_type,

    // ========== Status Output ==========
    output wire auth,
    output reg  auth_valid,
    output reg  done
);
  // Internal state <-> permutation signals
  wire [319:0] ascon_state_in;
  wire [319:0] ascon_state_out;
  reg          perm_start;
  wire         perm_done;
  reg  [  3:0] perm_rounds;

  // Datapath operation code
  reg  [  3:0] core_op;

  // Operation codes for datapath (must match datapath module)
  localparam OP_IDLE = 4'd0;
  localparam OP_LD_KEY = 4'd1;  // Load 128-bit key
  localparam OP_LD_NPUB = 4'd2;  // Load 128-bit nonce
  localparam OP_INIT = 4'd3;  // Initialize.	Build S = IV||K||N
  localparam OP_PERM_WB = 4'd4;  // Permutation writeback
  localparam OP_KADD2 = 4'd5;  // S3,S4 ^= K after init
  localparam OP_ABS_AD = 4'd6;  // Absorb AD
  localparam OP_ABS_MSG = 4'd7;  // Absorb MSG
  localparam OP_PAD_AD = 4'd8;  // Pad AD
  localparam OP_PAD_MSG = 4'd9;  // Pad MSG
  localparam OP_DOM_SEP = 4'd10;  // Domain separation
  localparam OP_KADD3 = 4'd11;  // S2,S3 ^= K before final
  localparam OP_KADD4 = 4'd12;  // S3,S4 ^= K for tag
  localparam OP_LD_TAG = 4'd13;  // Load received tag for verification

  // BDI type encoding (matches reference)
  localparam [1:0] BDI_TYPE_NPUB = 2'b00;
  localparam [1:0] BDI_TYPE_AD = 2'b01;
  localparam [1:0] BDI_TYPE_MSG = 2'b10;

  // FSM encoding
  localparam IDLE = 5'd0;  // Waiting for operation to start
  localparam LD_KEY = 5'd1;  // Loading key K (for AEAD)
  localparam LD_NPUB = 5'd2;  // Loading nonce N (for AEAD)
  localparam INIT = 5'd3;  // S ← IV||K||N, permute 12 rounds
  localparam KADD_2 = 5'd4;  // S ← S ⊕ (0¹⁹²||K) after initialization
  localparam ABS_AD = 5'd5;  // Absorb associated data
  localparam PAD_AD = 5'd6;  // Pad associated data
  localparam PRO_AD = 5'd7;  // Permute after absorbing AD
  localparam DOM_SEP = 5'd8;  // Domain separation
  localparam ABS_MSG = 5'd9;  // Absorb message
  localparam PAD_MSG = 5'd10;  // Pad message
  localparam PRO_MSG = 5'd11;  // Permute after absorbing message
  localparam KADD_3 = 5'd12;  // S2,S3 ^= K before final
  localparam FINAL = 5'd13;  // Finalization
  localparam KADD_4 = 5'd14;  // S3,S4 ^= K for tag
  localparam SQZ_TAG = 5'd15;  // Squeeze tag
  localparam VER_TAG = 5'd16;  // Verify tag

  reg [4:0] fsm_state;
  reg [4:0] next_fsm_state;

  // Latched control flags (mirrors core_rtl flow control)
  reg flag_eoi, next_flag_eoi;
  reg flag_ad_eot, next_flag_ad_eot;
  reg flag_ad_pad, next_flag_ad_pad;
  reg flag_msg_pad, next_flag_msg_pad;
  reg init_loaded, next_init_loaded;

  // FSM sequential logic
  always @(posedge clk or posedge rst) begin
    if (rst) begin
      fsm_state    <= IDLE;
      flag_eoi     <= 1'b0;
      flag_ad_eot  <= 1'b0;
      flag_ad_pad  <= 1'b0;
      flag_msg_pad <= 1'b0;
      init_loaded  <= 1'b0;
    end else begin
      fsm_state    <= next_fsm_state;
      flag_eoi     <= next_flag_eoi;
      flag_ad_eot  <= next_flag_ad_eot;
      flag_ad_pad  <= next_flag_ad_pad;
      flag_msg_pad <= next_flag_msg_pad;
      init_loaded  <= next_init_loaded;
    end
  end

  // FSM combinational logic
  always @(*) begin
    // defaults
    next_fsm_state    = fsm_state;
    next_flag_eoi     = flag_eoi;
    next_flag_ad_eot  = flag_ad_eot;
    next_flag_ad_pad  = flag_ad_pad;
    next_flag_msg_pad = flag_msg_pad;
    next_init_loaded  = init_loaded;

    key_ready         = 1'b0;
    bdi_ready         = 1'b0;
    bdo_valid         = 1'b0;
    bdo_type          = 2'b00;
    auth_valid        = 1'b0;
    done              = 1'b0;

    perm_start        = 1'b0;
    perm_rounds       = 4'd0;
    core_op           = OP_IDLE;

    case (fsm_state)
      IDLE: begin
        key_ready = 1'b1;
        if (key_valid) begin
          next_flag_eoi = 1'b0;
          next_flag_ad_eot = 1'b0;
          next_flag_ad_pad = 1'b0;
          next_flag_msg_pad = 1'b0;
          next_init_loaded = 1'b0;
          next_fsm_state = LD_KEY;
        end
      end

      LD_KEY: begin
        key_ready      = 1'b1;
        core_op        = OP_LD_KEY;
        next_fsm_state = LD_NPUB;
      end

      LD_NPUB: begin
        bdi_ready = 1'b1;
        if (bdi_valid != 16'd0 && bdi_type == BDI_TYPE_NPUB) begin
          core_op        = OP_LD_NPUB;
          next_flag_eoi  = bdi_eoi;
          next_fsm_state = INIT;
        end
      end

      INIT: begin
        if (!init_loaded) begin
          core_op = OP_INIT;
          next_init_loaded = 1'b1;
        end else begin
          perm_rounds = 4'd12;
          if (perm_done) begin
            core_op          = OP_PERM_WB;
            next_init_loaded = 1'b0;
            next_fsm_state   = KADD_2;
          end else begin
            perm_start = 1'b1;
          end
        end
      end

      KADD_2: begin
        core_op = OP_KADD2;
        if (flag_eoi || (bdi_valid != 16'd0)) begin
          if (flag_eoi) begin
            next_fsm_state = DOM_SEP;
          end else if (bdi_type == BDI_TYPE_AD) begin
            next_fsm_state = ABS_AD;
          end else if (bdi_type == BDI_TYPE_MSG) begin
            next_fsm_state = DOM_SEP;
          end
        end
      end

      ABS_AD: begin
        if (bdi_valid != 16'd0 && bdi_type == BDI_TYPE_AD) begin
          bdi_ready = 1'b1;
          core_op   = OP_ABS_AD;
          if (bdi_eot) begin
            next_flag_ad_eot = 1'b1;
          end
          if (bdi_eoi) begin
            next_flag_eoi = 1'b1;
          end
          if (bdi_valid != 16'hFFFF) begin
            next_flag_ad_pad = 1'b1;
          end
          next_fsm_state = PRO_AD;
        end
      end

      PAD_AD: begin
        core_op          = OP_PAD_AD;
        next_flag_ad_pad = 1'b1;
        next_fsm_state   = PRO_AD;
      end

      PRO_AD: begin
        perm_rounds = 4'd8;
        if (perm_done) begin
          core_op = OP_PERM_WB;
          if (flag_ad_eot == 1'b0) begin
            next_fsm_state = ABS_AD;
          end else if (flag_ad_pad == 1'b0) begin
            next_fsm_state = PAD_AD;
          end else begin
            next_fsm_state = DOM_SEP;
          end
        end else begin
          perm_start = 1'b1;
        end
      end

      DOM_SEP: begin
        core_op = OP_DOM_SEP;
        if (flag_eoi) begin
          next_flag_msg_pad = 1'b1;
          next_fsm_state = PAD_MSG;
        end else begin
          next_fsm_state = ABS_MSG;
        end
      end

      ABS_MSG: begin
        if (bdi_valid != 16'd0 && bdi_type == BDI_TYPE_MSG) begin
          bdi_ready = 1'b1;
          bdo_valid = 1'b1;  // Output ciphertext (enc) or plaintext (dec)
          bdo_type  = 2'b10;  // MSG type
          core_op   = OP_ABS_MSG;
          // Wait for both input accepted and output consumed
          if (bdo_ready) begin
            if (bdi_eoi) begin
              next_flag_eoi = 1'b1;
            end
            if (bdi_valid != 16'hFFFF) begin
              next_flag_msg_pad = 1'b1;
              next_fsm_state = KADD_3;
            end else begin
              next_fsm_state = PRO_MSG;
            end
          end
        end
      end

      PAD_MSG: begin
        core_op           = OP_PAD_MSG;
        next_flag_msg_pad = 1'b1;
        next_fsm_state    = KADD_3;
      end

      PRO_MSG: begin
        perm_rounds = 4'd8;
        if (perm_done) begin
          core_op = OP_PERM_WB;
          if (flag_eoi == 1'b0) begin
            next_fsm_state = ABS_MSG;
          end else if (flag_msg_pad == 1'b0) begin
            next_fsm_state = PAD_MSG;
          end else begin
            next_fsm_state = KADD_3;
          end
        end else begin
          perm_start = 1'b1;
        end
      end

      KADD_3: begin
        core_op        = OP_KADD3;
        next_fsm_state = FINAL;
      end

      FINAL: begin
        perm_rounds = 4'd12;
        if (perm_done) begin
          core_op        = OP_PERM_WB;
          next_fsm_state = KADD_4;
        end else begin
          perm_start = 1'b1;
        end
      end

      KADD_4: begin
        core_op        = OP_KADD4;
        next_fsm_state = SQZ_TAG;
      end

      SQZ_TAG: begin
        if (decrypt) begin
          // Decryption: receive tag for verification
          if (bdi_valid != 16'd0 && bdi_type == 2'b11) begin  // TAG type
            bdi_ready = 1'b1;
            core_op = OP_LD_TAG;
            next_fsm_state = VER_TAG;
          end
        end else begin
          // Encryption: output tag
          bdo_valid = 1'b1;
          bdo_type  = 2'b11;
          if (bdo_ready) begin
            next_fsm_state = VER_TAG;
          end
        end
      end

      VER_TAG: begin
        if (decrypt) begin
          auth_valid = 1'b1;
        end
        done           = 1'b1;
        next_fsm_state = IDLE;
      end

      default: begin
        next_fsm_state = IDLE;
      end
    endcase
  end

  // state core
  ascon_core core (
      .clk(clk),
      .rst(rst),
      .decrypt(decrypt),
      .key(key),
      .bdi(bdi),
      .bdi_valid_bytes(bdi_valid),
      .core_op(core_op),
      .perm_state_out(ascon_state_out),
      .state_to_perm(ascon_state_in),
      .bdo(bdo),
      .auth(auth)
  );

  // permutation
  ascon_permutation perm (
      .rst(rst),
      .clk(clk),
      .start(perm_start),
      .rounds(perm_rounds),
      .ascon_state_in(ascon_state_in),
      .ascon_state_out(ascon_state_out),
      .done(perm_done)
  );

endmodule
