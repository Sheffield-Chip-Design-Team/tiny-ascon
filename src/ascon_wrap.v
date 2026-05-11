// ========== FSM (Finite State Machine) States ==========
// Hardware sequencing for Ascon-AEAD128.

module ascon_wrap (
  input wire         clk,
  input wire         rst,
  input wire         en,
  input wire         phase_valid,
  input wire         last_byte,
  input wire  [1:0]  bdi_type,
  input wire         ad_en,
  input wire         encrypt_en,
  input wire  [7:0]  byte_in,
  output wire [7:0]  byte_out,
  output reg         phase_ready
);

// Design Questtions:
// Should the wrapper prevent the user from breaking the protocol?
// 

// 5.1 Key Transfer
// step 0 - wait for key_ready to be asserted by ASCON core
// step 1 - shift in key (128 bits = 16 bytes)
// step 2 - assert key_valid for 1 cycle
// (key_ready goes low) - Keep key interface stable
// step 3 - wait for key_ready to be deasserted by ASCON core

// 5.2 BDI Transfer
// step 0 - wait for bdi_ready to be asserted by ASCON core
// step 1 - shift in BDI (128 bits = 16 bytes)
// step 2 - assert bdi_valid for 1 cycle
// (bdi ready goes low) - Keep BD interface stable
// step 3 - wait for bdi_ready to be asserted again by ASCON core

//5.3 BDO Transfer
// step 0 - wait for bdo_valid to be asserted by ASCON core
// step 2 - assert bdo_ready until we are done shifting out the data
// step 1 - shift out BDO (128 bits = 16 bytes)
// step 3 - de-assert bdo_valid

// FSM control flow requirements - resuse shift flops (there is a lot of them here)
// key handshake
// shift in key data

// == Local Paramaters Signals==========
localparam IDLE               = 3'd0;
localparam SHIFT_KEY_IN       = 3'd1;
localparam SHIFT_NONCE_IN     = 3'd2;
localparam SHIFT_AD_IN        = 3'd3;



localparam SHIFT_PLAINTEXT_IN = 3'd4;
localparam SHIFT_BDO_OUT      = 3'd5;
localparam COLLECT_TAG        = 3'd6;
// ========== Internal Signals ==========
 
  // ASCON core interface signals
  // TODO - do we need a reg for key?
  reg          key_valid;
  wire         key_ready;

  // TODO do we need a reg for bdi vectors?

  reg [15:0]   bdi_valid;
  reg          bdi_eot;
  reg          bdi_eoi;
  wire         bdi_ready;

  wire         bdo_ready;
  wire [127:0] w_bdo;
  // TODO - do we need regs for bdo outputs?

  wire         bdo_valid;
  wire [1:0]   bdo_type;
  wire         auth;
  wire         auth_valid;
  wire         done;

  // FSM control signals
  wire         decrypt_en;

  reg [2:0]    ctrl_state;
  reg [2:0]    next_ctrl_state;
  reg [5:0]    phase_cntr;
  reg [1:0]    plaintext_chunk_cntr; 
  reg          data_shift_en;

  reg [127:0] data_shift_reg;      // only use this one register for shifting 
  reg         last_byte_p;
  reg         prev_last_byte;
  reg         last_byte_p_delay;

  assign decrypt_en = ~encrypt_en;
  
  always @(posedge clk or posedge rst) begin
    if (rst) begin
      ctrl_state <= IDLE;
    end else begin
      ctrl_state <= next_ctrl_state;
    end
  end

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      prev_last_byte    <= 0;
      last_byte_p       <= 0;
      last_byte_p_delay <= 0;
    end else begin
      prev_last_byte    <= last_byte;
      last_byte_p       <= last_byte & ~prev_last_byte; 
      last_byte_p_delay <= last_byte_p;
    end
  end

  // Minimal output wiring for now: expose the least-significant byte of the
  // core's BDO bus.
  assign byte_out = w_bdo[7:0];

  // Always ready to accept BDO from the core (encryption path).
  assign bdo_ready = 1'b1;

  // TODO - fix these unused signals
  wire _unused_ok = &{ad_en, bdo_valid, bdo_type, auth, auth_valid, done, bdi_ready, key_ready, w_bdo[127:8]};

  always @(posedge clk or posedge rst) begin
    if (rst) begin
      // Conservative reset to avoid X-propagation.
      key_valid            <= 1'b0;
      bdi_valid            <= 16'd0;
      bdi_eot              <= 1'b0;
      bdi_eoi              <= 1'b0;
      next_ctrl_state      <= IDLE;
      phase_cntr           <= 6'd0;
      plaintext_chunk_cntr <= 2'd0;
      data_shift_en        <= 1'b0;
      data_shift_reg       <= 128'd0;
      phase_ready          <= 1'b1;
    end else begin
    case (ctrl_state)
      IDLE: begin  
        if (en && key_ready && encrypt_en) begin
          next_ctrl_state <= SHIFT_KEY_IN;
          phase_ready     <= 0; // Assert phase_ready to indicate we are ready for key input  
        end else if (phase_valid && decrypt_en) begin
          // TODO - handle decryption start 
          next_ctrl_state <= IDLE;
        end else begin
          next_ctrl_state <= IDLE;
        end
      end

      SHIFT_KEY_IN: begin
        // Phase Handshake
        if (phase_valid) begin
          data_shift_en <= 1;
          phase_ready   <= 0; 
          // shift in the first byte of the key to kick off the process
          data_shift_reg <= {data_shift_reg[119:0], byte_in};
        end else begin
          if (~data_shift_en) begin
            phase_ready   <= 1; 
          end
        end
        if (data_shift_en) begin
          if (phase_cntr < 15) begin
            // Shift in key, byte by byte
            data_shift_reg <= {data_shift_reg[119:0], byte_in};
            phase_cntr     <= phase_cntr + 1;
            if (phase_cntr == 14) begin
              key_valid  <= 1; // Assert key_valid for 1 cycle
            end
          end else if (phase_cntr == 15) begin
            next_ctrl_state <= SHIFT_NONCE_IN;
            key_valid       <= 0; // De-assert key_valid after 1 cycle
            phase_cntr      <= 0; // Reset counter for next phase
            data_shift_en   <= 0; // Stop shifting data after key is in
            phase_ready     <= 1; // Assert phase_ready to indicate we are done with key input
          end
        end
      end

      SHIFT_NONCE_IN: begin
        // Phase Handshake
        if (phase_valid) begin
          data_shift_en <= 1;
          phase_ready   <= 0; 
          // shift in the first byte of the nonce immediately
          data_shift_reg <= {data_shift_reg[119:0], byte_in};
        end else begin
          if (~data_shift_en) begin
            phase_ready  <= 1; 
          end
        end
        // Nonce shift in
        if (data_shift_en) begin 
          if (phase_cntr < 15) begin
            // Shift in nonce, byte by byte
            data_shift_reg <= {data_shift_reg[119:0], byte_in};
            phase_cntr     <= phase_cntr + 1;
          end else if (phase_cntr == 14) begin
            phase_cntr <= phase_cntr + 1;
            bdi_valid  <= 16'hffff; // Assert bdi_valild for 1 cycles 
          end else if (phase_cntr == 15) begin
            phase_ready <= 1;     // Assert phase_ready to indicate we are done with nonce input
            bdi_valid   <= 16'd0; // De-assert key_valid after 1 cycle
            phase_cntr  <= 0;     // Reset counter for next phase
            data_shift_en <= 0;     // Stop shifting data after nonce is in
            // Move to next phase after shifting in nonce
            next_ctrl_state <= SHIFT_PLAINTEXT_IN; 
          end
        end
      end

    // SHIFT_AD_IN: begin
    //   bdi_type   <= 2'b01; // Additional Data type
    //   phase_done <= bdi_ready;
    //   if (phase_cntr < ) begin
    //     // Shift in nonce, byte by byte
    //     data_shift_reg <= {data_shift_reg[119:0], byte_in};
    //     phase_cntr     <= phase_cntr + 1;
    //   end else if (phase_cntr == 15) begin
    //     // Move to next phase after shifting in key
    //     phase_cntr <= phase_cntr + 1;
    //     bdi_valid  <= 1; // Assert key_valid for 1 cycle
    //   end else if (phase_cntr == 16) begin
    //     bdi_valid  <= 0; // De-assert key_valid after 1 cycle
    //     phase_cntr <= 0; // Reset counter for next phase
    //     // Move to next phase after shifting in nonce
    //     next_ctrl_state <= SHIFT_AD_IN; 
    //   end
    // end

    SHIFT_PLAINTEXT_IN: begin
      //bdi_type   <= 2'b10; // Plaintext type
      phase_ready <= 1'b0; // TODO - need to determine when to assert phase_ready for plaintext in

      if (phase_valid) begin
        plaintext_chunk_cntr <= 0; // Reset chunk counter at the start of plaintext phase
        data_shift_en        <= 1;
      end
      
      if (data_shift_en) begin
        // Shift in plaintext, byte by byte
        data_shift_reg       <= {data_shift_reg[119:0], byte_in};
        plaintext_chunk_cntr <= plaintext_chunk_cntr + 1;

        if (plaintext_chunk_cntr == 0) begin
          bdi_valid <= 16'd0; // De-assert bdi_valid after 1 cycle
        end

        if (plaintext_chunk_cntr == 1) begin
          bdi_valid <= 16'd2; // Assert bdi_valid for 1 cycle after shifting in 16 bytes of plaintext
      
          if (last_byte_p) begin
            // If this is the last byte of plaintext, also assert bdi_eot
            bdi_eot   <= 1;
            bdi_eoi   <= 1; // Assert end of input for the plaintext
          end else if (last_byte_p_delay) begin
            bdi_eot   <= 0;
            bdi_eoi   <= 0; // De-assert end of input after 1 cycle
          end
        end
      end
    end
    default: begin
      phase_ready <= 1'b1;
      next_ctrl_state <= IDLE;
    end
    endcase
    end
  end

// ======= ASCON Core Instance =======

  ascon_top u_ascon_top (
    .clk           (clk),
    .rst           (rst),
    .decrypt       (decrypt_en), 
    // ========== Key Input Port ==========
    .key           (data_shift_reg),
    .key_valid     (key_valid),
    .key_ready     (key_ready),
    // ========== Block Data Input (BDI) ==========
    .bdi           (data_shift_reg),
    .bdi_valid     (bdi_valid),
    .bdi_type      (bdi_type),
    .bdi_eot       (bdi_eot),
    // End of type signal
    .bdi_eoi       (bdi_eoi),
    // End of Input signal
    .bdi_ready     (bdi_ready),
    // ========== Block Data Output (BDO) ==========
    .bdo_ready     (bdo_ready),
    .bdo           (w_bdo),
    .bdo_valid     (bdo_valid),
    .bdo_type      (bdo_type),
    // ========== Status Output ==========
    .auth          (auth),
    .auth_valid    (auth_valid),
    .done          (done)
  );
   
endmodule
