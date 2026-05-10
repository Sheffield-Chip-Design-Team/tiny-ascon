# Visualizing a state
"""
word size = 64 bits unsigned integer
Si = word i within the state
State = S0 || S1 || S2 || S3 || S4
State size = 64 x 5 = 320 bits

State visualization (little-endian bit indexing):
S0    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
            s(0,0)                                                          s(0,63)

S1    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
            s(1,0)                                                          s(1,63)

S2    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
            s(2,0)                                                          s(2,63)

S3    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
            s(3,0)                                                          s(3,63)

S4    LSB -> [][][][][][][][][][][][][][][][][][][][][][][]....[][][][][][][] <- MSB
            s(4,0)                                                          s(4,63)

However, we work with integers here.
Python abstracts away endianness for integers. When converting between bytes and integers,
you specify endianness explicitly. Internally, Python handles the representation.

Sizes of each param:

- Key K: 128 bits
- Nonce N: 128 bits
- Initialization Vector IV: 64 bits (fixed value for Ascon-AEAD128 = 0x00001000808c0001)

- State: 320 bits (5 words of 64 bits each)

- Rate r: 128 bits for Ascon-AEAD128
- Capacity c: 192 bits for Ascon-AEAD128

- Associated Data A: variable length
- Plaintext P: variable length
- Ciphertext C: variable length

Important clarifications for correctness:
- Per-lane mapping: when loading/storing bytes into the 64-bit state lanes, use little-endian (le64) per lane. This applies to IV||K||N loading, AAD/PT absorption, and CT/TAG emission.
- Domain separation: after processing AAD (even if empty), set the MSB of S4: S4 ^= (1 << 63).
- Padding: for AAD and PT, append 0x01 followed by zeros to fill a 16-byte block.
- Outputs: ciphertext is le64(S0)||le64(S1) per block (truncate for partial tails); tag is le64(S3)||le64(S4).
"""


def ascon_initialize(K, N):
    """
    Initialize the Ascon state with key K, nonce N, and initialization vector IV.
    Args:
        K : The 128 bit secret key.
        N : The 128 bit nonce.
        IV: The initialization vector as a 64-bit unsigned integer.
    Returns:
        State: The initialized state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
    """
    State = [0] * 5
    # NIST SP 800-232 Ascon-AEAD128 IV (matches official reference layout)
    IV = 0x00001000808C0001

    # Convert key and nonce ints (big-endian) to bytes
    key_bytes = int128_to_bytes(K)
    nonce_bytes = int128_to_bytes(N)

    # S ← IV || K || N, where each 64-bit lane uses little-endian byte-to-int
    def le64(b):
        return int.from_bytes(b, "little")

    kh = le64(key_bytes[0:8])  # Upper 64 bits of K
    kl = le64(key_bytes[8:16])  # Lower 64 bits of K
    nh = le64(nonce_bytes[0:8])  # Upper 64 bits of N
    nl = le64(nonce_bytes[8:16])  # Lower 64 bits of N

    State[0] = IV
    State[1] = kh
    State[2] = kl
    State[3] = nh
    State[4] = nl

    # Perform 12 rounds of the Ascon permutation
    State = ascon_permutation(State, 12)

    # S ← S ⊕ (0^192 ‖ K)
    # XOR K into the last 2 rows of the state
    # This mixes in the key one more time
    State[3] ^= kh  # XOR upper 64 bits of K
    State[4] ^= kl  # XOR lower 64 bits of K

    return State


def ascon_permutation(State, rounds):
    """
    Apply the Ascon permutation to the state for a given number of rounds.
    Args:
        State : The current state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
        rounds: The number of rounds to apply the permutation. Must be a positive integer.
    Returns:
        State: The permuted state as a list of five 64-bit unsigned integers [S0, S1, S2, S3, S4].
    """
    for i in range(0, rounds):
        # 𝑝 = 𝑝𝐿 ∘ 𝑝𝑆 ∘ 𝑝𝐶
        # Constant Addition Layer (𝑝𝐶) where round constant is XORed to S2
        State[2] ^= get_round_constant(rounds, i)

        # S-box Layer (𝑝𝑆) — apply vertically for each bit position 0 to 63
        for k in range(64):  # for each column (bit position)
            S_box_input = []

            # Extract the k-th bit from each of the 5 rows to form vertical slice
            for j in range(5):
                S_box_input.append((State[j] >> k) & 1)

            S_box_output = s_box_compute(S_box_input)

            for j in range(5):
                # clear k-th bit then set according to S_box_output[j]
                State[j] = (State[j] & ~(1 << k)) | ((S_box_output[j] & 1) << k)

        # Linear Diffusion Layer (𝑝𝐿)
        State = linear_diffusion_layer(State)

    return State


def process_associated_data(State, A, r=128):
    # Process A in bytes, rate=16 bytes
    def le64(b):
        return int.from_bytes(b, "little")

    if len(A) > 0:
        # Pad the last block
        pad_len = 16 - (len(A) % 16) - 1
        a_padding = b"\x01" + (b"\x00" * pad_len)
        a_padded = A + a_padding

        # Then process each block (128 bit wide) by XORing with state and permuting
        for i in range(0, len(a_padded), 16):
            blk = a_padded[i : i + 16]
            # XOR with the first two rows of State and apply permutation...
            State[0] ^= le64(blk[0:8])  # XOR upper 64 bits of block
            State[1] ^= le64(blk[8:16])  # XOR lower 64 bits of block
            State = ascon_permutation(State, 8)  # Apply 8 rounds of permutation

    # Domain separation S ← S ⊕ (0319 ‖ 1)
    # XOR the MSB of S4 (always, regardless of A length)
    State[4] ^= 1 << 63
    return State


def process_plaintext(State, P, r=128):
    C = []  # List to hold ciphertext blocks

    def le64(b):
        return int.from_bytes(b, "little")

    def to_le64(x):
        return x.to_bytes(8, "little")

    rate = 16
    p_lastlen = len(P) % rate
    pad_len = rate - p_lastlen - 1
    p_padding = b"\x01" + (b"\x00" * pad_len)
    p_padded = P + p_padding

    # first t-1 blocks
    for i in range(0, len(p_padded) - rate, rate):
        blk = p_padded[i : i + rate]
        # XOR with the first two rows of State and apply permutation... S[0∶127] ← S[0∶127] ⊕ 𝑃𝑖
        State[0] ^= le64(blk[0:8])  # XOR upper 64 bits of block
        State[1] ^= le64(blk[8:16])  # XOR lower 64 bits of block
        # Extract ciphertext from state
        C.append(to_le64(State[0]) + to_le64(State[1]))
        State = ascon_permutation(State, 8)  # Apply 8 rounds of permutation

    # last block
    blk = p_padded[len(p_padded) - rate :]
    # Process the last block (which may be partial)
    # S[0∶127] ← S[0∶127] ⊕ pad(𝑃𝑛, 128)
    State[0] ^= le64(blk[0:8])
    State[1] ^= le64(blk[8:16])
    if p_lastlen > 0:
        # Emit ciphertext for the last block truncated to |P_n| bits
        chunk = to_le64(State[0]) + to_le64(State[1])
        # KAT vectors are byte-aligned; truncate to the exact plaintext byte length
        C.append(chunk[:p_lastlen])

    return State, C


def finalize(State, K):
    key_bytes = int128_to_bytes(K)

    def le64(b):
        return int.from_bytes(b, "little")

    def to_le64(x):
        return x.to_bytes(8, "little")

    kh = le64(key_bytes[0:8])
    kl = le64(key_bytes[8:16])

    # S ← S ⊕ (0^128 ‖ K || 0^64)
    State[2] ^= kh
    State[3] ^= kl

    State = ascon_permutation(State, 12)

    # S ← S ⊕ (0^192 ‖ K), and extract tag
    T0 = State[3] ^ kh
    T1 = State[4] ^ kl
    T = to_le64(T0) + to_le64(T1)
    return T


def ascon_aead128_enc(K, N, A, P):
    # Initialize
    State = ascon_initialize(K, N)

    # Process associated data (bytes)
    State = process_associated_data(State, A)

    # Process plaintext (bytes)
    State, C = process_plaintext(State, P)

    # Finalization
    T = finalize(State, K)

    return C, T


def pad(X, r=128):
    """
    Pad the input bitstring X according to the padding rule:
    Append a single '1' bit followed by the minimum number of '0' bits
    such that the length of the padded bitstring is a multiple of r.

    Args:
        X : The input bitstring.
        r : rate - The number of input bits processed per invocation of the
            underlying permutation. Must be a positive integer.
            Note that the rate and capacity of Ascon-AEAD128 are 128 and 192 bits, respectively.
    Returns:
        str: The padded bitstring.
    """
    pad_len = r - (len(X) % r)
    return X + "1" + ("0" * (pad_len - 1))


def get_round_constant(rnd, i):
    return CONST[16 - rnd + i]


def s_box_compute(X):
    # Where X = 𝑥0, ..., 𝑥4. A 5 bit word taken by slicing the state vertically
    # 𝑠(0,𝑗), 𝑠(1,𝑗), … , 𝑠(4,𝑗)
    result = [0] * 5
    result[0] = X[4] & X[1] ^ X[3] ^ X[2] & X[1] ^ X[2] ^ X[1] & X[0] ^ X[1] ^ X[0]
    result[1] = (
        X[4] ^ X[3] & X[2] ^ X[3] & X[1] ^ X[3] ^ X[2] & X[1] ^ X[2] ^ X[1] ^ X[0]
    )
    result[2] = X[4] & X[3] ^ X[4] ^ X[2] ^ X[1] ^ 1
    result[3] = X[4] & X[0] ^ X[4] ^ X[3] & X[0] ^ X[3] ^ X[2] ^ X[1] ^ X[0]
    result[4] = X[4] & X[1] ^ X[4] ^ X[3] ^ X[1] & X[0] ^ X[1]

    return [(b & 1) for b in result]  # ensure each output bit is either 0 or 1


def linear_diffusion_layer(S):
    x0, x1, x2, x3, x4 = S

    # applied a mask to ensure 64 bit words
    x0 = (x0 ^ rotr(x0, 19) ^ rotr(x0, 28)) & MASK64
    x1 = (x1 ^ rotr(x1, 61) ^ rotr(x1, 39)) & MASK64
    x2 = (x2 ^ rotr(x2, 1) ^ rotr(x2, 6)) & MASK64
    x3 = (x3 ^ rotr(x3, 10) ^ rotr(x3, 17)) & MASK64
    x4 = (x4 ^ rotr(x4, 7) ^ rotr(x4, 41)) & MASK64

    return [x0, x1, x2, x3, x4]


# Count the number of set bits in an integer
# https://stackoverflow.com/a/64848298/23139916
def count_set_bits(n):
    count = n.bit_count()
    return count


# Count total number of bits
# https://python-reference.readthedocs.io/en/latest/docs/ints/bit_length.html
def count_total_bits(n):
    if n == 0:
        return 1
    total_bits = n.bit_length()
    return total_bits


def int128_to_bytes(i):
    return i.to_bytes(16, "big")


def rotr(val, r):
    r %= 64
    return ((val >> r) | ((val << (64 - r)) & MASK64)) & MASK64


# Constants

# 1. Constant-Addition Layer 𝑝𝐶
CONST = [
    0x000000000000003C,
    0x000000000000002D,
    0x000000000000001E,
    0x000000000000000F,
    0x00000000000000F0,
    0x00000000000000E1,
    0x00000000000000D2,
    0x00000000000000C3,
    0x00000000000000B4,
    0x00000000000000A5,
    0x0000000000000096,
    0x0000000000000087,
    0x0000000000000078,
    0x0000000000000069,
    0x000000000000005A,
    0x000000000000004B,
]

# 2. Mask for 64 bits
MASK64 = (1 << 64) - 1
