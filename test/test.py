import os
import sys
import random
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

sys.path.append(str(Path(__file__).resolve().parents[1] / "test"))
from ascon import ascon_encrypt

VERBOSE = int(os.getenv("VERBOSE", "1"))
MAX_LEN = int(os.getenv("MAX_LEN", "32"))

TYPE_NPUB = 0b00
TYPE_AD = 0b01
TYPE_MSG = 0b10


def _bytes_hex(data: bytes) -> str:
    return "".join(f"{b:02X}" for b in data)

def _log_vec(dut, name: str, data: bytes, verbose: int = 2):
    if VERBOSE >= verbose:
        dut._log.info("%s %s", name.ljust(8), _bytes_hex(data))

def _ctrl_word(*, valid: int, last: int, bdi_type: int,
               ad_en: int, encrypt_en: int, en:int) -> int:
    return (
          ((valid & 1)      << 0)
        | ((encrypt_en & 1) << 1)
        | ((ad_en & 1)      << 2)
        | ((bdi_type & 3)   << 3)
        | ((last & 1)       << 5)
        | ((en & 1)         << 6)
    )

async def _wait_ready(dut, timeout_cycles: int = 200_000):
    for _ in range(timeout_cycles):
        bit6 = dut.uio_out.value[6]
        if bit6.is_resolvable and int(bit6) == 1:
            break
        await RisingEdge(dut.clk)
    else:
        raise AssertionError("timeout waiting for phase_ready uio_out[6] to go high")

async def _shift_out_byte(dut, *, bdi_type: int, ad_en: int, encrypt_en: int = 1) -> int:
    await _wait_ready(dut)
    return 0xFF
    # byte = dut.uo_out.value
    # if not byte.is_resolvable:
    #      print("uo_out is X/Z while ready")
    # out = int(byte) & 0xFF
    # base = _ctrl_word(start=0, last=0, bdi_type=bdi_type, ad_en=ad_en, encrypt_en=encrypt_en)
    # dut.uio_in.value = base | 0x01
    # await RisingEdge(dut.clk)
    # dut.uio_in.value = base
    # return out

async def _reset(dut):
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)

async def _shift_in_byte(
    dut,
    byte: int,
):
    # await _wait_ready(dut)
    dut.ui_in.value = byte & 0xFF
    await RisingEdge(dut.clk)

async def _enable_encrypt(dut, encrypt_en: int, ad_en):
    dut.uio_in.value = _ctrl_word(valid=0, last=0, bdi_type=0, ad_en=ad_en, encrypt_en=encrypt_en, en=1)
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)

async def _start_phase(dut, bdi_type: int, ad_en: int, encrypt_en: int, timeout_cycles: int = 5):
    
    # Wait for phase_ready (uio_out[6]) to go high before key input begins
    await _wait_ready(dut, timeout_cycles=5)
    
    for _ in range(random.randint(1, 10)):
        await RisingEdge(dut.clk)

    dut.uio_in.value = _ctrl_word(valid=1, last=0, bdi_type=bdi_type, ad_en=ad_en, encrypt_en=encrypt_en, en=1)
    
async def _input_key (dut, key: bytes):   
    await _start_phase(dut, bdi_type=TYPE_NPUB, ad_en=0, encrypt_en=1)

    byte_count = 0
    for byte in reversed(key):
        byte_count += 1
        dut._log.info("Shifting in key byte (%d/16) : 0x%02X", byte_count, byte)
        await _shift_in_byte(dut, byte)
        dut.uio_in.value = _ctrl_word(valid=0, last=0, bdi_type=0, ad_en=0, encrypt_en=1, en=1)
        assert byte_count <= 16, "Key length exceeds 16 bytes"
    
    for _ in range(5):
        await RisingEdge(dut.clk)

async def _input_npub(dut, npub: bytes):
    await _start_phase(dut, bdi_type=TYPE_NPUB, ad_en=0, encrypt_en=1)
    byte_count = 0
    for byte in reversed(npub):
        byte_count += 1
        dut._log.info("Shifting in nonce byte (%d/16) : 0x%02X", byte_count, byte)
        await _shift_in_byte(dut, byte)
        dut.uio_in.value = _ctrl_word(valid=0, last=0, bdi_type=0, ad_en=0, encrypt_en=1, en=1)
        assert byte_count <= 16, "Nonce length exceeds 16 bytes"
     
async def _run_encrypt_one(dut, key: bytes, npub: bytes, ad: bytes, pt: bytes):
    await _enable_encrypt(dut, encrypt_en=1, ad_en=0)
   
    _log_vec(dut, "Key:", key,  verbose=1)
    await _input_key(dut, key)
    
    _log_vec(dut, "Nonce:",npub, verbose=1)
    await _input_npub(dut, npub)

    for _ in range(50):
        await RisingEdge(dut.clk)

#     if len(key) != 16 or len(npub) != 16:
#         raise ValueError("key/npub must be 16 bytes")
#     if len(pt) == 0:
#         raise ValueError("zero-length MSG not supported by byte-strobe interface")

#     ad_en = 1 if len(ad) > 0 else 0
    
#     # start transfer
#     dut.uio_in[0].value = 1
#     dut.uio_in[1].value = 0
#     await RisingEdge(dut.clk)
#     dut.uio_in[0].value = 0  

    
#     # KEY
#     for b in key:
#         await _shift_in_byte(dut, b, bdi_type=TYPE_KEY, last=0, ad_en=ad_en)

#     # NPUB
#     for b in npub:
#         await _shift_in_byte(dut, b, bdi_type=TYPE_NPUB, last=0, ad_en=ad_en)

#     # AD (optional)
#     if len(ad) > 0:
#         for i, b in enumerate(ad):
#             await _shift_in_byte(
#                 dut,
#                 b,
#                 bdi_type=TYPE_AD,
#                 last=1 if i == (len(ad) - 1) else 0,
#                 ad_en=ad_en,
#             )

#     # MSG + ciphertext streaming (block-by-block)
#     ct_hw = bytearray()
#     idx = 0
#     while idx < len(pt):
#         block = pt[idx : idx + 16]
#         for j, b in enumerate(block):
#             is_last = 1 if (idx + j) == (len(pt) - 1) else 0
#             await _shift_in_byte(dut, b, bdi_type=TYPE_MSG, last=is_last, ad_en=ad_en)

#         for _ in range(len(block)):
#             ct_hw.append(await _shift_out_byte(dut, bdi_type=TYPE_MSG, ad_en=ad_en))

#         idx += len(block)

#     # TAG (16 bytes)
#     tag_hw = bytearray()
#     for _ in range(16):
#         tag_hw.append(await _shift_out_byte(dut, bdi_type=TYPE_MSG, ad_en=ad_en))

#     return bytes(ct_hw), bytes(tag_hw)


@cocotb.test()
async def test_enc_tiny_io(dut):
    random.seed(int(os.getenv("SEED", "31415")))

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start(start_high=False))

    await _reset(dut)

    key  = bytes(random.getrandbits(8) for _ in range(16))
    npub = bytes(random.getrandbits(8) for _ in range(16))

    # _log_vec(dut, "key", key)
    # _log_vec(dut, "npub", npub)

    # AD can be 0..MAX_LEN; MSG is 1..MAX_LEN (0 not representable with byte-strobe IO)
    for msglen in range(1, MAX_LEN + 1):
        for adlen in range(0, MAX_LEN + 1):
            ad = bytes(random.getrandbits(8) for _ in range(adlen))
            pt = bytes(random.getrandbits(8) for _ in range(msglen))
            # ct_ref, tag_ref = ascon_encrypt(key, npub, ad, pt)

            # dut._log.info("ENC ad:%d msg:%d", adlen, msglen)
            # if VERBOSE >= 3:
            #     _log_vec(dut, "ad", ad, verbose=3)
            #     _log_vec(dut, "pt", pt, verbose=3)

    await _run_encrypt_one(dut, key, npub, ad, pt)

            # assert ct_hw == ct_ref, "ciphertext mismatch"
            # assert tag_hw == tag_ref, "tag mismatch"
