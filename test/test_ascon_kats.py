#!/usr/bin/env python3
import binascii
import time

from ascon128 import ascon_aead128_enc

KAT_FILE = "LWC_AEAD_KAT_128_128.txt"


def parse_kat_file(filename):
    """Parse NIST LWC AEAD KAT vectors."""
    vectors = []
    with open(filename, "r") as f:
        current = {}
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith("Count ="):
                if current:
                    vectors.append(current)
                current = {}

            key, val = [x.strip() for x in line.split("=", 1)]
            current[key] = val

        if current:
            vectors.append(current)

    return vectors


def hex_to_bytes(x):
    return b"" if x == "" else binascii.unhexlify(x)


def run_kats():
    print("=" * 70)
    print("ASCON-128 AEAD Known Answer Tests (KATs)")
    print("=" * 70)
    print(f"Test Vector File: {KAT_FILE}")

    vectors = parse_kat_file(KAT_FILE)
    total = len(vectors)
    passed = 0

    # Statistics
    stats = {
        "empty_ad_empty_pt": 0,
        "with_ad_empty_pt": 0,
        "empty_ad_with_pt": 0,
        "with_ad_with_pt": 0,
        "total_ad_bytes": 0,
        "total_pt_bytes": 0,
        "max_ad_len": 0,
        "max_pt_len": 0,
    }

    print(f"Total test vectors: {total}")
    print("Running tests...\n")

    start_time = time.time()

    for v in vectors:
        key = hex_to_bytes(v["Key"])
        nonce = hex_to_bytes(v["Nonce"])
        ad = hex_to_bytes(v["AD"])
        pt = hex_to_bytes(v["PT"])

        # CT field = ciphertext || tag, where tag is ALWAYS 16 bytes (128 bits)
        ct_full = v["CT"].lower()

        # split into ciphertext and tag
        tag = ct_full[-32:]  # last 16 bytes (32 hex chars)
        ct = ct_full[:-32]  # everything before the tag

        K = int.from_bytes(key, "big")
        N = int.from_bytes(nonce, "big")

        # Update statistics
        ad_len = len(ad)
        pt_len = len(pt)
        stats["total_ad_bytes"] += ad_len
        stats["total_pt_bytes"] += pt_len
        stats["max_ad_len"] = max(stats["max_ad_len"], ad_len)
        stats["max_pt_len"] = max(stats["max_pt_len"], pt_len)

        if ad_len == 0 and pt_len == 0:
            stats["empty_ad_empty_pt"] += 1
        elif ad_len > 0 and pt_len == 0:
            stats["with_ad_empty_pt"] += 1
        elif ad_len == 0 and pt_len > 0:
            stats["empty_ad_with_pt"] += 1
        else:
            stats["with_ad_with_pt"] += 1

        C_blocks, T = ascon_aead128_enc(K, N, ad, pt)

        # join ciphertext blocks
        C = b"".join(C_blocks).hex()
        T_hex = T.hex()

        if C == ct and T_hex == tag:
            passed += 1
        else:
            end_time = time.time()
            print("❌ FAILED TEST:")
            print("Count =", v["Count"])
            print("expected CT:", ct)
            print("got     CT:", C)
            print("expected TAG:", tag)
            print("got     TAG:", T_hex)
            print(f"\nTests stopped after {passed} passed tests")
            print(f"Execution time: {end_time - start_time:.3f} seconds")
            return

    end_time = time.time()
    execution_time = end_time - start_time

    print("=" * 70)
    print("✅ ALL TESTS PASSED!")
    print("=" * 70)
    print()
    print("TEST RESULTS")
    print("-" * 70)
    print(f"  Total test vectors:              {total:>6}")
    print(f"  Passed:                          {passed:>6}")
    print(f"  Failed:                          {total - passed:>6}")
    print(f"  Success rate:                    {100.0 * passed / total:>5.1f}%")
    print()
    print("TEST VECTOR DISTRIBUTION")
    print("-" * 70)
    print(f"  Empty AD & Empty PT:             {stats['empty_ad_empty_pt']:>6}")
    print(f"  With AD & Empty PT:              {stats['with_ad_empty_pt']:>6}")
    print(f"  Empty AD & With PT:              {stats['empty_ad_with_pt']:>6}")
    print(f"  With AD & With PT:               {stats['with_ad_with_pt']:>6}")
    print()
    print("  AD = Associated Data (authenticated but not encrypted)")
    print("  PT = Plaintext (encrypted to produce ciphertext)")
    print()
    print("DATA PROCESSED")
    print("-" * 70)
    print(f"  Total AD processed:              {stats['total_ad_bytes']:>6,} bytes")
    print(f"  Total PT processed:              {stats['total_pt_bytes']:>6,} bytes")
    print(f"  Maximum AD length:               {stats['max_ad_len']:>6} bytes")
    print(f"  Maximum PT length:               {stats['max_pt_len']:>6} bytes")
    print()
    print("PERFORMANCE METRICS")
    print("-" * 70)
    print(f"  Execution time:                  {execution_time:>6.3f} seconds")
    print(
        f"  Throughput:                      {total / execution_time:>6.1f} tests/sec"
    )
    print(
        f"  Average time per test:           {execution_time * 1000 / total:>6.2f} ms"
    )
    print("=" * 70)


if __name__ == "__main__":
    run_kats()
