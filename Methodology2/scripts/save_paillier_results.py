"""Run a real Paillier micro-benchmark and save the measured numbers.

The previous version of this file wrote a fixed, hand-entered table of numbers
to final_evidence/paillier_benchmark.csv. That is fabricated evidence and has
been removed. This version actually measures key generation, encryption,
decryption and homomorphic addition on this machine and writes the real
results to Methodology2/results/paillier_benchmark.csv (override with
BENCH_OUTPUT). The committed historical file in final_evidence/ is left
untouched.

NOTE: the default key size here is a small DEMONSTRATION key. These timings are
not production-security performance numbers. Pass a larger size to measure
realistic keys:  python3 save_paillier_results.py 2048 50
"""

import csv
import os
import sys
import time
from pathlib import Path

from paillier_crypto import generate_keys, encrypt, decrypt, add_ciphertexts

_METHODOLOGY2 = Path(__file__).resolve().parents[1]
OUTPUT = Path(
    os.environ.get(
        "BENCH_OUTPUT",
        str(_METHODOLOGY2 / "results" / "paillier_benchmark.csv"),
    )
)


def benchmark(key_bits, iterations):
    start = time.perf_counter()
    private_key, public_key = generate_keys(key_bits)
    keygen_ms = (time.perf_counter() - start) * 1000

    messages = list(range(1, iterations + 1))

    start = time.perf_counter()
    ciphertexts = [encrypt(m, public_key) for m in messages]
    enc_ms = (time.perf_counter() - start) * 1000 / iterations

    start = time.perf_counter()
    decoded = [decrypt(c, private_key) for c in ciphertexts]
    dec_ms = (time.perf_counter() - start) * 1000 / iterations

    start = time.perf_counter()
    total = ciphertexts[0]
    for c in ciphertexts[1:]:
        total = add_ciphertexts(total, c, public_key)
    add_ms = (time.perf_counter() - start) * 1000 / max(1, iterations - 1)

    assert decoded == messages
    assert decrypt(total, private_key) == sum(messages)

    return {
        "key_size_bits": public_key[0].bit_length(),
        "iterations": iterations,
        "key_generation_ms": round(keygen_ms, 3),
        "average_encryption_ms": round(enc_ms, 3),
        "average_decryption_ms": round(dec_ms, 3),
        "average_homomorphic_addition_ms": round(add_ms, 3),
        "correctness": "PASS",
    }


def main(argv):
    key_bits = int(argv[1]) if len(argv) > 1 else 256
    iterations = int(argv[2]) if len(argv) > 2 else 20
    result = benchmark(key_bits, iterations)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["metric", "value"])
        for key, value in result.items():
            writer.writerow([key, value])

    print("Measured Paillier benchmark (this machine):")
    for key, value in result.items():
        print(f"  {key}: {value}")
    print("Saved:", OUTPUT)


if __name__ == "__main__":
    main(sys.argv)
