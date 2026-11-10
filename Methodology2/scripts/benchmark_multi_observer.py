import csv
import os
import time
from pathlib import Path
from paillier_crypto import (
    generate_keys,
    encrypt,
    decrypt,
    add_ciphertexts
)

KEY_BITS = 256
OBSERVER_COUNTS = [1, 3, 5, 10]

# Freshly generated results go to Methodology2/results/ by default so the
# committed historical evidence in final_evidence/ is never overwritten.
# Override with BENCH_OUTPUT=/path/to/file.csv.
_METHODOLOGY2 = Path(__file__).resolve().parents[1]
OUTPUT = Path(
    os.environ.get(
        "BENCH_OUTPUT",
        str(_METHODOLOGY2 / "results" / "multi_observer_benchmark.csv"),
    )
)

private_key, public_key = generate_keys(KEY_BITS)
results = []

for count in OBSERVER_COUNTS:
    penalties = [10] * count

    start = time.perf_counter()
    encrypted = [encrypt(value, public_key) for value in penalties]
    encryption_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    total = encrypted[0]
    for ciphertext in encrypted[1:]:
        total = add_ciphertexts(total, ciphertext, public_key)
    aggregation_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    result = decrypt(total, private_key)
    decryption_ms = (time.perf_counter() - start) * 1000

    assert result == sum(penalties)

    row = {
        "key_bits": KEY_BITS,
        "observers": count,
        "encryption_ms": round(encryption_ms, 3),
        "aggregation_ms": round(aggregation_ms, 3),
        "decryption_ms": round(decryption_ms, 3),
        "total_penalty": result,
        "correctness": "PASS"
    }
    results.append(row)
    print(row)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print("MULTI-OBSERVER BENCHMARK PASSED")
print("Results saved to:", OUTPUT)
