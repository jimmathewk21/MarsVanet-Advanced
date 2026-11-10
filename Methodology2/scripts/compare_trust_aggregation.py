import csv
import os
import statistics
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
TRIALS = 20
PLAINTEXT_REPEATS = 10000
PENALTY = 10

# Fresh results default to Methodology2/results/; committed evidence in
# final_evidence/ is left intact. Override with BENCH_OUTPUT.
_METHODOLOGY2 = Path(__file__).resolve().parents[1]
OUTPUT = Path(
    os.environ.get(
        "BENCH_OUTPUT",
        str(_METHODOLOGY2 / "results" / "trust_aggregation_comparison.csv"),
    )
)

private_key, public_key = generate_keys(KEY_BITS)
results = []

for count in OBSERVER_COUNTS:
    penalties = [PENALTY] * count
    plain_times = []
    encryption_times = []
    aggregation_times = []
    decryption_times = []
    pipeline_times = []

    for _ in range(TRIALS):
        start = time.perf_counter()
        for _ in range(PLAINTEXT_REPEATS):
            plain_total = sum(penalties)
        plain_ms = (time.perf_counter() - start) * 1000
        plain_times.append(plain_ms / PLAINTEXT_REPEATS)

        start = time.perf_counter()
        encrypted = [encrypt(value, public_key) for value in penalties]
        encryption_times.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        encrypted_total = encrypted[0]
        for value in encrypted[1:]:
            encrypted_total = add_ciphertexts(
                encrypted_total, value, public_key
            )
        aggregation_times.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        encrypted_result = decrypt(encrypted_total, private_key)
        decryption_times.append((time.perf_counter() - start) * 1000)

        assert plain_total == encrypted_result == sum(penalties)

        pipeline_times.append(
            encryption_times[-1]
            + aggregation_times[-1]
            + decryption_times[-1]
        )

    plain_ms = statistics.median(plain_times)
    encryption_ms = statistics.median(encryption_times)
    aggregation_ms = statistics.median(aggregation_times)
    decryption_ms = statistics.median(decryption_times)
    pipeline_ms = statistics.median(pipeline_times)

    row = {
        "key_bits": KEY_BITS,
        "observers": count,
        "trials": TRIALS,
        "plaintext_sum_median_ms": round(plain_ms, 6),
        "encryption_median_ms": round(encryption_ms, 3),
        "encrypted_aggregation_median_ms": round(aggregation_ms, 3),
        "decryption_median_ms": round(decryption_ms, 3),
        "encrypted_pipeline_median_ms": round(pipeline_ms, 3),
        "correctness": "PASS"
    }

    results.append(row)
    print(row)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

print("REPEATED TRUST AGGREGATION COMPARISON PASSED")
print("Results saved to:", OUTPUT)
