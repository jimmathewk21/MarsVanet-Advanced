import time
from paillier_crypto import (
    generate_keys,
    encrypt,
    decrypt,
    add_ciphertexts
)

TEST_BITS = 256
ITERATIONS = 20

start = time.perf_counter()
private_key, public_key = generate_keys(TEST_BITS)
keygen_ms = (time.perf_counter() - start) * 1000

messages = list(range(1, ITERATIONS + 1))

start = time.perf_counter()
ciphertexts = [encrypt(m, public_key) for m in messages]
encrypt_avg_ms = (time.perf_counter() - start) * 1000 / ITERATIONS

start = time.perf_counter()
decoded = [decrypt(c, private_key) for c in ciphertexts]
decrypt_avg_ms = (time.perf_counter() - start) * 1000 / ITERATIONS

start = time.perf_counter()
total = ciphertexts[0]
for ciphertext in ciphertexts[1:]:
    total = add_ciphertexts(total, ciphertext, public_key)
addition_avg_ms = (time.perf_counter() - start) * 1000 / (ITERATIONS - 1)

assert decoded == messages
assert decrypt(total, private_key) == sum(messages)

print("Key size:", public_key[0].bit_length(), "bits (test only)")
print("Iterations:", ITERATIONS)
print(f"Key generation: {keygen_ms:.3f} ms")
print(f"Average encryption: {encrypt_avg_ms:.3f} ms")
print(f"Average decryption: {decrypt_avg_ms:.3f} ms")
print(f"Average homomorphic addition: {addition_avg_ms:.3f} ms")
print("Correctness checks: PASS")
