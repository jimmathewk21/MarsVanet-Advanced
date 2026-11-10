from paillier_crypto import generate_keys, encrypt, decrypt, add_ciphertexts
from dos_evidence import calculate_dos_evidence

observers = [
    (150, 100),
    (200, 100),
    (300, 100)
]

scores = [
    calculate_dos_evidence(rate, threshold)
    for rate, threshold in observers
]

private_key, public_key = generate_keys(64)

encrypted_total = encrypt(0, public_key)

for score in scores:
    encrypted_score = encrypt(score, public_key)
    encrypted_total = add_ciphertexts(
        encrypted_total,
        encrypted_score,
        public_key
    )

decrypted_total = decrypt(encrypted_total, private_key)
expected_total = sum(scores)
average_score = decrypted_total / len(scores)

print("Observer count:", len(observers))
print("Individual evidence scores:", scores)
print("Plaintext total:", expected_total)
print("Decrypted encrypted total:", decrypted_total)
print("Average evidence score:", average_score)

assert decrypted_total == expected_total

print("ENCRYPTED DOS EVIDENCE INTEGRATION TEST PASSED")
