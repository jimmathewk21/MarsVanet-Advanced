from paillier_crypto import (
    generate_keys,
    encrypt,
    decrypt,
    add_ciphertexts
)

observer_scores = [35, 45, 20]
private_key, public_key = generate_keys(64)

encrypted_scores = [
    encrypt(score, public_key)
    for score in observer_scores
]

encrypted_total = encrypt(0, public_key)

for ciphertext in encrypted_scores:
    encrypted_total = add_ciphertexts(
        encrypted_total,
        ciphertext,
        public_key
    )

decrypted_total = decrypt(encrypted_total, private_key)
expected_total = sum(observer_scores)

print("Observer count:", len(observer_scores))
print("Individual DoS evidence scores:", observer_scores)
print("Individual scores encrypted: YES")
print("Expected total:", expected_total)
print("Decrypted aggregate:", decrypted_total)

assert decrypted_total == expected_total

print("ENCRYPTED DOS EVIDENCE TEST PASSED")
