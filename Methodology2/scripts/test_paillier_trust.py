from paillier_crypto import (
    generate_keys,
    encrypt,
    decrypt,
    add_ciphertexts
)

SCALE = 100

private_key, public_key = generate_keys(64)

penalties = [40, 40, 20]

encrypted_total = encrypt(0, public_key)

for penalty in penalties:
    encrypted_penalty = encrypt(penalty, public_key)
    encrypted_total = add_ciphertexts(
        encrypted_total,
        encrypted_penalty,
        public_key
    )

total_penalty = decrypt(encrypted_total, private_key)
trust_penalty = total_penalty / SCALE

print("Encrypted trust penalties:", penalties)
print("Decrypted aggregate:", total_penalty)
print("Aggregate trust penalty:", trust_penalty)

assert total_penalty == sum(penalties)
assert trust_penalty == 1.0

print("PAILLIER TRUST AGGREGATION TEST PASSED")
