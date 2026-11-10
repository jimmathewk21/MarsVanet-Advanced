from paillier_crypto import (
    generate_keys,
    encrypt,
    decrypt,
    add_ciphertexts
)

SCALE = 100
penalties = [40, 40, 20]

private_key, public_key = generate_keys(64)

encrypted_contributions = [
    encrypt(penalty, public_key)
    for penalty in penalties
]

encrypted_total = encrypt(0, public_key)

for encrypted_value in encrypted_contributions:
    encrypted_total = add_ciphertexts(
        encrypted_total,
        encrypted_value,
        public_key
    )

total_penalty = decrypt(encrypted_total, private_key)
aggregate_penalty = total_penalty / SCALE

print("Number of observers:", len(penalties))
print("Individual penalties:", penalties)
print("Individual contributions encrypted: YES")
print("Aggregate decrypted total:", total_penalty)
print("Aggregate penalty:", aggregate_penalty)

assert total_penalty == sum(penalties)
assert aggregate_penalty == 1.0

print("MULTI-OBSERVER TRUST TEST PASSED")
