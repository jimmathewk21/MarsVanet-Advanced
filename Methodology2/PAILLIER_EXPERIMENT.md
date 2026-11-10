# Paillier Privacy-Preserving Trust Aggregation

## Objective

Evaluate Paillier encryption as a separate privacy component for aggregating trust-related penalty values in the SDN-based VANET project.

## Cryptographic Operations

For public key N = pq, encryption uses:

c = (1 + N)^m * r^N mod N^2

where m is the message and r is a random integer coprime to N.

Decryption uses the private value phi(N):

m_hat = ((c^phi(N) mod N^2) - 1) / N

m = m_hat * inverse(phi(N), N) mod N

Ciphertexts can be multiplied modulo N^2 to add their underlying messages modulo N.

## Trust Aggregation Test

The test aggregated the integer penalties:

- 40
- 40
- 20

The decrypted aggregate was 100. With a scale factor of 100, the aggregate penalty was 1.0.

Result: PASS.

## Preliminary Benchmark

The recorded benchmark used a 256-bit demonstration key and 20 iterations.

| Metric | Measured result |
|---|---:|
| Key generation | 0.732 ms |
| Average encryption | 0.342 ms |
| Average decryption | 0.333 ms |
| Average homomorphic addition | 0.001 ms |
| Correctness checks | PASS |

These are preliminary measurements from a small test key. They are not production-security performance results.

## Relationship to the DoS Defense

This experiment is a separate cryptographic proof of concept. Paillier encryption has not yet been integrated into the live Ryu controller or its detection and mitigation stages.

The current experiment demonstrates encrypted integer aggregation. It does not establish that encrypted trust aggregation improves attack detection or network performance.

## Limitations and Future Work

- Use a well-reviewed cryptographic implementation and appropriately sized keys before making security claims.
- Repeat benchmarks across multiple runs and key sizes.
- Define how multiple vehicles or observers generate and validate trust contributions.
- Design and test integration with the Ryu controller separately.
- Evaluate end-to-end processing overhead before comparing network performance.
