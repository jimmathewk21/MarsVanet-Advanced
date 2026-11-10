from dos_evidence import calculate_dos_evidence

cases = [
    (50, 100, 0),
    (100, 100, 25),
    (150, 100, 50),
    (200, 100, 75),
    (300, 100, 100)
]

for packet_rate, threshold, expected in cases:
    actual = calculate_dos_evidence(packet_rate, threshold)
    print(
        f"Rate={packet_rate}, threshold={threshold}, "
        f"score={actual}, expected={expected}"
    )
    assert actual == expected

print("DOS EVIDENCE SCORING TEST PASSED")
