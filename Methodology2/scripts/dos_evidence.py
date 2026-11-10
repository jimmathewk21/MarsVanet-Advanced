def calculate_dos_evidence(packet_rate, threshold):
    if packet_rate < 0 or threshold <= 0:
        raise ValueError("Packet rate must be non-negative and threshold positive")

    ratio = packet_rate / threshold

    if ratio < 1:
        return 0
    if ratio < 1.5:
        return 25
    if ratio < 2:
        return 50
    if ratio < 3:
        return 75
    return 100
