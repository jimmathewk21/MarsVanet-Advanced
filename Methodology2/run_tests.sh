#!/usr/bin/env bash
# Run every test that does NOT require the live SDN/SUMO runtime.
#
# These tests cover the runtime-independent logic plus the mocked Ryu adapter:
# Paillier crypto, privacy-preserving aggregation, DoS evidence scoring,
# mobility-aware detection, progressive mitigation, and OpenFlow polling. They
# need only the Python standard library (no Ryu/Mininet/SUMO).
#
# Usage:  bash Methodology2/run_tests.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$HERE/scripts"
TESTS="$HERE/tests"

echo "============================================================"
echo "1) unittest suite (tests/)"
echo "============================================================"
( cd "$TESTS" && python3 -m unittest discover -p 'test_*.py' -v )

echo
echo "============================================================"
echo "2) original standalone check scripts (scripts/)"
echo "============================================================"
for t in test_paillier_trust.py test_dos_evidence.py \
         test_encrypted_dos_evidence.py test_encrypted_dos_integration.py \
         test_multi_observer_trust.py ; do
    echo "--- $t ---"
    ( cd "$SCRIPTS" && python3 "$t" )
done

echo
echo "All runtime-independent tests completed."
