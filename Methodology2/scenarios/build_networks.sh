#!/usr/bin/env bash
# Build the SUMO .net.xml files for the urban and highway scenarios from their
# node/edge sources. Requires SUMO's `netconvert` on PATH (install SUMO).
#
# Usage:  bash Methodology2/scenarios/build_networks.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v netconvert >/dev/null 2>&1; then
    echo "netconvert not found. Install SUMO and ensure netconvert is on PATH."
    echo "  Debian/Ubuntu: sudo apt-get install sumo sumo-tools"
    echo "  then: export SUMO_HOME=/usr/share/sumo"
    exit 2
fi

echo "Building urban network..."
netconvert \
    --node-files "$HERE/urban/urban.nod.xml" \
    --edge-files "$HERE/urban/urban.edg.xml" \
    --output-file "$HERE/urban/urban.net.xml"

echo "Building highway network..."
netconvert \
    --node-files "$HERE/highway/highway.nod.xml" \
    --edge-files "$HERE/highway/highway.edg.xml" \
    --output-file "$HERE/highway/highway.net.xml"

echo "Done. Built:"
echo "  $HERE/urban/urban.net.xml"
echo "  $HERE/highway/highway.net.xml"
