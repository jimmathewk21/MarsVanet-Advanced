#!/usr/bin/env bash
set -u

LABEL="${1:-snapshot}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$HERE/../results/runs"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$RESULTS/${STAMP}_${LABEL}"

mkdir -p "$OUT"

AP_MON="${DOS_AP2_BRIDGE:-ap2}"
OF=(-O OpenFlow13)

run() {
    local outfile="$1"
    shift
    {
        echo "# $(date -Is)"
        echo "# $*"
        "$@"
    } > "$OUT/$outfile" 2>&1
    echo "  saved $OUT/$outfile"
}

if ! command -v ovs-ofctl >/dev/null 2>&1; then
    echo "ovs-ofctl not found. Run this inside the Mininet-WiFi VM as root."
    exit 2
fi

echo "Collecting evidence -> $OUT"

run "show_${AP_MON}.txt" ovs-ofctl "${OF[@]}" show "$AP_MON"
run "show_ap1.txt" ovs-ofctl "${OF[@]}" show ap1
run "show_s1.txt" ovs-ofctl "${OF[@]}" show s1
run "bridge_ports.txt" ovs-vsctl list-ports "$AP_MON"
run "controllers.txt" ovs-vsctl list controller
run "dumpflows_${AP_MON}.txt" ovs-ofctl "${OF[@]}" dump-flows "$AP_MON"
run "dumpflows_s1.txt" ovs-ofctl "${OF[@]}" dump-flows s1
run "dumpports_${AP_MON}.txt" ovs-ofctl "${OF[@]}" dump-ports "$AP_MON"
run "meters_${AP_MON}.txt" ovs-ofctl "${OF[@]}" dump-meters "$AP_MON"
run "meterstats_${AP_MON}.txt" ovs-ofctl "${OF[@]}" meter-stats "$AP_MON"

echo "Done. Snapshot: $OUT"
