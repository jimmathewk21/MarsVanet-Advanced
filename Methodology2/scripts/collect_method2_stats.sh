#!/bin/bash
OUT="$HOME/sdn_vanet_sumo/method2_network_stats.csv"
echo "timestamp,flow_packets,flow_bytes" > "$OUT"
while true; do
    TS=$(date +%s)
    COUNTS=$(sudo ovs-ofctl -O OpenFlow13 dump-flows s1 2>/dev/null | awk '
    /n_packets=/ {
        p=0; b=0
        if (match($0,/n_packets=[0-9]+/)) p=substr($0,RSTART+10,RLENGTH-10)
        if (match($0,/n_bytes=[0-9]+/)) b=substr($0,RSTART+8,RLENGTH-8)
        packets+=p
        bytes+=b
    }
    END {print packets+0 "," bytes+0}')
    echo "$TS,$COUNTS" >> "$OUT"
    sleep 5
done
