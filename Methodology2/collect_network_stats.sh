#!/bin/bash
OUT="$HOME/sdn_vanet_sumo/method2_live_network_stats.csv"
echo "timestamp,port,rx_packets,rx_bytes,tx_packets,tx_bytes,rx_drops,tx_drops" > "$OUT"
for i in $(seq 1 12); do
  TS=$(date +%s)
  sudo ovs-ofctl -O OpenFlow13 dump-ports ap2 | awk -v ts="$TS" '
  /port / && /rx pkts=/ {
    port=$2
    gsub(/"/,"",port)
    rxp=rb=rd=txp=tb=td=0
    for(j=1;j<=NF;j++) {
      if($j ~ /^rx$/) {
        split($(j+2),a,"="); rxp=a[2]
        split($(j+3),a,"="); rb=a[2]
        split($(j+4),a,"="); rd=a[2]
      }
      if($j ~ /^tx$/) {
        split($(j+2),a,"="); txp=a[2]
        split($(j+3),a,"="); tb=a[2]
        split($(j+4),a,"="); td=a[2]
      }
    }
    print ts "," port "," rxp "," rb "," txp "," tb "," rd "," td
  }' >> "$OUT"
  sleep 5
done
echo "Saved to $OUT"
cat "$OUT"
