# Connectivity fix: AP OVS ports + station association

Symptoms observed in the VM:

| Component        | Status |
|------------------|--------|
| Ryu controller   | connected to the switches |
| ap1 (`ap1-wlan1`)| exists in Linux, **missing from the ap1 OVS bridge** |
| ap2 (`ap2-wlan1`)| present in the ap2 OVS bridge |
| sta1             | associated to ap2, ping fails |
| sta2, sta3       | Wi-Fi disconnected, interfaces down |
| ping             | failing |

These are **two different problems at two different layers**. Fixing one does
not fix the other.

---

## Problem 1 — ap1's wlan interface is not on the ap1 OVS bridge (confirmed)

This is a **datapath** problem. The path a packet must take is:

```
sta  ─wifi─▶  apX bridge  ─wired port─▶  s1  ─wired port─▶  apY bridge  ─wifi─▶  sta
```

If `ap1-wlan1` is not a port on the `ap1` bridge, a station associated to ap1
can transmit over the air but its frames never enter the bridge, so OpenFlow
never sees them and nothing is forwarded. ap2 works because its wlan port *is*
attached — which is exactly why ap2-side association looked fine while anything
involving ap1 failed.

### Fix (already applied in `scripts/sdn_vanet_2ap.py`)

After `apX.start([c0])`, the script now calls `ensure_ap_wireless_port()` for
**both** APs. It attaches the wlan interface only if it is missing and then
prints the bridge membership so you can see it worked:

```python
ensure_ap_wireless_port(ap1)
ensure_ap_wireless_port(ap2)
```

### Manual equivalent / verification (run in the VM)

```bash
# See what is wrong:
sudo ovs-vsctl list-ports ap1        # ap1-wlan1 absent == the bug
sudo ovs-vsctl list-ports ap2        # ap2-wlan1 present

# Fix it by hand if needed:
sudo ovs-vsctl add-port ap1 ap1-wlan1

# Confirm each AP bridge now has BOTH a wlan port and its wired port to s1:
sudo ovs-vsctl list-ports ap1        # expect: ap1-wlan1  ap1-eth1 (or similar)
sudo ovs-vsctl list-ports ap2
```

`scripts/connectivity_test.py --aps ap1 ap2` performs this check automatically
and flags any AP whose bridge has no `*wlan*` port.

---

## Problem 2 — sta2/sta3 not associating, interfaces down (radio layer)

OVS ports cannot help a station that never associates. "Interface down /
Wi-Fi disconnected" is above the switch, at the 802.11 layer. Two things to do:

### 2a. Bring the interfaces up and check association (already applied)

The script now calls `bring_up_stations()`, which runs `ip link set
staX-wlan0 up` for every station and prints its `iw ... link` state. Static
stations are sometimes left down after build; this handles that.

### 2b. If still "Not connected", it is a propagation / coverage problem

The topology uses `logDistance` propagation with `exp=3`, which is aggressive:
at `range=35` the usable signal at the cell edge can be too weak to associate.
Check the positions vs. ranges:

```
ap1 @ x=15 range 35  -> covers x≈ -20..50
ap2 @ x=55 range 35  -> covers x≈  20..90
sta2 @ x=20 (near ap1 edge)      sta3 @ x=60 (well inside ap2)
```

sta3 at x=60 *should* associate with ap2, so if it is down, suspect the
interface-down issue (2a) or a stale `mac80211_hwsim`. sta2 at x=20 is near the
ap1 edge and is the most propagation-sensitive.

Make association reliable without editing code, using the new env knobs:

```bash
# Lower the path-loss exponent (less loss, larger effective range):
export DOS_PROP_EXP=2.3
# and/or widen the nominal AP range:
export DOS_AP_RANGE=45
# and/or set an explicit AP transmit power (dBm):
export DOS_AP_TXPOWER=20
sudo -E python3 Methodology2/scripts/sdn_vanet_2ap.py
```

Then verify association per station from the Mininet-WiFi CLI:

```
mn-wifi> sta2 iw dev sta2-wlan0 link     # expect "Connected to <bssid>"
mn-wifi> sta3 iw dev sta3-wlan0 link
mn-wifi> sta2 iw dev sta2-wlan0 scan | grep sdnvanet   # is the AP even visible?
```

If `mac80211_hwsim` is in a bad state from a previous crashed run, reset it:

```bash
sudo mn -c                      # clean up Mininet state
sudo rmmod mac80211_hwsim 2>/dev/null; sudo modprobe mac80211_hwsim
```

---

## Verify in order (so you learn whether Problem 1 was the only cause)

Do not test the attack/mitigation until these pass, and do not add a
high-priority forwarding rule to force pings through — that would bypass the
very defence logic you are trying to evaluate.

```
1. sudo ovs-vsctl list-ports ap1          # ap1-wlan1 present?           (Problem 1)
2. sudo ovs-vsctl list-ports ap2          # ap2-wlan1 present?
3. mn-wifi> sta2 iw dev sta2-wlan0 link   # sta2 associated?             (Problem 2)
   mn-wifi> sta3 iw dev sta3-wlan0 link   # sta3 associated?
4. mn-wifi> sta2 ping -c3 10.0.0.1        # same-cell / adjacent ping first
5. mn-wifi> sta3 ping -c3 10.0.0.2        # cross-AP path (attacker -> victim)
6. sudo python3 Methodology2/scripts/connectivity_test.py --aps ap1 ap2
```

If step 1 is fixed but step 5 still fails while stations are associated, the
remaining cause is elsewhere (e.g. the wired `apX <-> s1` links, controller
L2 learning, or ARP) — `connectivity_test.py` and `dump-flows ap2` will show
which. Only once 4 and 5 pass should you run the experiments in
`EXPERIMENTS.md`.
