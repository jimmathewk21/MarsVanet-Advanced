"""Deterministic Windows-native simulated defense comparison (not OVS evidence).

Run: py -3 run_comparison.py --seconds 35 --scenario combined
"""
from __future__ import annotations
import argparse
import csv
import math
from pathlib import Path
from engine import SimEngine

PROFILES = [
    ('No defenses',False,False,False,False),
    ('M1 only',True,False,False,True),
    ('M2 only',False,True,False,False),
    ('M3 only',False,False,True,False),
    ('Unified dynamic',True,True,True,False),
    ('Unified + M1 static',True,True,True,True),
]


def run_trial(profile, seconds=35, scenario='combined', seed=14):
    name, m1, m2, m3, static_rule = profile
    sim = SimEngine(seed=seed, mobility_model='legacy')
    sim.set_config({'m1_enabled':m1,'m2_enabled':m2,'m3_enabled':m3})
    if static_rule:
        sim.upsert_rule({'label':'Comparison: static malicious UDP block','source':'V07',
                         'traffic':'UDP_FLOOD','rsu':'*','priority':900,'action':'DROP','enabled':True})
    sim.set_scenario(scenario,attacker='V07',victim='V02')
    if not math.isfinite(seconds) or not 0 < seconds <= 3600:
        raise ValueError('seconds must be positive, finite and at most 3600')
    ticks=int(seconds*10)
    for _ in range(ticks):sim.step(.1)
    remainder = seconds - ticks / 10
    if remainder > 1e-9: sim.step(remainder)
    stats=sim.status()['stats']
    attacker=sim.vehicles['V07']
    return {
        'study_type':'SIMULATION_ONLY', 'profile':name, 'scenario':scenario, 'seed':seed,
        'simulated_seconds':round(sim.t,2), 'total_generated_packets':stats['sent'],
        'total_delivered_packets':stats['delivered'], 'total_dropped_packets':stats['dropped'],
        'overall_PDR_pct':stats['pdr'], 'legitimate_PDR_last_10s_pct':stats['legit_pdr'],
        'legitimate_PDR_whole_run_pct':round(100*stats['legitimate_delivered']/
            max(1,stats['legitimate_sent']),1),
        'attacker_sent_packets':attacker.sent,'attacker_delivered_packets':attacker.delivered,
        'attacker_delivery_pct':round(100*attacker.delivered/max(1,attacker.sent),1),
        'M1_static_drops':stats['m1_dropped'], 'M2_stage2_drops':stats['m2_dropped'],
        'M1_meter_drops':stats['m1_meter_drops'],'M2_meter_drops':stats['m2_meter_drops'],
        'M3_meter_drops':stats['m3_meter_drops'], 'M2_blocks_triggered':stats['m2_blocks'],
        'invalid_BSM':stats['invalid_safety'], 'attacker_final_reputation':round(attacker.reputation,2),
        'handovers':stats['handovers'],
    }


def main():
    parser=argparse.ArgumentParser(description='Simulated control-plane ablation study')
    parser.add_argument('--seconds',type=float,default=35)
    parser.add_argument('--scenario',choices=['normal','flood','misinformation','combined'],default='combined')
    parser.add_argument('--seed',type=int,default=14)
    parser.add_argument('--output',type=Path,default=Path('comparison_simulation.csv'))
    args=parser.parse_args()
    if not math.isfinite(args.seconds) or not 0 < args.seconds <= 3600:
        parser.error('seconds must be positive, finite and at most 3600')
    if args.output.exists(): parser.error('Refusing to overwrite an existing comparison file')
    trials=[run_trial(p,args.seconds,args.scenario,args.seed) for p in PROFILES]
    with args.output.open('x',newline='',encoding='utf-8') as output:
        writer=csv.DictWriter(output,fieldnames=trials[0].keys())
        writer.writeheader();writer.writerows(trials)
    for r in trials:
        print(f"{r['profile']:<19} PDR={r['overall_PDR_pct']:>5.1f}% "+
              f"legit-PDR(10s)={r['legitimate_PDR_last_10s_pct']:>5.1f}% "+
              f"M1drop={r['M1_static_drops']:>6} M2drop={r['M2_stage2_drops']:>6} "+
              f"attacker-delivered={r['attacker_delivered_packets']:>5} " +
              f"M3meterDrop={r['M3_meter_drops']:>5}")
    print('SIMULATED comparison written to:',args.output.resolve())


if __name__=='__main__':main()
