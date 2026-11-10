"""Small deterministic dashboard health check; SIMULATION ONLY, not a study.

python smoke_phase1.py --output docs/phase1-smoke-new.json
Output creation is exclusive. This never opens SUMO, browsers or settings.
"""
import argparse
import hashlib
import json
from pathlib import Path

from engine import SimEngine


def run_smoke():
    runs=[]
    for scenario in ('normal','combined'):
        sim=SimEngine(seed=14)
        stages=set()
        phases=[]
        lowest_reputation=1.
        for phase,seconds in (('baseline',5),('attack',20),('recovery',120)):
            sim.set_scenario(scenario if phase=='attack' else 'normal')
            before=sim.totals.copy();start=sim.t
            for _ in range(seconds*10):
                sim.step(.1)
                stages.add(sim.vehicles['V07'].m2_stage)
                lowest_reputation=min(lowest_reputation,sim.vehicles['V07'].reputation)
            phases.append({'phase':phase,'start_s':round(start,3),'end_s':round(sim.t,3),
                           'generated':sim.totals['sent']-before['sent'],
                           'received':sim.totals['delivered']-before['delivered'],
                           'dropped':sim.totals['dropped']-before['dropped']})
        counts=dict(sim.totals)
        assert counts['sent']==counts['delivered']+counts['dropped']
        assert len(sim.vehicles)==12
        if scenario=='normal':assert counts.get('invalid_safety',0)==0
        else:
            assert {'NORMAL','METER','BLOCK'} <= stages
            assert lowest_reputation < .2
            assert sim.vehicles['V07'].m2_stage=='NORMAL'
        runs.append({'scenario':scenario,'seed':14,'mobility_model':sim.mobility_model,
                     'simulated_seconds':round(sim.t,3),'vehicle_count':len(sim.vehicles),
                     'phases':phases,'counters':counts,'m2_stages_seen':sorted(stages),
                     'minimum_attacker_reputation':lowest_reputation,
                     'final_attacker_reputation':sim.vehicles['V07'].reputation,
                     'final_attacker_m2':sim.vehicles['V07'].m2_stage})
    here=Path(__file__).resolve().parent
    return {'status':'PASS','scope':'SIMULATION_ONLY health smoke; not a statistical performance comparison.',
            'sources_sha256':{name:hashlib.sha256((here/name).read_bytes()).hexdigest()
                              for name in ('engine.py','mobility.py','smoke_phase1.py')},'runs':runs}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.output and args.output.exists():raise FileExistsError(args.output)
    result=run_smoke()
    text=json.dumps(result,indent=2,allow_nan=False)+'\n'
    if args.output:
        with args.output.open('x',encoding='utf-8') as stream:stream.write(text)
    print(text)


if __name__=='__main__':main()
