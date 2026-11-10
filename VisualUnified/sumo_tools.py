"""Optional native Windows SUMO/TraCI vehicle mobility adapter.

SUMO supplies vehicle positions and speeds; MarsNet still simulates wireless
messages, SDN policy decisions and packet forwarding. Does NOT use Mininet.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
OUT = HERE / "sumo"
X = [90, 270, 840, 1010]
Y_CANVAS = [90, 170, 330, 520, 590]
VEHICLE_ROUTES = [(0, .05), (1, .58), (2, .13), (0, .45), (1, .12), (2, .65),
                  (0, .26), (1, .72), (0, .77), (2, .88), (1, .35), (0, .92)]
GRID_LOOPS = [
    [(0,1),(3,1),(3,3),(0,3),(0,1)],
    [(0,2),(3,2),(3,1),(0,1),(0,2)],
    [(1,0),(1,4),(2,4),(2,0),(1,0)],
]


def find_program(executable):
    exe = shutil.which(executable)
    if exe: return exe
    home = os.environ.get('SUMO_HOME')
    if home:
        candidate = Path(home) / 'bin' / (executable + ('.exe' if os.name == 'nt' else ''))
        if candidate.exists(): return str(candidate)
    return None


def edge_name(a, b):
    return f"e{a[0]}_{a[1]}_{b[0]}_{b[1]}"


def walk_loop(nodes):
    steps = []
    for a,b in zip(nodes,nodes[1:]):
        if a[0] != b[0] and a[1] != b[1]: raise ValueError('Only straight grid segments allowed')
        if a[0] == b[0]:
            sy = 1 if b[1] > a[1] else -1
            hops = [(a[0], j) for j in range(a[1], b[1] + sy, sy)]
        else:
            sx = 1 if b[0] > a[0] else -1
            hops = [(j, a[1]) for j in range(a[0], b[0] + sx, sx)]
        steps.extend(edge_name(u,v) for u,v in zip(hops,hops[1:]))
    return steps


def write_xml(tree, path):
    ET.indent(tree,space='  ')
    tree.write(path,encoding='utf-8',xml_declaration=True)


def write_inputs(folder=OUT):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    nodes = ET.Element('nodes')
    for j,y in enumerate(Y_CANVAS):
        for i,x in enumerate(X):
            ET.SubElement(nodes,'node',id=f'n{i}_{j}',x=str(x),y=str(660-y),type='priority')
    write_xml(ET.ElementTree(nodes),folder/'city.nod.xml')
    edges=ET.Element('edges')
    for j in range(len(Y_CANVAS)):
        for i in range(len(X)):
            for other in [(i+1,j),(i,j+1)]:
                if other[0]>=len(X) or other[1]>=len(Y_CANVAS): continue
                for a,b in [((i,j),other),(other,(i,j))]:
                    ET.SubElement(edges,'edge',id=edge_name(a,b),
                                  **{'from':f'n{a[0]}_{a[1]}','to':f'n{b[0]}_{b[1]}'},
                                  priority='1',numLanes='1',speed='25')
    write_xml(ET.ElementTree(edges),folder/'city.edg.xml')
    routes=ET.Element('routes')
    ET.SubElement(routes,'vType',id='car',accel='2.5',decel='4.5',sigma='0.3',length='4.8',minGap='2.2',maxSpeed='24')
    loops=[walk_loop(loop) for loop in GRID_LOOPS]
    for i,(route_i,offset) in enumerate(VEHICLE_ROUTES,1):
        edges=loops[route_i]
        # Rotate to varied starting roads, preserving one continuous route loop.
        ix=int(len(edges)*offset)%len(edges)
        rotated=edges[ix:]+edges[:ix]
        # Fifteen laps, enough for typical live demonstrations (>20 minutes).
        route_id=f'route-V{i:02}'
        ET.SubElement(routes,'route',id=route_id,edges=' '.join(rotated*15))
        ET.SubElement(routes,'vehicle',id=f'V{i:02}',type='car',route=route_id,
                      depart=f'{(i-1)*.05:.2f}',departSpeed='max',departLane='best')
    write_xml(ET.ElementTree(routes),folder/'city.rou.xml')
    config=ET.Element('configuration')
    inputs=ET.SubElement(config,'input')
    ET.SubElement(inputs,'net-file',value='city.net.xml')
    ET.SubElement(inputs,'route-files',value='city.rou.xml')
    times=ET.SubElement(config,'time')
    ET.SubElement(times,'begin',value='0')
    ET.SubElement(times,'end',value='3600')
    write_xml(ET.ElementTree(config),folder/'city.sumocfg')
    return folder


def build_sumo(folder=OUT):
    folder=write_inputs(folder)
    exe=find_program('netconvert')
    if not exe:
        raise ValueError('SUMO netconvert not found. Install native Windows SUMO, and set SUMO_HOME or add its bin folder to PATH.')
    command=[exe,'--node-files',str(folder/'city.nod.xml'),
             '--edge-files',str(folder/'city.edg.xml'),
             '--output-file',str(folder/'city.net.xml'),
             '--no-turnarounds','true']
    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    if result.returncode:
        raise ValueError('SUMO network build failed: '+(result.stderr or result.stdout)[-1100:])
    return folder/'city.sumocfg'


class SumoBridge:
    def __init__(self, seed=14):
        self.connection=None
        self.label='marsnet-' + uuid.uuid4().hex[:12]
        self.seed = seed
        self.target_time = 0.0
        self.expected_ids = {f'V{i:02}' for i in range(1,13)}
        self.net_offset = (0.0, 0.0)

    def start(self):
        try:
            import traci
        except ImportError:
            executable=find_program('sumo')
            tools=Path(executable).resolve().parent.parent/'tools' if executable else None
            if tools and (tools/'traci').is_dir():
                if str(tools) not in sys.path: sys.path.append(str(tools))
                try: import traci
                except ImportError:
                    raise ValueError('Bundled SUMO TraCI could not be imported; built-in mobility remains available.') from None
            else:
                raise ValueError('TraCI not found. Install native SUMO with its tools, or use built-in mobility.') from None
        sumo=find_program('sumo')
        if not sumo:
            raise ValueError('SUMO executable not found. Install Windows SUMO and add its bin directory to PATH.')
        cfg=build_sumo()
        try:
            location = ET.parse(cfg.parent/'city.net.xml').getroot().find('location')
            self.net_offset = tuple(float(v) for v in location.attrib['netOffset'].split(','))
            if len(self.net_offset)!=2:raise ValueError('Expected two coordinate offsets')
        except (OSError,ET.ParseError,AttributeError,KeyError,ValueError) as exc:
            raise ValueError(f'Invalid SUMO network coordinate metadata: {exc}') from None
        try:
            traci.start([sumo,'-c',str(cfg),'--step-length','0.1','--seed',str(self.seed),
                         '--no-warnings','true'],label=self.label)
            self.connection=traci.getConnection(self.label)
            self.target_time = self.connection.simulation.getTime()
        except Exception as exc:
            if self.connection is None:
                try:self.connection=traci.getConnection(self.label)
                except Exception:pass
            self.close()
            raise ValueError(f'Unable to launch SUMO: {exc}') from None

    def step(self, dt):
        if not self.connection: return {}
        if dt <= 0: return self.positions()
        # TraCI rounds steps up to its grid. Accumulate requested elapsed time,
        # rather than adding tiny wall-clock deltas to rounded SUMO time.
        self.target_time += dt
        if self.target_time > self.connection.simulation.getTime() + 1e-8:
            self.connection.simulationStep(self.target_time)
        return self.positions()

    def positions(self):
        if not self.connection: return {}
        positions={}
        for vid in self.connection.vehicle.getIDList():
            if vid not in self.expected_ids: continue
            x,y=self.connection.vehicle.getPosition(vid)
            # netconvert normalizes coordinates by default. Restore the source
            # grid before the screen's y flip (otherwise roads shift 90/70 m).
            ox,oy=self.net_offset
            positions[vid]={"x":x-ox,"y":660-(y-oy),"speed":self.connection.vehicle.getSpeed(vid)*3.6,
                            "angle":(self.connection.vehicle.getAngle(vid)-90)%360}
        return positions

    def close(self):
        if self.connection:
            try:self.connection.close()
            except Exception:pass
            self.connection=None


if __name__=='__main__':
    cfg=build_sumo()
    print('SUMO network ready:',cfg)
