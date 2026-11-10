"""Lane mobility, handover boundaries and native-adapter contracts; no GUI."""
import math
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from engine import SimEngine, LANE_ROUTES
from mobility import plan_vehicle, MIN_SPACING
from sumo_tools import SumoBridge


class MobilityTests(unittest.TestCase):
    def test_lane_geometry_stays_on_roads_and_wraps_continuously(self):
        for route in LANE_ROUTES:
            for i in range(int(route.length)):
                x,y,angle=route.pose(i)
                distance=min(*(abs(x-r) for r in (90,270,840,1010)),
                             *(abs(y-r) for r in (90,170,330,520,590)))
                self.assertLessEqual(distance,25)
                xx,yy,aa=route.pose(i+.5)
                self.assertLessEqual(math.hypot(xx-x,yy-y),.51)
                self.assertLess(abs((aa-angle+180)%360-180),8)
            first,last=route.pose(0),route.pose(route.length-1e-5)
            self.assertLess(math.hypot(first[0]-last[0],first[1]-last[1]),1e-4)

    def test_seed_replay_pause_and_reset(self):
        a,b=SimEngine(seed=34),SimEngine(seed=34)
        for _ in range(120): a.step(.1);b.step(.1)
        self.assertEqual(a.status(),b.status())
        a.set_running(False)
        positions=[(v.x,v.y,v.speed) for v in a.vehicles.values()]
        a.step(.2)
        self.assertEqual(positions,[(v.x,v.y,v.speed) for v in a.vehicles.values()])
        a.reset()
        self.assertEqual(a.mobility_model,'lane_v2')
        self.assertEqual(a.status()['vehicles'],SimEngine(seed=34).status()['vehicles'])

    def test_normal_driving_acceleration_and_safety_messages(self):
        sim=SimEngine()
        sim.config['loss_probability']=0
        for _ in range(600):
            speeds={v.id:v.speed for v in sim.vehicles.values()}
            sim.step(.1)
            for v in sim.vehicles.values():
                self.assertLessEqual(abs(v.speed-speeds[v.id])/.36,3.01)
                self.assertLessEqual(len(v.motion_trace),32)
        self.assertEqual(sim.totals['invalid_safety'],0)
        self.assertGreater(sim.totals['handovers'],0)

    def test_following_and_red_signal_stop(self):
        route=SimpleNamespace(distance_to_turn=lambda _:1000)
        car=SimpleNamespace(id='V01',x=150.,y=180.,angle=0.,speed=36.,cruise_speed=50.,
                            progress=0.,mobility_active=True,committed_junction=None,movement='cruising')
        lead=SimpleNamespace(id='V02',x=230.,y=180.,angle=0.,speed=0.,mobility_active=True)
        for i in range(100):
            plan=plan_vehicle(car,[car,lead],route,1,.1,14)
            car.x+=plan.distance;car.speed=plan.speed;car.movement=plan.status
            car.committed_junction=plan.committed_junction
            self.assertGreaterEqual(lead.x-car.x,MIN_SPACING-1e-6)
        car.x,car.speed,car.movement=190,20,'cruising'
        for i in range(100):
            plan=plan_vehicle(car,[car],route,16+i*.1,.1,14)
            car.x+=plan.distance;car.speed=plan.speed;car.movement=plan.status
            car.committed_junction=plan.committed_junction
            self.assertLessEqual(car.x,246.001)
        self.assertLess(car.speed,1)

    def test_coverage_hysteresis_and_rapid_handover_preserve_state(self):
        sim=SimEngine();v=sim.vehicles['V07']
        v.x,v.y,v.rsu=561,218,'RSU-1'
        for x in (561,564,561,563):
            v.x=x;sim._associate()
        self.assertEqual(v.handovers,0)
        v.reputation,v.m2_stage=.2,'METER'
        v.x=825;sim._associate();sim._associate()
        self.assertEqual(v.handovers,1)
        self.assertEqual((v.reputation,v.m2_stage),(.2,'METER'))
        v.x,v.y=-1000,-1000;sim._associate();sim.t+=5
        v.x,v.y=300,218;sim._associate();sim._associate()
        self.assertEqual(v.handovers,2)

    def test_rsu_path_counters_and_vehicle_receive_counts(self):
        sim=SimEngine();sim.config['loss_probability']=0
        v=sim.vehicles['V01'];rid=v.rsu
        self.assertTrue(sim._send(v.id,rid,'TELEMETRY',420))
        self.assertEqual(sim.rsu_stats[rid]['path_delivered'],1)
        self.assertTrue(sim._send(rid,v.id,'BEACON',100))
        self.assertEqual(v.received,1)
        rsu=next(r for r in sim.status()['rsus'] if r['id']==rid)
        self.assertIn(v.id,rsu['associated_vehicles'])
        self.assertEqual(rsu['traffic']['delivered_bytes'],520)

    def test_legacy_model_remains_constant_speed(self):
        sim=SimEngine(mobility_model='legacy');v=sim.vehicles['V01'];speed=v.speed
        sim.step(.1)
        self.assertEqual(v.speed,speed)
        self.assertEqual(sim.simulation_report()['metadata']['mobility_model'],'legacy')


class SumoAdapterTests(unittest.TestCase):
    def test_coordinate_heading_velocity_and_cumulative_clock(self):
        bridge=SumoBridge(seed=41)
        clock=[0.]
        calls=[]
        def step(target):
            calls.append(target);clock[0]=math.ceil((target-1e-9)*10)/10
        bridge.connection=SimpleNamespace(
            simulation=SimpleNamespace(getTime=lambda:clock[0]),simulationStep=step,
            vehicle=SimpleNamespace(getIDList=lambda:['V01','Visitor'],
              getPosition=lambda _:(210.,400.),getSpeed=lambda _:10.,getAngle=lambda _:0.))
        bridge.net_offset=(-90.,-70.)
        pos=bridge.step(.100001)['V01']
        self.assertEqual(pos,dict(x=300.,y=190.,speed=36.,angle=270.))
        bridge.step(.100001)
        self.assertAlmostEqual(calls[-1],.200002)
        self.assertEqual(set(bridge.positions()),{'V01'})
        self.assertNotEqual(bridge.label,SumoBridge().label)
        for bearing,expected in ((0,270),(90,0),(180,90),(270,180)):
            bridge.connection.vehicle.getAngle=lambda _,bearing=bearing:bearing
            self.assertEqual(bridge.positions()['V01']['angle'],expected)

    def test_launch_passes_seed_uses_own_connection_and_does_not_preadvance(self):
        with tempfile.TemporaryDirectory() as folder:
            cfg=Path(folder)/'city.sumocfg';cfg.touch()
            (Path(folder)/'city.net.xml').write_text('<net><location netOffset="-90,-70"/></net>')
            connection=SimpleNamespace(simulation=SimpleNamespace(getTime=lambda:0),simulationStep=Mock(),close=Mock())
            traci=SimpleNamespace(start=Mock(),getConnection=Mock(return_value=connection))
            bridge=SumoBridge(seed=37)
            with patch.dict('sys.modules',{'traci':traci}),patch('sumo_tools.find_program',return_value='sumo'),patch('sumo_tools.build_sumo',return_value=cfg):
                bridge.start()
            command=traci.start.call_args.args[0]
            self.assertEqual(command[command.index('--seed')+1],'37')
            self.assertEqual(traci.start.call_args.kwargs['label'],bridge.label)
            connection.simulationStep.assert_not_called()
            bridge.close();bridge.close()
            connection.close.assert_called_once()
            connection.close.reset_mock()
            connection.simulation.getTime=Mock(side_effect=RuntimeError('connection lost'))
            with patch.dict('sys.modules',{'traci':traci}),patch('sumo_tools.find_program',return_value='sumo'),patch('sumo_tools.build_sumo',return_value=cfg):
                with self.assertRaisesRegex(ValueError,'Unable to launch SUMO'):SumoBridge().start()
            connection.close.assert_called_once()

    def test_missing_native_program_never_launches(self):
        traci=SimpleNamespace(start=Mock())
        with patch.dict('sys.modules',{'traci':traci}),patch('sumo_tools.find_program',return_value=None):
            with self.assertRaisesRegex(ValueError,'executable not found'):SumoBridge().start()
        traci.start.assert_not_called()

    def test_departure_arrival_and_reappearance_preserve_identity(self):
        sim=SimEngine();v=sim.vehicles['V01'];v.reputation=.3
        snapshots=iter([{}, {'V01':dict(x=200,y=180,angle=0,speed=0)}, {},
                        {'V01':dict(x=202,y=180,angle=0,speed=10)}])
        sim.mobility_mode='sumo';sim.sumo_bridge=SimpleNamespace(step=lambda _:next(snapshots))
        sim.step(.1)
        self.assertFalse(v.mobility_active)
        self.assertEqual(sim.totals['sent'],0)
        self.assertFalse(v.motion_trace)
        sim.step(.1)
        self.assertTrue(v.mobility_active);self.assertEqual(v.movement,'stopped')
        sim.step(.1);self.assertFalse(v.mobility_active)
        sim.step(.1);self.assertIs(v,sim.vehicles['V01'])
        self.assertEqual(v.reputation,.3)
        self.assertEqual(v.x,202)


if __name__=='__main__':unittest.main()
