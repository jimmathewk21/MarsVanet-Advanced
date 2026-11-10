import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from sumo_tools import write_inputs,walk_loop,GRID_LOOPS,VEHICLE_ROUTES
from engine import SimEngine


class SumoInputTests(unittest.TestCase):
    def test_generate_valid_grid_and_routes_without_sumo(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=write_inputs(Path(temp))
            nodes=ET.parse(folder/'city.nod.xml').getroot()
            edges=ET.parse(folder/'city.edg.xml').getroot()
            routes=ET.parse(folder/'city.rou.xml').getroot()
            self.assertEqual(len(nodes.findall('node')),20)
            self.assertGreaterEqual(len(edges.findall('edge')),60)
            self.assertEqual(len(routes.findall('vehicle')),12)
            edge_ids={r.attrib['id']:r.attrib for r in edges.findall('edge')}
            for route in routes.findall('route'):
                sequence=route.attrib['edges'].split()
                self.assertGreater(len(sequence),100)
                self.assertTrue(all(edge in edge_ids for edge in sequence))
                for a,b in zip(sequence,sequence[1:]):
                    self.assertEqual(edge_ids[a]['to'],edge_ids[b]['from'])

    def test_loop_route_topology(self):
        for loop in GRID_LOOPS:
            path=walk_loop(loop)
            self.assertGreater(len(path),6)
            self.assertEqual(len(set(path)),len(path))

    def test_missing_optional_mobility_keeps_existing_simulation(self):
        sim = SimEngine()
        sim.set_scenario('combined')
        sim.step(.1)
        initial = sim.status()
        with patch('sumo_tools.SumoBridge.start', side_effect=ValueError('SUMO unavailable')):
            with self.assertRaisesRegex(ValueError, 'SUMO unavailable'):
                sim.set_mobility_mode('sumo')
        self.assertEqual(sim.mobility_mode, 'builtin')
        self.assertEqual(sim.t, initial['time'])
        self.assertEqual(sim.scenario, 'combined')
        self.assertIsNone(sim.sumo_bridge)


if __name__=='__main__':unittest.main()
