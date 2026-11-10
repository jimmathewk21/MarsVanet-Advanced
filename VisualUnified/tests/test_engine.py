"""Run with: py -3 -m unittest discover -s tests -v"""
import unittest
from engine import SimEngine, DEFAULT_CONFIG, position_on_route, ROUTES, reputation_policy


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = SimEngine(seed=14)
        self.engine.config['loss_probability'] = 0.0

    def tick(self, steps=100):
        for _ in range(steps): self.engine.step(.1)

    def test_spawns_twelve_vehicles_and_three_rsus(self):
        s = self.engine.status()
        self.assertEqual(len(s['vehicles']), 12)
        self.assertEqual(len(s['rsus']), 3)

    def test_vehicles_move_along_roads(self):
        first = self.engine.vehicles['V01'].x
        self.tick(10)
        self.assertGreater(self.engine.vehicles['V01'].x, first)

    def test_normal_traffic_has_v2v_and_v2i_delivery(self):
        self.tick(180)
        self.assertGreater(self.engine.totals['delivered'], 100)
        self.assertEqual(self.engine.totals['invalid_safety'], 0)
        self.assertGreater(self.engine.status()['stats']['legit_pdr'], 90)

    def test_handover_occurs_with_mobility(self):
        self.tick(1400)
        self.assertGreater(self.engine.totals['handovers'], 0)

    def test_m2_detects_flood_and_stages_to_block(self):
        self.engine.set_scenario('flood')
        self.tick(140)  # Original M2 requires a 10-second Stage 1 dwell.
        self.assertGreater(self.engine.reasons['RATE_LIMIT'], 0)
        self.assertGreater(self.engine.totals['m2_blocks'], 0)
        self.assertGreater(self.engine.reasons['M2_TEMP_BLOCK'], 0)

    def test_m3_deteriorates_reputation(self):
        self.engine.set_scenario('misinformation')
        self.tick(70)
        v = self.engine.vehicles['V07']
        self.assertLess(v.reputation, .2)
        self.assertEqual(reputation_policy(v.reputation), (100, 'SEVERE_THROTTLE'))
        self.assertEqual(v.last_invalid_reason, 'Reported speed exceeds allowed range')
        self.assertEqual(self.engine.totals['m2_blocks'], 0)

    def test_combined_attack_activates_both(self):
        self.engine.set_scenario('combined')
        self.tick(140)
        self.assertGreater(self.engine.totals['m2_blocks'], 0)
        self.assertLess(self.engine.vehicles['V07'].reputation, .2)
        self.assertGreater(self.engine.reasons['M2_TEMP_BLOCK'], 0)
        self.assertGreater(self.engine.reasons['RATE_LIMIT'], 0)

    def test_m1_static_rule_blocks_flood(self):
        self.engine.upsert_rule({'label':'Security rule','source':'V07','traffic':'UDP_FLOOD','rsu':'*',
                                 'priority':900,'action':'DROP','enabled':True})
        self.engine.set_scenario('flood')
        self.tick(25)
        self.assertGreater(self.engine.reasons['M1_STATIC_DROP'], 0)

    def test_disabling_m1_bypasses_rule(self):
        self.engine.upsert_rule({'label':'Security rule','source':'V07','traffic':'UDP_FLOOD','rsu':'*',
                                 'priority':900,'action':'DROP','enabled':True})
        self.engine.set_config({'m1_enabled':False})
        self.engine.set_scenario('flood')
        self.tick(25)
        self.assertEqual(self.engine.reasons['M1_STATIC_DROP'], 0)

    def test_disabling_m2_prevents_flood_stage2(self):
        self.engine.set_config({'m2_enabled':False})
        self.engine.set_scenario('flood')
        self.tick(100)
        self.assertEqual(self.engine.totals['m2_blocks'], 0)

    def test_disabling_m3_prevents_reputation_loss(self):
        self.engine.set_config({'m3_enabled':False})
        self.engine.set_scenario('misinformation')
        self.tick(80)
        self.assertEqual(self.engine.vehicles['V07'].reputation, 1)

    def test_static_priority_first_match(self):
        self.engine.upsert_rule({'label':'Allow low','source':'V07','traffic':'UDP_FLOOD','rsu':'*',
                                 'priority':100,'action':'ALLOW','enabled':True})
        self.engine.upsert_rule({'label':'Block high','source':'V07','traffic':'UDP_FLOOD','rsu':'*',
                                 'priority':900,'action':'DROP','enabled':True})
        rule=self.engine._matching_static_rule('V07','UDP_FLOOD','RSU-2')
        self.assertEqual(rule['action'],'DROP')

    def test_static_match_rsu_specific(self):
        self.engine.upsert_rule({'label':'AP1 only','source':'V07','traffic':'*','rsu':'RSU-1',
                                 'priority':900,'action':'DROP','enabled':True})
        self.assertIsNone(self.engine._matching_static_rule('V07','SAFETY','RSU-2'))

    def test_edit_and_delete_rule(self):
        state=self.engine.upsert_rule({'label':'test','source':'*','traffic':'*','rsu':'*',
                                       'priority':400,'action':'METER','rate_kbps':150,'enabled':True})
        rid=state['rules'][-1]['id']
        self.engine.upsert_rule({'label':'updated','source':'*','traffic':'*','rsu':'*',
                                 'priority':400,'action':'ALLOW','enabled':False},rid)
        self.assertEqual(self.engine.rules[-1]['label'],'updated')
        self.engine.delete_rule(rid)
        self.assertFalse(any(r['id']==rid for r in self.engine.rules))

    def test_invalid_rule_fields_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.upsert_rule({'source':'UNKNOWN','traffic':'*','rsu':'*','action':'DROP','enabled':True})
        with self.assertRaises(ValueError):
            self.engine.upsert_rule({'source':'*','traffic':'*','rsu':'*','action':'METER','rate_kbps':-5,'enabled':True})

    def test_invalid_configuration_rejected(self):
        with self.assertRaises(ValueError):self.engine.set_config({'base_pps':-1})
        with self.assertRaises(ValueError):self.engine.set_config({'flood_pps':100000})
        with self.assertRaises(ValueError):self.engine.set_config({'m3_enabled':'yes'})

    def test_scenario_validated(self):
        with self.assertRaises(ValueError):self.engine.set_scenario('imaginary')
        with self.assertRaises(ValueError):self.engine.set_scenario('flood',attacker='V01',victim='V01')

    def test_pause_prevents_motion_and_packets(self):
        self.engine.set_running(False)
        x=self.engine.vehicles['V01'].x
        self.tick(50)
        self.assertEqual(self.engine.vehicles['V01'].x,x)
        self.assertEqual(self.engine.totals['sent'],0)

    def test_speed_factor_changes_simulated_time(self):
        self.engine.set_speed(4)
        self.tick(5)
        self.assertAlmostEqual(self.engine.t,5 * .1 * 4)

    def test_reset_keeps_rules_and_settings(self):
        self.engine.set_config({'base_pps':200})
        self.engine.upsert_rule({'label':'custom','source':'*','traffic':'*','rsu':'*',
                                 'priority':750,'action':'DROP','enabled':True})
        self.engine.set_scenario('combined')
        self.tick(50)
        self.engine.reset()
        self.assertEqual(self.engine.t,0)
        self.assertEqual(self.engine.config['base_pps'],200)
        self.assertTrue(any(r['label']=='custom' for r in self.engine.rules))

    def test_no_route_when_outside_radio(self):
        v=self.engine.vehicles['V07'];v.rsu=None
        p,link=self.engine._route('V07','RSU-1')
        self.assertEqual(p,[])
        self.assertIsNone(link)

    def test_report_is_labelled_simulation(self):
        self.tick(20)
        report=self.engine.simulation_report()
        self.assertEqual(report['metadata']['mode'],'simulation')
        self.assertIn('history',report)

    def test_reputation_policy_thresholds(self):
        self.assertEqual(reputation_policy(1),(None,'NORMAL'))
        self.assertEqual(reputation_policy(.65),(None,'MONITOR'))
        self.assertEqual(reputation_policy(.52),(500,'LIGHT_THROTTLE'))
        self.assertEqual(reputation_policy(.34),(200,'HEAVY_THROTTLE'))
        self.assertEqual(reputation_policy(.04),(100,'SEVERE_THROTTLE'))

    def test_safety_displacement_validity(self):
        v=self.engine.vehicles['V05']
        v.last_report={'vehicle_id':'V05','timestamp':1.0,'x':100,'y':100,'speed_kmh':30}
        good,reason=self.engine._check_safety_message(v,{'vehicle_id':'V05','timestamp':1.5,'x':104,'y':105,'speed_kmh':30})
        self.assertTrue(good)
        bad,reason=self.engine._check_safety_message(v,{'vehicle_id':'V05','timestamp':1.5,'x':1000,'y':1000,'speed_kmh':30})
        self.assertFalse(bad)
        self.assertEqual(reason,'Implausible vehicle displacement')


if __name__=='__main__': unittest.main()
