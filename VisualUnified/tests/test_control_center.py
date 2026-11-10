"""Authoritative simulated flow execution and pure preview regression checks."""
from copy import deepcopy
import pickle
import unittest
from unittest.mock import patch

from engine import SimEngine
from control_center import NODE_IPS, packet_for, analyze_rules
from methodology import md


class ControlCenterTests(unittest.TestCase):
    def setUp(self):
        self.sim=SimEngine(seed=14)
        self.sim.config['loss_probability']=0
        self.v=self.sim.vehicles['V07']
        self.packet=dict(source_ip='10.0.0.7',destination_ip='10.0.0.2',protocol='UDP',src_port=40007,dst_port=9999,size=1024)

    def install(self,**kwargs):
        before={r['id'] for r in self.sim.rules}
        self.sim.upsert_rule(dict(source='V07',traffic='UDP_FLOOD',action='DROP',priority=800,**kwargs))
        return next(r['id'] for r in self.sim.rules if r['id'] not in before)

    def fingerprint(self):
        return pickle.dumps({k:v for k,v in vars(self.sim).items() if k not in ('lock','sumo_bridge')})

    def meter(self):
        self.v.m2_stage='METER';self.v.meter_expires=100;self.v.m2_next_poll=100

    def test_advanced_fields_match_real_packet_path(self):
        rid=self.install(destination='V02',source_ip=NODE_IPS['V07'],destination_ip=NODE_IPS['V02'],
                         protocol='UDP',src_port=40007,dst_port=9999)
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        self.sim._send('V07','V03','UDP_FLOOD',1024)
        self.sim._send('V08','V02','UDP_FLOOD',1024)
        self.sim._send('V07','V02','TELEMETRY',420)
        self.assertEqual(self.sim.reasons['M1_STATIC_DROP'],1)
        self.assertEqual(self.sim.flow_stats[rid]['match_count'],1)
        self.assertEqual(len(self.v.rate_tracker),1)

    def test_rule_hits_are_not_inferred_from_snapshots_or_animation(self):
        rid=self.install()
        for _ in range(7):self.sim._send('V07','V02','UDP_FLOOD',1024)
        before=deepcopy(self.sim.flow_stats)
        for _ in range(5):self.sim.status()
        self.assertEqual(self.sim.flow_stats,before)
        self.assertEqual(before[rid]['match_count'],7)
        self.assertEqual(before[rid]['last_matched'],0)
        self.assertNotIn('m2-meter:V07',before)

    def test_read_only_preview_and_draft_do_not_mutate_any_engine_state(self):
        self.meter();self.v.reputation=.1
        self.install()
        before=self.fingerprint()
        preview=self.sim.preview_packet(self.packet)
        draft=self.sim.analyze_rule(dict(source='V07',traffic='UDP_FLOOD',action='ALLOW'))
        self.assertEqual(preview['action'],'DROP')
        self.assertTrue(draft['warnings'])
        self.assertEqual(self.fingerprint(),before)
        self.assertTrue(self.sim.preview_packet(dict(self.packet,source_ip='192.0.2.1'))['action']=='ALLOW')

    def test_duplicate_shadow_conflict_and_ties_are_deterministic(self):
        rid=self.install()
        duplicate=self.sim.analyze_rule(dict(source='V07',traffic='UDP_FLOOD',action='DROP',priority=700))
        self.assertTrue(any(w['kind']=='duplicate' for w in duplicate['warnings']))
        conflicting=self.sim.analyze_rule(dict(source='V07',traffic='UDP_FLOOD',action='ALLOW',priority=700))
        self.assertTrue(any(w['kind']=='shadowed' and w['conflict'] for w in conflicting['warnings']))
        self.sim.upsert_rule(dict(source='V07',traffic='UDP_FLOOD',action='ALLOW',priority=800))
        self.assertEqual(self.sim.preview_packet(self.packet)['selected_static_rule'],rid)
        partial=self.sim.analyze_rule(dict(source='*',destination='V02',action='ALLOW'))
        self.assertTrue(any(w['kind']=='overlap' and w['conflict'] for w in partial['warnings']))

    def test_allow_cannot_bypass_block_and_safety_exemption_is_explicit(self):
        self.sim.upsert_rule(dict(source='V07',action='ALLOW',priority=999))
        self.v.blocked_until=100;self.v.m2_stage='BLOCK';self.v.reputation=.1
        plan=self.sim.preview_packet(self.packet)
        self.assertEqual((plan['action'],plan['deciding_rule']),('DROP','m2-block:V07'))
        safety=self.sim.preview_packet(dict(self.packet,destination_ip='10.0.1.2',dst_port=5005,size=220))
        self.assertEqual(safety['action'],'ALLOW');self.assertEqual(safety['meters'],[])
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        self.assertEqual(self.sim.flow_stats['m2-block:V07']['match_count'],1)
        self.assertNotIn('m3-meter:V07',self.sim.flow_stats)

    def test_explicit_static_safety_drop_stops_observation_and_warns(self):
        self.sim.upsert_rule(dict(source='V07',traffic='SAFETY',action='DROP'))
        self.sim._send_safety(self.v,True)
        self.assertEqual(self.v.reputation,1)
        self.assertTrue(any(w['kind']=='safety' for w in self.sim.status()['rule_warnings']))
        self.assertEqual(self.sim.totals['observed_safety'],0)

    def test_static_allow_does_not_bypass_safety_parser_or_double_observe_peer_copy(self):
        self.sim.upsert_rule(dict(source='V07',action='ALLOW'))
        self.meter();self.v.reputation=.3
        self.sim._send_safety(self.v,True)
        self.assertAlmostEqual(self.v.reputation,.14)
        self.assertEqual(self.sim.totals['observed_safety'],1)
        self.assertEqual(self.sim.totals['invalid_safety'],1)

    def test_multiple_meters_account_once_and_report_actual_exhausted_owner(self):
        self.sim.upsert_rule(dict(source='V07',traffic='UDP_FLOOD',action='METER',rate_kbps=700))
        rid=self.sim.rules[-1]['id'];self.meter();self.v.reputation=.1
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        self.assertEqual(self.sim.flow_stats[rid]['match_count'],1)
        self.assertEqual(self.sim.flow_stats['m2-meter:V07']['match_count'],1)
        self.assertEqual(self.sim.flow_stats['m3-meter:V07']['match_count'],1)
        self.v.meter_buckets[('m1',rid)]['tokens']=0
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        actual=self.sim.last_decisions['V07']
        self.assertEqual(actual['outcome'],'RATE_LIMIT')
        self.assertEqual(actual['deciding_rule'],rid)
        self.assertEqual(actual['meter_rate_kbps'],100)

    def test_edit_and_delete_only_reset_own_static_counters_and_budgets(self):
        self.sim.upsert_rule(dict(source='V07',traffic='UDP_FLOOD',action='METER',rate_kbps=500))
        rid=self.sim.rules[-1]['id'];self.v.reputation=.1
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        dynamic=deepcopy(self.v.meter_buckets[('m3','m3')])
        self.sim.upsert_rule(dict(source='V07',traffic='UDP_FLOOD',action='ALLOW'),rid)
        self.assertNotIn(rid,self.sim.flow_stats)
        self.assertNotIn(('m1',rid),self.v.meter_buckets)
        self.assertEqual(self.v.meter_buckets[('m3','m3')],dynamic)
        self.sim.delete_rule(rid)
        self.assertEqual(self.v.reputation,.1)
        self.assertEqual(self.v.meter_buckets[('m3','m3')],dynamic)

    def test_expiry_recovery_retains_other_vehicle_and_static_state(self):
        self.sim.upsert_rule(dict(source='V08',action='DROP'))
        rid=self.sim.rules[-1]['id'];self.v.m2_stage='BLOCK';self.v.blocked_until=30
        self.v.detector.stage=md.STAGE_BLOCK;self.v.detector.blocked_at=0
        self.v.reputation=.1
        other=self.sim.vehicles['V08'];other.reputation=.2
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        self.sim.t=31;self.sim._detect_attack(self.v)
        self.assertEqual(self.v.m2_stage,'NORMAL')
        self.assertEqual(other.reputation,.2)
        self.assertTrue(any(r['id']==rid for r in self.sim.rules))
        self.assertEqual(self.v.reputation,.1)
        retired=next(f for f in self.sim.flow_table() if f['id']=='m2-block:V07')
        self.assertFalse(retired['active']);self.assertEqual(retired['match_count'],1)

    def test_handover_does_not_reset_policy_counters_or_reputation(self):
        self.meter();self.v.reputation=.1
        self.sim._send('V07','V02','UDP_FLOOD',1024)
        count=self.sim.flow_stats['m3-meter:V07']['match_count']
        self.v.x,self.v.y,self.v.rsu=300,218,'RSU-1';self.sim._associate()
        self.v.x=825;self.sim._associate()
        self.assertEqual(self.sim.flow_stats['m3-meter:V07']['match_count'],count)
        self.assertEqual(self.v.reputation,.1)
        self.assertEqual(self.sim.preview_packet(self.packet)['meter_rate_kbps'],100)

    def test_timeline_is_bounded_unique_structured_and_clears_on_reset_only(self):
        self.sim.set_scenario('combined')
        self.sim._observe_reputation(self.v,True,'impossible displacement',1)
        self.assertTrue(any(e['vehicle']=='V07' and e['kind']=='M3 · INVALID' for e in self.sim.events))
        for _ in range(220):self.sim._event('SYSTEM','bounded')
        self.assertEqual(len(self.sim.events),180)
        ids=[e['id'] for e in self.sim.events]
        self.assertEqual(len(set(ids)),180);self.assertEqual(ids,sorted(ids,reverse=True))
        self.assertTrue(all('origin' in e and 'details' in e for e in self.sim.events))
        self.sim.reset();self.assertFalse(self.sim.flow_stats);self.assertFalse(self.sim.last_decisions)

    def test_invalid_fields_are_atomic_and_protected_state_is_not_editable(self):
        for fields in (dict(priority=True),dict(priority=1.5),dict(dst_port=65536),dict(source_ip='bad'),
                       dict(protocol='ICMP',dst_port=99),dict(origin='M2'),dict(match_count=999),dict(destination='V99')):
            before=self.fingerprint()
            with self.subTest(fields=fields),self.assertRaises(ValueError):self.sim.upsert_rule(fields)
            self.assertEqual(self.fingerprint(),before)
        with self.assertRaises(ValueError):self.sim.upsert_rule({},'m2-block:V07')
        with self.assertRaises(ValueError):self.sim._validated_rule({'id':'m2-block:V07'},'m2-block:V07')
        for data in (dict(self.packet,size=True),dict(self.packet,dst_port=-1),dict(self.packet,protocol='SCTP'),dict(self.packet,source_ip='10.0.0.1/24')):
            with self.assertRaises(ValueError):self.sim.preview_packet(data)

    def test_disabled_gate_and_unsupported_protocol_are_honest(self):
        self.sim.upsert_rule(dict(source='V07',protocol='TCP',action='DROP'))
        self.assertEqual(self.sim.preview_packet(self.packet)['action'],'ALLOW')
        self.assertEqual(self.sim.preview_packet(dict(self.packet,protocol='TCP'))['action'],'DROP')
        self.assertTrue(any(w['kind']=='unsupported-offered-traffic' for w in analyze_rules(self.sim.rules)))
        self.sim.set_config({'m1_enabled':False})
        self.assertEqual(self.sim.preview_packet(dict(self.packet,protocol='TCP'))['action'],'ALLOW')
        self.assertFalse(next(f for f in self.sim.flow_table() if f['id']==self.sim.rules[-1]['id'])['active'])

    def test_conflict_analysis_is_bounded_but_draft_checks_remain_focused(self):
        rules=[self.sim._validated_rule(dict(source='V07',traffic='UDP_FLOOD',action='DROP'),f'rule-{i}') for i in range(100)]
        warnings=analyze_rules(rules)
        self.assertEqual(len(warnings),257)
        self.assertEqual(warnings[-1]['kind'],'limit')
        focused=analyze_rules(rules,focus='rule-99')
        self.assertEqual(len(focused),99)
        self.assertTrue(all('rule-99' in (w['rule_id'],w['other_id']) for w in focused))


if __name__=='__main__':unittest.main()
