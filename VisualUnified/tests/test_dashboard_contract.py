"""Presentation contracts; no browser, switch or privileged process required."""

from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

from engine import SimEngine


STATIC = Path(__file__).resolve().parents[1] / 'static'


class _Ids(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        self.ids.update(value for key, value in attrs if key == 'id')


class DashboardContractTests(unittest.TestCase):
    def test_script_references_existing_dashboard_elements(self):
        parser = _Ids()
        parser.feed((STATIC / 'index.html').read_text(encoding='utf-8'))
        script = (STATIC / 'app.js').read_text(encoding='utf-8')
        references = set(re.findall(r"\$\('([A-Za-z][A-Za-z0-9]*)'\)", script))
        self.assertFalse(references - parser.ids, references - parser.ids)

    def test_current_static_rule_identity_is_exposed_without_changing_policy(self):
        sim = SimEngine()
        sim.upsert_rule({'label': 'Dashboard probe', 'source': 'V07',
                         'traffic': 'UDP_FLOOD', 'rsu': '*', 'priority': 950,
                         'action': 'DROP', 'enabled': True})
        state = sim.status()
        rule = next(rule for rule in state['rules'] if rule['label'] == 'Dashboard probe')
        selected = next(item for item in state['runtime_policies'] if item['vehicle'] == 'V07')
        self.assertEqual(selected['static_rule_id'], rule['id'])
        self.assertEqual(selected['static_action'], 'DROP')
        self.assertEqual(selected['effective_udp_action'], 'DROP')
        self.assertEqual(sim.totals['sent'], 0)

    def test_default_guided_scenario_has_observable_detection_block_and_recovery(self):
        sim = SimEngine(seed=14)
        for _ in range(50):
            sim.step(.1)
        sim.set_scenario('flood', attacker='V07', victim='V02')
        seen_meter = False
        seen_block = False
        for _ in range(450):
            sim.step(.1)
            stage = sim.status()['vehicles'][6]['m2_state']
            seen_meter |= stage == 'METER'
            if stage == 'BLOCK':
                seen_block = True
                break
        self.assertTrue(seen_meter)
        self.assertTrue(seen_block)
        sim.set_scenario('normal')
        for _ in range(400):
            sim.step(.1)
            if sim.vehicles['V07'].m2_stage == 'NORMAL':
                break
        self.assertEqual(sim.vehicles['V07'].m2_stage, 'NORMAL')
        self.assertGreater(sim.totals['legitimate_delivered'], 0)


if __name__ == '__main__':
    unittest.main()
