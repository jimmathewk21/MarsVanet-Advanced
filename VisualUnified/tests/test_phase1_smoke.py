import unittest
from smoke_phase1 import run_smoke


class Phase1SmokeTests(unittest.TestCase):
    def test_twelve_vehicle_normal_and_combined_runs(self):
        report=run_smoke()
        self.assertEqual(report['status'],'PASS')
        for run in report['runs']:
            self.assertEqual(run['vehicle_count'],12)
            self.assertEqual(run['simulated_seconds'],145)
            self.assertEqual([p['start_s'] for p in run['phases']],[0,5,25])
            for phase in run['phases']:
                self.assertEqual(phase['generated'],phase['received']+phase['dropped'])
            self.assertEqual(run['final_attacker_m2'],'NORMAL')


if __name__=='__main__':unittest.main()
