import json
import threading
import tempfile
import sys
import os
import subprocess
from unittest.mock import patch
from contextlib import redirect_stderr
import io
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import run


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.old_engine, self.old_settings = run.ENGINE, run.SETTINGS
        self.settings_dir = tempfile.TemporaryDirectory()
        run.ENGINE = run.SimEngine()
        run.SETTINGS = Path(self.settings_dir.name) / 'controller_settings.json'

    def tearDown(self):
        run.ENGINE, run.SETTINGS = self.old_engine, self.old_settings
        self.settings_dir.cleanup()

    @classmethod
    def setUpClass(cls):
        cls.server=run.LocalHTTPServer(('127.0.0.1',0),run.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.port=cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method,path,payload=None,content_type='application/json'):
        client=HTTPConnection('127.0.0.1',self.port,timeout=5)
        data=json.dumps(payload).encode() if payload is not None else None
        client.request(method,path,body=data,headers={'Content-Type':content_type})
        r=client.getresponse()
        body=r.read(); status=r.status; ctype=r.getheader('Content-Type')
        client.close()
        return status,body,ctype

    def test_static_assets(self):
        for path in ['/','/styles.css','/app.js']:
            status,body,ctype=self.request('GET',path)
            self.assertEqual(status,200)
            self.assertGreater(len(body),100)

    def test_live_state_contract(self):
        status,body,_=self.request('GET','/api/state')
        self.assertEqual(status,200)
        state=json.loads(body)
        for key in ['vehicles','rsus','rules','runtime_policies','history','stats','events','mobility_mode']:
            self.assertIn(key,state)

    def test_scenario_and_report_export(self):
        status,body,_=self.request('POST','/api/scenario',{'scenario':'combined','attacker':'V07','victim':'V02'})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['scenario'],'combined')
        status,body,ctype=self.request('GET','/api/report')
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['metadata']['mode'],'simulation')

    def test_rule_post_and_toggle(self):
        data={'label':'API rule','source':'V07','traffic':'UDP_FLOOD','rsu':'*',
              'priority':950,'action':'DROP','enabled':True}
        status,body,_=self.request('POST','/api/rules',data)
        self.assertEqual(status,200)
        rid=next(r['id'] for r in json.loads(body)['rules'] if r['label']=='API rule')
        status,body,_=self.request('POST',f'/api/rules/{rid}/toggle',{})
        self.assertEqual(status,200)
        r=next(r for r in json.loads(body)['rules'] if r['id']==rid)
        self.assertFalse(r['enabled'])
        self.request('POST','/api/rules-delete',{'id':rid})

    def test_error_paths(self):
        status,body,_=self.request('POST','/api/config',{'base_pps':-123})
        self.assertEqual(status,400)
        status,body,_=self.request('GET','/api/unknown')
        self.assertEqual(status,404)
        status,body,_=self.request('POST','/api/run',{'running':'maybe'})
        self.assertEqual(status,400)

    def test_unsupported_mobility_mode(self):
        status,body,_=self.request('POST','/api/mobility',{'mode':'spaceflight'})
        self.assertEqual(status,400)

    def test_rejected_updates_leave_state_and_profile_unchanged(self):
        initial = run.ENGINE.status()
        status, _, _ = self.request('POST', '/api/config', {'base_pps': 150, 'bogus': 1})
        self.assertEqual(status, 400)
        self.assertEqual(run.ENGINE.config, initial['config'])
        status, _, _ = self.request('POST', '/api/scenario',
                                    {'scenario': 'flood', 'attacker': 'V02'})
        self.assertEqual(status, 400)
        self.assertEqual(run.ENGINE.attacker, initial['attacker'])
        self.assertFalse(run.SETTINGS.exists())

    def test_control_endpoints_and_preview_have_no_persistence_side_effect(self):
        before=run.ENGINE.status()
        for path,key in (('/api/flows','flows'),('/api/events','events')):
            status,body,_=self.request('GET',path)
            self.assertEqual(status,200);self.assertIn(key,json.loads(body))
        status,body,_=self.request('POST','/api/policy-preview',dict(source_ip='10.0.0.7',destination_ip='10.0.0.2',protocol='UDP',src_port=40007,dst_port=9999,size=1024))
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['action'],'ALLOW')
        status,body,_=self.request('POST','/api/rules-analyze',dict(source='V07',action='DROP'))
        self.assertEqual(status,200);self.assertIn('warnings',json.loads(body))
        self.assertFalse(run.SETTINGS.exists())
        self.assertEqual(run.ENGINE.status(),before)

    def test_combined_trial_flow_counters_and_timeline_over_local_http(self):
        self.request('POST','/api/scenario',dict(scenario='combined'))
        for _ in range(140):run.ENGINE.step(.1)
        status,body,_=self.request('GET','/api/state')
        snapshot=json.loads(body)
        self.assertEqual(status,200)
        rows={r['id']:r for r in snapshot['flow_table']}
        self.assertGreater(rows['m2-block:V07']['match_count'],0)
        self.assertGreater(rows['m3-meter:V07']['match_count'],0)
        self.assertEqual(snapshot['decision_inspector']['V07']['last_packet']['scope'],'actual simulated packet')
        self.assertTrue(any(e['kind']=='M3 · INVALID' and e['vehicle']=='V07' for e in snapshot['controller_events']))

    def test_advanced_rule_persists_and_reloads_with_defaults_for_legacy_rules(self):
        fields=dict(label='IPv4 match',source='V07',destination='V02',protocol='UDP',
                    source_ip='10.0.0.7',destination_ip='10.0.0.2',src_port=40007,dst_port=9999,action='METER',rate_kbps=200)
        status,body,_=self.request('POST','/api/rules',fields)
        self.assertEqual(status,200)
        saved=json.loads(run.SETTINGS.read_text())
        run.ENGINE=run.SimEngine();run.load_profile()
        rule=next(r for r in run.ENGINE.rules if r['label']=='IPv4 match')
        for name,value in fields.items():self.assertEqual(rule[name],value)
        self.assertEqual(len(saved['rules']),len(run.ENGINE.rules))
        self.assertEqual(next(r for r in run.ENGINE.rules if r['id']=='rule-example')['destination'],'*')

    def test_profile_failure_rolls_back_controller_and_preserves_saved_file(self):
        self.request('POST','/api/rules',dict(source='V07',action='DROP'))
        before=run.ENGINE.status();saved=run.SETTINGS.read_bytes()
        with patch.object(run,'save_profile',side_effect=OSError('simulated disk failure')):
            status,body,_=self.request('POST','/api/rules',dict(source='V08',action='DROP'))
        self.assertEqual(status,500);self.assertIn('rolled back',json.loads(body)['error'])
        self.assertEqual(run.ENGINE.status(),before)
        self.assertEqual(run.SETTINGS.read_bytes(),saved)

    def test_invalid_preview_and_protected_rule_fields_are_rejected(self):
        for path,data in (('/api/policy-preview',dict(source_ip='not-an-ip')),
                          ('/api/rules',dict(origin='M2',action='DROP')),
                          ('/api/rules-analyze',dict(priority=1.5))):
            status,body,_=self.request('POST',path,data)
            self.assertEqual(status,400);self.assertIn('error',json.loads(body))
        self.assertFalse(run.SETTINGS.exists())

    def test_duplicate_saved_ids_do_not_partially_apply_configuration(self):
        profile={'config':{'base_pps':300},'rules':[dict(id='duplicate',action='DROP'),dict(id='duplicate',action='ALLOW')]}
        run.SETTINGS.write_text(json.dumps(profile))
        run.load_profile()
        self.assertEqual(run.ENGINE.config['base_pps'],120)
        self.assertEqual(run.ENGINE.m2_config.base_threshold_pps,120)
        self.assertEqual(len(run.ENGINE.rules),1)

    def test_concurrent_changes_persist_one_complete_snapshot(self):
        with ThreadPoolExecutor(max_workers=5) as pool:
            responses = list(pool.map(lambda i: self.request('POST', '/api/rules', {
                'label': f'Concurrent {i}', 'source': 'V07', 'action': 'DROP',
                'traffic': 'UDP_FLOOD', 'priority': 500, 'enabled': True}), range(10)))
        self.assertTrue(all(status == 200 for status, _, _ in responses))
        profile = json.loads(run.SETTINGS.read_text(encoding='utf-8'))
        self.assertEqual(profile['rules'], run.ENGINE.status()['rules'])
        self.assertEqual(len({r['id'] for r in profile['rules']}), 11)

    def test_concurrent_edits_persist_one_whole_revision(self):
        _,body,_=self.request('POST','/api/rules',dict(source='V07',action='ALLOW'))
        rid=json.loads(body)['rules'][-1]['id']
        changes=[dict(source='V07',destination='V02',protocol='UDP',dst_port=9000+i,
                      priority=600+i,action='METER',rate_kbps=200+i) for i in range(5)]
        with ThreadPoolExecutor(max_workers=5) as pool:
            responses=list(pool.map(lambda data:self.request('POST',f'/api/rules/{rid}',data),changes))
        self.assertTrue(all(status==200 for status,_,_ in responses))
        rule=next(r for r in run.ENGINE.rules if r['id']==rid)
        self.assertIn((rule['priority'],rule['dst_port'],rule['rate_kbps']),[(r['priority'],r['dst_port'],r['rate_kbps']) for r in changes])
        self.assertEqual(json.loads(run.SETTINGS.read_text())['rules'],run.ENGINE.rules)

    def test_worker_stops_without_advancing_after_stop(self):
        stop = threading.Event()
        stop.set()
        worker = threading.Thread(target=run.run_engine, args=(stop,))
        worker.start()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(run.ENGINE.t, 0)

    def test_busy_port_fails_main_before_starting_worker(self):
        with patch.object(sys, 'argv', ['run.py', '--no-browser', '--port', str(self.port)]), \
             patch.object(run.threading, 'Thread') as thread, \
             redirect_stderr(io.StringIO()) as error:
            with self.assertRaises(SystemExit) as exit_error:
                run.main()
        self.assertEqual(exit_error.exception.code, 2)
        self.assertIn('Could not start local server', error.getvalue())
        thread.assert_not_called()

    def test_launcher_forwards_options_and_uses_its_directory(self):
        launcher = (run.BASE / 'START_WINDOWS.bat').read_text()
        self.assertIn('cd /d "%~dp0"', launcher)
        self.assertIn('py -3 run.py %*', launcher)
        self.assertIn('python run.py %*', launcher)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows batch launcher')
    def test_launcher_runs_help_with_an_available_python(self):
        command_processor = os.environ.get('ComSpec', r'C:\Windows\System32\cmd.exe')
        result = subprocess.run([command_processor, '/c', str(run.BASE / 'START_WINDOWS.bat'), '--help'],
                                cwd=run.BASE.parent, input='\n', text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('MarsVanet unified visual simulator', result.stdout)
        self.assertIn('--port', result.stdout)


if __name__=='__main__': unittest.main()
