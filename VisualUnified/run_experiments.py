"""Reproducible, instrumented SIMULATION_ONLY studies. No dashboard/settings IO.

Run from VisualUnified: python run_experiments.py --output experiments/study-v1
The subclass observes the existing engine; it does not replace its policies.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import csv
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import platform
import sys
from xml.sax.saxutils import escape

try:
    from .engine import SimEngine, DEFAULT_CONFIG, reputation_policy
except ImportError:
    from engine import SimEngine, DEFAULT_CONFIG, reputation_policy

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from benchmark.core import confidence_interval_95


# Preserve the older run_comparison.py interface and its six-profile CSV.
PROFILES = {
    'no_defense': (False, False, False, False),
    'm1_only': (True, False, False, True),
    'm2_only': (False, True, False, False),
    'm3_only': (False, False, True, False),
    'unified_dynamic': (True, True, True, False),
    'unified_static': (True, True, True, True),
}
SCENARIOS = ('normal', 'flood', 'combined')
PHASES = ('baseline', 'attack', 'recovery')
CLASSES = ('benign', 'malicious_flood', 'malicious_safety')
COUNT_FIELDS = ('generated', 'received', 'dropped', 'rate_limited', 'policy_dropped',
                'generated_bytes', 'received_bytes', 'controller_generated', 'controller_received')
PACKET_FIELDS = ('sequence', 'time', 'phase', 'source', 'destination', 'traffic',
                 'ground_truth', 'bytes', 'received', 'reason', 'drop_owner', 'link')


@dataclass(frozen=True)
class StudySpec:
    seeds: tuple[int, ...] = (14, 15, 16, 17, 18)
    scenarios: tuple[str, ...] = SCENARIOS
    baseline_seconds: float = 10.0
    attack_seconds: float = 20.0
    recovery_seconds: float = 150.0
    step_seconds: float = .1
    attacker: str = 'V07'
    victim: str = 'V02'

    def validate(self):
        if not self.seeds or len(set(self.seeds)) != len(self.seeds):
            raise ValueError('Seeds must be nonempty and unique independent trial identifiers')
        if len(self.seeds) > 31:
            raise ValueError('At most 31 seeds are supported by the reused Student-t critical-value table')
        if any(type(seed) is not int or seed < 0 for seed in self.seeds):
            raise ValueError('Seeds must be nonnegative integers')
        if not self.scenarios or len(set(self.scenarios)) != len(self.scenarios) or any(
                name not in SCENARIOS for name in self.scenarios):
            raise ValueError('Choose unique scenarios from normal, flood, combined')
        for duration in (self.baseline_seconds, self.attack_seconds, self.recovery_seconds):
            if not math.isfinite(duration) or not 0 < duration <= 600:
                raise ValueError('Each phase duration must be finite and in (0, 600]')
            if abs(duration * 10 - round(duration * 10)) > 1e-7:
                raise ValueError('Durations must be multiples of the 0.1-second engine step')
        if self.step_seconds != .1:
            raise ValueError('This study fixes the observation step at 0.1 seconds')
        ids = {f'V{i:02}' for i in range(1, 13)}
        if self.attacker not in ids or self.victim not in ids or self.attacker == self.victim:
            raise ValueError('Attacker and victim must be distinct modeled vehicles')

    @property
    def attack_end(self):
        return self.baseline_seconds + self.attack_seconds

    @property
    def end(self):
        return self.attack_end + self.recovery_seconds


def metric(value=None, explanation=None):
    if value is None and not explanation:
        raise ValueError('Missing metrics require an explanation')
    return {'value': value, 'explanation': explanation}


def ratio(numerator, denominator):
    return metric(100 * numerator / denominator) if denominator else metric(
        explanation='No generated packets in this class/window.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def run_id(profile, scenario, seed, spec):
    spec.validate()
    if profile not in PROFILES or scenario not in spec.scenarios or seed not in spec.seeds:
        raise ValueError('Unknown experiment matrix entry')
    digest = hashlib.sha256(canonical(asdict(spec)).encode()).hexdigest()[:12]
    return f'{scenario}__{profile}__seed-{seed}__{digest}'


def matrix(spec):
    spec.validate()
    return [(profile, scenario, seed) for scenario in spec.scenarios
            for seed in spec.seeds for profile in PROFILES]


class EvidenceEngine(SimEngine):
    """Passive, complete packet and decision accounting for the existing engine."""

    def __init__(self, spec, seed, packet_sink=None, state_sink=None):
        self.spec = spec
        self.phase = 'baseline'
        self.injected_safety = False
        self.packet_sink, self.state_sink = packet_sink, state_sink
        self.counts = defaultdict(Counter)
        self.reason_counts = defaultdict(Counter)
        self.all_events, self.decisions, self.transitions = [], [], []
        self.first_drop = {}
        self.alerts = defaultdict(set)
        self.restricted_sources = defaultdict(set)
        self.durations = Counter()
        self.offered_hash, self.mobility_hash = hashlib.sha256(), hashlib.sha256()
        self.sequence = 0
        self.meter_seen = Counter()
        super().__init__(seed=seed, mobility_model='legacy')
        self.previous_policy = self.policy_snapshot()

    def policy_snapshot(self):
        return {v.id: (v.m2_stage if self.config['m2_enabled'] else 'DISABLED',
                       reputation_policy(v.reputation)[1] if self.config['m3_enabled'] else 'DISABLED')
                for v in self.vehicles.values()}

    def _event(self, kind, msg, level='info', **context):
        super()._event(kind, msg, level, **context)
        self.all_events.append(dict(self.events[0], time=round(self.t, 9), phase=self.phase))

    def _send_safety(self, v, is_misinfo, timestamp=None):
        previous = self.injected_safety
        self.injected_safety = bool(is_misinfo)
        try:
            return super()._send_safety(v, is_misinfo, timestamp)
        finally:
            self.injected_safety = previous

    def _observe_reputation(self, v, bad, reason='invalid report', severity=1.0):
        if self.config['m3_enabled']:
            self.decisions.append({'time': round(self.t, 9), 'phase': self.phase,
                                   'vehicle': v.id, 'consistent': not bad, 'reason': reason,
                                   'severity': severity, 'injected_malicious': self.injected_safety,
                                   'reputation_before': v.reputation})
            if bad:
                self.alerts[(self.phase, 'm3')].add(v.id)
        super()._observe_reputation(v, bad, reason, severity)
        if self.config['m3_enabled']:
            self.decisions[-1]['reputation_after'] = v.reputation

    def _detect_attack(self, v, observe=False):
        before = v.m2_stage
        super()._detect_attack(v, observe)
        if before != 'METER' and v.m2_stage == 'METER':
            self.alerts[(self.phase, 'm2')].add(v.id)

    def _record_packet(self, src, dst, traffic, size, delivered, reason, route, link, meter):
        truth = ('malicious_flood' if traffic == 'UDP_FLOOD' else
                 'malicious_safety' if traffic == 'SAFETY' and self.injected_safety else 'benign')
        owner = ''
        for name in ('m1', 'm2', 'm3'):
            current = self.totals[f'{name}_meter_drops']
            if reason == 'RATE_LIMIT' and current > self.meter_seen[name]:
                owner = name
            self.meter_seen[name] = current
        if reason == 'M1_STATIC_DROP': owner = 'm1'
        if reason == 'M2_TEMP_BLOCK': owner = 'm2'
        self.sequence += 1
        packet = dict(zip(PACKET_FIELDS, (self.sequence, round(self.t, 9), self.phase, src, dst,
                      traffic, truth, size, int(delivered), reason, owner, link or '')))
        self.offered_hash.update((canonical([packet[k] for k in (
            'sequence', 'time', 'phase', 'source', 'destination', 'traffic', 'ground_truth', 'bytes')]) + '\n').encode())
        if self.packet_sink:
            self.packet_sink(packet)
        c = self.counts[(self.phase, truth)]
        c['generated'] += 1
        c['received'] += int(delivered)
        c['dropped'] += int(not delivered)
        c['rate_limited'] += int(reason == 'RATE_LIMIT')
        c['policy_dropped'] += int(bool(owner))
        c['generated_bytes'] += size
        c['received_bytes'] += size * int(delivered)
        if traffic == 'SAFETY' and dst.startswith('RSU-'):
            c['controller_generated'] += 1
            c['controller_received'] += int(delivered)
        self.reason_counts[(self.phase, truth)][reason] += 1
        if truth != 'benign' and owner:
            self.first_drop.setdefault(owner, round(self.t, 9))
        super()._record_packet(src, dst, traffic, size, delivered, reason, route, link, meter)

    def _step(self, dt):
        # Integrate previous observed states on [previous t, current t). State
        # changes and packet outcomes occur at the current engine step boundary.
        for vid, (m2, m3) in self.previous_policy.items():
            if vid == self.spec.attacker:
                self.durations[(self.phase, 'm2_meter')] += dt * (m2 == 'METER')
                self.durations[(self.phase, 'm2_block')] += dt * (m2 == 'BLOCK')
                self.durations[(self.phase, 'm3_meter')] += dt * (m3 in ('LIGHT_THROTTLE', 'HEAVY_THROTTLE', 'SEVERE_THROTTLE'))
        super()._step(dt)
        policies = self.policy_snapshot()
        for vid, policy in policies.items():
            if policy != self.previous_policy[vid]:
                self.transitions.append({'time': round(self.t, 9), 'phase': self.phase,
                                         'vehicle': vid, 'm2': policy[0], 'm3': policy[1],
                                         'reputation': self.vehicles[vid].reputation})
            if policy[0] in ('METER', 'BLOCK'):
                self.restricted_sources[(self.phase, 'm2')].add(vid)
            if reputation_policy(self.vehicles[vid].reputation)[0] is not None and self.config['m3_enabled']:
                self.restricted_sources[(self.phase, 'm3')].add(vid)
        self.previous_policy = policies
        positions = [(v.id, round(v.x, 9), round(v.y, 9), v.rsu) for v in self.vehicles.values()]
        self.mobility_hash.update((canonical([round(self.t, 9), positions]) + '\n').encode())
        if self.state_sink and self.tick_index % 10 == 0:
            for v in self.vehicles.values():
                self.state_sink({'time': round(self.t, 9), 'phase': self.phase, 'vehicle': v.id,
                                 'x': v.x, 'y': v.y, 'rsu': v.rsu or '', 'reputation': v.reputation,
                                 'm2': policies[v.id][0], 'm3': policies[v.id][1],
                                 'm2_pps': v.m2_rate, 'm2_threshold': self._threshold(v)})


def phase_counts(sim, phase):
    return {name: {key: sim.counts[(phase, name)][key] for key in COUNT_FIELDS}
            for name in CLASSES}


def benign_ids(spec, scenario, phase):
    ids = {f'V{i:02}' for i in range(1, 13)}
    if scenario != 'normal' and phase != 'baseline':
        ids.remove(spec.attacker)
    return ids


def recovery_delay(samples, attack_end, end, predicate, was_restricted):
    if not was_restricted:
        return metric(explanation='No corresponding attacker restriction was observed during attack.')
    # Require a normal tail lasting >= one simulated second. Transitions, not
    # healthy legitimate traffic alone, establish recovery of this policy.
    tail_start = None
    for time, state in samples:
        if time < attack_end: continue
        if predicate(state):
            if tail_start is None: tail_start = time
        else:
            tail_start = None
    if tail_start is not None and end - tail_start >= 1 - 1e-7:
        return metric(max(0.0, tail_start - attack_end))
    return metric(explanation='Recovery not observed for a one-second stable tail; right-censored at run end.')


def calculate_metrics(sim, profile, scenario, boundary_states):
    spec = sim.spec
    metrics = {}
    for phase in PHASES:
        counts = phase_counts(sim, phase)
        benign = counts['benign']
        malicious = Counter()
        for name in CLASSES[1:]: malicious.update(counts[name])
        records = {
            'legitimate_pdr_pct': ratio(benign['received'], benign['generated']),
            'malicious_delivery_pct': ratio(malicious['received'], malicious['generated']),
            'malicious_suppression_pct': ratio(malicious['dropped'], malicious['generated']),
            'malicious_policy_drop_pct': ratio(malicious['policy_dropped'], malicious['generated']),
            'benign_policy_drop_pct': ratio(benign['policy_dropped'], benign['generated']),
            'udp_flood_delivery_pct': ratio(counts['malicious_flood']['received'], counts['malicious_flood']['generated']),
            'malicious_safety_delivery_pct': ratio(counts['malicious_safety']['received'], counts['malicious_safety']['generated']),
            'malicious_safety_controller_delivery_pct': ratio(counts['malicious_safety']['controller_received'], counts['malicious_safety']['controller_generated']),
            'transmitted_packets': metric(explanation='Engine has no independent MAC/link transmission stage; generated means endpoint forwarding attempts.'),
            'network_latency_ms': metric(explanation='Engine delivery is instantaneous; no measured propagation/queue/receiver delay.'),
        }
        for method in ('m2', 'm3'):
            eligible = benign_ids(spec, scenario, phase)
            for source, key in ((sim.alerts, 'benign_source_alert_rate_pct'),
                                (sim.restricted_sources, 'benign_source_restriction_rate_pct')):
                records[f'{method}_{key}'] = (ratio(len(source[(phase, method)] & eligible), len(eligible))
                    if sim.config[f'{method}_enabled'] else metric(explanation=f'{method.upper()} disabled in this profile.'))
        for key in ('m2_meter', 'm2_block', 'm3_meter'):
            method = key[:2]
            records[f'{key}_duration_s'] = (metric(round(sim.durations[(phase, key)], 9))
                if sim.config[f'{method}_enabled'] else metric(explanation=f'{method.upper()} disabled in this profile.'))
        metrics[phase] = records

    attack = metrics['attack']
    attack['m1_detection_delay_s'] = metric(explanation='M1 is a preconfigured static rule; it does not detect attacks.')
    for method, kind in (('m2', 'M2 · DETECTION'), ('m3', None)):
        enabled = sim.config[f'{method}_enabled']
        if method == 'm2':
            evidence = [e['time'] for e in sim.all_events if e['kind'] == kind and
                        e['phase'] == 'attack' and e['message'].startswith(spec.attacker + ':')]
        else:
            evidence = [d['time'] for d in sim.decisions if d['phase'] == 'attack' and
                        d['vehicle'] == spec.attacker and d['injected_malicious'] and not d['consistent']]
        missing_reason = (f'{method.upper()} disabled.' if not enabled else
                          'No matching dynamic detection observed; absence is not zero latency.')
        if enabled and method == 'm2' and PROFILES[profile][3]:
            missing_reason = 'No M2 detection observed; the preconfigured M1 DROP removes flood packets before M2 observation.'
        if enabled and method == 'm3' and scenario != 'combined':
            missing_reason = 'No injected inconsistent safety reports in this scenario; M3 is not a generic flood detector.'
        attack[f'{method}_detection_delay_s'] = (metric(evidence[0] - spec.baseline_seconds) if evidence else metric(
            explanation=missing_reason))
    for method in ('m1', 'm2', 'm3'):
        time = sim.first_drop.get(method)
        attack[f'{method}_first_malicious_drop_delay_s'] = (metric(time - spec.baseline_seconds)
            if time is not None else metric(explanation='No malicious packet drop attributed to this policy.'))
    recovery = metrics['recovery']
    attack_state = boundary_states['attack']
    # All attacker transitions plus exact attack-end state preserve restrictions
    # spanning a phase boundary even when no transition occurs at that boundary.
    samples = [(spec.attack_end, attack_state)] + [(t['time'], t) for t in sim.transitions
              if t['vehicle'] == spec.attacker and t['time'] > spec.attack_end]
    samples.append((spec.end, boundary_states['recovery']))
    for name, predicate, restricted in (
        ('m2_recovery_delay_s', lambda s: s['m2'] == 'NORMAL', sim.durations[('attack', 'm2_meter')] + sim.durations[('attack', 'm2_block')] > 0),
        ('m3_meter_recovery_delay_s', lambda s: s['m3'] in ('NORMAL', 'MONITOR'), sim.durations[('attack', 'm3_meter')] > 0),
        ('m3_reputation_recovery_delay_s', lambda s: s['reputation'] >= .8, attack_state['reputation'] < .8 and sim.config['m3_enabled']),
    ):
        recovery[name] = recovery_delay(samples, spec.attack_end, spec.end, predicate, restricted)
    recovery['legitimate_throughput_recovery_s'] = metric(explanation=(
        'Not inferred from healthy legitimate PDR. Moving connectivity changes capacity; '
        'no stationary throughput restoration criterion is defined. Policy restoration is measured separately.'))
    recovery['m1_rule_removal_delay_s'] = metric(explanation=(
        'Static rule remains configured throughout; no rule-removal recovery is scheduled.'
        if PROFILES[profile][3] else 'No active study M1 static rule in this profile.'))
    return metrics


def audit_counters(sim):
    totals = Counter()
    for counter in sim.counts.values(): totals.update(counter)
    for key, engine_key in (('generated', 'sent'), ('received', 'delivered'),
                            ('dropped', 'dropped'), ('generated_bytes', None),
                            ('received_bytes', 'delivered_bytes')):
        expected = (sim.totals['delivered_bytes'] + sim.totals['dropped_bytes']
                    if engine_key is None else sim.totals[engine_key])
        if totals[key] != expected:
            raise AssertionError(f'Packet ledger mismatch for {key}: {totals[key]} != {expected}')
    if totals['generated'] != totals['received'] + totals['dropped']:
        raise AssertionError('Generated != received + dropped')
    observed_reasons = Counter()
    for reasons in sim.reason_counts.values(): observed_reasons.update(reasons)
    if observed_reasons != sim.reasons:
        raise AssertionError('Observed reason ledger does not match engine reasons')
    if totals['rate_limited'] != sim.reasons['RATE_LIMIT'] or totals['rate_limited'] != sum(
            sim.totals[f'{name}_meter_drops'] for name in ('m1', 'm2', 'm3')):
        raise AssertionError('Rate-limit attribution does not reconcile')
    false_safety = sum(sim.counts[(p, 'malicious_safety')]['generated'] for p in PHASES)
    semantic_benign = sum(sim.counts[(p, 'benign')]['generated'] for p in PHASES)
    if sim.totals['legitimate_sent'] != semantic_benign + false_safety:
        raise AssertionError('Legacy non-flood classification discrepancy is not explained by malicious safety')
    false_received = sum(sim.counts[(p, 'malicious_safety')]['received'] for p in PHASES)
    benign_received = sum(sim.counts[(p, 'benign')]['received'] for p in PHASES)
    if sim.totals['legitimate_delivered'] != benign_received + false_received:
        raise AssertionError('Legacy non-flood reception discrepancy is not explained by malicious safety')
    return {'status': 'PASS', 'ledger_generated': totals['generated'],
            'legacy_non_flood_generated': sim.totals['legitimate_sent'],
            'semantic_benign_generated': semantic_benign,
            'malicious_safety_counted_as_non_flood_by_dashboard': false_safety,
            'semantic_benign_received': benign_received,
            'malicious_safety_received_counted_as_non_flood_by_dashboard': false_received}


def run_trial(spec, profile, scenario, seed, packet_sink=None, state_sink=None):
    spec.validate()
    m1, m2, m3, static = PROFILES[profile]
    sim = EvidenceEngine(spec, seed, packet_sink, state_sink)
    sim.set_config({'m1_enabled': m1, 'm2_enabled': m2, 'm3_enabled': m3})
    # A fresh engine never loads controller_settings.json or dashboard rules.
    if static:
        sim.upsert_rule({'label': 'Study: known attacker flood class', 'source': spec.attacker,
                         'traffic': 'UDP_FLOOD', 'rsu': '*', 'priority': 900,
                         'action': 'DROP', 'enabled': True})
    sim.previous_policy = sim.policy_snapshot()
    boundary_states = {}
    for phase, duration in zip(PHASES, (spec.baseline_seconds, spec.attack_seconds, spec.recovery_seconds)):
        sim.phase = phase
        sim.set_scenario(scenario if phase == 'attack' else 'normal', spec.attacker, spec.victim)
        for _ in range(round(duration * 10)):
            sim.step(spec.step_seconds)
        v = sim.vehicles[spec.attacker]
        policy = sim.policy_snapshot()[v.id]
        boundary_states[phase] = {'m2': policy[0], 'm3': policy[1], 'reputation': v.reputation}
    return {
        'study_type': 'SIMULATION_ONLY', 'run_id': run_id(profile, scenario, seed, spec),
        'profile': profile, 'scenario': scenario, 'seed': seed, 'spec': asdict(spec),
        'config': dict(sim.config), 'rules': sim.rules, 'boundary_states': boundary_states,
        'offered_packet_sha256': sim.offered_hash.hexdigest(),
        'mobility_sha256': sim.mobility_hash.hexdigest(),
        'counts': {phase: phase_counts(sim, phase) for phase in PHASES},
        'reasons': {phase: {name: dict(sim.reason_counts[(phase, name)]) for name in CLASSES} for phase in PHASES},
        'metrics': calculate_metrics(sim, profile, scenario, boundary_states),
        'counter_audit': audit_counters(sim), 'events': sim.all_events,
        'decisions': sim.decisions, 'transitions': sim.transitions,
        'handovers': sim.totals['handovers'],
    }


def verify_equivalence(results):
    grouped = defaultdict(list)
    for result in results: grouped[(result['scenario'], result['seed'])].append(result)
    for key, rows in grouped.items():
        if {r['profile'] for r in rows} != set(PROFILES):
            raise AssertionError(f'Incomplete or duplicate profile matrix for {key}')
        if len(rows) != len(PROFILES): raise AssertionError(f'Duplicate trials for {key}')
        for name in ('offered_packet_sha256', 'mobility_sha256'):
            if len({r[name] for r in rows}) != 1:
                raise AssertionError(f'Unmatched {name} for {key}; comparison is invalid')
    return {'status': 'PASS', 'matched_scenario_seed_groups': len(grouped),
            'checks': ['all offered packet identities/times/sizes/ground-truth labels',
                       'all 0.1-second vehicle positions and RSU associations']}


def summarize(results):
    grouped = defaultdict(list)
    for r in results:
        for phase, records in r['metrics'].items():
            for name, record in records.items():
                grouped[(r['scenario'], r['profile'], phase, name)].append(record)
    rows = []
    for (scenario, profile, phase, name), records in sorted(grouped.items()):
        values = [r['value'] for r in records if r['value'] is not None]
        ci = confidence_interval_95(values)
        rows.append(dict(scenario=scenario, profile=profile, phase=phase, metric=name,
                         mean=ci['mean'], ci95_low=ci['low'], ci95_high=ci['high'], n=ci['n'],
                         missing=len(records) - len(values), explanation='; '.join(sorted(
                             {r['explanation'] for r in records if r['explanation']})) or ci['explanation']))
    return rows


def paired_differences(results):
    baseline = {(r['scenario'], r['seed']): r for r in results if r['profile'] == 'no_defense'}
    rows = []
    for scenario in sorted({r['scenario'] for r in results}):
        for profile in PROFILES:
            if profile == 'no_defense': continue
            for name in ('legitimate_pdr_pct', 'malicious_policy_drop_pct', 'benign_policy_drop_pct'):
                differences = []
                for r in results:
                    if r['scenario'] != scenario or r['profile'] != profile: continue
                    a = r['metrics']['attack'][name]['value']
                    b = baseline[(scenario, r['seed'])]['metrics']['attack'][name]['value']
                    if a is not None and b is not None: differences.append(a - b)
                ci = confidence_interval_95(differences)
                rows.append(dict(scenario=scenario, profile=profile, metric=name,
                                 mean_difference_pp=ci['mean'], ci95_low=ci['low'], ci95_high=ci['high'], n=ci['n']))
    return rows


def write_csv(path, rows, fields=None):
    rows = list(rows)
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@contextmanager
def compressed_csv(path, fields):
    # mtime=0 and no embedded filename permit byte-reproducible raw evidence.
    with path.open('xb') as raw:
        with io.TextIOWrapper(gzip.GzipFile(filename='', mode='wb',
                fileobj=raw, mtime=0), encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            yield writer.writerow


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def graph_svg(path, summary, scenario, metric_name, title):
    """Small standalone SVG figure; standard library, no plotting installation."""
    rows = [next(r for r in summary if r['scenario'] == scenario and r['profile'] == p
                 and r['phase'] == 'attack' and r['metric'] == metric_name) for p in PROFILES]
    maximum = max([100] + [r['ci95_high'] or r['mean'] or 0 for r in rows])
    width, left, top, plot_width = 1020, 215, 100, 650
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1020" height="420" viewBox="0 0 1020 420">',
             '<rect width="1020" height="420" fill="white"/>',
             f'<title>{escape(title)} — {escape(scenario)} — SIMULATION ONLY</title>',
             '<g font-family="Arial,sans-serif" fill="#172b3a">',
             f'<text x="24" y="30" font-size="20">{escape(title)} — {escape(scenario)}</text>',
             '<text x="24" y="54" font-size="13">SIMULATION ONLY · mean and untruncated 95% Student-t CI across seeded trials</text>']
    for tick in range(0, 101, 20):
        x = left + tick / maximum * plot_width
        parts.append(f'<path d="M{x:.2f} 84 V350" stroke="#dce4e8"/><text x="{x:.2f}" y="373" font-size="12">{tick}%</text>')
    for i, row in enumerate(rows):
        y = top + i * 42
        parts.append(f'<text x="15" y="{y+16}" font-size="14">{escape(row["profile"])}</text>')
        value = row['mean']
        if value is None:
            parts.append(f'<text x="{left}" y="{y+16}" font-size="13">unavailable (n=0)</text>')
            continue
        bar = value / maximum * plot_width
        parts.append(f'<rect x="{left}" y="{y}" width="{bar:.3f}" height="23" fill="#267d9c"/>')
        if row['ci95_low'] is not None:
            lo, hi = (left + row[key] / maximum * plot_width for key in ('ci95_low', 'ci95_high'))
            parts.append(f'<path d="M{lo:.3f} {y+11} H{hi:.3f} M{lo:.3f} {y+6} V{y+16} M{hi:.3f} {y+6} V{y+16}" stroke="#101010" fill="none" stroke-width="1.5"/>')
        parts.append(f'<text x="890" y="{y+16}" font-size="13">{value:.2f}% (n={row["n"]})</text>')
    parts.append('<text x="24" y="405" font-size="12">Attack window only. Seeds vary modeled radio loss; routes and speeds are fixed. No real OpenFlow measurements.</text></g></svg>')
    with path.open('x', encoding='utf-8') as stream: stream.write('\n'.join(parts))


def source_manifest():
    paths = [Path(__file__).resolve(), ROOT / 'VisualUnified/engine.py', ROOT / 'VisualUnified/mobility.py', ROOT / 'VisualUnified/control_center.py', ROOT / 'VisualUnified/methodology.py',
             ROOT / 'benchmark/core.py', ROOT / 'Methodology2/scripts/mobility_detector.py',
             ROOT / 'Methodology2/scripts/med2_config.py']
    paths += [ROOT / 'Methodology3' / name for name in ('message_consistency.py', 'reputation_engine.py', 'safety_messages.py')]
    return {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def report_text(spec, results, summary, equivalence):
    lines = ['# VisualUnified reproducible simulation study', '',
             '**SIMULATION ONLY.** Generated by actual instrumented SimEngine execution; no real OpenFlow/SUMO measurements.', '',
             f'Executed {len(results)} runs: {len(PROFILES)} profiles × {len(spec.scenarios)} scenarios × {len(spec.seeds)} seeds.',
             f'Seeds: {list(spec.seeds)}. Windows: {spec.baseline_seconds:g} s baseline / {spec.attack_seconds:g} s attack / {spec.recovery_seconds:g} s recovery; step 0.1 s.',
             f'Equivalence check: {equivalence["status"]}; {equivalence["matched_scenario_seed_groups"]} matched scenario/seed groups. All packet-ledger audits passed.', '',
             '## Attack-window results', '',
             '| Scenario | Profile | Benign PDR % | Malicious delivery % | Malicious policy drop % | Benign policy drop % |',
             '|---|---|---:|---:|---:|---:|']
    for scenario in spec.scenarios:
        for profile in PROFILES:
            cells = []
            for name in ('legitimate_pdr_pct', 'malicious_delivery_pct', 'malicious_policy_drop_pct', 'benign_policy_drop_pct'):
                row = next(r for r in summary if r['scenario'] == scenario and r['profile'] == profile
                           and r['phase'] == 'attack' and r['metric'] == name)
                cells.append('null' if row['mean'] is None else f'{row["mean"]:.3f}')
            lines.append(f'| {scenario} | {profile} | ' + ' | '.join(cells) + ' |')
    lines += ['', '## Benign-source false alarms and collateral drops', '',
              '| Scenario | Profile | M2 benign alerts % | M3 benign alerts % | M3 benign sources rate-restricted % |',
              '|---|---|---:|---:|---:|']
    for scenario in spec.scenarios:
        for profile in PROFILES:
            cells = []
            for name in ('m2_benign_source_alert_rate_pct', 'm3_benign_source_alert_rate_pct',
                         'm3_benign_source_restriction_rate_pct'):
                row = next(r for r in summary if r['scenario'] == scenario and r['profile'] == profile
                           and r['phase'] == 'attack' and r['metric'] == name)
                cells.append('null' if row['mean'] is None else f'{row["mean"]:.3f}')
            lines.append(f'| {scenario} | {profile} | ' + ' | '.join(cells) + ' |')
    lines += ['', 'An alert is a detector observation, not necessarily a restrictive policy or a packet drop. Benign policy-drop ratios in the first table are independent packet evidence. Normal-control results expose incidental consistency failures in the built-in motion model.', '',
              '## Packet accounting discrepancies', '']
    combined = [r for r in results if r['scenario'] == 'combined']
    if combined:
        examples = [r for r in combined if r['profile'] == 'no_defense']
        low = min(r['counter_audit']['malicious_safety_counted_as_non_flood_by_dashboard'] for r in examples)
        high = max(r['counter_audit']['malicious_safety_counted_as_non_flood_by_dashboard'] for r in examples)
        lines.append(f'In the combined No Defense runs, {low}–{high} deliberately malicious safety packet copies per run appear in the legacy non-flood/"legitimate" count. The new ground-truth ledger separates them; counters reconcile exactly. Attacker vehicle totals also include valid telemetry and safety, so they are not malicious packet totals.')
    lines += ['', 'These are means, not a significance claim. Full unrounded trial values, sample sizes, missing explanations and 95% Student-t intervals are in metrics.csv and summary.csv. paired_differences.csv compares each profile with No Defense using matching seeds.', '',
              '## Timing and recovery', '',
              '| Scenario | Profile | M2 detection s | M3 detection s | M2 recovery s | M3 meter recovery s | M3 trust >=0.80 recovery s |',
              '|---|---|---:|---:|---:|---:|---:|']
    for scenario in spec.scenarios:
        if scenario == 'normal': continue
        for profile in PROFILES:
            cells = []
            for phase, name in (('attack', 'm2_detection_delay_s'), ('attack', 'm3_detection_delay_s'),
                                ('recovery', 'm2_recovery_delay_s'), ('recovery', 'm3_meter_recovery_delay_s'),
                                ('recovery', 'm3_reputation_recovery_delay_s')):
                row = next(r for r in summary if r['scenario'] == scenario and r['profile'] == profile and r['phase'] == phase and r['metric'] == name)
                cells.append('null' if row['mean'] is None else f'{row["mean"]:.3f} (n={row["n"]})')
            lines.append(f'| {scenario} | {profile} | ' + ' | '.join(cells) + ' |')
    lines += ['', '## Method and limitations', '',
              '- Built-in deterministic routes/speeds, 12 vehicles, 3 RSUs, V07 attacker, V02 victim. The engine defaults (including 1% modeled radio loss and 2 Mbps RSU backhaul) are saved per trial. Seeds vary radio loss, not the mobility population.',
              '- Flood/combined attack: 320 attempted 1024-byte UDP flood packets/s for the attack window. Combined additionally changes V07 safety speed to 280 km/h (wire value in m/s), 2 safety reports/s, 220 bytes per delivered endpoint copy. Normal telemetry: 1.3 schedule opportunities/s, 420 bytes, when associated; infrastructure beacons approximately 1 Hz. Peer safety copies depend on deterministic proximity. normal is a matched no-attack control.',
              '- M1 only and unified_static use a preinstalled V07/UDP_FLOOD DROP. This assumes the attacker and attack-only traffic class are already known and is intentionally favorable to M1; it is not learned detection or a validation of the original all-UDP source block. Unified_dynamic leaves the example M1 rule disabled to expose M2/M3 interaction. Static DROP hides the flood from M2.',
              '- Generated means endpoint _send attempts. Received means the engine returned successful logical delivery. Dropped = generated - received. RATE_LIMIT is an observed drop reason, a subset of dropped. Transmitted is null: this engine has no independent radio/MAC transmission counter. All packet ledgers are complete, unlike sampled dashboard dots.',
              '- Ground truth marks UDP_FLOOD and deliberately injected false safety copies malicious. Valid safety/telemetry from V07 remain benign. Incidental physical inconsistencies in the built-in motion remain benign-intent workload errors and can trigger M3; false-positive metrics are workload-conditioned benign-source alert/restriction fractions, not a real-world classifier FPR.',
              '- Attack-window benign-source denominators are 11 in flood/combined and 12 in normal; baseline uses 12. Recovery excludes the prior attacker so its carried-over restrictions are not mislabeled false positives. An enabled detector with no eligible-source alerts measures 0%; a disabled detector is null.',
              '- M2 detection is first actual Stage 1 event for the attacker. M3 detection is first controller-observed injected safety report that fails consistency checking. M1 detection latency is null. First malicious packet drop is a separate observation. Attribution of RATE_LIMIT uses the first exhausted budget reported by the engine, not a claim of exclusive causation when multiple budgets apply.',
              '- Mitigation duration integrates attacker policy state. Recovery is a policy-normal tail of at least one simulated second after attack end; missing recovery is right-censored. M2 NORMAL, M3 meter removed (MONITOR/NORMAL), and M3 reputation >=0.80 are distinct. No healthy legitimate PDR is converted into a zero throughput-recovery delay.',
              '- The legacy dashboard/runner calls all non-flood packets legitimate, including injected malicious safety; per-attacker counters mix valid and malicious classes; UI legitimate PDR is a rolling 10-second value. This study uses packet ground truth and exact phase counters instead, and audits those differences. Empty windows are null, never the dashboard default 100%.',
              '- No queue/propagation latency, hardware limits, wireless contention, OpenFlow acknowledgments, or real meter statistics are measured. Policy/meter rates and rule matches are not packet-drop evidence. Suppression includes radio/no-route/congestion loss, so policy-attributed drop ratios are also reported.',
              '- 0.1-second boundary observations bound timing precision; exact packet/event simulation timestamps are retained. Phases own their scheduled steps: baseline (0,B], attack (B,B+A], recovery (B+A,end]. Packet times at a shared numeric boundary belong to the preceding step phase.',
              '- Repetitions are independent seeded modeled-loss trials with paired randomness across profiles. Confidence intervals describe this fixed simulated workload only. Timing means/intervals exclude null trials; n and missing counts must be read together. No claim of statistical significance, realism, or generalization is made. SVG graphs use a small standard-library renderer and show untruncated t intervals, which can extend beyond 0–100%.',
              '', '## Reproduce', '',
              '```powershell', 'cd C:\\Users\\jimk7\\Desktop\\Projects\\ComputerNetworks\\MarsVanet\\VisualUnified',
              'py -3 run_experiments.py --output experiments/study-v1-repeat', '```', '',
              'The runner refuses existing output directories. It never reads/saves dashboard settings. manifest.json records source SHA256, environment and exact specification. Every run has a full packet CSV.gz, one-second state CSV.gz, events, safety decisions, transitions and metrics.']
    return '\n'.join(lines) + '\n'


def execute_study(spec, output):
    spec.validate()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    sources_before = source_manifest()
    write_json(output / 'manifest.json', {'study_type': 'SIMULATION_ONLY', 'spec': asdict(spec),
        'profiles': PROFILES, 'engine_defaults': DEFAULT_CONFIG, 'mobility_model': 'legacy', 'sources_sha256': sources_before,
        'python': sys.version, 'platform': platform.platform(),
        'executed_utc': datetime.now(timezone.utc).isoformat()})
    results = []
    try:
        for profile, scenario, seed in matrix(spec):
            directory = output / run_id(profile, scenario, seed, spec)
            directory.mkdir()
            with compressed_csv(directory / 'packets.csv.gz', PACKET_FIELDS) as packet_sink, compressed_csv(
                    directory / 'states.csv.gz', ('time', 'phase', 'vehicle', 'x', 'y', 'rsu',
                        'reputation', 'm2', 'm3', 'm2_pps', 'm2_threshold')) as state_sink:
                result = run_trial(spec, profile, scenario, seed, packet_sink, state_sink)
            write_json(directory / 'result.json', result)
            # Retain lightweight results in memory; detailed decisions stay per-run.
            results.append({k: v for k, v in result.items() if k not in ('events', 'decisions', 'transitions')})
            print(f'{scenario:8} {profile:16} seed={seed}: {result["counter_audit"]["status"]}', flush=True)
        if source_manifest() != sources_before:
            raise AssertionError('Source files changed during execution; rerun from a stable source snapshot')
        equivalence = verify_equivalence(results)
        write_json(output / 'equivalence.json', equivalence)
        summary = summarize(results)
        write_csv(output / 'summary.csv', summary)
        write_csv(output / 'paired_differences.csv', paired_differences(results))
        metric_rows, count_rows = [], []
        for r in results:
            common = {key: r[key] for key in ('run_id', 'profile', 'scenario', 'seed')}
            for phase, records in r['metrics'].items():
                for name, record in records.items():
                    metric_rows.append(dict(common, phase=phase, metric=name, **record))
            for phase, classes in r['counts'].items():
                for name, counts in classes.items():
                    count_rows.append(dict(common, phase=phase, ground_truth=name, **counts,
                        transmitted=None, transmitted_explanation='No independent transmission stage in engine'))
        write_csv(output / 'metrics.csv', metric_rows)
        write_csv(output / 'traffic_counts.csv', count_rows)
        for scenario in spec.scenarios:
            for name, title in (('legitimate_pdr_pct', 'Benign packet delivery'),
                                ('malicious_delivery_pct', 'Malicious packet delivery'),
                                ('malicious_policy_drop_pct', 'Malicious policy-attributed drops')):
                graph_svg(output / f'{scenario}__{name}.svg', summary, scenario, name, title)
        with (output / 'REPORT.md').open('x', encoding='utf-8') as stream:
            stream.write(report_text(spec, results, summary, equivalence))
        write_json(output / 'completion.json', {'status': 'PASS', 'runs': len(results), 'equivalence': equivalence})
        write_json(output / 'artifact_sha256.json', {
            str(p.relative_to(output)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob('*')) if p.is_file()})
    except Exception as exc:
        write_json(output / 'failure.json', {'status': 'FAILED', 'error': str(exc)})
        raise
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'experiments/study-v1')
    parser.add_argument('--seeds', type=int, nargs='+', default=[14, 15, 16, 17, 18])
    parser.add_argument('--scenarios', nargs='+', choices=SCENARIOS, default=list(SCENARIOS))
    parser.add_argument('--baseline-seconds', type=float, default=10)
    parser.add_argument('--attack-seconds', type=float, default=20)
    parser.add_argument('--recovery-seconds', type=float, default=150)
    args = parser.parse_args()
    spec = StudySpec(tuple(args.seeds), tuple(args.scenarios), args.baseline_seconds,
                     args.attack_seconds, args.recovery_seconds)
    try:
        spec.validate()
        if args.output.exists(): parser.error('Refusing to overwrite an existing study directory')
        execute_study(spec, args.output)
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
