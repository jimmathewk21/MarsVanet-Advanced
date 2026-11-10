"""Read-only verification of saved simulation evidence, hashes and packet metrics."""
from collections import Counter, defaultdict
import argparse
import csv
import gzip
import hashlib
import json
import math
from pathlib import Path
from xml.etree import ElementTree

try:
    from .run_experiments import (ROOT, PHASES, CLASSES, COUNT_FIELDS, StudySpec,
                                  ratio, summarize, verify_equivalence)
except ImportError:
    from run_experiments import (ROOT, PHASES, CLASSES, COUNT_FIELDS, StudySpec,
                                 ratio, summarize, verify_equivalence)


def validate_study(directory, allow_source_drift=False):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    source_drift = []
    for relative, expected in manifest['sources_sha256'].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            source_drift.append(relative)
    if source_drift and not allow_source_drift:
        raise AssertionError(f'Source changed since execution: {source_drift[0]}')
    artifacts = json.loads((directory / 'artifact_sha256.json').read_text(encoding='utf-8'))
    for relative, expected in artifacts.items():
        path = (directory / relative).resolve()
        if not path.is_relative_to(directory): raise AssertionError('Invalid artifact path')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise AssertionError(f'Artifact checksum mismatch: {relative}')
    results, total_packets = [], 0
    for path in sorted(directory.glob('*/result.json')):
        result = json.loads(path.read_text(encoding='utf-8'))
        spec = StudySpec(**result['spec'])
        counts = defaultdict(Counter)
        reasons = defaultdict(Counter)
        offered_hash = hashlib.sha256()
        previous_time = 0
        first_drop = {}
        with gzip.open(path.parent / 'packets.csv.gz', 'rt', encoding='utf-8', newline='') as stream:
            for sequence, packet in enumerate(csv.DictReader(stream), 1):
                if int(packet['sequence']) != sequence: raise AssertionError('Non-contiguous packet ledger')
                time, phase, truth = float(packet['time']), packet['phase'], packet['ground_truth']
                start, end = {'baseline': (0, spec.baseline_seconds),
                              'attack': (spec.baseline_seconds, spec.attack_end),
                              'recovery': (spec.attack_end, spec.end)}[phase]
                if not start < time <= end or time < previous_time:
                    raise AssertionError('Packet time/phase mismatch')
                previous_time = time
                received, size = int(packet['received']), int(packet['bytes'])
                if received not in (0, 1) or bool(received) != (packet['reason'] == 'FORWARDED'):
                    raise AssertionError('Receive flag does not match packet outcome')
                expected_owner = {'M1_STATIC_DROP': 'm1', 'M2_TEMP_BLOCK': 'm2'}.get(packet['reason'])
                if expected_owner and packet['drop_owner'] != expected_owner:
                    raise AssertionError('Policy drop owner does not match outcome')
                if packet['reason'] == 'RATE_LIMIT' and packet['drop_owner'] not in ('m1', 'm2', 'm3'):
                    raise AssertionError('Rate-limit outcome has no owning budget')
                if truth == 'malicious_flood' and packet['traffic'] != 'UDP_FLOOD':
                    raise AssertionError('Invalid flood ground truth')
                if truth == 'malicious_safety' and (packet['traffic'] != 'SAFETY' or
                        phase != 'attack' or result['scenario'] != 'combined' or packet['source'] != spec.attacker):
                    raise AssertionError('Invalid malicious safety ground truth')
                c = counts[(phase, truth)]
                c.update(generated=1, received=received, dropped=1-received,
                         generated_bytes=size, received_bytes=size*received,
                         rate_limited=int(packet['reason'] == 'RATE_LIMIT'),
                         policy_dropped=int(bool(packet['drop_owner'])))
                if packet['traffic'] == 'SAFETY' and packet['destination'].startswith('RSU-'):
                    c.update(controller_generated=1, controller_received=received)
                reasons[(phase, truth)][packet['reason']] += 1
                if truth != 'benign' and packet['drop_owner']:
                    first_drop.setdefault(packet['drop_owner'], time)
                # Recreate the exact offered identity hash from the saved raw ledger.
                identity = [sequence, time, phase, packet['source'], packet['destination'],
                            packet['traffic'], truth, size]
                offered_hash.update((json.dumps(identity, sort_keys=True, separators=(',', ':')) + '\n').encode())
                total_packets += 1
        if offered_hash.hexdigest() != result['offered_packet_sha256']:
            raise AssertionError('Offered identity hash does not match saved packets')
        for phase in PHASES:
            for truth in CLASSES:
                actual = {key: counts[(phase, truth)][key] for key in COUNT_FIELDS}
                if actual != result['counts'][phase][truth]:
                    raise AssertionError(f'Raw packet/count mismatch: {path.parent.name}, {phase}, {truth}')
                if dict(reasons[(phase, truth)]) != result['reasons'][phase][truth]:
                    raise AssertionError('Raw packet/drop-reason mismatch')
            benign = counts[(phase, 'benign')]
            malicious = counts[(phase, 'malicious_flood')] + counts[(phase, 'malicious_safety')]
            for name, expected in (
                ('legitimate_pdr_pct', ratio(benign['received'], benign['generated'])['value']),
                ('benign_policy_drop_pct', ratio(benign['policy_dropped'], benign['generated'])['value']),
                ('malicious_delivery_pct', ratio(malicious['received'], malicious['generated'])['value']),
                ('malicious_policy_drop_pct', ratio(malicious['policy_dropped'], malicious['generated'])['value']),
            ):
                observed = result['metrics'][phase][name]['value']
                if (expected is None) != (observed is None) or (expected is not None and
                        not math.isclose(expected, observed, abs_tol=1e-9)):
                    raise AssertionError(f'Metric does not match raw ledger: {name}')
        for owner, time in first_drop.items():
            observed = result['metrics']['attack'][f'{owner}_first_malicious_drop_delay_s']['value']
            if not math.isclose(time-spec.baseline_seconds, observed, abs_tol=1e-9):
                raise AssertionError('First observed drop timing does not match raw ledger')
        results.append({key: value for key, value in result.items()
                        if key not in ('events', 'decisions', 'transitions')})
    expected_runs = len(manifest['profiles']) * len(manifest['spec']['seeds']) * len(manifest['spec']['scenarios'])
    if len(results) != expected_runs: raise AssertionError('Incomplete saved trial matrix')
    verify_equivalence(results)
    with (directory / 'summary.csv').open(encoding='utf-8', newline='') as stream:
        saved_summary = list(csv.DictReader(stream))
    expected_summary = summarize(results)
    if len(saved_summary) != len(expected_summary): raise AssertionError('Incomplete summary')
    for saved, expected in zip(saved_summary, expected_summary):
        for key, value in expected.items():
            if saved[key] != (str(value) if value is not None else ''):
                raise AssertionError(f'Summary mismatch: {key}')
    graphs = list(directory.glob('*.svg'))
    if len(graphs) != len(manifest['spec']['scenarios']) * 3: raise AssertionError('Missing comparison graphs')
    for graph in graphs: ElementTree.parse(graph)
    return {'status': 'PASS', 'runs': len(results), 'packets_independently_recounted': total_packets,
            'artifact_hashes_checked': len(artifacts), 'svg_figures_checked': len(graphs),
            'source_identity': 'DIFFERENT' if source_drift else 'MATCH',
            'source_drift': source_drift,
            'scope': 'Saved artifact/ledger validation; current-code replay is not verified.' if source_drift else
                     'Saved artifacts and source fingerprints match.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--allow-source-drift', action='store_true',
                        help='Audit saved ledgers after code changes; explicitly report source differences.')
    args = parser.parse_args()
    print(json.dumps(validate_study(args.directory,args.allow_source_drift), indent=2))


if __name__ == '__main__':
    main()
