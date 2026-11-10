#!/usr/bin/env python3
"""Plan or run a deterministic MarsVanet benchmark trial."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

try:
    from .compatibility import validate_controller_compatibility
    from .topology_spec import TOPOLOGY_SPEC
    from .core import (
        CONFIGURATIONS, OFFERED_LOADS, WINDOWS, WORKLOADS,
        environment_metadata, generate_matrix,
        summarize_metric_files,
    )
except ImportError:  # direct ``python benchmark/run_benchmark.py`` invocation
    from compatibility import validate_controller_compatibility
    from topology_spec import TOPOLOGY_SPEC
    from core import (
        CONFIGURATIONS, OFFERED_LOADS, WINDOWS, WORKLOADS,
        environment_metadata, generate_matrix,
        summarize_metric_files,
    )


ROOT = Path(__file__).resolve().parents[1]


def controller_command(configuration: str) -> list[str]:
    modules = {
        "methodology1": "Methodology1/scripts/dos_defense_static.py",
        "methodology2": "Methodology2/scripts/dos_defense_v2.py",
        "methodology3": "Methodology3/controller.py",
    }
    if configuration == "no_defense":
        return ["ryu-manager", "--ofp-tcp-listen-port", "6653",
                "ryu.app.simple_switch_13"]
    return ["ryu-manager", "--ofp-tcp-listen-port", "6653", modules[configuration]]


def plan_document(root_seed: int = 1, repetitions: int = 3) -> dict:
    runs = generate_matrix(root_seed, repetitions)
    matrix = []
    for run in runs:
        matrix.append({
            **asdict(run),
            "controller_command": controller_command(run.configuration),
            "execution_status": "plan_only_not_executed",
        })
    return {
        "title": "MarsVanet Phase 2 cross-methodology benchmark plan",
        "phase": 2,
        "mode": "dry_run",
        "executed": False,
        "environment": environment_metadata(),
        "common_topology": "common_2ap_candidate_v1",
        "topology_status": "runtime_checks_available_not_run_in_plan_mode",
        "topology_spec": TOPOLOGY_SPEC,
        "topology_command": ["<explicit create_topology/start_topology API; not invoked by plan mode>"],
        "compatibility_validator_command": ["python", "benchmark/compatibility.py"],
        "compatibility_report": validate_controller_compatibility(ROOT),
        "workloads": {
            "volumetric_udp": {
                "description": "sta1 legitimate UDP to sta2 plus sta3 volumetric UDP to sta2",
                "applicable_configurations": ["no_defense", "methodology1", "methodology2"],
                "not_applicable": {"methodology3": "M3 only scores structurally valid UDP/5005 safety messages."},
            },
            "safety_consistency": {
                "description": "Methodology 3 sta3 valid telemetry, five impossible-displacement messages, and 200 valid recovery messages; concurrent sta3 UDP/5001 data-plane probe",
                "applicable_configurations": list(CONFIGURATIONS),
                "interpretation": "Live safety consistency currently supports Methodology 3 only. Other methods are not treated as equivalent consistency detectors.",
            },
        },
        "phases_seconds": {
            "baseline": WINDOWS["baseline_seconds"],
            "attack": WINDOWS["attack_seconds"],
            "recovery": WINDOWS["recovery_seconds"],
        },
        "phase_windows_by_workload": {
            workload: run.windows for workload, run in (
                (name, next(item for item in runs if item.workload == name))
                for name in WORKLOADS
            )
        },
        "offered_loads": OFFERED_LOADS,
        "live_blockers": [
            "This plan does not run live topology checks or traffic.",
            "Methodology 2 flow-counter semantics and stage transition timing remain live-validation requirements.",
            "Methodology 3 detection and mitigation delays remain null because controller logs are not mapped to the runner monotonic clock; false positives have no independent oracle.",
            "Methodology 3's controller logs have no sender sequence IDs or monotonic timestamps, so decision coverage is order-correlated and detection/mitigation delays remain null.",
            "M1 drops all UDP from 10.0.0.3 regardless of destination; M2 detects sustained rates; M3 consumes only valid-format UDP/5005 and evaluates consistency/reputation.",
        ],
        "runs": matrix,
    }


def execute_live_trial(root, run, artifacts, *, ryu_manager, controller_port,
                       severe_measurement_seconds=10.0,
                       normal_measurement_seconds=10.0):
    """Route only supported live workload/controller pairs to their adapters."""
    try:
        from .live_trial import run_live_trial, run_methodology3_safety_trial
    except ImportError:
        from live_trial import run_live_trial, run_methodology3_safety_trial
    if run.workload == "volumetric_udp" and run.configuration in {
            "no_defense", "methodology1", "methodology2"}:
        return run_live_trial(root, run, artifacts, ryu_manager=ryu_manager,
                              controller_port=controller_port)
    if run.workload == "safety_consistency" and run.configuration == "methodology3":
        return run_methodology3_safety_trial(
            root, run, artifacts, ryu_manager=ryu_manager,
            controller_port=controller_port,
            severe_measurement_seconds=severe_measurement_seconds,
            normal_measurement_seconds=normal_measurement_seconds,
        )
    raise ValueError(f"unsupported live workload/configuration: "
                     f"{run.workload}/{run.configuration}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-seed", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--workload", choices=("all",) + WORKLOADS, default="all")
    parser.add_argument("--live", action="store_true",
                        help="run one live trial (requires Ubuntu, root, Mininet-WiFi and Ryu)")
    parser.add_argument("--configuration", choices=CONFIGURATIONS,
                        default="no_defense",
                        help="controller configuration for --live (default: no_defense)")
    parser.add_argument("--ryu-manager", default="ryu-manager",
                        help="Ryu manager executable (default: ryu-manager from PATH)")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--severe-measurement-seconds", type=float, default=10.0,
                        help="M3 steady severe-throttle probe interval (0..60 s)")
    parser.add_argument("--normal-measurement-seconds", type=float, default=10.0,
                        help="M3 post-recovery normal probe interval (0..60 s)")
    parser.add_argument("--artifacts", type=Path,
                        default=Path("benchmark/artifacts"),
                        help="live artifact directory (must be inside benchmark/)")
    parser.add_argument("--output", type=Path,
                        help="optional output path for the plan JSON (refuses overwrite)")
    parser.add_argument("--summarize", type=Path, metavar="ARTIFACT_DIR",
                        help="summarize existing per-run *.metrics.json artifacts")
    args = parser.parse_args(argv)
    if args.live and args.summarize:
        parser.error("--live and --summarize cannot be used together")
    if args.summarize:
        files = sorted(args.summarize.glob("*.metrics.json"))
        if not files:
            parser.error(f"no *.metrics.json artifacts found under {args.summarize}")
        print(json.dumps(summarize_metric_files(files), indent=2, sort_keys=True))
        return 0
    if args.repetitions < 1:
        parser.error("--repetitions must be at least 1")
    workloads = WORKLOADS if args.workload == "all" else (args.workload,)
    doc = plan_document(args.root_seed, args.repetitions)
    if workloads != WORKLOADS:
        doc["runs"] = [run for run in doc["runs"] if run["workload"] in workloads]
    if args.live:
        if args.summarize:
            parser.error("--live and --summarize cannot be used together")
        live_workload = args.workload
        if live_workload == "all":
            if args.configuration == "methodology3":
                parser.error("select --workload safety_consistency for Methodology 3")
            # Preserve the existing live default: one volumetric trial, even
            # though dry-run planning defaults to the complete matrix.
            live_workload = "volumetric_udp"
        if live_workload not in ("volumetric_udp", "safety_consistency"):
            parser.error("select one supported live workload")
        if (live_workload == "volumetric_udp"
                and args.configuration == "methodology3"):
            parser.error("Methodology 3 volumetric_udp is not an applicable flood-detector trial")
        if (live_workload == "safety_consistency"
                and args.configuration != "methodology3"):
            parser.error("live safety_consistency currently supports Methodology 3 only")
        if (live_workload == "volumetric_udp"
                and (args.severe_measurement_seconds != 10.0
                     or args.normal_measurement_seconds != 10.0)):
            parser.error("steady measurement interval options apply only to safety_consistency")
        if any(not 0 < value <= 60 for value in (
                args.severe_measurement_seconds, args.normal_measurement_seconds)):
            parser.error("M3 steady measurement intervals must be in (0, 60] seconds")
        if args.repetitions != 1:
            parser.error("one live trial is supported; pass --repetitions 1")
        artifacts = args.artifacts.resolve()
        try:
            artifacts.relative_to((ROOT / "benchmark").resolve())
        except ValueError:
            parser.error("--artifacts must stay inside the benchmark/ directory")
        try:
            from .live_trial import _require_live_host
        except ImportError:
            from live_trial import _require_live_host
        try:
            _require_live_host()
        except RuntimeError as error:
            print(f"Live run refused: {error}", file=sys.stderr)
            return 2
        run = next(item for item in generate_matrix(args.root_seed, 1,
                                                     workloads=(live_workload,))
                   if item.configuration == args.configuration)
        result = execute_live_trial(
            ROOT, run, artifacts, ryu_manager=args.ryu_manager,
            controller_port=args.controller_port,
            severe_measurement_seconds=args.severe_measurement_seconds,
            normal_measurement_seconds=args.normal_measurement_seconds,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    rendered = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = args.output.resolve()
        benchmark_root = (ROOT / "benchmark").resolve()
        try:
            output_path.relative_to(benchmark_root)
        except ValueError:
            parser.error("--output must stay inside the new benchmark/ directory")
        args.output = output_path
        if args.output.exists():
            parser.error(f"refusing to overwrite {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
