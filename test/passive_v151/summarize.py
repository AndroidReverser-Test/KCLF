#!/usr/bin/env python3
"""Summarize recorded measurements; never controls a device."""
import collections
import json
from pathlib import Path
import statistics
import sys


def summarize(directory):
    directory = Path(directory)
    data = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    groups = collections.defaultdict(list)
    totals = collections.Counter()
    for c in data["cases"]:
        groups[(c["backend"], c["hold_us"], c["target"])].append(c)
        for name in ("scans", "reads", "read_fail", "maps_fail", "limited", "structural", "rejected",
                     "work", "errors", "churn", "guarded_calls", "guarded_unexpected"):
            totals[name] += c.get("health", {}).get(name, 0)
    rows = []
    for key, cases in sorted(groups.items()):
        rows.append(dict(backend=key[0], hold_us=key[1], target=key[2], cases=len(cases),
                         any_detected=sum(c["outcome"] == "detected" for c in cases),
                         ctx=sum(any("rule=ctx_v151 " in s for s in c.get("findings", [])) for c in cases),
                         x16=sum(any("rule=x16_boundary " in s for s in c.get("findings", [])) for c in cases),
                         inconclusive=sum(c["outcome"] == "inconclusive_context" for c in cases),
                         errors=sum(c["outcome"] == "test_error" for c in cases)))
    perf = []
    for enabled in (0, 1):
        phases = [x for x in data["baseline"].get("benchmark", []) if x["enabled"] == enabled]
        if not phases:
            continue
        elapsed = sum(x["elapsed_ns"] for x in phases)
        perf.append(dict(enabled=enabled, phases=len(phases), seconds=elapsed / 1e9,
                         scanner_one_core_cpu_percent=100 * sum(x["cpu_ns"] for x in phases) / elapsed,
                         scanner_cpu_ms_per_scan=(sum(x["cpu_ns"] for x in phases) / 1e6 /
                                                  max(1, sum(x["scans"] for x in phases))),
                         workload_batches_per_second=sum(x["work"] for x in phases) / (elapsed / 1e9),
                         frames_per_second=sum(x["frames"] for x in phases) / (elapsed / 1e9),
                         work_p99_us_by_phase=[x["work_p99_us"] for x in phases],
                         median_work_p99_upper_us=statistics.median(x["work_p99_us"] for x in phases),
                         frame_p99_upper_us_by_phase=[x["frame_p99_us"] for x in phases],
                         scan_p99_upper_us_by_phase=[x["scan_p99_us"] for x in phases]))
    return dict(evidence=str(directory), result=data["result"], period_ms=data.get("period_ms", 50),
                cases=len(data["cases"]), outcomes=dict(collections.Counter(x["outcome"] for x in data["cases"])),
                constructors=sum(x.get("constructor_end", False) for x in data["cases"]),
                alive=sum(x.get("alive", False) for x in data["cases"]), groups=rows,
                baseline=data["baseline"].get("stress", {}), performance=perf, recorded_totals=totals,
                cleanup={k: data.get(k) for k in ("final_kpm_num", "test_app_uninstalled", "remote_test_files_removed",
                                                 "boot_unchanged", "selinux_unchanged", "module_left_loaded")})


if __name__ == "__main__":
    for argument in sys.argv[1:]:
        result = summarize(argument)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        (Path(argument) / "analysis.json").write_text(text, encoding="utf-8")
        print(text)
