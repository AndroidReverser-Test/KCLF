#!/usr/bin/env python3
"""Drive KCLF against already-installed real apps and keep the evidence.

This is a device test, not part of the host regression.  It never installs or
clears app data.  Superkey is read from KCLF_SUPERKEY and never written to the
results.

Example:
  $env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
  python kpms/kclf/test/realapp-inject.py --serial 3bb96edd `
    --package com.chinamworld.main --package com.ss.android.ugc.aweme `
    --so /data/local/tmp/libtest.so --thread main --repeat 1
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

KPM = "kclf"


class Device:
    def __init__(self, adb, serial):
        self.adb = adb
        self.serial = serial

    def sh(self, command, timeout=60):
        argv = [self.adb]
        if self.serial:
            argv += ["-s", self.serial]
        argv += ["shell", command]
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
        text = p.stdout.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
        return p.returncode, text

    def ctl(self, key, args=""):
        return self.sh(f"/data/local/tmp/kpatch {key} kpm ctl0 {KPM} {args}".strip())


def status_line(text, request_id):
    if request_id is None:
        return None
    pattern = re.compile(r"(^|\s)id=%d\s" % request_id)
    for line in text.splitlines():
        if pattern.search(line):
            return line.strip()
    return None


def terminal(line):
    return bool(line) and ("state=done" in line or "state=failed" in line or
                           "state=cancelled" in line)


def wait_pid(dev, package, timeout=40):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, out = dev.sh(f"pidof {package}")
        pids = out.split()
        if pids:
            return pids[0]
        time.sleep(0.5)
    return None


def main_thread_tid(pid):
    return pid


def find_thread(dev, pid, kind):
    _, out = dev.sh(f"ls /proc/{pid}/task")
    tids = [t for t in out.split() if t.strip().isdigit()]
    if kind == "any":
        return tids[0] if tids else None
    for tid in tids:
        _, comm = dev.sh(f"cat /proc/{pid}/task/{tid}/comm")
        name = comm.strip()
        if kind == "binder" and name.startswith("binder"):
            return tid
        if kind == "worker" and name and not name.startswith("binder"):
            return tid
    return None


def save(outdir, name, text):
    path = outdir / name
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return path


def run_one(dev, key, package, so, thread_kind, backend, outdir, repeat_index,
            observe, do_release, timeout):
    record = {"package": package, "repeat": repeat_index, "thread_kind": thread_kind}
    pid = wait_pid(dev, package)
    if not pid:
        record["error"] = "package not running"
        return record
    record["pid"] = pid
    tid = main_thread_tid(pid) if thread_kind == "main" else find_thread(dev, pid, thread_kind)
    if not tid:
        record["error"] = f"no {thread_kind} thread"
        return record
    record["tid"] = tid
    _, comm = dev.sh(f"cat /proc/{pid}/task/{tid}/comm")
    record["comm"] = comm.strip()

    prefix = f"{package.replace('.', '_')}-{repeat_index}"
    _, before = dev.ctl(key, "status")
    save(outdir, f"{prefix}-status-before.txt", before)
    _, log_start = dev.sh("date +'%m-%d %H:%M:%S.000'")
    record["log_start"] = log_start.strip()

    flags = "wake" if backend == "manual" else "linker,wake"
    start = time.time()
    _, out = dev.ctl(key, f"inject,{tid},{so},{flags}")
    record["inject"] = out.strip()
    m = re.search(r"queued id=(\d+)", out)
    request_id = int(m.group(1)) if m else None
    record["id"] = request_id
    if request_id is None:
        record["error"] = "inject was not queued"
        save(outdir, f"{prefix}-inject.txt", out)
        record["elapsed_s"] = round(time.time() - start, 3)
        return record

    line = None
    while time.time() - start < timeout:
        _, out = dev.ctl(key, "status")
        line = status_line(out, request_id)
        if terminal(line):
            break
        time.sleep(0.2)
    record["elapsed_s"] = round(time.time() - start, 3)
    record["status"] = line
    _, after = dev.ctl(key, "status")
    save(outdir, f"{prefix}-status-after.txt", after)
    save(outdir, f"{prefix}-inject.txt", record["inject"] + "\n" + (line or ""))

    ok = bool(line) and "state=done" in line
    image = None
    if ok:
        m = re.search(r"image=(\d+)", line)
        if m:
            image = int(m.group(1))
        record["image"] = image

    if observe:
        time.sleep(observe)

    _, alive = dev.sh(f"pidof {package}")
    record["alive_after"] = bool(alive.split())
    _, logs = dev.sh(f"logcat -d --pid={pid} -T '{record['log_start']}'")
    save(outdir, f"{prefix}-logcat.txt", logs)
    record["perfare"] = [l for l in logs.splitlines() if "Perfare" in l][-4:]
    _, crash = dev.sh("logcat -d -b crash -t 300")
    save(outdir, f"{prefix}-crash-buffer.txt", crash)
    record["crash_buffer_hits"] = [l for l in crash.splitlines() if pid in l]
    _, images = dev.ctl(key, "images")
    save(outdir, f"{prefix}-images.txt", images)
    record["images"] = images.strip()

    if ok and image is not None and do_release:
        # Release every reference from a live thread of the owner process.
        refs = 0
        for line2 in images.splitlines():
            if f"image={image} " in line2 and "state=live" in line2:
                m = re.search(r"refs=(\d+)", line2)
                if m:
                    refs = int(m.group(1))
        released = 0
        for _ in range(refs):
            _, r = dev.ctl(key, f"release,{tid},{image},wake")
            save(outdir, f"{prefix}-release-{released}.txt", r)
            released += 1
            time.sleep(0.5)
        record["released"] = released
        time.sleep(0.5)
        _, images2 = dev.ctl(key, "images")
        save(outdir, f"{prefix}-images-after-release.txt", images2)
        record["images_after_release"] = images2.strip()
        _, alive2 = dev.sh(f"pidof {package}")
        record["alive_after_release"] = bool(alive2.split())
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    parser.add_argument("--adb", default=shutil.which("adb") or "adb")
    parser.add_argument("--package", action="append", required=True)
    parser.add_argument("--so", default="/data/local/tmp/libtest.so")
    parser.add_argument("--backend", choices=("manual", "linker"), default="manual")
    parser.add_argument("--thread", choices=("main", "binder", "worker", "any"), default="main")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--observe", type=float, default=12,
                        help="seconds to keep the image after a successful load; a "
                             "payload with a background thread must be given enough time "
                             "to finish before release (the driver releases afterwards)")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--no-release", action="store_true")
    parser.add_argument("--outdir", default=None)
    args = parser.parse_args()

    key = os.environ.get("KCLF_SUPERKEY")
    if not key:
        print("KCLF_SUPERKEY is not set", file=sys.stderr)
        return 2
    dev = Device(args.adb, args.serial)
    rc, probe = dev.ctl(key, "probe")
    if rc or "completion=" not in probe:
        print("kclf is not loaded or probe failed:\n" + probe, file=sys.stderr)
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = Path(args.outdir) if args.outdir else Path("build") / f"kclf-realapp-{stamp}"
    outdir.mkdir(parents=True, exist_ok=True)
    save(outdir, "probe.txt", probe)
    _, selinux = dev.sh("getenforce")
    _, boot = dev.sh("cat /proc/sys/kernel/random/boot_id")
    _, kpm = dev.sh(f"/data/local/tmp/kpatch {key} kpm list")
    meta = {"serial": args.serial, "package": args.package, "so": args.so,
            "backend": args.backend, "thread": args.thread, "repeat": args.repeat,
            "probe": probe.strip(), "selinux": selinux.strip(), "boot_id": boot.strip(),
            "kpm": kpm.strip(), "started": stamp}
    save(outdir, "meta.json", json.dumps(meta, indent=2))

    records = []
    for package in args.package:
        for i in range(args.repeat):
            print(f"[{package}] repeat {i + 1}/{args.repeat} thread={args.thread} ...", flush=True)
            rec = run_one(dev, key, package, args.so, args.thread, args.backend,
                          outdir, i, args.observe, not args.no_release, args.timeout)
            records.append(rec)
            print("  " + json.dumps({k: rec.get(k) for k in
                                     ("pid", "tid", "comm", "id", "state", "elapsed_s",
                                      "alive_after", "image", "error") if k in rec}),
                  flush=True)

    _, final_status = dev.ctl(key, "status")
    _, final_images = dev.ctl(key, "images")
    save(outdir, "status-final.txt", final_status)
    save(outdir, "images-final.txt", final_images)
    summary = {"meta": meta, "records": records,
               "final_status": final_status.strip(), "final_images": final_images.strip(),
               "passed": all("state=done" in (r.get("status") or "") and
                             r.get("alive_after") and
                             r.get("alive_after_release", True) and
                             not r.get("crash_buffer_hits") and
                             ("no manual images" in r.get("images_after_release", "no manual images"))
                             for r in records)}
    save(outdir, "summary.json", json.dumps(summary, indent=2, ensure_ascii=False))
    print(json.dumps({"outdir": str(outdir), "passed": summary["passed"]}, ensure_ascii=False))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
