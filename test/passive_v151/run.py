#!/usr/bin/env python3
"""Isolated passive KCLF 1.5.1 ordinary-App detection and overhead measurement.

Never alters the injector. Only a previously absent test package and a unique
remote directory are changed. KCLF_SUPERKEY is never persisted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
import uuid
import zipfile

PACKAGE = "com.kclf.passive151"
LOG = f"/data/user/0/{PACKAGE}/files/events.txt"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--serial", required=True)
    p.add_argument("--adb", default="adb")
    p.add_argument("--sdk", default="D:/androidSDK")
    p.add_argument("--ndk", default="D:/androidSDK/ndk/27.0.12077973")
    p.add_argument("--suite", choices=("pilot", "full", "bench"), default="pilot")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--period-ms", type=int, choices=(50, 100, 250), default=50)
    p.add_argument("--build-only", action="store_true")
    args = p.parse_args()
    if not 1 <= args.rounds <= 10:
        p.error("rounds must be 1..10")
    source = Path(__file__).resolve().parent
    module = source.parents[1]
    workspace = module.parents[1]
    output = workspace / "build" / ("kclf-passive-" + uuid.uuid4().hex[:12])
    output.mkdir(parents=True)
    snapshot = output / "source"
    snapshot.mkdir()
    for file in source.iterdir():
        if file.is_file():
            shutil.copy2(file, snapshot / file.name)
    remote = "/data/local/tmp/" + output.name
    key = os.environ.get("KCLF_SUPERKEY", "")
    if not args.build_only and not re.fullmatch(r"[A-Za-z0-9_.+-]+", key):
        raise SystemExit("Set KCLF_SUPERKEY")
    summary = {"output": str(output), "package": PACKAGE, "suite": args.suite,
               "rounds": args.rounds, "period_ms": args.period_ms, "cases": [], "commands": [], "baseline": {}}
    installed = loaded = started = remote_created = False
    print("Evidence: " + str(output), flush=True)

    def redact(s):
        return s.replace(key, "<redacted>") if key else s

    def save(name, data):
        (output / name).write_text(redact(data), encoding="utf-8")

    def persist():
        save("summary.json", json.dumps(summary, indent=2, ensure_ascii=False))

    def run(command, check=True, timeout=60):
        result = subprocess.run([str(x) for x in command], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(redact(result.stdout + result.stderr))
        return result

    def adb(*words, check=True):
        return run([args.adb, "-s", args.serial, *words], check=check)

    def root(command, check=True):
        return adb("shell", f"/data/local/tmp/kpatch {key} su -c {shlex.quote(command)}", check=check).stdout.strip()

    def kpm(*words, check=True):
        result = adb("shell", "/data/local/tmp/kpatch", key, "kpm", *words, check=False)
        summary["commands"].append({"kpm": list(words), "rc": result.returncode, "output": result.stdout.strip()})
        if check and result.returncode:
            raise RuntimeError("KPM " + redact(result.stdout + result.stderr))
        return result.stdout.strip()

    def ctl(command):
        return kpm("ctl0", "kclf", command)

    def events():
        return root("cat " + shlex.quote(LOG), check=False)

    def wait(action, predicate, seconds=20):
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            last = action()
            if predicate(last):
                return last
            time.sleep(.1)
        raise TimeoutError(str(last)[-4000:])

    def fields(line):
        return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)(?:\s|$)", line)}

    def health(text):
        lines = [x for x in text.splitlines() if x.startswith("HEALTH ")]
        return fields(lines[-1]) if lines else {}

    def stop():
        nonlocal started
        if started:
            adb("shell", "am", "force-stop", PACKAGE)
            wait(lambda: adb("shell", "pidof", PACKAGE, check=False).stdout.strip(), lambda x: not x)
            started = False
        if loaded:
            ctl("reap")

    def start(mode="scan"):
        nonlocal started
        stop()
        started = True
        adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity", "--es", "mode", mode)
        pid = wait(lambda: adb("shell", "pidof", PACKAGE, check=False).stdout.strip(), lambda x: x.isdigit())
        def ready(text):
            if "ERROR" in text:
                raise RuntimeError(text)
            return f"READY pid={pid} " in text
        text = wait(events, ready)
        needed = ["dumpable=0", "seccomp=2 no_new_privs=0", "CapEff:\t0000000000000000", "untrusted_app",
                  "CONTROLS ", "nice=10 priority_rc=0"]
        if any(x not in text for x in needed) or " uid=0 " in text or "DETECT " in text:
            raise AssertionError("Ordinary identity / negative controls failed: " + text)
        ready_line = next(x for x in text.splitlines() if x.startswith("READY "))
        tids = fields(ready_line)
        libs = re.search(r"library=(\S+)", ready_line)[1]
        time.sleep(.25)
        return int(pid), tids, libs, text

    def case(index, target, hold, unload, backend="manual"):
        name = f"{index:03}-{target}-{hold}us-{backend}-{'unload' if unload else 'resident'}"
        result = {"name": name, "target": target, "hold_us": hold, "unload": unload, "backend": backend}
        summary["cases"].append(result)
        try:
            pid, tids, libs, before = start()
            tid = tids[target]
            result.update(pid=pid, tid=tid, observer=tids["scanner"])
            save(name + ".before.txt", before)
            result["queued"] = ctl(f"inject,{tid},{libs}/libpayload{hold}.so,{backend},wake" + (",unload" if unload else ""))
            if "queued id=" not in result["queued"]:
                raise RuntimeError(result["queued"])
            def complete(status):
                if "state=failed" in status:
                    raise RuntimeError(status)
                return "state=done" in status and "pending=" not in status and " map=" not in status
            status = wait(lambda: ctl("status"), complete, seconds=15)
            time.sleep(1.1)
            text = events()
            save(name + ".events.txt", text)
            save(name + ".status.txt", status)
            findings = [x for x in text.splitlines() if x.startswith("DETECT ")]
            markers = [x for x in text.splitlines() if x.startswith("PAYLOAD ")]
            marker_ok = lambda phase: any(f"phase={phase} " in x and f"pid={pid} tid={tid} " in x for x in markers)
            result.update(status=status, detections=len(findings), findings=findings, markers=markers,
                          constructor_begin=marker_ok("BEGIN"), constructor_end=marker_ok("END"),
                          finalizer=marker_ok("FINI"), health=health(text),
                          alive=adb("shell", "pidof", PACKAGE, check=False).stdout.strip() == str(pid))
            if findings and markers:
                first = int(re.search(r"ns=(\d+)", findings[0])[1])
                begin = next(int(re.search(r"ns=(\d+)", x)[1]) for x in markers if "phase=BEGIN " in x)
                result["detect_after_constructor_begin_us"] = (first - begin) / 1000
            if not result["constructor_begin"] or not result["constructor_end"] or not result["alive"]:
                raise AssertionError("Injection execution/liveness not established")
            if unload and not result["finalizer"]:
                raise AssertionError("Finalizer not observed")
            if not result["health"] or result["health"].get("errors") or result["health"].get("maps_fail"):
                raise AssertionError("Missing health or business/maps errors")
            if "ERROR" in text:
                raise AssertionError(text)
            result["outcome"] = ("detected" if findings else "inconclusive_context" if
                                 result["health"].get("guarded_unexpected") else "executed_not_detected")
            print(f"CASE {name} {result['outcome']} detections={len(findings)} work_errors={result['health']['errors']}", flush=True)
        except Exception as error:
            result["outcome"] = "test_error"
            result["error"] = redact(str(error))
            save(name + ".error-events.txt", events())
            print("CASE ERROR " + name + " " + result["error"], flush=True)
            raise
        finally:
            stop()
            persist()

    try:
        sdk = Path(args.sdk)
        bt = sdk / "build-tools/35.0.1"
        android_jar = max((sdk / "platforms").glob("android-*"), key=lambda x: int(x.name.split("-")[-1])) / "android.jar"
        cc = Path(args.ndk) / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
        for directory in ("classes", "dex"):
            (output / directory).mkdir()
        common = [cc, "--target=aarch64-linux-android31", "-O2", "-Wall", "-Wextra", "-Werror",
                  "-shared", "-fPIC", "-Wl,-z,max-page-size=16384"]
        run([*common, "-DKCLF_CODEGEN_HOST", f"-DPERIOD_NS={args.period_ms * 1000000}ULL",
             source / "probe.c", source / "gate.S", module / "kclf_codegen.c", "-ldl",
             "-o", output / "libpassive151.so"])
        run([*common, source / "normal.c", "-o", output / "libnormal.so"])
        for hold in (0, 2000, 20000, 200000):
            run([*common, f"-DHOLD_US={hold}", source / "payload.c", f"-Wl,-soname,libpayload{hold}.so",
                 "-o", output / f"libpayload{hold}.so"])
        run(["javac", "-source", "8", "-target", "8", "-Xlint:-options", "-classpath", android_jar,
             "-d", output / "classes", source / "MainActivity.java"])
        run([bt / "d8.bat", "--lib", android_jar, "--min-api", "31", "--output", output / "dex",
             *sorted((output / "classes").rglob("*.class"))])
        run([bt / "aapt2.exe", "link", "--manifest", source / "AndroidManifest.xml", "-I", android_jar,
             "--min-sdk-version", "31", "--target-sdk-version", "35", "-o", output / "base.apk"])
        with zipfile.ZipFile(output / "base.apk", "a", zipfile.ZIP_DEFLATED) as z:
            z.write(output / "dex/classes.dex", "classes.dex")
            for library in sorted(output.glob("*.so")):
                z.write(library, "lib/arm64-v8a/" + library.name)
        keystore = output / "test.keystore"
        run(["keytool", "-genkeypair", "-keystore", keystore, "-storepass", "android", "-keypass", "android",
             "-alias", "test", "-dname", "CN=KCLF Passive Audit", "-keyalg", "RSA", "-validity", "30"])
        run([bt / "zipalign.exe", "-f", "4", output / "base.apk", output / "aligned.apk"])
        run([bt / "apksigner.bat", "sign", "--ks", keystore, "--ks-pass", "pass:android", "--key-pass",
             "pass:android", "--out", output / "app.apk", output / "aligned.apk"])
        run([bt / "apksigner.bat", "verify", output / "app.apk"])
        sha = lambda file: hashlib.sha256(Path(file).read_bytes()).hexdigest()
        summary.update(module_sha256=sha(module / "kclf.kpm"), apk_sha256=sha(output / "app.apk"),
                       source_sha256={x.name: sha(x) for x in source.iterdir() if x.is_file()},
                       generator_sha256=sha(module / "kclf_codegen.c"))
        if args.build_only:
            summary["result"] = "built_only"
            return
        if kpm("num") != "0":
            raise RuntimeError("Existing KPM: refusing to change device state")
        if adb("shell", "pm", "path", PACKAGE, check=False).stdout.strip():
            raise RuntimeError("Test package already exists: refusing to replace it")
        summary["device"] = {
            "android": adb("shell", "getprop", "ro.build.version.release").stdout.strip(),
            "kernel": adb("shell", "uname", "-a").stdout.strip(),
            "selinux": adb("shell", "getenforce").stdout.strip(),
            "boot_id": adb("shell", "cat", "/proc/sys/kernel/random/boot_id").stdout.strip(),
        }
        adb("shell", "mkdir", remote)
        remote_created = True
        adb("push", module / "kclf.kpm", remote + "/kclf.kpm")
        adb("install", "-t", output / "app.apk")
        installed = True
        start()
        time.sleep(10)
        text = events()
        save("baseline-stress.txt", text)
        h = health(text)
        if ("DETECT " in text or "INCONCLUSIVE " in text or not h or h["errors"] or h["maps_fail"] or
                h["rejected"] < 5000 // args.period_ms or h["churn"] < 100):
            raise AssertionError("Passive negative/stress baseline failed: " + text)
        summary["baseline"]["stress"] = h
        print("PASS negative stress: exact-template decoy rejected, no detections/business errors", flush=True)
        if args.suite in ("full", "bench"):
            start("bench")
            text = wait(events, lambda x: "BENCH_DONE" in x, seconds=55)
            save("baseline-benchmark.txt", text)
            phases = [fields(x) for x in text.splitlines() if x.startswith("BENCH ")]
            summary["baseline"]["benchmark"] = phases
            if len(phases) != 8 or any(x["errors"] or x["detections"] for x in phases) or "DETECT " in text or "INCONCLUSIVE " in text:
                raise AssertionError("Paired overhead benchmark failed")
            print("PASS 8 paired scan-off/on benchmark phases", flush=True)
        stop()
        if args.suite == "bench":
            summary["result"] = "completed_benchmark"
            return
        kpm("load", remote + "/kclf.kpm")
        loaded = True
        save("probe.txt", ctl("probe"))
        matrix = [("pre", 200000, True), ("pre", 0, True), ("pre", 0, False), ("scanner", 200000, True),
                  ("guarded",0,True),("guarded",0,False)]
        if args.suite == "full":
            matrix = [(target, hold, unload) for _ in range(args.rounds)
                      for hold in (0, 20000, 200000) for target in ("main", "pre", "new", "scanner", "guarded")
                      for unload in (False, True)]
            matrix += [("pre", 2000, True)] * args.rounds
        for i, (target, hold, unload) in enumerate(matrix, 1):
            case(i, target, hold, unload)
        if args.suite == "full":
            for j in range(args.rounds):
                case(len(matrix) + j + 1, "new", 200000, False, "linker")
        summary["result"] = "completed_measurement"
    except Exception as error:
        summary["result"] = "test_error"
        summary["error"] = redact(str(error))
        print("ERROR " + summary["error"], flush=True)
        raise
    finally:
        if installed:
            try:
                save("last-events.txt", events())
                stop()
            except Exception as error:
                summary["stop_error"] = redact(str(error))
        if loaded:
            try:
                ctl("reap")
                idle = ctl("quiesce")
                save("quiesce.txt", idle)
                if "quiesce=idle" in idle:
                    kpm("unload", "kclf")
                    loaded = False
                else:
                    summary["cleanup_error"] = "Not idle; module deliberately retained"
            except Exception as error:
                summary["cleanup_error"] = redact(str(error))
        if installed and not loaded:
            try:
                adb("uninstall", PACKAGE)
                installed = False
                summary["test_app_uninstalled"] = True
            except Exception as error:
                summary["uninstall_error"] = redact(str(error))
        if remote_created and not loaded:
            try:
                # Exact per-run paths; never a recursive or shared-directory removal.
                adb("shell", "rm", "-f", remote + "/kclf.kpm")
                adb("shell", "rmdir", remote)
                summary["remote_test_files_removed"] = True
            except Exception as error:
                summary["remote_cleanup_error"] = redact(str(error))
        if "device" in summary:
            summary["final_kpm_num"] = kpm("num", check=False)
            summary["boot_unchanged"] = adb("shell", "cat", "/proc/sys/kernel/random/boot_id").stdout.strip() == summary["device"]["boot_id"]
            summary["selinux_unchanged"] = adb("shell", "getenforce").stdout.strip() == summary["device"]["selinux"]
        summary["module_left_loaded"] = loaded
        summary["app_left_installed"] = installed
        persist()
        print("Evidence: " + str(output), flush=True)


if __name__ == "__main__":
    main()
