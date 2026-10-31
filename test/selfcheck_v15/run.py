#!/usr/bin/env python3
"""Run an isolated, non-debuggable ordinary-App KCLF 1.5.x self-check audit.

Only this newly installed package and this run's module are modified. The
injector is copied byte-for-byte, not patched. KCLF_SUPERKEY is never saved.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid
import zipfile

PACKAGE = "com.kclf.selfcheckv15"
PRIVATE = "/data/user/0/" + PACKAGE + "/files/events.txt"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--sdk", default="D:/androidSDK")
    parser.add_argument("--ndk", default="D:/androidSDK/ndk/27.0.12077973")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--suite", choices=("pilot", "full"), default="pilot")
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 20:
        parser.error("rounds must be 1..20")
    source = Path(__file__).resolve().parent
    module = source.parents[1]
    workspace = module.parents[1]
    output = workspace / "build" / ("kclf-selfcheck-" + uuid.uuid4().hex[:12])
    output.mkdir(parents=True)
    key = os.environ.get("KCLF_SUPERKEY", "")
    if not args.build_only and not re.fullmatch(r"[A-Za-z0-9_.+-]+", key):
        raise SystemExit("Set KCLF_SUPERKEY in the environment")
    summary = {"output": str(output), "package": PACKAGE, "suite": args.suite,
               "rounds": args.rounds, "cases": [], "commands": []}
    installed = loaded = started = False
    remote = "/data/local/tmp/" + output.name
    print("Evidence: " + str(output), flush=True)

    def redact(value):
        return value.replace(key, "<redacted>") if key else value

    def save(name, data):
        (output / name).write_text(redact(data), encoding="utf-8")

    def run(command, check=True, timeout=60):
        result = subprocess.run([str(w) for w in command], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(redact(result.stdout + result.stderr))
        return result

    def adb(*words, check=True):
        return run([args.adb, "-s", args.serial, *words], check=check)

    def root(command, check=True):
        return adb("shell", f"/data/local/tmp/kpatch {key} su -c {shlex.quote(command)}",
                   check=check).stdout.strip()

    def kpm(*words, check=True):
        result = adb("shell", "/data/local/tmp/kpatch", key, "kpm", *words, check=False)
        summary["commands"].append({"kpm": list(words), "rc": result.returncode,
                                     "output": result.stdout.strip()})
        if check and result.returncode:
            raise RuntimeError("KPM: " + redact(result.stdout + result.stderr))
        return result.stdout.strip()

    def ctl(command, check=True):
        return kpm("ctl0", "kclf", command, check=check)

    def events():
        return root("cat " + shlex.quote(PRIVATE), check=False)

    def wait(action, predicate, seconds=20):
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            last = action()
            if predicate(last):
                return last
            time.sleep(.1)
        raise TimeoutError(str(last))

    def persist():
        save("summary.json", json.dumps(summary, ensure_ascii=False, indent=2))

    def stop():
        nonlocal started
        if started:
            adb("shell", "am", "force-stop", PACKAGE)
            wait(lambda: adb("shell", "pidof", PACKAGE, check=False).stdout.strip(), lambda s: not s)
            started = False
        if loaded:
            ctl("reap")

    def start(mode):
        nonlocal started
        stop()
        started = True
        launch = adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity",
                     "--es", "mode", mode, check=False)
        save("last-launch.txt", launch.stdout + launch.stderr)
        def ready(s):
            if "ERROR" in s:
                raise RuntimeError(s)
            return bool(re.search(r"READY pid=\d+ main=\d+ mode=" + mode, s))
        text = wait(events, ready)
        match = re.search(r"READY pid=(\d+) main=(\d+) mode=\S+ library=(\S+) detections=(\d+)", text)
        if not match or match[4] != "0":
            raise AssertionError("Baseline detection or malformed READY: " + text)
        checks = ["dumpable=0", "untrusted_app", "CapEff:\t0000000000000000", "Seccomp:\t2",
                  "FILTER tsync_rc=0", "ABI_OK"]
        if any(s not in text for s in checks) or " uid=0 " in text:
            raise AssertionError("Ordinary-app identity/coverage not established: " + text)
        controls = re.findall(r"CONTROL label=(\S+) tid=(\d+) calls=600 traps=(\d+) errors=(\d+) detections=(\d+)", text)
        if len(controls) != 3 or any(c[2:] != ("600", "0", "0") for c in controls):
            raise AssertionError("Negative controls failed: " + text)
        tids = {"main": int(match[2])}
        for label, tid in re.findall(r"THREAD_READY label=(\S+) tid=(\d+)", text):
            tids[label] = int(tid)
        if mode == "denyexec" and "EXEC_GUARD mprotect_rc=-1 errno=1 mmap_blocked=1 mmap_errno=1" not in text:
            raise AssertionError("Executable mapping filter not proven active: " + text)
        return int(match[1]), tids, match[3], text

    def one_case(index, mode, target, backend, unload=False):
        name = f"{index:03}-{mode}-{target}-{backend}-{'unload' if unload else 'resident'}"
        case = {"name": name, "mode": mode, "target": target, "backend": backend, "unload": unload}
        summary["cases"].append(case)
        try:
            pid, tids, libs, baseline = start(mode)
            tid = tids[target]
            case.update(pid=pid, tid=tid, controls=1800)
            save(name + ".before.txt", baseline)
            flags = f",{backend},wake" + (",unload" if unload else "")
            case["queued"] = ctl(f"inject,{tid},{libs}/libauditpayload.so{flags}")
            deadline = time.monotonic() + 12
            status = text = ""
            while time.monotonic() < deadline:
                text = events()
                status = ctl("status")
                if mode == "terminate" and "RESPONSE exit_group" in text:
                    break
                if "state=failed" in status:
                    break
                if "state=done" in status and "pending=" not in status and " map=" not in status:
                    break
                time.sleep(.1)
            text = events()
            save(name + ".events.txt", text)
            save(name + ".status.txt", status)
            tail = text.split("READY ")[-1]
            findings = re.findall(r"DETECT tid=(0x[0-9a-f]+) nr=(0x[0-9a-f]+)", tail)
            case["detections"] = len(findings)
            case["detected_syscalls"] = [int(nr, 16) for _, nr in findings]
            case["target_thread_matches"] = bool(findings) and all(int(t, 16) == tid for t, _ in findings)
            case["constructor_ran"] = f"PAYLOAD_INIT pid={pid} tid={tid}" in text
            case["finalizer_ran"] = f"PAYLOAD_FINI pid={pid} tid={tid}" in text
            case["constructor_before_detection"] = (case["constructor_ran"] and bool(findings) and
                                                       text.index("PAYLOAD_INIT") < text.index("DETECT tid="))
            case["status"] = status
            case["process_alive"] = bool(adb("shell", "pidof", PACKAGE, check=False).stdout.strip())
            case["framework_done"] = "state=done" in status
            case["outcome"] = "detected" if findings else "not_detected_or_not_executed"
            if mode == "terminate":
                case["response_exit"] = "RESPONSE exit_group" in text
            print(json.dumps({k: v for k, v in case.items() if k not in ("queued", "status")}, ensure_ascii=False), flush=True)
        except Exception as error:
            case["error"] = redact(str(error))
            case["outcome"] = "test_error"
            save(name + ".error-events.txt", events())
            print("CASE ERROR " + name + ": " + case["error"], flush=True)
        finally:
            stop()
            persist()

    try:
        sdk, ndk = Path(args.sdk), Path(args.ndk)
        bt = sdk / "build-tools/35.0.1"
        platform = max((sdk / "platforms").glob("android-*"), key=lambda p: int(p.name.split("-")[-1]))
        android_jar = platform / "android.jar"
        cc = ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe"
        for name in ("classes", "dex"):
            (output / name).mkdir()
        common = [cc, "--target=aarch64-linux-android31", "-O2", "-Wall", "-Wextra", "-Werror",
                  "-shared", "-fPIC", "-Wl,-z,max-page-size=16384"]
        run([*common, source / "probe.c", source / "gate.S", "-ldl", "-o", output / "libselfcheck.so"])
        run([*common, source / "payload.c", "-Wl,-soname,libauditpayload.so", "-o", output / "libauditpayload.so"])
        run(["javac", "-source", "8", "-target", "8", "-Xlint:-options", "-classpath", android_jar,
             "-d", output / "classes", source / "MainActivity.java"])
        run([bt / "d8.bat", "--lib", android_jar, "--min-api", "31", "--output", output / "dex",
             *sorted((output / "classes").rglob("*.class"))])
        run([bt / "aapt2.exe", "link", "--manifest", source / "AndroidManifest.xml", "-I", android_jar,
             "--min-sdk-version", "31", "--target-sdk-version", "35", "-o", output / "base.apk"])
        with zipfile.ZipFile(output / "base.apk", "a", zipfile.ZIP_DEFLATED) as package:
            package.write(output / "dex/classes.dex", "classes.dex")
            for name in ("libselfcheck.so", "libauditpayload.so"):
                package.write(output / name, "lib/arm64-v8a/" + name)
        keystore = output / "test.keystore"
        run(["keytool", "-genkeypair", "-keystore", keystore, "-storepass", "android", "-keypass", "android",
             "-alias", "test", "-dname", "CN=KCLF Selfcheck Test", "-keyalg", "RSA", "-validity", "30"])
        run([bt / "zipalign.exe", "-f", "4", output / "base.apk", output / "aligned.apk"])
        run([bt / "apksigner.bat", "sign", "--ks", keystore, "--ks-pass", "pass:android",
             "--key-pass", "pass:android", "--out", output / "app.apk", output / "aligned.apk"])
        run([bt / "apksigner.bat", "verify", output / "app.apk"])
        sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
        summary.update(module_sha256=sha(module / "kclf.kpm"), apk_sha256=sha(output / "app.apk"),
                       framework_commit=run(["git", "-C", module, "rev-parse", "HEAD"]).stdout.strip(),
                       source_sha256={p.name: sha(p) for p in source.iterdir() if p.is_file()})
        if args.build_only:
            summary["result"] = "built_only"
            return
        if kpm("num") != "0":
            raise RuntimeError("A KPM was already loaded; refusing to alter it")
        if adb("shell", "pm", "path", PACKAGE, check=False).stdout.strip():
            raise RuntimeError("Test package already exists; refusing to replace user data")
        summary["device"] = {
            "serial": args.serial, "kernel": adb("shell", "uname", "-a").stdout.strip(),
            "android": adb("shell", "getprop", "ro.build.version.release").stdout.strip(),
            "selinux": adb("shell", "getenforce").stdout.strip(),
            "boot_id": adb("shell", "cat", "/proc/sys/kernel/random/boot_id").stdout.strip(),
            "libc_sha256": adb("shell", "sha256sum", "/apex/com.android.runtime/lib64/bionic/libc.so").stdout.strip(),
        }
        adb("shell", "mkdir", remote)
        adb("push", module / "kclf.kpm", remote + "/kclf.kpm")
        adb("install", "-t", output / "app.apk")
        installed = True
        for mode in ("observe", "denyexec"):
            pid, tids, libs, text = start(mode)
            save("baseline-" + mode + ".txt", text)
            summary.setdefault("baselines", []).append({"mode": mode, "pid": pid, "tids": tids,
                                                        "ordinary_calls": 1800, "detections": 0})
            print("PASS baseline " + mode + " 1800/1800 trapped legitimate calls, 0 detections", flush=True)
            stop()
        kpm("load", remote + "/kclf.kpm")
        loaded = True
        save("probe.txt", ctl("probe"))
        cases = [("observe", "audit-new", "manual", True)]
        if args.suite == "full":
            cases = []
            for _ in range(args.rounds):
                for target in ("main", "audit-pre", "audit-new"):
                    for unload in (False, True):
                        cases.append(("observe", target, "manual", unload))
                cases.append(("observe", "audit-new", "linker", False))
                cases.append(("denyexec", "audit-new", "manual", True))
                cases.append(("terminate", "audit-new", "manual", False))
        for index, case in enumerate(cases, 1):
            one_case(index, *case)
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
                idle = ctl("quiesce", check=False)
                save("quiesce.txt", idle)
                if "quiesce=idle" in idle:
                    kpm("unload", "kclf")
                    loaded = False
                else:
                    summary["cleanup_error"] = "Not idle: module deliberately retained"
                summary["final_kpm_num"] = kpm("num")
            except Exception as error:
                summary["cleanup_error"] = redact(str(error))
        if installed and not loaded:
            try:
                adb("uninstall", PACKAGE)
                summary["test_app_uninstalled"] = True
                # Exact per-run targets only; never a broad or recursive delete.
                adb("shell", "rm", "-f", remote + "/kclf.kpm")
                adb("shell", "rmdir", remote)
                summary["remote_test_files_removed"] = True
            except Exception as error:
                summary["uninstall_error"] = redact(str(error))
        if "device" in summary:
            summary["boot_unchanged"] = adb("shell", "cat", "/proc/sys/kernel/random/boot_id").stdout.strip() == summary["device"]["boot_id"]
            summary["selinux_unchanged"] = adb("shell", "getenforce").stdout.strip() == summary["device"]["selinux"]
        summary["module_left_loaded"] = loaded
        persist()
        print("Evidence: " + str(output), flush=True)


if __name__ == "__main__":
    main()
