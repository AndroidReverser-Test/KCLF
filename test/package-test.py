"""Test the existing benign KCLF payload in explicitly selected installed apps.

Requires a freshly built kclf.kpm, an Android NDK clang executable, adb, and
KCLF_SUPERKEY in the environment. Apps must initially be stopped. The runner
launches and force-stops only the selected packages, never clears their data,
and removes its uniquely named libraries and markers after each package.
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
import sys
import time
import traceback
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="append", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--observe", type=float, default=5)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    key = os.environ.get("KCLF_SUPERKEY")
    if not key:
        parser.error("set KCLF_SUPERKEY in the process environment")
    if args.repeat < 1 or args.repeat > 20 or args.observe < 1:
        parser.error("repeat must be 1..20 and observe must be >= 1 second")
    for package in args.package:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package):
            parser.error("invalid package name")
    module_dir = Path(__file__).resolve().parents[1]
    repo = module_dir.parents[1]
    run_id = "kclf-packages-" + uuid.uuid4().hex[:12]
    out = (args.out or repo / "build" / run_id).resolve()
    out.mkdir(parents=True, exist_ok=False)
    remote = "/data/local/tmp/" + run_id
    prefix = run_id.replace("-", "_") + "_"
    events = []
    results = []
    cleanup_errors = []
    loaded = False
    module = out / "kclf.kpm"
    shutil.copyfile(module_dir / "kclf.kpm", module)
    shutil.copyfile(__file__, out / "package-test.py")
    shutil.copyfile(module_dir / "test/app/jni/payload.c", out / "payload.c")

    def log(message):
        message = str(message).replace(key, "<redacted>")
        events.append(message)
        print(message, flush=True)

    def save(name, value):
        (out / name).write_text(value, encoding="utf-8")

    def run(command, allow=False, timeout=30):
        process = subprocess.run([str(x) for x in command], capture_output=True,
                                 encoding="utf-8", errors="replace", timeout=timeout)
        text = (process.stdout + process.stderr).strip().replace(key, "<redacted>")
        if process.returncode and not allow:
            raise RuntimeError(f"command failed rc={process.returncode}: {text}")
        return process.returncode, text

    def adb(*parts, allow=False, timeout=30):
        return run([args.adb, "-s", args.serial, *parts], allow, timeout)

    def shell(*parts, allow=False, timeout=30):
        command = " ".join(shlex.quote(str(x)) for x in parts)
        return adb("shell", command, allow=allow, timeout=timeout)[1]

    def root(command, allow=False):
        return shell("/data/local/tmp/kpatch", key, "su", "-c", command, allow=allow)

    def ctl(command, allow=False):
        rc, value = adb("shell", " ".join(shlex.quote(x) for x in
                       ["/data/local/tmp/kpatch", key, "kpm", "ctl0", "kclf", command]),
                       allow=allow)
        log(f"ctl {command}: rc={rc}\n{value}")
        return rc, value

    def kpm(*parts, allow=False):
        value = shell("/data/local/tmp/kpatch", key, "kpm", *parts, allow=allow)
        log("kpm " + " ".join(parts) + ": " + value)
        return value

    def check(condition, message):
        if not condition:
            raise RuntimeError(message)
        log("PASS: " + message)

    def process_id(package):
        value = shell("pidof", package, allow=True).strip()
        return int(value) if value.isdigit() else None

    def stop(package):
        old = process_id(package)
        shell("am", "force-stop", package)
        if old:
            for _ in range(30):
                if root(f"if [ -d /proc/{old} ]; then echo alive; else echo gone; fi") == "gone":
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(f"old process {old} did not exit")

    def start(package, component):
        value = shell("am", "start", "-W", "-n", component, timeout=45)
        log(value)
        check("Status: ok" in value, f"{package}: activity starts")
        time.sleep(args.observe)
        target = process_id(package)
        check(target is not None, f"{package}: one main process running")
        return target

    def wait_result():
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            _, value = ctl("status")
            if re.search(r"state=(done|failed|cancelled)", value) and not re.search(r"pending=| map=", value):
                return value
            time.sleep(0.15)
        raise RuntimeError("injection timed out; module must be drained before unloading")

    baseline = {}
    try:
        baseline["modules"] = kpm("list")
        check(not re.search(r"(?m)^kclf\s*$", baseline["modules"]), "no existing kclf module")
        for package in args.package:
            check(not shell("pidof", package, allow=True).strip(), f"{package}: initially stopped")
        baseline["boot_id"] = root("cat /proc/sys/kernel/random/boot_id")
        baseline["selinux"] = root("getenforce")
        baseline["kernel"] = shell("uname", "-a")
        baseline["serial"] = args.serial
        baseline["module_sha256"] = hashlib.sha256(module.read_bytes()).hexdigest()
        baseline["dmesg"] = root("dmesg")
        baseline["crash"] = shell("logcat", "-b", "crash", "-d", "-v", "threadtime")
        save("baseline.json", json.dumps({k: v for k, v in baseline.items()
                                          if k not in ("dmesg", "crash")}, indent=2))
        save("dmesg-before.txt", baseline["dmesg"])
        save("crash-before.txt", baseline["crash"])
        shell("mkdir", remote)
        adb("push", module, remote + "/kclf.kpm")
        kpm("load", remote + "/kclf.kpm")
        loaded = True
        check(bool(re.search(r"(?m)^kclf\s*$", kpm("list"))), "module is really loaded")
        _, probe = ctl("probe")
        save("probe.txt", probe)
        check("pt_regs=ok" in probe and "hook=getpid" in probe, "runtime frame and completion hook ready")
        ctl("sym")

        for index, package in enumerate(args.package):
            record = {"package": package, "cases": [], "passed": False}
            results.append(record)
            paths = []
            markers = []
            launched = False
            try:
                log("PACKAGE: " + package)
                package_dump = shell("dumpsys", "package", package)
                save(package + "-package.txt", package_dump)
                code_match = re.search(r"(?m)^\s*codePath=(/data/app/\S+)\s*$", package_dump)
                check(code_match is not None and "primaryCpuAbi=arm64-v8a" in package_dump,
                      "installed arm64 package path resolved")
                libdir = code_match[1] + "/lib/arm64"
                files = f"/data/user/0/{package}/files"
                root("test -d " + shlex.quote(libdir) + " && test -d " + shlex.quote(files))
                library = libdir + f"/lib{prefix}{index}.so"
                truncated = libdir + f"/lib{prefix}{index}_truncated.so"
                planned_paths = [library, truncated]
                local_so = out / Path(library).name
                build = [args.clang, "--target=aarch64-linux-android26", "-shared", "-fPIC", "-O2",
                         "-Wall", "-Wextra", "-Werror", "-ffixed-x18", "-Wl,-z,max-page-size=16384",
                         f'-DKCLF_APP_FILES="{files}"', f'-DKCLF_APP_MARKER_PREFIX="{prefix}"',
                         module_dir / "test/app/jni/payload.c", "-o", local_so]
                _, compiler_output = run(build)
                save(package + "-build.txt", subprocess.list2cmdline([str(x) for x in build]) + "\n" + compiler_output)
                record["payload_sha256"] = hashlib.sha256(local_so.read_bytes()).hexdigest()
                readelf = args.clang.with_name("llvm-readelf.exe" if os.name == "nt" else "llvm-readelf")
                if readelf.exists():
                    save(package + "-elf.txt", run([readelf, "-h", "-l", "-d", local_so])[1])
                adb("push", local_so, remote + "/" + local_so.name)
                for path in planned_paths:
                    root("test ! -e " + shlex.quote(path))
                # Copy only uniquely named test files; retain the app's normal apk_data_file label.
                root("cp " + shlex.quote(remote + "/" + local_so.name) + " " + shlex.quote(library))
                paths.append(library)
                root("dd if=" + shlex.quote(library) + " of=" + shlex.quote(truncated) + " bs=64 count=1 2>/dev/null")
                paths.append(truncated)
                for path in paths:
                    root("chown 1000:1000 " + shlex.quote(path) + " && chmod 0644 " + shlex.quote(path) +
                         " && chcon u:object_r:apk_data_file:s0 " + shlex.quote(path))
                save(package + "-file-labels.txt", root("ls -lZ " + " ".join(map(shlex.quote, paths))))
                component = shell("cmd", "package", "resolve-activity", "--brief", package).splitlines()[-1].strip()
                check(component.startswith(package + "/"), "launcher component resolved")
                launched = True
                target = start(package, component)
                record["pid"] = target
                record["component"] = component
                record["library"] = library
                status = root(f"cat /proc/{target}/status")
                domain = root(f"cat /proc/{target}/attr/current")
                save(package + "-status.txt", status + "\n" + domain)
                check(re.search(r"Seccomp:\s+2", status) is not None and "untrusted_app" in domain,
                      "ordinary app keeps seccomp and SELinux domain")
                threads = root(f"ps -T -p {target} -o TID,CMD")
                save(package + "-threads.txt", threads)
                save(package + "-maps-before.txt", root(f"cat /proc/{target}/maps"))
                marker = files + "/" + prefix + str(target)
                root("test ! -e " + shlex.quote(marker))
                markers.append(marker)

                def inject_case(name, tid, path, unload=False, expected="done", error=None):
                    root("rm -f " + shlex.quote(marker))
                    command = f"inject,{tid},{path},wake,linker" + (",unload" if unload else "")
                    started = time.monotonic()
                    ctl(command)
                    value = wait_result()
                    elapsed = time.monotonic() - started
                    save(package + "-" + name + "-status.txt", value)
                    check("state=" + expected in value and "loading=0" in value,
                          name + ": expected terminal state with no outstanding callbacks/mapping")
                    if error is not None:
                        check(error in value, name + ": expected diagnostic")
                    check(process_id(package) == target, name + ": original process survives")
                    maps = root(f"cat /proc/{target}/maps")
                    save(package + "-" + name + "-maps.txt", maps)
                    witness = None
                    if expected == "done":
                        check("via=__loader_dlopen" in value, name + ": Android loader used")
                        witness = root("cat " + shlex.quote(marker))
                        log("marker: " + witness)
                        save(package + "-" + name + "-marker.txt", witness)
                        check(re.search(rf"^pid={target} tid={tid} marker=0x[0-9a-f]+$", witness) is not None,
                              name + ": constructor executes in the exact PID/TID")
                        check((Path(path).name in maps) != unload, name + ": expected SO mapping lifetime")
                        if unload:
                            check("unload=ok rc=0" in value, name + ": dlclose succeeds")
                    else:
                        check(Path(path).name not in maps, name + ": failed SO has no persistent mapping")
                        check(root("if [ -e " + shlex.quote(marker) + " ]; then echo hit; else echo absent; fi") == "absent",
                              name + ": failed payload constructor did not execute")
                    record["cases"].append({"name": name, "tid": tid, "status": value,
                                             "marker": witness, "seconds": round(elapsed, 3)})
                    ctl("reap")

                inject_case("missing", target, library + ".missing", expected="failed", error="stage=prepare")
                inject_case("truncated", target, truncated, expected="failed", error="stage=loader")
                for iteration in range(args.repeat):
                    inject_case(f"main-unload-{iteration + 1}", target, library, unload=True)
                binders = re.findall(r"(?mi)^\s*(\d+)\s+binder:[^\n]+$", threads)
                check(bool(binders), "a Binder worker exists")
                binder = int(binders[0])
                record["binder_tid"] = binder
                inject_case("binder-unload", binder, library, unload=True)
                inject_case("main-resident", target, library)
                time.sleep(args.observe)
                check(process_id(package) == target, "resident payload observation: original process remains alive")
                save(package + "-activity-after.txt", shell("dumpsys", "activity", "activities"))
                stop(package)
                replacement = start(package, component)
                record["restart_pid"] = replacement
                check(replacement != target, "force-stop and restart creates a new process")
                check(Path(library).name not in root(f"cat /proc/{replacement}/maps"),
                      "new process does not inherit injected SO")
                record["passed"] = True
            except Exception as exc:
                record["error"] = str(exc).replace(key, "<redacted>")
                log("PACKAGE ERROR: " + record["error"])
                save(package + "-error.txt", traceback.format_exc().replace(key, "<redacted>"))
            finally:
                try:
                    if launched:
                        stop(package)
                    ctl("reap")
                    if paths or markers:
                        root("rm -f " + " ".join(map(shlex.quote, paths + markers)))
                    check(not shell("pidof", package, allow=True).strip(), package + ": stopped state restored")
                    for path in paths + markers:
                        root("test ! -e " + shlex.quote(path))
                    log("PASS: " + package + ": unique test libraries and markers removed")
                except Exception as exc:
                    cleanup_errors.append(str(exc))
                    log("PACKAGE CLEANUP ERROR: " + str(exc))
    except Exception as exc:
        cleanup_errors.append(str(exc).replace(key, "<redacted>"))
        log("RUN ERROR: " + str(exc))
        save("error.txt", traceback.format_exc().replace(key, "<redacted>"))
    finally:
        if loaded:
            try:
                ctl("reap")
                rc, quiet = ctl("quiesce", allow=True)
                check(rc == 0 and "quiesce=idle" in quiet, "all work drained before module unload")
                ctl("reap")
                kpm("unload", "kclf")
                loaded = False
                check(kpm("list") == baseline["modules"], "original KPM list restored")
            except Exception as exc:
                cleanup_errors.append(str(exc))
                log("MODULE CLEANUP ERROR: " + str(exc))
        if "dmesg" in baseline:
            try:
                after = root("dmesg")
                crash = shell("logcat", "-b", "crash", "-d", "-v", "threadtime")
                save("dmesg-after.txt", after)
                save("crash-after.txt", crash)
                save("logcat-after.txt", shell("logcat", "-d", "-v", "threadtime", timeout=45))
                faults = [line for line in after.splitlines()
                          if re.search(r"BUG:|WARNING:|Oops:|Kernel panic", line)
                          and line not in baseline["dmesg"]]
                new_crash = [line for line in crash.splitlines() if line not in baseline["crash"]]
                target_crashes = [line for line in new_crash if any(p in line for p in args.package)]
                save("new-kernel-faults.txt", "\n".join(faults))
                save("new-target-crashes.txt", "\n".join(target_crashes))
                check(not faults, "no new retained kernel BUG/WARNING/Oops/panic")
                check(not target_crashes, "no new target-app entry in retained crash buffer")
                check(root("cat /proc/sys/kernel/random/boot_id") == baseline["boot_id"], "device did not reboot")
                check(root("getenforce") == baseline["selinux"], "SELinux mode unchanged")
                if not loaded:
                    # Only remove files created by this run; rmdir requires an empty directory.
                    staged = [remote + "/kclf.kpm"] + [remote + "/" + p.name for p in out.glob("*.so")]
                    root("rm -f " + " ".join(map(shlex.quote, staged)))
                    root("rmdir " + shlex.quote(remote))
            except Exception as exc:
                cleanup_errors.append(str(exc))
                log("FINAL VERIFICATION ERROR: " + str(exc))
        passed = len(results) == len(args.package) and all(r["passed"] for r in results) and not cleanup_errors
        summary = {"run_id": run_id, "passed": passed, "packages": results,
                   "cleanup_errors": cleanup_errors, "module_retained": loaded}
        save("summary.json", json.dumps(summary, ensure_ascii=False, indent=2))
        log("ALL PACKAGE CASES PASSED" if passed else "PACKAGE TEST FAILED; see summary.json")
        save("results.txt", "\n".join(events) + "\n")
        print("Evidence: " + str(out), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
