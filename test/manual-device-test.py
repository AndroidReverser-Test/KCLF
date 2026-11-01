#!/usr/bin/env python3
"""Isolated native-process regression for the manual backend.

Requires KCLF_SUPERKEY in the environment; never records the key. Only this
run's processes/module are changed. No app data, SELinux or seccomp policy is
changed. Test artifacts/evidence are retained, and unsafe modules are NOT
unloaded. Run after rebuilding kclf.kpm and the ASan host tests.
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--serial", required=True)
    ap.add_argument("--clang", required=True)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--kpm", type=Path, help="test a separately built module without replacing the release artifact")
    ap.add_argument("--expect-poll", action="store_true", help="require all successful requests to complete via poll")
    ap.add_argument("--app", action="store_true", help="also exercise the installed, stopped com.kclf.apptest fixture")
    args = ap.parse_args()
    key = os.environ.get("KCLF_SUPERKEY", "")
    if not re.fullmatch(r"[A-Za-z0-9_@.+-]+", key):
        raise SystemExit("Set a shell-safe KCLF_SUPERKEY")
    module = Path(__file__).resolve().parents[1]
    kpm_file = (args.kpm or module / "kclf.kpm").resolve()
    if not kpm_file.is_file():
        raise SystemExit("KPM file does not exist")
    run_id = "kclf-manual-" + uuid.uuid4().hex[:12]
    output = module.parents[1] / "build" / run_id
    output.mkdir(parents=True)
    remote = "/data/local/tmp/" + run_id
    events, targets = [], []
    loaded = False
    functional_passed = False
    app_started = False
    package = "com.kclf.apptest"
    baseline = ""

    def adb(*words, check=True):
        try:
            r = subprocess.run([args.adb, "-s", args.serial, *words], text=True,
                               encoding="utf-8", errors="replace", capture_output=True, timeout=40)
        except subprocess.TimeoutExpired:
            # TimeoutExpired includes argv, which can contain the superkey.
            raise RuntimeError("adb operation timed out (arguments redacted)") from None
        if check and r.returncode:
            raise RuntimeError("adb operation failed: " + r.stdout + r.stderr)
        return r.returncode, r.stdout.strip()

    def root(command, check=True):
        return adb("shell", f"/data/local/tmp/kpatch {key} su -c {shlex.quote(command)}", check=check)[1]

    def kpm(*words, check=True):
        rc, text = adb("shell", "/data/local/tmp/kpatch", key, "kpm", *words, check=False)
        events.append({"command": list(words), "rc": rc, "text": text})
        if check and rc:
            raise RuntimeError(f"kpm {words}: {text} (rc={rc})")
        return rc, text

    def ctl(command, check=True):
        return kpm("ctl0", "kclf", command, check=check)[1]

    def check(value, message):
        events.append({"pass": bool(value), "message": message})
        print(("PASS " if value else "FAIL ") + message, flush=True)
        if not value:
            raise AssertionError(message)

    def wait_state(state="done"):
        until = time.monotonic() + 30
        last = ""
        while time.monotonic() < until:
            last = ctl("status")
            if f"state={state}" in last and "pending=" not in last and " map=" not in last:
                if args.expect_poll and state == "done":
                    check("done=poll" in last, "request completed through sleepable poll")
                return last
            if state == "done" and "state=failed" in last:
                raise AssertionError(last)
            time.sleep(.15)
        raise TimeoutError(last)

    def reap():
        ctl("reap")
        check("no requests" in ctl("status"), "request slot reclaimed")

    def start(mode="normal"):
        pid = int(root(f"sh {remote}/launch.sh {mode}"))
        targets.append(pid)
        # launch.sh returns before dlopen/stdio startup finishes. Arm only
        # after this owned fixture reaches its advertised idle point; otherwise
        # a correct safe-point refusal becomes a timing-dependent test failure.
        until = time.monotonic() + 10
        while time.monotonic() < until:
            fields = root(f"cat /proc/{pid}/syscall", check=False).split()
            if fields and fields[0].isdigit() and int(fields[0]) in (101, 115):
                check("kclf-target dlopen(libdl.so)=0x" in root(f"cat {remote}/{mode}.log"),
                      "owned target initialized and reached nanosleep idle point")
                return pid
            time.sleep(.05)
        raise TimeoutError("owned target did not reach its nanosleep idle point")

    def inject(pid, name="libkclf_payload.so", flags="", expected="done"):
        ctl(f"inject,{pid},{remote}/{name}{flags}")
        return wait_state(expected)

    def release(pid, identity):
        ctl(f"release,{pid},{identity},wake")
        return wait_state()

    def ranges(pid):
        return [(int(m[1], 16), int(m[2], 16), m[3]) for line in root(f"cat /proc/{pid}/maps").splitlines()
                if (m := re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)", line))]

    def overlaps(pid, begin, size):
        return [item for item in ranges(pid) if item[0] < begin + size and item[1] > begin]

    def image_extent(status):
        m = re.search(r"resident=([0-9a-f]+)\+(\d+)", status)
        return int(m[1], 16), int(m[2])

    def await_running():
        until = time.monotonic() + 10
        while time.monotonic() < until:
            value = ctl("status")
            if "state=running" in value:
                return value
            if "state=failed" in value:
                raise AssertionError(value)
            time.sleep(.05)
        raise TimeoutError("constructor did not reach RUNNING")

    def marker(pid):
        return root(f"cat {remote}/manual_{pid}.log")

    def stop(pid):
        root(f"if [ -r /proc/{pid}/cmdline ] && grep -q {remote}/kclf_target /proc/{pid}/cmdline; "
             f"then kill -KILL {pid}; fi", check=False)

    def build(name, source, *extra):
        subprocess.run([args.clang, "--target=aarch64-linux-android31", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-shared", "-fPIC", "-Wl,-z,max-page-size=16384", *extra,
                        str(module / "test" / source), "-o", str(output / name)], check=True)
        adb("push", str(output / name), remote + "/" + name)

    try:
        check("kclf" not in kpm("list")[1].splitlines(), "no pre-existing kclf module")
        events.append({"kpm_sha256": hashlib.sha256(kpm_file.read_bytes()).hexdigest(),
                       "kernel": adb("shell", "uname", "-a")[1],
                       "page_size": adb("shell", "getconf", "PAGESIZE")[1]})
        if args.app:
            check(not adb("shell", "pidof", package, check=False)[1], "test app was stopped; no existing app session is interrupted")
            apk = adb("shell", "pm", "path", package)[1].removeprefix("package:")
            check(apk.startswith("/data/app/") and apk.endswith("/base.apk"), "installed self-owned app fixture exists")
        boot = root("cat /proc/sys/kernel/random/boot_id")
        policy = root("getenforce")
        baseline = root("dmesg")
        (output / "dmesg-before.txt").write_text(baseline, encoding="utf-8")
        adb("shell", "mkdir", remote)
        adb("push", str(kpm_file), remote + "/kclf.kpm")
        for local in (module / "test/kclf_target", module / "test/libkclf_payload.so",
                      module / "test/launch.sh"):
            adb("push", str(local), remote + "/" + local.name)
        adb("shell", "chmod", "755", remote + "/kclf_target")
        if not args.smoke:
            for name, packing in (("libmanual.so", "none"), ("libmanual_aps2.so", "android"),
                                  ("libmanual_relr.so", "relr"), ("libmanual_both.so", "android+relr")):
                build(name, "manual_payload.c", "-Wl,--pack-dyn-relocs=" + packing, "-Wl,-soname," + name)
            build("libmanual_sysv.so", "manual_payload.c", "-Wl,--hash-style=sysv")
            build("libmanual_tls.so", "manual_tls.c")
            build("libmanual_ifunc.so", "manual_ifunc.c")
            build("libmanual_ifunc_init.so", "manual_ifunc_init.c")
            build("libmanual_unresolved.so", "manual_unresolved.c")
            build("libkclf_manual_absent.so", "manual_missing.c", "-Wl,-soname,libkclf_manual_absent.so")
            build("libmanual_missing.so", "manual_payload.c", "-L" + str(output), "-Wl,--no-as-needed", "-lkclf_manual_absent")
        kpm("load", remote + "/kclf.kpm")
        loaded = True
        check("pt_regs=ok" in ctl("probe"), "runtime register frame available")
        pid = start()
        for bad in (
            f"inject,{pid},{remote}/libkclf_payload.so,wake,resume",
            f"inject,{pid},{remote}/libkclf_payload.so,wake,wake",
            f"inject,{pid},{remote}/libkclf_payload.so,manual,linker",
            f"inject,{pid},{remote}/libkclf_payload.so,linker,keepelf",
            f"release,{pid},1,unload",
            f"inject,2147483648,{remote}/libkclf_payload.so",
            f"release,{pid},18446744073709551616",
            "cancel,4", "images,32", "status,unexpected",
        ):
            rc, message = kpm("ctl0", "kclf", bad, check=False)
            check(rc != 0 and "error:" in message, "invalid control command rejected with diagnostic: " + bad)
        check("no requests" in ctl("status"), "rejected commands never queue target work")
        status = inject(pid)
        check("err=" not in status, "successful load has no uninitialized error result")
        check("via=manual" in status and "refs=1" in status, "unmodified existing payload loads without linker backend")
        check(f"pid={pid} " in root(f"cat {remote}/hit_{pid}"), "original payload constructor independently witnessed")
        identity = re.search(r"image=(\d+)", status).group(1)
        reap()
        check("refs=2" in inject(pid), "same manual image reused and reference incremented")
        reap()
        check("refs=1" in release(pid, identity), "release decrements without unmapping a referenced image")
        reap()
        check("refs=0" in release(pid, identity), "last release runs finalizers and unmaps")
        reap()
        check("no manual images" in ctl("images"), "resident registry drained")
        check("via=__loader_dlopen" in inject(pid, flags=",linker,unload"), "explicit legacy linker backend still works")
        reap()
        if not args.smoke:
            for name in ("libmanual.so", "libmanual_aps2.so", "libmanual_relr.so", "libmanual_both.so", "libmanual_sysv.so"):
                case = start()
                st = inject(case, name)
                image_id = re.search(r"image=(\d+)", st).group(1)
                extent = image_extent(st)
                owned = overlaps(case, *extent)
                check(any("x" in row[2] for row in owned) and all(not ("w" in row[2] and "x" in row[2]) for row in owned),
                      name + ": executable mapping with no writable-executable pages")
                check(marker(case).splitlines() == ["init-101 value=2468 data=1 weak=1", "init-102 value=2468 data=1 weak=1"],
                      name + ": import data, undefined weak, data relocations and constructor order")
                reap()
                inject(case, name)
                reap()
                check(len(marker(case).splitlines()) == 2, name + ": repeat load does not rerun constructors")
                release(case, image_id)
                reap()
                release(case, image_id)
                reap()
                check([line.split()[0] for line in marker(case).splitlines()] == ["init-101", "init-102", "fini-102", "fini-101"],
                      name + ": finalizers run once, in reverse order")
                check(not overlaps(case, *extent), name + ": exact resident allocation unmapped")
            for name, error_text in (("libmanual_missing.so", "DT_NEEDED"), ("libmanual_tls.so", "PT_TLS"),
                                     ("libmanual_ifunc.so", "IFUNC"), ("libmanual_ifunc_init.so", "IFUNC initializer"),
                                     ("libmanual_unresolved.so", "unresolved import"),
                                     ("absent.so", "open library failed")):
                failed = inject(pid, name, expected="failed")
                check(error_text in failed, name + ": clear failure without redirect/fallback")
                reap()
                check("no manual images" in ctl("images"), name + ": failed-load mapping/registry rolled back")
            fast = start()
            check("unload=ok" in inject(fast, "libmanual_both.so", ",unload"), "construct-and-unload manual transaction")
            check(len(marker(fast).splitlines()) == 4, "immediate unload runs constructors and finalizers")
            reap()
            fp = start("fp")
            inject(fp, flags=",unload")
            reap()
            time.sleep(3)
            check("fp-state-failure" not in root(f"cat {remote}/fp.log"), "FPSIMD preserved through manual constructors")
            filtered = start("seccomp")
            inject(filtered, flags=",wake,unload")
            reap()
            check(f"pid={filtered} " in root(f"cat {remote}/hit_{filtered}"), "seccomp target completes manual trampoline")
            dying = start("hold")
            ctl(f"inject,{dying},{remote}/libkclf_payload.so")
            await_running()
            stop(dying)
            time.sleep(.5)
            reap()
            check("no manual images" in ctl("images"), "target dies in constructor: process-owned registry safely reaped")
            dead_resident = start()
            inject(dead_resident, "libmanual.so")
            reap()
            stop(dead_resident)
            time.sleep(.5)
            reap()
            check("no manual images" in ctl("images"), "target exits after successful resident load: registry reaped")
            slow = start("slow")
            ctl(f"inject,{slow},{remote}/libmanual.so")
            check("state=armed" in ctl("status"), "manual resume waits for a return boundary")
            ctl("cancel,0")
            reap()
            check("no manual images" in ctl("images"), "cancel before preparation creates no resident object")
            # Paginated metadata remains independent of four short-lived request slots.
            paged = []
            for _ in range(8):
                instance = start()
                st = inject(instance, "libmanual.so")
                paged.append((instance, re.search(r"image=(\d+)", st).group(1)))
                reap()
            found, cursor = set(), ""
            while True:
                page = ctl("images" + cursor)
                found.update(re.findall(r"image=(\d+)", page))
                match = re.search(r"next=(\d+)", page)
                if not match:
                    break
                cursor = "," + match[1]
            check(found == {identity for _, identity in paged}, "all resident IDs accessible across images pagination")
            for instance, identity in paged:
                release(instance, identity)
                reap()
            if args.app:
                adb("shell", "am", "start", "-W", "-n", package + "/.MainActivity")
                app_started = True
                app_pid = int(adb("shell", "pidof", package)[1])
                app_status = root(f"cat /proc/{app_pid}/status")
                check(re.search(r"Seccomp:\s+2", app_status) and "untrusted_app" in root(f"cat /proc/{app_pid}/attr/current"),
                      "ordinary app has zygote seccomp and untrusted_app domain")
                app_library = apk.removesuffix("/base.apk") + "/lib/arm64/libkclfapp_payload.so"
                check(root(f"if [ -e /data/user/0/{package}/files/hit_{app_pid} ]; then echo old; fi") == "",
                      "app marker did not exist before manual injection")
                ctl(f"inject,{app_pid},{app_library},wake")
                app_result = wait_state()
                check("via=manual" in app_result, "ordinary app main thread manual loading")
                check(f"pid={app_pid} " in root(f"cat /data/user/0/{package}/files/hit_{app_pid}"), "ordinary app constructor independently witnessed")
                app_image = re.search(r"image=(\d+)", app_result).group(1)
                app_extent = image_extent(app_result)
                reap()
                release(app_pid, app_image)
                reap()
                check(not overlaps(app_pid, *app_extent), "ordinary app resident allocation released")
                check(adb("shell", "pidof", package)[1] == str(app_pid), "ordinary app survives manual load and release")
                adb("shell", "am", "force-stop", package)
                app_started = False
            resident = start()
            st = inject(resident, "libmanual.so")
            image_id = re.search(r"image=(\d+)", st).group(1)
            reap()
            check("quiesce=busy" in ctl("quiesce", check=False), "resident images prevent an idle quiesce")
            release(resident, image_id)
            reap()
            check("quiesce=idle" in ctl("quiesce"), "release remains available while quiescing")
        check(root("cat /proc/sys/kernel/random/boot_id") == boot, "device boot identity unchanged")
        check(root("getenforce") == policy, "SELinux mode unchanged")
        functional_passed = True
        events.append({"functional_cases": "passed"})
    finally:
        for pid in targets:
            stop(pid)
        if app_started:
            adb("shell", "am", "force-stop", package, check=False)
        if loaded:
            time.sleep(.5)
            ctl("reap", check=False)
            quiet = ctl("quiesce", check=False)
            if "quiesce=idle" in quiet:
                kpm("unload", "kclf")
                loaded = False
            else:
                print("Module retained: not safe to unload. " + quiet, flush=True)
        after = root("dmesg", check=False)
        (output / "dmesg-after.txt").write_text(after, encoding="utf-8")
        faults = [line for line in after.splitlines() if re.search(r"BUG:|WARNING:|Oops:|Kernel panic", line) and line not in baseline]
        # Functional assertions alone are not a successful device acceptance.
        # Keep kernel warnings and cleanup failures visible in the final result.
        events.append({"new_kernel_faults": faults, "module_retained": loaded,
                       "result": "PASS" if functional_passed and not faults and not loaded else "FAIL"})
        (output / "results.json").write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
        adb("pull", remote, str(output), check=False)
        print("Evidence: " + str(output), flush=True)
    if faults or loaded:
        raise SystemExit("Kernel diagnostics/cleanup require attention")


if __name__ == "__main__":
    main()
