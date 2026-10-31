#!/usr/bin/env python3
"""Verify the hardened KCLF against the 1.4.1 detection rules.

KCLF_SUPERKEY is read from the environment and never saved as evidence.
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

PACKAGE = "com.kclf.obsprobe"
PRIVATE = "/data/user/0/" + PACKAGE + "/files/"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--sdk", default="D:/androidSDK")
    parser.add_argument("--ndk", default="D:/androidSDK/ndk/27.0.12077973")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 100:
        parser.error("--rounds must be in 1..100")
    source = Path(__file__).resolve().parent
    module = source.parents[1]
    workspace = module.parents[1]
    output = workspace / "build" / ("kclf-observability-" + uuid.uuid4().hex[:12])
    output.mkdir(parents=True)
    events, cases, completions = [], [], []
    key = os.environ.get("KCLF_SUPERKEY", "")
    if not args.build_only and not re.fullmatch(r"[A-Za-z0-9_.+-]+", key):
        raise SystemExit("Set a shell-safe KCLF_SUPERKEY")
    loaded = installed_here = own_app_started = False
    boot_before = policy_before = ""
    metadata = {"output": str(output), "package": PACKAGE, "rounds": args.rounds}
    print("Evidence: " + str(output), flush=True)

    def save(name, value):
        if key:
            value = value.replace(key, "<redacted>")
        (output / name).write_text(value, encoding="utf-8")

    def run(command, check=True, timeout=120):
        result = subprocess.run([str(x) for x in command], text=True, encoding="utf-8",
                                errors="replace", capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError("Command failed: " + result.stdout + result.stderr)
        return result

    def adb(*words, check=True):
        return run([args.adb, "-s", args.serial, *words], check=check, timeout=60)

    def root(command, check=True):
        return adb("shell", f"/data/local/tmp/kpatch {key} su -c {shlex.quote(command)}",
                   check=check).stdout.strip()

    def kpm(*words, check=True):
        result = adb("shell", "/data/local/tmp/kpatch", key, "kpm", *words, check=False)
        events.append({"kpm": list(words), "rc": result.returncode, "output": result.stdout.strip()})
        if check and result.returncode:
            raise RuntimeError("KPM command failed: " + result.stdout + result.stderr)
        return result.stdout.strip()

    def ctl(command):
        return kpm("ctl0", "kclf", command)

    def check(value, description):
        events.append({"pass": bool(value), "message": description})
        print(("PASS " if value else "FAIL ") + description, flush=True)
        if not value:
            raise AssertionError(description)

    def until(action, predicate, seconds=20):
        deadline = time.monotonic() + seconds
        last = ""
        while time.monotonic() < deadline:
            last = action()
            if predicate(last):
                return last
            time.sleep(.12)
        raise TimeoutError(str(last))

    def app_events():
        return root("cat " + PRIVATE + "events.txt", check=False)

    def stop_app():
        nonlocal own_app_started
        if own_app_started:
            adb("shell", "am", "force-stop", PACKAGE)
            until(lambda: adb("shell", "pidof", PACKAGE, check=False).stdout.strip(), lambda s: not s)
            own_app_started = False

    def start_app(mode):
        nonlocal own_app_started
        stop_app()
        adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity", "--es", "mode", mode)
        own_app_started = True
        pid = until(lambda: adb("shell", "pidof", PACKAGE, check=False).stdout.strip(), lambda s: s.isdigit())
        pattern = rf"READY pid={pid} tid=(\d+) mode={mode} library=(\S+)"
        text = until(app_events, lambda s: bool(re.search(pattern, s)))
        match = re.search(pattern, text)
        check("ERROR" not in text and "uid=0 " not in text and "CapEff:\t0000000000000000" in text,
              mode + ": detector runs without capabilities")
        check("dumpable=0" in text and "untrusted_app" in text and "Seccomp:\t2" in text,
              mode + ": non-debuggable untrusted_app with seccomp")
        return int(pid), int(match[1]), match[2]

    def await_done():
        def complete(text):
            if "state=failed" in text:
                raise RuntimeError(text)
            return "state=done" in text and "pending=" not in text and " map=" not in text
        return until(lambda: ctl("status"), complete)

    def after_ready(text):
        lines = text.splitlines()
        for index in range(len(lines) - 1, -1, -1):
            if lines[index].startswith("READY "):
                return "\n".join(lines[index + 1:])
        return text

    def payload_markers(pid, tid):
        text = root("cat " + PRIVATE + "payload.txt", check=False)
        return [line for line in text.splitlines() if f"pid={pid} " in line and f"tid={tid} " in line]

    try:
        sdk, ndk = Path(args.sdk), Path(args.ndk)
        build_tools = max((sdk / "build-tools").iterdir(),
                          key=lambda p: tuple(map(int, p.name.split("."))))
        platform = max((sdk / "platforms").glob("android-*"),
                       key=lambda p: int(p.name.split("-")[-1]))
        android_jar = platform / "android.jar"
        toolbin = ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
        common = [toolbin / "clang.exe", "--target=aarch64-linux-android31",
                  "-O2", "-Wall", "-Wextra", "-Werror"]
        shared = [*common, "-shared", "-fPIC", "-Wl,-z,max-page-size=16384"]
        for directory in ("classes", "dex", "kpm"):
            (output / directory).mkdir()
        for file in module.iterdir():
            if file.suffix in (".c", ".h") or file.name == "Makefile":
                shutil.copy2(file, output / "kpm" / file.name)

        def wsl_path(path):
            path = Path(path).resolve().as_posix()
            return "/mnt/" + path[0].lower() + path[2:]

        built = run(["wsl", "-e", "make", "-C", wsl_path(output / "kpm"),
                     "KP_DIR=" + wsl_path(workspace),
                     "TARGET_COMPILE=aarch64-linux-gnu-", "-j4"], timeout=180)
        save("build-kpm.txt", built.stdout + built.stderr)
        run([*shared, source / "probe.c", "-ldl", "-o", output / "libobsprobe.so"])
        run([*shared, source / "payload.c", "-Wl,-soname,libobspayload.so",
             "-o", output / "libobspayload.so"])
        run([*shared, "-DOBS_ALTERNATE=1", source / "payload.c",
             "-Wl,-soname,libobsother.so", "-o", output / "libobsother.so"])
        run(["javac", "-source", "8", "-target", "8", "-Xlint:-options",
             "-classpath", android_jar, "-d", output / "classes", source / "MainActivity.java"])
        run([build_tools / "d8.bat", "--lib", android_jar, "--min-api", "31",
             "--output", output / "dex", *sorted((output / "classes").rglob("*.class"))])
        run([build_tools / "aapt2.exe", "link", "--manifest", source / "AndroidManifest.xml",
             "-I", android_jar, "--min-sdk-version", "31", "--target-sdk-version", "35",
             "-o", output / "base.apk"])
        with zipfile.ZipFile(output / "base.apk", "a", zipfile.ZIP_DEFLATED) as package:
            package.write(output / "dex/classes.dex", "classes.dex")
            for name in ("libobsprobe.so", "libobspayload.so", "libobsother.so"):
                package.write(output / name, "lib/arm64-v8a/" + name)
        keystore = workspace / "build/kclf-observability-debug.keystore"
        if not keystore.exists():
            run(["keytool", "-genkeypair", "-keystore", keystore, "-storepass", "android",
                 "-keypass", "android", "-alias", "androiddebugkey", "-dname",
                 "CN=KCLF Observation Test", "-keyalg", "RSA", "-validity", "10000"])
        run([build_tools / "zipalign.exe", "-f", "4", output / "base.apk", output / "aligned.apk"])
        run([build_tools / "apksigner.bat", "sign", "--ks", keystore, "--ks-pass",
             "pass:android", "--key-pass", "pass:android", "--out", output / "app.apk",
             output / "aligned.apk"])
        run([build_tools / "apksigner.bat", "verify", output / "app.apk"])
        metadata.update({
            "module_sha256": sha(output / "kpm/kclf.kpm"),
            "workspace_module_sha256": sha(module / "kclf.kpm"),
            "apk_sha256": sha(output / "app.apk"),
            "payload_sha256": sha(output / "libobspayload.so"),
            "framework_commit": run(["git", "-C", module, "rev-parse", "HEAD"]).stdout.strip(),
            "source_sha256": {p.name: sha(p) for p in sorted(source.iterdir()) if p.is_file()},
        })
        if args.build_only:
            metadata["result"] = "built_only"
            return

        check(kpm("num") == "0", "no pre-existing KPM")
        check(not adb("shell", "pm", "path", PACKAGE, check=False).stdout.strip(),
              "separate test package is not already installed")
        boot_before = root("cat /proc/sys/kernel/random/boot_id")
        policy_before = root("getenforce")
        metadata["device"] = {
            "serial": args.serial,
            "android": adb("shell", "getprop", "ro.build.version.release").stdout.strip(),
            "sdk": adb("shell", "getprop", "ro.build.version.sdk").stdout.strip(),
            "kernel": adb("shell", "uname", "-a").stdout.strip(),
            "selinux": policy_before, "boot_id": boot_before,
        }
        save("dmesg-before.txt", root("dmesg"))
        remote = "/data/local/tmp/" + output.name
        adb("shell", "mkdir", remote)
        adb("push", str(output / "kpm/kclf.kpm"), remote + "/kclf.kpm")
        adb("install", "-t", str(output / "app.apk"))
        installed_here = True

        # Baseline before any module is loaded: the fixture's own rules must be
        # silent, and the seccomp guard must demonstrably work.
        for mode in ("plain", "guard", "normal"):
            pid, tid, libraries = start_app(mode)
            time.sleep(1.2)
            text = app_events()
            check("KCLF_EXEC" not in text and "KNOWN_MANUAL" not in text and "KNOWN_HEADER" not in text
                  and "RESIDUAL_TAG" not in text and "ERROR" not in text,
                  mode + ": negative controls produce no positive")
            if mode == "guard":
                check("guard=1 control_traps=100" in text, "guard: anonymous stub is trapped (100/100)")
            save("negative-" + mode + ".events.txt", text)
            cases.append({"case": "negative-" + mode, "pass": True, "pid": pid, "tid": tid})
            stop_app()

        kpm("load", remote + "/kclf.kpm")
        loaded = True
        probe = ctl("probe")
        save("probe.txt", probe)
        check("pt_regs=ok" in probe and "completion=el0" in probe and "watch=on" in probe
              and re.search(r"installed=\d+/\d+", probe) is not None,
              "fresh KPM EL0 completion backend is ready (watched syscalls)")

        for backend in ("manual", "linker"):
            for unload in (False, True):
                if backend == "linker" and unload:
                    continue  # the manual unload path is the interesting one
                for index in range(args.rounds):
                    name = f"guard-{backend}-{'unload' if unload else 'resident'}-{index + 1:02}"
                    pid, tid, libraries = start_app("guard")
                    flags = "," + backend + ",wake" + (",unload" if unload else "")
                    queued = ctl(f"inject,{tid},{libraries}/libobspayload.so{flags}")
                    check("queued" in queued, name + ": queued on the protected app thread")
                    status = await_done()
                    save(name + ".status.txt", status)
                    check(f"pid={tid}" in status and "state=done" in status,
                          name + ": injection completed")
                    if backend == "manual" and not unload:
                        match = re.search(r"done=(syscall|poll)", status)
                        check(match is not None and "hdr=scrubbed" in status,
                              name + ": EL0 completion path and scrubbed ELF header")
                        if match:
                            completions.append(match[1])
                    time.sleep(1.2)
                    text = app_events()
                    save(name + ".events.txt", text)
                    tail = after_ready(text)
                    check("kind=unexpected" not in tail,
                          name + ": no guarded informational syscall from anonymous code")
                    check("KNOWN_MANUAL" not in text and "KNOWN_HEADER" not in text,
                          name + ": legacy known-image rules stay silent")
                    check("RESIDUAL_TAG" not in text,
                          name + ": no fixed framework tag in anonymous executable memory")
                    check("ERROR" not in text, name + ": fixture still alive")
                    adb("shell", "pidof", PACKAGE)
                    own_lines = payload_markers(pid, tid)
                    check(any(line.startswith("init ") for line in own_lines),
                          name + ": constructor ran on the injected thread")
                    if unload:
                        check(any(line.startswith("fini ") for line in own_lines),
                              name + ": finalizer ran for unload mode")
                    save(name + ".payload.txt", "\n".join(own_lines))
                    ctl("reap")
                    cases.append({"case": name, "pass": True, "pid": pid, "tid": tid})
                    stop_app()

        # The default backend removes the ELF header anchor but readable code
        # stays readable: a content-only scanner must still find the known code.
        for index in range(args.rounds):
            name = f"plain-manual-resident-{index + 1:02}"
            pid, tid, libraries = start_app("plain")
            ctl(f"inject,{tid},{libraries}/libobspayload.so,manual,wake")
            status = await_done()
            extent = re.search(r"resident=([0-9a-f]+)\+(\d+)", status)
            check(extent is not None and "hdr=scrubbed" in status,
                  name + ": image resident with scrubbed ELF headers")
            text = until(app_events, lambda s: "RESIDUAL_TEXT" in s, seconds=8)
            tail = after_ready(text)
            check("KNOWN_MANUAL" not in text and "KNOWN_HEADER" not in text,
                  name + ": header-based rules stay silent")
            check("RESIDUAL_TAG" not in text,
                  name + ": recovery marker is a per-request token, not a fixed tag")
            residual = re.findall(r"RESIDUAL_TEXT addr=([0-9a-f]+)", tail)
            check(bool(residual), name + ": content-only scan still finds the known code (residual)")
            if residual and extent:
                base, size = int(extent[1], 16), int(extent[2])
                check(any(base <= int(at, 16) < base + size for at in residual),
                      name + ": residual hit lies inside the recorded image extent")
            save(name + ".status.txt", status)
            save(name + ".events.txt", text)
            ctl("reap")
            cases.append({"case": name, "pass": True, "pid": pid, "tid": tid})
            stop_app()

        # keepelf keeps the header, but the randomized leading pad still keeps
        # it out of every mapping start, so the legacy rule cannot anchor.
        for index in range(args.rounds):
            name = f"plain-manual-keepelf-{index + 1:02}"
            pid, tid, libraries = start_app("plain")
            ctl(f"inject,{tid},{libraries}/libobspayload.so,manual,wake,keepelf")
            status = await_done()
            check("hdr=kept" in status, name + ": keepelf image reports kept headers")
            text = until(app_events, lambda s: "KNOWN_HEADER" in s, seconds=8)
            check("KNOWN_MANUAL" not in text,
                  name + ": legacy region-start rule cannot anchor on the header")
            check("KNOWN_HEADER" in text,
                  name + ": page-level header scan does find the retained header")
            check("RESIDUAL_TAG" not in text,
                  name + ": keepelf does not reintroduce a fixed framework tag")
            save(name + ".status.txt", status)
            save(name + ".events.txt", text)
            ctl("reap")
            cases.append({"case": name, "pass": True, "pid": pid, "tid": tid})
            stop_app()

        check("syscall" in completions,
              "EL0 completion was observed at a watched syscall: " + ",".join(sorted(set(completions))))

        pid, tid, libraries = start_app("plain")
        ctl(f"inject,{tid},{libraries}/libobsother.so,manual,wake")
        status = await_done()
        image = re.search(r"image=(\d+)", status)[1]
        time.sleep(1.2)
        text = app_events()
        check("KNOWN_MANUAL" not in text and "KNOWN_HEADER" not in text and "RESIDUAL_TAG" not in text
              and "ERROR" not in text,
              "different valid manual ELF is not falsely called the known payload")
        save("negative-other-manual.events.txt", text)
        save("negative-other-manual.status.txt", status)
        ctl("reap")
        ctl(f"release,{tid},{image},wake")
        await_done()
        ctl("reap")
        cases.append({"case": "negative-other-manual", "pass": True, "pid": pid, "tid": tid})
        stop_app()
        metadata["result"] = "passed"
    except Exception as error:
        metadata["result"] = "failed"
        metadata["error"] = str(error).replace(key, "<redacted>") if key else str(error)
        print("FAILED " + metadata["error"], flush=True)
        raise
    finally:
        if installed_here:
            try:
                save("last-app.events.txt", app_events())
                save("all-payload.txt", root("cat " + PRIVATE + "payload.txt", check=False))
                stop_app()
            except Exception as error:
                metadata["app_cleanup_error"] = str(error)
        if loaded:
            try:
                ctl("reap")
                idle = ctl("quiesce")
                save("quiesce.txt", idle)
                if "quiesce=idle" in idle:
                    kpm("unload", "kclf")
                    loaded = False
                else:
                    metadata["module_cleanup_error"] = "Not idle; module left loaded"
                metadata["final_kpm_num"] = kpm("num")
            except Exception as error:
                metadata["module_cleanup_error"] = str(error)
        if installed_here and not loaded:
            try:
                adb("uninstall", PACKAGE)
                metadata["test_app_uninstalled"] = True
            except Exception as error:
                metadata["uninstall_error"] = str(error)
        if boot_before:
            try:
                metadata["boot_unchanged"] = root("cat /proc/sys/kernel/random/boot_id") == boot_before
                metadata["selinux_unchanged"] = root("getenforce") == policy_before
                save("dmesg-after.txt", root("dmesg"))
            except Exception as error:
                metadata["postcheck_error"] = str(error)
        metadata["cases"] = cases
        metadata["completion_paths"] = sorted(set(completions))
        metadata["module_left_loaded"] = loaded
        save("results.json", json.dumps(events, ensure_ascii=False, indent=2))
        save("summary.json", json.dumps(metadata, ensure_ascii=False, indent=2))
        print("Evidence: " + str(output), flush=True)


if __name__ == "__main__":
    main()
