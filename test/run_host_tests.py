#!/usr/bin/env python3
"""One Linux/WSL entry point for local tests; never connects to a device."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile


def main():
    module = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    # UBSan normally recovers after reporting UB; tests must fail instead.
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    scripts = (
        "test_helpers.py", "test_maps.py", "test_manual_elf.py", "test_provider.py",
        "test_symbols.py", "test_compat.py", "test_completion.py", "test_runtime.py",
    )
    for name in scripts:
        print(f"\n=== {name} ===", flush=True)
        subprocess.run([sys.executable, str(module / "test" / name)], check=True, env=environment)
    with tempfile.TemporaryDirectory(prefix="kclf-host-") as directory:
        for name, extra in (
            ("test_btf", []),
            ("test_codegen", ["-DKCLF_CODEGEN_HOST", str(module / "kclf_codegen.c")]),
        ):
            exe = Path(directory) / name
            print(f"\n=== {name} ===", flush=True)
            subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O2",
                            "-fno-strict-aliasing", "-fsanitize=address,undefined",
                            "-fno-omit-frame-pointer", *extra,
                            str(module / "test" / (name + ".c")), "-o", str(exe)], check=True)
            arguments = (["4096"], ["16384"], ["65536"]) if name == "test_codegen" else ([],)
            for args in arguments:
                subprocess.run([str(exe), *args], cwd=directory, check=True, env=environment)
    print("\nAll 10 host suites passed (not a kernel/device certification).", flush=True)


if __name__ == "__main__":
    main()
