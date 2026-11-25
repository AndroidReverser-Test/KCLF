#!/usr/bin/env python3
"""ASan/UBSan tests of the real freestanding manual ELF implementation."""
from pathlib import Path
import subprocess
import tempfile

module = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="kclf-manual-elf-") as directory:
    exe = Path(directory) / "test"
    dependency = Path(directory) / "dependency.c"
    dependency.write_text("int fixture(void) { return 7; }\n")
    payload = Path(directory) / "payload.c"
    payload.write_text("extern int fixture(void); int result; "
                       "__attribute__((constructor)) static void init(void) { result = fixture(); }\n")
    compiler = "aarch64-linux-gnu-gcc"
    flags = ["-shared", "-fPIC", "-nostdlib", "-Wl,--hash-style=both", "-Wl,-z,max-page-size=4096"]
    subprocess.run([compiler, *flags, str(dependency), "-Wl,-soname,libfixture.so",
                    "-o", str(Path(directory) / "libfixture.so")], check=True)
    fixture = Path(directory) / "payload.so"
    subprocess.run([compiler, *flags, str(payload), "-L" + directory, "-lfixture", "-o", str(fixture)], check=True)
    subprocess.run([
        "gcc", "-std=gnu11", "-DKCLF_ELF_HOST", "-Wall", "-Wextra", "-Werror",
        "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(module), str(module / "kclf_elf.c"),
        str(module / "test/test_manual_elf.c"), "-o", str(exe)
    ], check=True)
    subprocess.run([str(exe), str(fixture)], check=True)
