#!/usr/bin/env python3
"""ASan/UBSan tests of the real freestanding manual ELF implementation."""
from pathlib import Path
import subprocess
import tempfile

module = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="kclf-manual-elf-") as directory:
    exe = Path(directory) / "test"
    subprocess.run([
        "gcc", "-std=gnu11", "-DKCLF_ELF_HOST", "-Wall", "-Wextra", "-Werror",
        "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(module), str(module / "kclf_elf.c"),
        str(module / "test/test_manual_elf.c"), "-o", str(exe)
    ], check=True)
    subprocess.run([str(exe), str(module / "test/libkclf_payload.so")], check=True)
