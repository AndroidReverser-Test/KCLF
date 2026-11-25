#!/usr/bin/env python3
"""Build the TLS fixtures with an explicit NDK clang path (Windows/Linux)."""
import argparse
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--clang', required=True, help='NDK bin/clang or clang.exe')
parser.add_argument('--out', type=Path, default=root / 'build/tls')
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
common = [args.clang, '--target=aarch64-linux-android29', '-Wall', '-Wextra', '-Werror', '-O2', '-I.']
for name, flags, sources in [
    ('tls-runtime', [], ['test/tls/runtime.c', 'test/tls/registers.S', 'kclf_tls.S']),
    ('tls-elf', ['-DKCLF_ELF_HOST'], ['test/tls/elf.c', 'kclf_elf.c']),
    ('tls-host', [], ['test/tls/host.c']),
    ('libtls-payload.so', ['-shared', '-fPIC', '-fno-emulated-tls', '-Wl,-z,max-page-size=16384'], ['test/tls/payload.c']),
]:
    subprocess.run([*common, *flags, *sources, '-o', str(args.out.resolve() / name)], cwd=root, check=True)
print('Built TLS fixtures:', args.out.resolve())
