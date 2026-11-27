# ELF TLS regression

[Documentation](README.md) · [Build and use](USAGE.md)

Run commands from the repository root. Fixture sources live in [test/tls](../test/tls).

These sources exercise the manual backend's payload-local ELF TLS runtime
(`kclf_tls.S` / `kclf_tls.h`) and the `R_AARCH64_TLSDESC` relocation path.

- `elf.c` + `kclf_elf.c` (`-DKCLF_ELF_HOST`): PT_TLS validation, local TLS symbols,
  signed addends, 16-byte descriptor targets, external-symbol/missing-runtime
  rejection and APS2-packed TLSDESC.
- `runtime.c` + `registers.S` + `kclf_tls.S`: the exact position-independent runtime
  copied by the kernel module. Covers old/new threads, file template and zero-filled
  .tbss, 64 KiB alignment, all-GPR/SIMD/FPCR/FPSR/NZCV preservation, key-creation
  failure, thread destructor, signal re-entry and setspecific/mmap/signal-mask
  failure. Failure cases deliberately abort isolated child processes.
- `prepare.py`: ASan/UBSan fault injection against the production preparation and
  rollback functions: relocated templates, 4K/16K/64K metadata, mapping/copy/protection
  errors, retry ownership, failed key initialization, abandoned execution and IFUNC rejection.
- `host.c` + `payload.c`: end-to-end injection target and TLS payload. Build the
  payload with `-fno-emulated-tls` on Android; otherwise clang emits compiler-rt
  emutls and the ELF TLS path is not used.

## Automated regression

Run `make test` on Linux/WSL for all 16 host suites. Build Android fixtures with:

```powershell
python test/tls/build.py --clang D:/androidSDK/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe
.\test\app\build.ps1 -SdkRoot D:\androidSDK -NdkRoot D:\androidSDK\ndk\27.0.12077973
adb install -r -t build/kclf-apptest/app.apk
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python test/tls/device-test.py --serial '<SERIAL>' --repeat 3
```

The installed app must be signed with the same debug key as an earlier installation
when updating. The runner starts/stops this test app and its own native hosts, checks
pointer initializers, thread isolation, image reuse, NODELETE rejection, key exhaustion,
rollback and safe KPM unload. It refuses a pre-existing KCLF instance. Evidence is saved
under `build/kclf-tls-*/` without the superkey. Pass `--kpm` and `--expect-poll` for an
independently built `KCLF_TEST_NO_BTF`/`KCLF_TEST_NO_NOFAULT` fallback module.

Runtime timings are local samples including register save/restore and test call overhead;
they are sensitive to device load/frequency and are not a cross-device performance promise.
The resolver uses an 800-byte stack frame, calls pthread_getspecific on the warm path,
and makes syscalls only on first access and thread teardown. SVE/SME callers, raw-clone
threads and TLS use from other pthread-key destructors are outside the supported contract.

## Manual commands

The Android builds below use the NDK clang; run them from the `kpms/kclf`
directory (adjust the SDK/NDK paths).

```sh
CLANG=$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang
$CLANG --target=aarch64-linux-android26 -fPIE -pie -O2 -I. \
  test/tls/runtime.c test/tls/registers.S kclf_tls.S -o tls-runtime
$CLANG --target=aarch64-linux-android26 -O2 -DKCLF_ELF_HOST -I. \
  test/tls/elf.c kclf_elf.c -o tls-elf
$CLANG --target=aarch64-linux-android29 -shared -fPIC -O2 -fno-emulated-tls \
  test/tls/payload.c -o libtls-payload.so
$CLANG --target=aarch64-linux-android26 -O2 test/tls/host.c -o tls-host
```

Run the two self-contained tests on the device first:

```sh
adb push tls-elf tls-runtime /data/local/tmp/
adb shell chmod 755 /data/local/tmp/tls-elf /data/local/tmp/tls-runtime
adb shell /data/local/tmp/tls-elf
adb shell /data/local/tmp/tls-runtime
```

For the injection test, load the KPM, start the host with a writable result directory,
and inject the payload twice (the second load exercises image reuse without a second
TLS key creation):

```sh
adb push tls-host libtls-payload.so /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/tls-host; \
  mkdir -p /data/local/tmp/tls-result; chmod 777 /data/local/tmp/tls-result; \
  nohup env KCLF_TLS_DIR=/data/local/tmp/tls-result /data/local/tmp/tls-host &'
TID=$(adb shell pidof tls-host)
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,$TID,/data/local/tmp/libtls-payload.so,wake"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,$TID,/data/local/tmp/libtls-payload.so,wake"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf status
adb shell "cat /data/local/tmp/tls-result/result-$TID"
```

Expected result file: `TLS failed=0 threads=8 tid=$TID`. The image must report
`nodelete=tls`, and `unload`/`release` must be rejected until the target exits.
