#!/usr/bin/env python3
"""TLS regression against native fixtures and the installed com.kclf.apptest.

Only manages its own native processes, the test app and a KCLF instance it loads.
The superkey is read from an environment variable and never written to evidence.
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

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = 'com.kclf.apptest'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--adb', default='adb')
parser.add_argument('--serial', required=True)
parser.add_argument('--key-env', default='KCLF_SUPERKEY')
parser.add_argument('--kpm', type=Path, default=ROOT / 'kclf.kpm')
parser.add_argument('--fixtures', type=Path, default=ROOT / 'build/tls')
parser.add_argument('--repeat', type=int, default=3)
parser.add_argument('--expect-poll', action='store_true')
args = parser.parse_args()
key = os.environ[args.key_env]
if not re.fullmatch(r'[A-Za-z0-9_@.+-]+', key) or not 1 <= args.repeat <= 20:
    raise SystemExit('Invalid superkey syntax or repeat count')
run_id = 'kclf-tls-' + uuid.uuid4().hex[:12]
remote = '/data/local/tmp/' + run_id
evidence = ROOT / 'build' / run_id
evidence.mkdir(parents=True)
transcript, checks = [], []
native = None
loaded = False
passed = False
app_started = False


def log(message):
    text = str(message).replace(key, '<redacted>')
    transcript.append(text)
    print(text, flush=True)


def adb(*parts, allow=False):
    result = subprocess.run([args.adb, '-s', args.serial, *map(str, parts)],
                            capture_output=True, text=True, errors='replace', timeout=45)
    output = (result.stdout + result.stderr).strip().replace(key, '<redacted>')
    if result.returncode and not allow:
        raise RuntimeError('adb failed: ' + output)
    return output


def root(command):
    return adb('shell', '/data/local/tmp/kpatch ' + key + ' su -c ' + shlex.quote(command))


def kpm(*parts):
    result = adb('shell', '/data/local/tmp/kpatch', key, 'kpm', *parts)
    log(' '.join(parts) + ' => ' + result)
    return result


def ctl(command):
    return kpm('ctl0', 'kclf', command)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    checks.append(message)
    log('PASS: ' + message)


def complete(expected):
    start = time.monotonic()
    while time.monotonic() - start < 20:
        status = ctl('status')
        if re.search(r'state=(done|failed|cancelled)', status) and not re.search(r'pending=| map=', status):
            check('state=' + expected in status, 'request completes as ' + expected)
            if expected == 'done' and args.expect_poll:
                check('done=poll' in status, 'completion uses poll fallback')
            return status
        time.sleep(.1)
    raise RuntimeError('request did not drain within 20 seconds')


def drain():
    for _ in range(100):
        ctl('reap')
        if 'no manual images' in ctl('images'):
            return
        time.sleep(.1)
    raise RuntimeError('image registry did not drain')


def stop_native():
    global native
    if native:
        # Only kill the exact executable started by this run, even after PID reuse.
        if adb('shell', 'readlink', f'/proc/{native}/exe', allow=True) == remote + '/tls-host':
            adb('shell', 'kill', str(native))
        native = None


def start_native(exhaust=False):
    global native
    option = ' --exhaust-keys' if exhaust else ''
    command = (f'nohup env KCLF_TLS_DIR={remote} {remote}/tls-host{option} '
               f'>{remote}/host.log 2>&1 </dev/null & echo $!')
    native = int(adb('shell', command).splitlines()[-1])
    for _ in range(50):
        output = adb('shell', 'cat', remote + '/host.log', allow=True)
        if f'pid={native}' in output:
            check(not exhaust or 'keys=' in output, 'native fixture ready')
            return native
        time.sleep(.1)
    raise RuntimeError('native fixture startup failed')


def exercise(target, payload, marker, app=False):
    ctl(f'inject,{target},{payload},manual,wake,unload')
    check('ELF TLS requires residency' in complete('failed'), 'first unload rejected before TLS initialization')
    check('no manual images' in ctl('images'), 'rejected load rolled back both mappings')
    ctl('reap')
    ctl(f'inject,{target},{payload},manual,wake')
    complete('done')
    result = adb('shell', 'run-as', PACKAGE, 'cat', marker) if app else adb('shell', 'cat', marker)
    log(result)
    check(result == f'TLS failed=0 threads=8 tid={target}', 'relocated template, BSS, alignment and eight threads')
    images = ctl('images')
    check('nodelete=tls' in images and 'refs=1' in images, 'TLS image is resident with one reference')
    image_id = re.search(r'\bimage=(\d+)', images).group(1)
    ctl('reap')
    ctl(f'inject,{target},{payload},manual,wake')
    complete('done')
    check('refs=2' in ctl('images'), 'repeat load reuses image')
    after = adb('shell', 'run-as', PACKAGE, 'cat', marker) if app else adb('shell', 'cat', marker)
    check(after == result, 'reuse does not rerun the constructor')
    ctl('reap')
    ctl(f'release,{target},{image_id},wake')
    check('NODELETE' in complete('failed'), 'release rejects a live TLS image')
    check('refs=2' in ctl('images'), 'rejected release preserves references')
    check(adb('shell', 'pidof', PACKAGE) == str(target) if app else
          adb('shell', 'readlink', f'/proc/{target}/exe') == remote + '/tls-host', 'target survives')


try:
    check('kclf' not in kpm('list'), 'no pre-existing KCLF instance')
    boot = adb('shell', 'cat', '/proc/sys/kernel/random/boot_id')
    enforcing = adb('shell', 'getenforce')
    before = root('dmesg')
    (evidence / 'dmesg-before.txt').write_text(before, encoding='utf-8')
    log('KPM SHA256=' + hashlib.sha256(args.kpm.read_bytes()).hexdigest())
    adb('shell', 'mkdir', '-p', remote)
    for name in ['tls-runtime', 'tls-elf', 'tls-host', 'libtls-payload.so']:
        adb('push', args.fixtures / name, remote + '/' + name)
    adb('push', args.kpm, remote + '/kclf.kpm')
    adb('shell', 'chmod', '755', remote + '/tls-runtime', remote + '/tls-elf', remote + '/tls-host')
    for name in ['tls-elf', 'tls-runtime']:
        result = adb('shell', remote + '/' + name)
        log(result)
        check('PASS ' in result, name + ' passed')
    kpm('load', remote + '/kclf.kpm')
    loaded = True
    probe = ctl('probe')
    if args.expect_poll:
        check('btf=0' in probe and 'nofault=0' in probe, 'fallback test build confirmed')
    target = start_native(exhaust=True)
    ctl(f'inject,{target},{remote}/libtls-payload.so,manual,wake')
    check('rc=-11' in complete('failed'), 'pthread key exhaustion aborts before constructors')
    check('no manual images' in ctl('images'), 'key allocation failure rolls back image and TLS runtime')
    stop_native()
    drain()
    for iteration in range(args.repeat):
        target = start_native()
        exercise(target, remote + '/libtls-payload.so', remote + '/result-' + str(target))
        stop_native()
        drain()
        adb('shell', 'am', 'force-stop', PACKAGE)
        adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
        app_started = True
        target = int(adb('shell', 'pidof', PACKAGE))
        package_path = adb('shell', 'pm', 'path', PACKAGE).splitlines()[0].removeprefix('package:')
        payload = package_path.rsplit('/', 1)[0] + '/lib/arm64/libkclfapp_tls.so'
        exercise(target, payload, f'files/result-{target}', app=True)
        adb('shell', 'am', 'force-stop', PACKAGE)
        app_started = False
        drain()
    passed = True
finally:
    stop_native()
    if app_started:
        adb('shell', 'am', 'force-stop', PACKAGE)
    try:
        if loaded:
            drain()
            check('quiesce=idle' in ctl('quiesce'), 'KCLF is idle before unload')
            kpm('unload', 'kclf')
            check('kclf' not in kpm('list'), 'KCLF unloaded')
        if 'before' in globals():
            after = root('dmesg')
            (evidence / 'dmesg-after.txt').write_text(after, encoding='utf-8')
            previous = set(before.splitlines())
            new_warnings = [line for line in after.splitlines() if line not in previous
                            and re.search(r'\b(?:BUG:|BUG at|WARNING:|Oops:|Kernel panic)', line, re.I)]
            check(not new_warnings, 'no new retained kernel warnings')
            check(adb('shell', 'cat', '/proc/sys/kernel/random/boot_id') == boot, 'boot ID unchanged')
            check(adb('shell', 'getenforce') == enforcing, 'SELinux mode unchanged')
    except Exception:
        passed = False
        raise
    finally:
        (evidence / 'results.json').write_text(json.dumps({'passed': passed, 'checks': checks,
            'kpm_sha256': hashlib.sha256(args.kpm.read_bytes()).hexdigest()}, indent=2), encoding='utf-8')
        (evidence / 'transcript.txt').write_text('\n'.join(transcript) + '\n', encoding='utf-8')
        log('Evidence: ' + str(evidence))
if not passed:
    raise SystemExit(1)
log(f'PASS: {len(checks)} TLS device assertions')
