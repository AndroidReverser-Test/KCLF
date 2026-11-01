#!/system/bin/sh
# Run only test artifacts in this directory. No system settings are changed.
set -eu
base=${0%/*}
case ${1:-} in
    normal|unload|fp|slow|hold|seccomp|rewrite-zero|rewrite-fill|rewrite-machine|rewrite-mixed) mode=$1 ;;
    *) exit 2 ;;
esac
export KCLF_TEST_VERBOSE=1
export KCLF_TEST_DIR=$base
export KCLF_TEST_SLEEP_MS=100
export KCLF_TEST_PHDR_EVERY=10
case $mode in
    slow) export KCLF_TEST_SLEEP_MS=5000 ;;
    hold) export KCLF_TEST_HOLD_MS=2000 ;;
    fp) export KCLF_TEST_FP=1 KCLF_TEST_CLOBBER_FP=1 ;;
    seccomp) export KCLF_TEST_SECCOMP=1 ;;
    rewrite-*) export KCLF_TEST_PROVIDER_REWRITE=${mode#rewrite-} ;;
esac
library=
case $mode in
    rewrite-*) library=$base/libkclf_rewritten.so ;;
esac
nohup "$base/kclf_target" 1200 "$library" >"$base/$mode.log" 2>&1 </dev/null &
echo $!
