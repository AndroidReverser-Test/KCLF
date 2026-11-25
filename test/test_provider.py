#!/usr/bin/env python3
"""Compile and exercise the manual loader's load-origin provider selection."""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]
manual = (MODULE / "kclf_manual.c").read_text()
start = manual.index("/* Loaded providers are chosen")
end = manual.index("static int add_needed(")
selection = manual[start:end]

PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define KCLF_PATH_MAX 256

struct km_provider {
    char name[256];
    char path[KCLF_PATH_MAX];
};
struct km_context {
    struct km_provider providers[8];
    unsigned nproviders, nscope, scope[8];
};
static char last_error[256];

static void report(void *context, const char *why, const char *detail)
{
    (void)context;
    snprintf(last_error, sizeof(last_error), "%s%s%s", why, *detail ? ": " : "", detail);
}
'''

MAIN = r'''
static struct km_context c;

static void reset(void)
{
    memset(&c, 0, sizeof(c));
    memset(last_error, 0, sizeof(last_error));
}
static unsigned add(const char *name, const char *path, int in_scope)
{
    unsigned i = c.nproviders++;
    snprintf(c.providers[i].name, sizeof(c.providers[i].name), "%s", name);
    snprintf(c.providers[i].path, sizeof(c.providers[i].path), "%s", path);
    if (in_scope) c.scope[c.nscope++] = i;
    return i;
}
int main(void)
{
    unsigned system1, system2, art;

    reset();
    add("libc++.so", "/apex/com.android.vndk.v31/lib64/libc++.so", 0);
    add("libc++.so", "/apex/com.android.conscrypt/lib64/libc++.so", 0);
    art = add("libc++.so", "/apex/com.android.art/lib64/libc++.so", 0);
    system1 = add("libc++.so", "/system/lib64/libc++.so", 0);
    system2 = add("libc++.so", "/system/lib64/libc++.so", 0);
    c.scope[c.nscope++] = (unsigned)select_provider(&c, "/system/lib64/liblog.so", "libc++.so");
    assert(c.scope[c.nscope - 1] == system1);
    c.scope[c.nscope++] = (unsigned)select_provider(&c, "/apex/com.android.art/lib64/libfoo.so", "libc++.so");
    assert(c.scope[c.nscope - 1] == art);
    c.scope[c.nscope++] = (unsigned)select_provider(&c, "/data/local/tmp/libtest.so", "libc++.so");
    assert(c.scope[c.nscope - 1] == system1);
    c.scope[c.nscope++] = (unsigned)select_provider(&c, "/vendor/lib64/libfoo.so", "libc++.so");
    assert(c.scope[c.nscope - 1] == 0);
    c.scope[c.nscope++] = (unsigned)select_provider(&c, "/odm/lib64/libfoo.so", "libc++.so");
    assert(c.scope[c.nscope - 1] == 0);
    puts("origin selection: dir/APEX/partition/platform/vendor: PASS");

    reset();
    add("libc++.so", "/system/lib64/libc++.so", 0);
    add("libc++.so", "/system/lib64/libc++.so", 1);
    assert(select_provider(&c, "/system/lib64/liblog.so", "libc++.so") == 1);
    puts("same-path duplicate prefers the resident instance: PASS");

    reset();
    add("libc++.so", "/system_ext/lib64/libc++.so", 0);
    add("libc++.so", "/system/lib64/libc++.so", 0);
    assert(select_provider(&c, "/system_ext/lib64/libfoo.so", "libc++.so") == 0);
    assert(select_provider(&c, "/system/lib64/libfoo.so", "libc++.so") == 1);
    puts("exact directory beats same partition: PASS");

    reset();
    add("libc++.so", "/apex/com.android.vndk.v31/lib64/libc++.so", 0);
    add("libc++.so", "/apex/com.android.conscrypt/lib64/libc++.so", 0);
    add("libc++.so", "/apex/com.android.art/lib64/libc++.so", 0);
    assert(select_provider(&c, "/data/local/tmp/libtest.so", "libc++.so") == -EEXIST);
    assert(strstr(last_error, "ambiguous loaded SONAME"));
    puts("unresolvable distinct origins fail explicitly: PASS");

    reset();
    add("libc++.so", "", 0);
    add("libc++.so", "", 0);
    assert(select_provider(&c, "/data/local/tmp/libtest.so", "libc++.so") == -EEXIST);
    assert(strstr(last_error, "ambiguous loaded SONAME"));
    puts("multiple unknown-origin providers fail instead of guessing: PASS");

    reset();
    add("libc.so", "/system/lib64/libc.so", 0);
    assert(select_provider(&c, "/system/lib64/libfoo.so", "libm.so") == -ENOENT);
    assert(strstr(last_error, "not already loaded"));
    puts("missing DT_NEEDED remains an explicit failure: PASS");

    reset();
    add("libc++.so", "/apex/com.android.runtime/lib64/libc++.so", 0);
    assert(select_provider(&c, "/data/local/tmp/libtest.so", "libc++.so") == 0);
    assert(select_provider(&c, "", "libc++.so") == 0);
    puts("runtime APEX and unavailable importer path fallbacks: PASS");
    (void)system2;
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="kclf-provider-") as directory:
    source = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    source.write_text(PRELUDE + selection + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
