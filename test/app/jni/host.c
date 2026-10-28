#include <jni.h>

/* Presence of one JNI library makes the package's nativeLibraryDir real and
 * gives the app linker namespace a permitted /data/app/.../lib/arm64 path. */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}
