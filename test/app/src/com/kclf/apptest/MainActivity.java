package com.kclf.apptest;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;

import java.io.File;

/**
 * Deliberately ordinary: a debuggable third-party app with the zygote seccomp
 * filter, a main thread parked in epoll_pwait, a binder pool and one thread
 * that loops in nanosleep. KCLF is tested against both blocking styles.
 */
public final class MainActivity extends Activity {
    static {
        System.loadLibrary("kclfhost");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        File files = getFilesDir();
        Log.i("KCLFAPP", "created pid=" + Process.myPid() + " tid=" + Process.myTid()
                + " files=" + files.getAbsolutePath()
                + " libdir=" + getApplicationInfo().nativeLibraryDir);

        Thread sleeper = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        Thread.sleep(50);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "kclf-sleeper");
        sleeper.start();

        /* Returning to the main looper leaves the UI thread in epoll_pwait. */
        Log.i("KCLFAPP", "ready");
    }
}
