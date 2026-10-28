package com.kclf.apptest;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;

import java.io.File;

/**
 * Deliberately ordinary: a debuggable third-party app with the zygote seccomp
 * filter, a main thread parked in epoll_pwait, a binder pool and one thread
 * that loops in Thread.sleep. Native probes add pipe read and nanosleep.
 */
public final class MainActivity extends Activity {
    private Thread sleeper;
    private static native int startProbes();
    static {
        System.loadLibrary("kclfhost");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        File files = getFilesDir();
        int probeResult = startProbes();
        if (probeResult != 0) throw new IllegalStateException("native probes: " + probeResult);
        Log.i("KCLFAPP", "created pid=" + Process.myPid() + " tid=" + Process.myTid()
                + " files=" + files.getAbsolutePath()
                + " libdir=" + getApplicationInfo().nativeLibraryDir);

        sleeper = new Thread(new Runnable() {
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

    @Override
    protected void onDestroy() {
        if (sleeper != null) sleeper.interrupt();
        super.onDestroy();
    }
}
