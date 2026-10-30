package com.kclf.obsprobe;

import android.app.Activity;
import android.os.Bundle;

/** A separate, non-debuggable fixture. Its detectors run with the app UID. */
public final class MainActivity extends Activity {
    static { System.loadLibrary("obsprobe"); }
    private static native void start(String files, String libraries, String mode);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        String mode = getIntent().getStringExtra("mode");
        start(getFilesDir().getAbsolutePath(), getApplicationInfo().nativeLibraryDir,
              mode == null ? "plain" : mode);
    }
}
