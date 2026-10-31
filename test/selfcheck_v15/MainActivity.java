package com.kclf.selfcheckv15;

import android.app.Activity;
import android.os.Bundle;

public final class MainActivity extends Activity {
    static { System.loadLibrary("selfcheck"); }
    private static native void start(String files, String libraries, String mode);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        String mode = getIntent().getStringExtra("mode");
        start(getFilesDir().getAbsolutePath(), getApplicationInfo().nativeLibraryDir,
              mode == null ? "observe" : mode);
    }
}
