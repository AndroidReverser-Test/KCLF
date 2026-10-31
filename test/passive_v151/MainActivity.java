package com.kclf.passive151;
import android.app.Activity;
import android.os.Bundle;
import android.view.Choreographer;
import android.widget.TextView;

public final class MainActivity extends Activity implements Choreographer.FrameCallback {
    static { System.loadLibrary("passive151"); }
    private static native void start(String files, String libraries, String mode);
    private static native void frame(long interval, long work);
    private TextView label;
    private long previous, number, checksum;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        label = new TextView(this);
        label.setText("Isolated passive detector / animated workload");
        label.setTextSize(20);
        setContentView(label);
        String mode = getIntent().getStringExtra("mode");
        start(getFilesDir().getAbsolutePath(), getApplicationInfo().nativeLibraryDir, mode == null ? "scan" : mode);
        Choreographer.getInstance().postFrameCallback(this);
    }
    @Override public void doFrame(long time) {
        long begin = System.nanoTime();
        long value = number++;
        for (int i = 0; i < 5000; i++) value = (value * 1664525L + 1013904223L) ^ (value >>> 17);
        checksum ^= value;
        label.setTranslationX((float)(20 * Math.sin(number * .03)));
        if (number % 30 == 0) label.setText("Passive audit\nFrames: " + number + "\nChecksum: " + checksum);
        if (previous != 0) frame(time - previous, System.nanoTime() - begin);
        previous = time;
        Choreographer.getInstance().postFrameCallback(this);
    }
}
