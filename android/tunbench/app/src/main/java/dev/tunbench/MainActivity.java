package dev.tunbench;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Locale;

/**
 * Settings, Start/Stop, live engine stats and worker-thread telemetry. Also drivable from a shell:
 * am start -n dev.tunbench/.MainActivity --es action start [--es host H] [--es port P] [--es mtu M]
 *     [--es engine hev|honk] [--es cpus LIST]
 * am start -n dev.tunbench/.MainActivity --es action stop
 * am start -n dev.tunbench/.MainActivity --es action telemetry   (then: run-as dev.tunbench cat
 *     files/telemetry.txt; the service also rewrites it once per second while running)
 * A scripted start without engine or cpus means hev and no pinning. For hev, host and port name
 * the SOCKS5 server; for honk, the upstream every flow is relayed to.
 */
public class MainActivity extends Activity {
    static final String PREFS = "tunbench";
    static final String DEFAULT_HOST = "127.0.0.1";
    static final int DEFAULT_PORT = 1080;
    static final int DEFAULT_MTU = 8500;

    private static final int REQ_VPN = 1;
    private static final int REQ_NOTIFY = 2;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private EditText hostField;
    private EditText portField;
    private EditText mtuField;
    private EditText engineField;
    private EditText cpusField;
    private Button toggle;
    private TextView statsView;

    private long[] lastStats;
    private long lastStatsAt;

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            updateStats();
            handler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        hostField.setText(prefs.getString(TunService.EXTRA_HOST, DEFAULT_HOST));
        portField.setText(String.valueOf(prefs.getInt(TunService.EXTRA_PORT, DEFAULT_PORT)));
        mtuField.setText(String.valueOf(prefs.getInt(TunService.EXTRA_MTU, DEFAULT_MTU)));
        engineField.setText(prefs.getString(TunService.EXTRA_ENGINE, TunService.ENGINE_HEV));
        cpusField.setText(prefs.getString(TunService.EXTRA_CPUS, ""));

        boolean scripted = getIntent().hasExtra("action");
        if (!scripted && Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFY);
        }
        if (savedInstanceState == null) {
            handleIntent(getIntent());
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        Bundle extras = intent.getExtras();
        if (extras == null || !extras.containsKey("action")) {
            return;
        }
        // Accept both --es and --ei for the numeric extras.
        if (extras.containsKey("host")) {
            hostField.setText(String.valueOf(extras.get("host")));
        }
        if (extras.containsKey("port")) {
            portField.setText(String.valueOf(extras.get("port")));
        }
        if (extras.containsKey("mtu")) {
            mtuField.setText(String.valueOf(extras.get("mtu")));
        }
        String action = String.valueOf(extras.get("action"));
        intent.removeExtra("action");
        if ("start".equals(action)) {
            engineField.setText(extras.containsKey("engine") ? String.valueOf(extras.get("engine"))
                    : TunService.ENGINE_HEV);
            cpusField.setText(extras.containsKey("cpus") ? String.valueOf(extras.get("cpus")) : "");
            startVpn();
        } else if ("telemetry".equals(action)) {
            TunService.writeTelemetry(this);
        } else if ("stop".equals(action)) {
            stopVpn();
        } else {
            toast("unknown action: " + action);
        }
    }

    private void startVpn() {
        String host = hostField.getText().toString().trim();
        String engine = engineField.getText().toString().trim();
        String cpus = cpusField.getText().toString().trim();
        if (!TunService.ENGINE_HEV.equals(engine) && !TunService.ENGINE_HONK.equals(engine)) {
            toast("engine must be hev or honk");
            return;
        }
        if (!cpus.matches("[0-9,\\- ]*")) {
            toast("cpus: a list like 0-1 or 0-2,7, or empty");
            return;
        }
        int port;
        int mtu;
        try {
            port = Integer.parseInt(portField.getText().toString().trim());
            mtu = Integer.parseInt(mtuField.getText().toString().trim());
        } catch (NumberFormatException e) {
            toast("port and MTU must be numbers");
            return;
        }
        if (host.isEmpty() || port < 1 || port > 65535 || mtu < 576 || mtu > 65535) {
            toast("invalid host, port (1-65535) or MTU (576-65535)");
            return;
        }
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putString(TunService.EXTRA_HOST, host)
                .putInt(TunService.EXTRA_PORT, port)
                .putInt(TunService.EXTRA_MTU, mtu)
                .putString(TunService.EXTRA_ENGINE, engine)
                .putString(TunService.EXTRA_CPUS, cpus)
                .apply();

        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN);
        } else {
            onActivityResult(REQ_VPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_VPN) {
            return;
        }
        if (resultCode != RESULT_OK) {
            toast("VPN consent denied");
            return;
        }
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        Intent start = new Intent(this, TunService.class)
                .setAction(TunService.ACTION_START)
                .putExtra(TunService.EXTRA_HOST, prefs.getString(TunService.EXTRA_HOST, DEFAULT_HOST))
                .putExtra(TunService.EXTRA_PORT, prefs.getInt(TunService.EXTRA_PORT, DEFAULT_PORT))
                .putExtra(TunService.EXTRA_MTU, prefs.getInt(TunService.EXTRA_MTU, DEFAULT_MTU))
                .putExtra(TunService.EXTRA_ENGINE,
                        prefs.getString(TunService.EXTRA_ENGINE, TunService.ENGINE_HEV))
                .putExtra(TunService.EXTRA_CPUS, prefs.getString(TunService.EXTRA_CPUS, ""));
        startForegroundService(start);
    }

    private void stopVpn() {
        startService(new Intent(this, TunService.class).setAction(TunService.ACTION_STOP));
    }

    private void updateStats() {
        boolean on = TunService.running;
        boolean worker = on && TunService.engineRunning();
        toggle.setText(on ? "Stop" : "Start");

        StringBuilder sb = new StringBuilder();
        sb.append("service: ").append(on ? "running" : "stopped")
                .append(", engine ").append(TunService.engine).append(": ")
                .append(worker ? "running" : "stopped").append('\n');
        sb.append("cpus: asked ").append(TunService.cpus.isEmpty() ? "-" : TunService.cpus)
                .append(", in effect ").append(TunService.affinity.isEmpty() ? "-"
                        : TunService.affinity)
                .append(", worker tid ").append(TunService.engineTid).append('\n');
        if (TunService.lastError != null) {
            sb.append("error: ").append(TunService.lastError).append('\n');
        }

        long[] s = TunService.stats();
        long now = SystemClock.elapsedRealtime();
        double secs = lastStats == null ? 0 : (now - lastStatsAt) / 1000.0;
        sb.append(line("TX", s[0], s[1], secs > 0 ? s[0] - lastStats[0] : 0,
                secs > 0 ? s[1] - lastStats[1] : 0, secs));
        sb.append(line("RX", s[2], s[3], secs > 0 ? s[2] - lastStats[2] : 0,
                secs > 0 ? s[3] - lastStats[3] : 0, secs));
        lastStats = s;
        lastStatsAt = now;
        sb.append('\n').append(TunService.telemetryLine().replace(' ', '\n')).append('\n');
        statsView.setText(sb);
    }

    private static String line(String dir, long pkts, long bytes, long dPkts, long dBytes,
            double secs) {
        double pps = secs > 0 ? dPkts / secs : 0;
        double mbps = secs > 0 ? dBytes * 8 / secs / 1e6 : 0;
        return String.format(Locale.ROOT, "%s: %d pkts, %d bytes (%.0f pkt/s, %.1f Mbit/s)\n",
                dir, pkts, bytes, pps, mbps);
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(tick);
        super.onPause();
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }

    private void buildUi() {
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        hostField = field(root, "Host (hev: SOCKS5 server; honk: upstream)",
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        portField = field(root, "Port", InputType.TYPE_CLASS_NUMBER);
        mtuField = field(root, "MTU", InputType.TYPE_CLASS_NUMBER);
        engineField = field(root, "Engine (hev or honk)", InputType.TYPE_CLASS_TEXT);
        cpusField = field(root, "Worker CPUs (e.g. 0-1, 7; empty: no pinning)",
                InputType.TYPE_CLASS_TEXT);

        toggle = new Button(this);
        toggle.setText("Start");
        toggle.setOnClickListener(v -> {
            if (TunService.running) {
                stopVpn();
            } else {
                startVpn();
            }
        });
        root.addView(toggle);

        statsView = new TextView(this);
        statsView.setTypeface(Typeface.MONOSPACE);
        statsView.setPadding(0, pad, 0, 0);
        root.addView(statsView);

        ScrollView scroll = new ScrollView(this);
        scroll.setFitsSystemWindows(true);
        scroll.addView(root);
        setContentView(scroll);
    }

    private EditText field(LinearLayout parent, String label, int inputType) {
        TextView tv = new TextView(this);
        tv.setText(label);
        parent.addView(tv);
        EditText et = new EditText(this);
        et.setInputType(inputType);
        et.setSingleLine(true);
        parent.addView(et, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return et;
    }
}
