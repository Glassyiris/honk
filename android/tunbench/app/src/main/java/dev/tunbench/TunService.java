package dev.tunbench;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TunService extends VpnService {
    static final String ACTION_START = "dev.tunbench.START";
    static final String ACTION_STOP = "dev.tunbench.STOP";
    static final String EXTRA_HOST = "host";
    static final String EXTRA_PORT = "port";
    static final String EXTRA_MTU = "mtu";
    static final String EXTRA_ENGINE = "engine";
    static final String EXTRA_CPUS = "cpus";
    static final String ENGINE_HEV = "hev";
    static final String ENGINE_HONK = "honk";
    static final String TELEMETRY_FILE = "telemetry.txt";

    private static final String TAG = "TunBench";
    private static final String CHANNEL = "tunbench";
    private static final int NOTIFICATION_ID = 1;
    /** hev's worker inherits this name from the thread that starts it, which identifies it. */
    private static final String HEV_THREAD = "hev-worker";

    static volatile boolean running;
    static volatile String lastError;
    /** The engine that runs (or ran last), the CPU list asked for and the one in effect. */
    static volatile String engine = ENGINE_HEV;
    static volatile String cpus = "";
    static volatile String affinity = "";
    /** TID of the engine's worker thread, 0 if unknown. */
    static volatile int engineTid;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable telemetryTick = new Runnable() {
        @Override
        public void run() {
            writeTelemetry(TunService.this);
            handler.postDelayed(this, 1000);
        }
    };

    private ParcelFileDescriptor tun;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (action == null || ACTION_STOP.equals(action)) {
            shutdown();
            return START_NOT_STICKY;
        }

        // ACTION_START, or the system starting us as an always-on VPN: use saved settings.
        SharedPreferences prefs = getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE);
        String host = intent.hasExtra(EXTRA_HOST) ? intent.getStringExtra(EXTRA_HOST)
                : prefs.getString(EXTRA_HOST, MainActivity.DEFAULT_HOST);
        int port = intent.getIntExtra(EXTRA_PORT, prefs.getInt(EXTRA_PORT, MainActivity.DEFAULT_PORT));
        int mtu = intent.getIntExtra(EXTRA_MTU, prefs.getInt(EXTRA_MTU, MainActivity.DEFAULT_MTU));
        String eng = intent.hasExtra(EXTRA_ENGINE) ? intent.getStringExtra(EXTRA_ENGINE)
                : prefs.getString(EXTRA_ENGINE, ENGINE_HEV);
        String cpuList = intent.hasExtra(EXTRA_CPUS) ? intent.getStringExtra(EXTRA_CPUS)
                : prefs.getString(EXTRA_CPUS, "");

        goForeground(host, port, mtu, eng, cpuList);
        stopTunnel();
        try {
            startTunnel(host, port, mtu, eng, cpuList == null ? "" : cpuList.trim());
            lastError = null;
        } catch (Exception e) {
            Log.e(TAG, "start failed", e);
            lastError = e.getMessage();
            shutdown();
        }
        return START_NOT_STICKY;
    }

    private void goForeground(String host, int port, int mtu, String eng, String cpuList) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(
                new NotificationChannel(CHANNEL, "TunBench", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        String text = eng + ": 198.18.0.0/15 -> " + host + ":" + port + ", MTU " + mtu
                + (cpuList == null || cpuList.isEmpty() ? "" : ", cpus " + cpuList);
        Notification n = new Notification.Builder(this, CHANNEL)
                .setContentTitle("TunBench")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setOngoing(true)
                .setContentIntent(open)
                .build();
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
    }

    private void startTunnel(String host, int port, int mtu, String eng, String cpuList)
            throws Exception {
        if (!ENGINE_HEV.equals(eng) && !ENGINE_HONK.equals(eng)) {
            throw new IllegalArgumentException("unknown engine: " + eng);
        }
        Builder b = new Builder()
                .setSession("TunBench")
                .setMtu(mtu)
                .addAddress("198.18.0.2", 32)
                .addRoute("198.18.0.0", 15);
        try {
            b.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            throw new IllegalStateException(e);
        }
        tun = b.establish();
        if (tun == null) {
            throw new IllegalStateException("establish() returned null: VPN consent missing");
        }

        engine = eng;
        cpus = cpuList;
        affinity = "";
        engineTid = 0;
        if (ENGINE_HONK.equals(eng)) {
            startHonk(host, port, mtu, cpuList);
        } else {
            startHev(host, port, mtu, cpuList);
        }
        running = true;
        handler.removeCallbacks(telemetryTick);
        handler.post(telemetryTick);
        Log.i(TAG, "started " + eng + ": " + host + ":" + port + ", mtu " + mtu + ", cpus '"
                + cpuList + "' -> '" + affinity + "', worker tid " + engineTid);
    }

    private void startHonk(String host, int port, int mtu, String cpuList) {
        // The fd stays ours and is closed in stopTunnel(), after the worker has stopped.
        if (!HonkEngine.start(tun.getFd(), mtu, host, port, cpuList)) {
            throw new IllegalStateException("HonkEngine.start failed (logcat tag HonkEngine)");
        }
        affinity = HonkEngine.workerAffinity();
        engineTid = HonkEngine.workerTid();
    }

    private void startHev(String host, int port, int mtu, String cpuList) throws Exception {
        File config = new File(getFilesDir(), "hev-socks5-tunnel.yml");
        String yaml = "tunnel:\n"
                + "  mtu: " + mtu + "\n"
                + "  ipv4: 198.18.0.2\n"
                + "socks5:\n"
                + "  port: " + port + "\n"
                + "  address: '" + host + "'\n"
                + "  udp: 'tcp'\n"
                + "misc:\n"
                + "  log-level: warn\n";
        try (FileOutputStream out = new FileOutputStream(config)) {
            out.write(yaml.getBytes(StandardCharsets.UTF_8));
        }

        // hev's TProxyStartService runs the tunnel on a pthread it creates, which inherits the
        // creating thread's CPU mask and name. So start it from a helper thread that is pinned
        // and named first: the worker (and any thread it spawns) gets the mask, and the name
        // finds its TID. The fd stays ours and is closed in stopTunnel().
        final int fd = tun.getFd();
        final String path = config.getAbsolutePath();
        final String[] effective = new String[1];
        final boolean[] ok = new boolean[1];
        final int[] helperTid = new int[1];
        Thread starter = new Thread(() -> {
            helperTid[0] = HonkEngine.gettid();
            effective[0] = HonkEngine.prepareThread(cpuList, HEV_THREAD);
            if (!effective[0].startsWith("error")) {
                ok[0] = TProxyService.TProxyStartService(path, fd);
            }
        }, "hev-start");
        starter.start();
        starter.join();
        if (effective[0] == null || effective[0].startsWith("error")) {
            throw new IllegalStateException(String.valueOf(effective[0]));
        }
        if (!ok[0]) {
            throw new IllegalStateException("TProxyStartService failed");
        }
        affinity = effective[0];
        engineTid = HonkEngine.findThread(HEV_THREAD, helperTid[0]);
    }

    private void stopTunnel() {
        handler.removeCallbacks(telemetryTick);
        if (running) {
            // Last snapshot while the worker still exists.
            writeTelemetry(this);
            if (ENGINE_HONK.equals(engine)) {
                HonkEngine.stop();
            } else {
                TProxyService.TProxyStopService();
            }
            running = false;
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (IOException ignored) {
            }
            tun = null;
        }
    }

    private void shutdown() {
        stopTunnel();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    /** {tx_packets, tx_bytes, rx_packets, rx_bytes} of the current (or last) engine. */
    static long[] stats() {
        return ENGINE_HONK.equals(engine) ? HonkEngine.stats() : TProxyService.TProxyGetStats();
    }

    static boolean engineRunning() {
        return ENGINE_HONK.equals(engine) ? HonkEngine.isRunning()
                : TProxyService.TProxyIsRunning();
    }

    /** One key=value line: the engine, the CPUs asked for, and the worker thread's telemetry. */
    static String telemetryLine() {
        boolean on = running;
        StringBuilder sb = new StringBuilder();
        sb.append("t_ms=").append(SystemClock.elapsedRealtime())
                .append(" engine=").append(on ? engine : "none")
                .append(" running=").append(on && engineRunning() ? 1 : 0)
                .append(" cpus_req=").append(cpus.isEmpty() ? "-" : cpus);
        if (on) {
            sb.append(' ').append(HonkEngine.telemetry(engineTid));
        }
        return sb.toString();
    }

    /** Writes telemetryLine() to files/telemetry.txt (replaced atomically). */
    static synchronized void writeTelemetry(Context ctx) {
        File dir = ctx.getFilesDir();
        File tmp = new File(dir, TELEMETRY_FILE + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write((telemetryLine() + "\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Log.w(TAG, "telemetry write failed", e);
            return;
        }
        if (!tmp.renameTo(new File(dir, TELEMETRY_FILE))) {
            Log.w(TAG, "telemetry rename failed");
        }
    }

    @Override
    public void onRevoke() {
        shutdown();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        super.onDestroy();
    }
}
