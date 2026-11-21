package dev.tunbench

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.io.IOException
import kotlin.concurrent.thread

class TunService : VpnService() {
    private val handler = Handler(Looper.getMainLooper())
    private val telemetryTick = object : Runnable {
        override fun run() {
            writeTelemetry(this@TunService)
            handler.postDelayed(this, 1000)
        }
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (intent == null || action == null || action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        if (action == ACTION_BENCH) {
            startBench(
                intent.getStringExtra(BenchActivity.EXTRA_PLAN),
                intent.getStringExtra(BenchActivity.EXTRA_RUN),
            )
            return START_NOT_STICKY
        }
        if (bench != null) {
            // MainActivity starts with startForegroundService(), which must be answered.
            goForeground("bench run in progress")
            Log.w(TAG, "a bench run is in progress; manual start ignored")
            return START_NOT_STICKY
        }

        // ACTION_START, or the system starting us as an always-on VPN: use saved settings.
        val prefs = getSharedPreferences(MainActivity.PREFS, MODE_PRIVATE)
        val host = if (intent.hasExtra(EXTRA_HOST)) intent.getStringExtra(EXTRA_HOST)
            else prefs.getString(EXTRA_HOST, MainActivity.DEFAULT_HOST)
        val port =
            intent.getIntExtra(EXTRA_PORT, prefs.getInt(EXTRA_PORT, MainActivity.DEFAULT_PORT))
        val mtu = intent.getIntExtra(EXTRA_MTU, prefs.getInt(EXTRA_MTU, MainActivity.DEFAULT_MTU))
        val eng = if (intent.hasExtra(EXTRA_ENGINE)) intent.getStringExtra(EXTRA_ENGINE)
            else prefs.getString(EXTRA_ENGINE, ENGINE_HEV)
        val cpuList = if (intent.hasExtra(EXTRA_CPUS)) intent.getStringExtra(EXTRA_CPUS)
            else prefs.getString(EXTRA_CPUS, "")

        stopTunnel()
        try {
            // Without VPN consent, startForeground() with the systemExempted type throws
            // (ForegroundServiceTypeNotAllowedException); report it like a failed establish().
            goForeground(
                "$eng: 198.18.0.0/15 -> $host:$port, MTU $mtu" +
                    if (cpuList.isNullOrEmpty()) "" else ", cpus $cpuList",
            )
            startTunnel(host, port, mtu, eng, cpuList?.trim { it <= ' ' }.orEmpty())
            lastError = null
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            lastError = e.message
            shutdown()
        }
        return START_NOT_STICKY
    }

    private fun goForeground(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "TunBench", NotificationManager.IMPORTANCE_LOW),
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val n = Notification.Builder(this, CHANNEL)
            .setContentTitle("TunBench")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setContentIntent(open)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    private fun startTunnel(host: String?, port: Int, mtu: Int, eng: String?, cpuList: String) {
        val name = eng.takeIf { it == ENGINE_HEV || it == ENGINE_HONK }
            ?: throw IllegalArgumentException("unknown engine: $eng")
        val b = tunBuilder(mtu)
        try {
            b.addDisallowedApplication(packageName)
        } catch (e: PackageManager.NameNotFoundException) {
            throw IllegalStateException(e)
        }
        val fd = b.establish()
            ?: throw IllegalStateException("establish() returned null: VPN consent missing")
        tun = fd

        engine = name
        cpus = cpuList
        affinity = ""
        engineTid = 0
        if (name == ENGINE_HONK) {
            startHonk(fd, host, port, mtu, cpuList)
        } else {
            startHev(fd, host, port, mtu, cpuList)
        }
        running = true
        handler.removeCallbacks(telemetryTick)
        handler.post(telemetryTick)
        Log.i(TAG, "started $name: $host:$port, mtu $mtu, cpus '$cpuList' -> '$affinity', " +
            "worker tid $engineTid")
    }

    /** The VPN both modes build: 198.18.0.2/32 in 198.18.0.0/15. */
    fun tunBuilder(mtu: Int): Builder = Builder()
        .setSession("TunBench")
        .setMtu(mtu)
        .addAddress("198.18.0.2", 32)
        .addRoute("198.18.0.0", 15)

    private fun startHonk(
        pfd: ParcelFileDescriptor,
        host: String?,
        port: Int,
        mtu: Int,
        cpuList: String,
    ) {
        // The fd stays ours and is closed in stopTunnel(), after the worker has stopped.
        check(HonkEngine.start(pfd.fd, mtu, host, port, cpuList)) {
            "HonkEngine.start failed (logcat tag HonkEngine)"
        }
        affinity = HonkEngine.workerAffinity()
        engineTid = HonkEngine.workerTid()
    }

    private fun startHev(
        pfd: ParcelFileDescriptor,
        host: String?,
        port: Int,
        mtu: Int,
        cpuList: String,
    ) {
        val config = File(filesDir, "hev-socks5-tunnel.yml")
        config.writeText(
            buildString {
                appendLine("tunnel:")
                appendLine("  mtu: $mtu")
                appendLine("  ipv4: 198.18.0.2")
                appendLine("socks5:")
                appendLine("  port: $port")
                appendLine("  address: '$host'")
                appendLine("  udp: 'tcp'")
                appendLine("misc:")
                appendLine("  log-level: warn")
            },
        )

        // hev's TProxyStartService runs the tunnel on a pthread it creates, which inherits the
        // creating thread's CPU mask and name. So start it from a helper thread that is pinned
        // and named first: the worker (and any thread it spawns) gets the mask, and the name
        // finds its TID. The fd stays ours and is closed in stopTunnel().
        val fd = pfd.fd
        val path = config.absolutePath
        var effective: String? = null
        var ok = false
        var helperTid = 0
        thread(name = "hev-start") {
            helperTid = HonkEngine.gettid()
            val pinned = HonkEngine.prepareThread(cpuList, HEV_THREAD)
            effective = pinned
            if (!pinned.startsWith("error")) {
                ok = TProxyService.TProxyStartService(path, fd)
            }
        }.join()
        val result = effective
        check(result != null && !result.startsWith("error")) { result.toString() }
        check(ok) { "TProxyStartService failed" }
        affinity = result
        engineTid = HonkEngine.findThread(HEV_THREAD, helperTid)
    }

    private fun stopTunnel() {
        handler.removeCallbacks(telemetryTick)
        if (running) {
            // Last snapshot while the worker still exists.
            writeTelemetry(this)
            if (engine == ENGINE_HONK) {
                HonkEngine.stop()
            } else {
                TProxyService.TProxyStopService()
            }
            running = false
        }
        try {
            tun?.close()
        } catch (_: IOException) {
        }
        tun = null
    }

    /**
     * Runs a plan on one dedicated thread (the Bench.run thread). A manual tunnel stops first, so
     * no other engine and no telemetry writer run during the plan. When run returns, the tun is
     * closed, files/runs/<run id>/done is written, the service stops and the Activity finishes.
     * BenchActivity starts this service with startService(): if startForeground() fails here,
     * the run ends with that reason and the service stops without a did-not-start crash.
     */
    private fun startBench(plan: String?, runId: String?) {
        if (bench != null) {
            Log.w(TAG, "a bench run is in progress; run $runId refused")
            writeBenchDone(this, runId, BENCH_BUSY)
            return
        }
        stopTunnel()
        try {
            goForeground("bench run $runId")
        } catch (e: Exception) {
            Log.e(TAG, "bench: start failed", e)
            endBench(runId, "start failed: ${e.message}")
            return
        }
        if (benchCancelled) {
            endBench(runId, "cancelled")
            return
        }
        val host = BenchHost(this)
        val planPath = File(filesDir, "plans/$plan").path
        val outDir = File(filesDir, "runs/$runId").path
        val run = BenchRun()
        bench = run
        thread(name = "tb-bench") {
            val result = try {
                Bench.run(host, planPath, outDir, runId.orEmpty()) ?: "ok"
            } catch (e: Throwable) {
                // Whatever failed (a JNI error, a missing native), the run still gets a done marker.
                Log.e(TAG, "bench: run failed", e)
                e.message ?: e.toString()
            }
            run.inRunner = false
            handler.post {
                bench = null
                endBench(runId, result, host.tunKept)
            }
        }
    }

    private fun endBench(runId: String?, result: String, tunKept: Boolean = false) {
        writeBenchDone(this, runId, result)
        benchRunId = null
        if (tunKept) {
            // hev did not stop, so the runner left its tun open rather than let hev touch a reused
            // fd. Only ending the process closes that fd and takes hev's stale threads with it,
            // which the next run would otherwise count as its own.
            Log.e(TAG, "bench: the tun is still open; ending the process")
            Process.killProcess(Process.myPid())
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        benchListener?.invoke()
    }

    private fun shutdown() {
        // During a plan, cancel it; its thread stops the service when run returns.
        if (stopBench()) return
        stopTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        // Called on a Binder thread; bench start and stop run on the main thread.
        handler.post { shutdown() }
    }

    override fun onDestroy() {
        stopBench()
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "dev.tunbench.START"
        const val ACTION_STOP = "dev.tunbench.STOP"
        const val ACTION_BENCH = "dev.tunbench.BENCH"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_ENGINE = "engine"
        const val EXTRA_CPUS = "cpus"
        const val ENGINE_HEV = "hev"
        const val ENGINE_HONK = "honk"
        const val TELEMETRY_FILE = "telemetry.txt"

        private const val TAG = "TunBench"
        private const val CHANNEL = "tunbench"
        private const val NOTIFICATION_ID = 1

        /** hev's worker inherits this name from the thread that starts it, which identifies it. */
        private const val HEV_THREAD = "hev-worker"

        @JvmField @Volatile
        var running = false

        @JvmField @Volatile
        var lastError: String? = null

        /** The engine that runs (or ran last), the CPU list asked for and the one in effect. */
        @JvmField @Volatile
        var engine = ENGINE_HEV

        @JvmField @Volatile
        var cpus = ""

        @JvmField @Volatile
        var affinity = ""

        /** TID of the engine's worker thread, 0 if unknown. */
        @JvmField @Volatile
        var engineTid = 0

        /** Called on the main thread when a bench run has ended (BenchActivity finishes). */
        @Volatile
        var benchListener: (() -> Unit)? = null

        /**
         * The run BenchActivity has requested, until it ends (endBench); main thread only. Set
         * before startService(), so a second start is refused before this service sees the first.
         */
        var benchRunId: String? = null

        /** Set by cancelBench(): a run requested but not started yet is not started. */
        @Volatile
        var benchCancelled = false

        /** The done marker of a run refused because another one is in progress. */
        const val BENCH_BUSY = "busy"

        /** One plan run. inRunner is cleared by its thread as soon as Bench.run() returns. */
        private class BenchRun {
            @Volatile
            var inRunner = true
        }

        /**
         * The run in progress; main thread only. Process-wide, so a recreated service still
         * refuses a new run. Cleared on the main thread by the message the run's thread posts
         * as its last step, after Bench.run() has returned.
         */
        private var bench: BenchRun? = null

        /** A run has been requested and has not ended (main thread only). */
        fun benchRunning(): Boolean = benchRunId != null

        /** Cancels run [runId] if it is the one in progress, else nothing. Main thread only. */
        fun cancelBench(runId: String?) {
            if (runId == null || runId != benchRunId) return
            benchCancelled = true
            stopBench()
        }

        /** Cancels the running plan; false if none is running. Main thread only. */
        fun stopBench(): Boolean {
            val run = bench ?: return false
            // Once Bench.run() has returned, a stop would cancel the next run instead.
            if (run.inRunner) Bench.stop()
            return true
        }

        /** A plain name inside files/plans/ or files/runs/: no path separator, not . or .. */
        fun isFileName(name: String?): Boolean =
            !name.isNullOrEmpty() && '/' !in name && name != "." && name != ".."

        /** Writes files/runs/<runId>/done (replaced atomically): "ok", or why the run stopped. */
        fun writeBenchDone(ctx: Context, runId: String?, result: String) {
            if (!isFileName(runId)) {
                Log.e(TAG, "bench: no done marker for run id '$runId': $result")
                return
            }
            val dir = File(ctx.filesDir, "runs/$runId")
            val tmp = File(dir, "done.tmp")
            try {
                dir.mkdirs()
                tmp.writeText(result + "\n")
            } catch (e: IOException) {
                Log.e(TAG, "bench: done marker write failed", e)
                return
            }
            if (!tmp.renameTo(File(dir, "done"))) {
                Log.e(TAG, "bench: done marker rename failed")
            }
        }

        /** {tx_packets, tx_bytes, rx_packets, rx_bytes} of the current (or last) engine. */
        @JvmStatic
        fun stats(): LongArray =
            if (engine == ENGINE_HONK) HonkEngine.stats() else TProxyService.TProxyGetStats()

        @JvmStatic
        fun engineRunning(): Boolean =
            if (engine == ENGINE_HONK) HonkEngine.isRunning() else TProxyService.TProxyIsRunning()

        /** One key=value line: the engine, the CPUs asked for, and the worker thread telemetry. */
        @JvmStatic
        fun telemetryLine(): String {
            val on = running
            val line = "t_ms=${SystemClock.elapsedRealtime()}" +
                " engine=${if (on) engine else "none"}" +
                " running=${if (on && engineRunning()) 1 else 0}" +
                " cpus_req=${cpus.ifEmpty { "-" }}"
            return if (on) "$line ${HonkEngine.telemetry(engineTid)}" else line
        }

        /** Writes telemetryLine() to files/telemetry.txt (replaced atomically). */
        @JvmStatic
        fun writeTelemetry(ctx: Context) {
            synchronized(TunService::class.java) {
                val dir = ctx.filesDir
                val tmp = File(dir, "$TELEMETRY_FILE.tmp")
                try {
                    // Open the file before sampling: no JNI call when it cannot be written.
                    tmp.outputStream().use { it.write((telemetryLine() + "\n").toByteArray()) }
                } catch (e: IOException) {
                    Log.w(TAG, "telemetry write failed", e)
                    return
                }
                if (!tmp.renameTo(File(dir, TELEMETRY_FILE))) {
                    Log.w(TAG, "telemetry rename failed")
                }
            }
        }
    }
}
