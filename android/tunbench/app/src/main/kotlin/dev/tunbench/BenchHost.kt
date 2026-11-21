package dev.tunbench

import android.hardware.display.DisplayManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import android.view.Display
import org.json.JSONObject
import java.io.IOException

/**
 * The host object Bench.run() calls back by name and JNI signature (crates/honk-android,
 * src/harness/mod.rs). All methods run on the bench thread, except startHev, which runs on the
 * runner's native thread tb-hev.
 *
 * Tun ownership: openTun keeps the ParcelFileDescriptor and returns its fd without detaching it.
 * The engine borrows that fd (honk and hev both leave it open when they stop); only closeTun
 * closes it, after the engine has stopped.
 */
class BenchHost(private val service: TunService) {
    private var tun: ParcelFileDescriptor? = null

    /** Establishes the VPN as the manual mode does, but routes only TunBench through it. */
    fun openTun(mtu: Int): Int {
        val pfd = try {
            service.tunBuilder(mtu).addAllowedApplication(service.packageName).establish()
        } catch (e: Exception) {
            Log.e(TAG, "openTun($mtu) failed", e)
            return -1
        }
        if (pfd == null) {
            Log.e(TAG, "openTun: establish() returned null: VPN consent missing")
            return -1
        }
        tun = pfd
        return pfd.fd
    }

    fun closeTun() {
        try {
            tun?.close()
        } catch (e: IOException) {
            Log.w(TAG, "closeTun failed", e)
        }
        tun = null
    }

    /** The runner left the tun open: hev did not stop (see stopHev in harness/mod.rs). */
    val tunKept: Boolean
        get() = tun != null

    fun startHev(configPath: String, tunFd: Int): Boolean =
        TProxyService.TProxyStartService(configPath, tunFd)

    fun stopHev(): Boolean = TProxyService.TProxyStopService()

    fun hevStats(): LongArray = TProxyService.TProxyGetStats()

    /** The screen, foreground and device state the runner checks at each window edge. */
    fun platform(): String {
        val power = service.getSystemService(PowerManager::class.java)
        val display = service.getSystemService(DisplayManager::class.java)
            .getDisplay(Display.DEFAULT_DISPLAY)
        val sdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            Build.VERSION.SDK_INT_FULL
        } else {
            Build.VERSION.SDK_INT
        }
        return JSONObject()
            .put("interactive", power.isInteractive)
            .put("display_state", display?.state ?: Display.STATE_UNKNOWN)
            .put("bench_activity_resumed", BenchActivity.topResumed)
            .put("sdk_int_full", sdk)
            .put("build_id", Build.ID)
            .put("thermal_status", power.currentThermalStatus)
            .toString()
    }

    fun progress(done: Int, total: Int) {
        Log.i(TAG, "bench: $done of $total lines written")
    }

    private companion object {
        const val TAG = "TunBench"
    }
}
