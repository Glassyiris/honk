package dev.tunbench

import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

/**
 * Runs a bench plan behind a black screen that keeps the phone interactive with nothing lit
 * (no text, icon or progress: no burn-in). Driven from a shell:
 *
 * am start -n dev.tunbench/.BenchActivity --es plan <file in files/plans/> --es run <run id>
 * am start -n dev.tunbench/.BenchActivity --ez stop true --es run <run id>
 *
 * TunService runs the plan and writes files/runs/<run id>/done when it ends; this Activity
 * finishes then. The stop intent cancels the run only if it is the one in progress and never
 * lights the screen; Back cancels the run in progress. Both finish this Activity at once. A tap
 * does nothing.
 */
class BenchActivity : ComponentActivity() {
    private val onBenchEnd = { finish() }

    /** This instance is the top resumed activity; see [topResumed]. */
    private var top = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.attributes = window.attributes.apply {
            screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_OFF
        }
        setContentView(View(this).apply { setBackgroundColor(Color.BLACK) })
        WindowCompat.getInsetsController(window, window.decorView).run {
            systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            hide(WindowInsetsCompat.Type.systemBars())
        }
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() = stop(TunService.benchRunId)
            },
        )
        if (savedInstanceState == null) {
            handle(intent)
        } else if (TunService.benchRunning() && TunService.benchListener == null) {
            // Recreated (configuration change) while its run goes on.
            follow()
        } else {
            // Restored after the process died, the run ended meanwhile, or another instance
            // follows it: nothing to show.
            finish()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(EXTRA_STOP, false)) {
            val run = intent.getStringExtra(EXTRA_RUN)
            if (run == TunService.benchRunId) {
                stop(run)
            } else {
                // A stop for another run must not take this run's screen away.
                Log.w(TAG, "bench: stop for run $run ignored")
            }
        } else {
            // Only an Activity that follows a run is on top to get a new intent.
            Log.w(TAG, "bench: a run is in progress; new run refused")
            TunService.writeBenchDone(this, intent.getStringExtra(EXTRA_RUN), TunService.BENCH_BUSY)
        }
    }

    override fun onTopResumedActivityChanged(isTopResumedActivity: Boolean) {
        super.onTopResumedActivityChanged(isTopResumedActivity)
        top = isTopResumedActivity
        topResumed = isTopResumedActivity
    }

    override fun onDestroy() {
        if (TunService.benchListener === onBenchEnd) {
            TunService.benchListener = null
        }
        // Process-wide: an instance destroyed while on top must not leave it set.
        if (top) topResumed = false
        super.onDestroy()
    }

    private fun handle(intent: Intent) {
        if (intent.getBooleanExtra(EXTRA_STOP, false)) {
            stop(intent.getStringExtra(EXTRA_RUN))
            return
        }
        val run = intent.getStringExtra(EXTRA_RUN)
        val plan = intent.getStringExtra(EXTRA_PLAN)
        val error = when {
            !TunService.isFileName(run) -> "run id missing or not a file name"
            !TunService.isFileName(plan) -> "plan missing or not a file name"
            TunService.benchRunning() -> TunService.BENCH_BUSY
            // Consent is granted by run.sh (appops ACTIVATE_VPN); never ask with a dialog here.
            VpnService.prepare(this) != null -> "VPN consent missing"
            else -> null
        }
        if (error != null) {
            Log.e(TAG, "bench: $error")
            TunService.writeBenchDone(this, run, error)
            finish()
            return
        }
        TunService.benchCancelled = false
        TunService.benchRunId = run
        follow()
        // This Activity is visible, so a plain start is allowed; TunService goes foreground itself.
        startService(
            Intent(this, TunService::class.java)
                .setAction(TunService.ACTION_BENCH)
                .putExtra(EXTRA_PLAN, plan)
                .putExtra(EXTRA_RUN, run),
        )
    }

    /** Follows the run in progress: lights the black screen and finishes when the run ends. */
    private fun follow() {
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        TunService.benchListener = onBenchEnd
    }

    /** Back and the stop intent: cancel run [run] if it is in progress, and finish now. */
    private fun stop(run: String?) {
        TunService.cancelBench(run)
        finish()
    }

    companion object {
        const val EXTRA_PLAN = "plan"
        const val EXTRA_RUN = "run"
        const val EXTRA_STOP = "stop"

        private const val TAG = "TunBench"

        /**
         * This Activity is the top resumed activity (not only resumed, as in split screen); read
         * by BenchHost.platform() on the bench thread.
         */
        @Volatile
        var topResumed = false
            private set
    }
}
