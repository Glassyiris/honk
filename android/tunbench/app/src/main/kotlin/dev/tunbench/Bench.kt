package dev.tunbench

/**
 * JNI entry points of the bench runner in libhonkengine.so (crates/honk-android, feature `bench`;
 * the surface is described in src/harness/mod.rs). Loads the library itself, so a first call does
 * not depend on HonkEngine having loaded it.
 */
object Bench {
    init {
        System.loadLibrary("honkengine")
    }

    /**
     * Runs the plan at planPath, writing outDir/plan.json and outDir/results.jsonl. Blocks until
     * the plan ends; returns null when every step was written, else why it stopped ("cancelled"
     * after stop()). Throws RuntimeException on a JNI error or a panic.
     */
    @JvmStatic
    external fun run(host: BenchHost, planPath: String, outDir: String, runId: String): String?

    /** Ends the current measurement as cancelled and makes run() return; before run(), cancels it. */
    @JvmStatic
    external fun stop()
}
