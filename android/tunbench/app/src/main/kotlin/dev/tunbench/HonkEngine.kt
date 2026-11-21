package dev.tunbench

/**
 * JNI entry points of libhonkengine.so (crates/honk-android): the honk-netstack engine, plus thread
 * helpers (affinity, naming, /proc telemetry) that the hev path uses too. Logs go to logcat
 * under the tag HonkEngine.
 */
object HonkEngine {
    init {
        System.loadLibrary("honkengine")
    }

    /**
     * Starts the worker thread on the tun fd (the fd stays the caller's). Every TCP flow is
     * relayed to targetHost:targetPort (null reads as empty); cpuList ("", "0-1", "0-2,7") pins the
     * worker. Returns false if it is already running or the setup failed.
     */
    @JvmStatic
    external fun start(
        tunFd: Int,
        mtu: Int,
        targetHost: String?,
        targetPort: Int,
        cpuList: String,
    ): Boolean

    /** Stops the worker and waits for it. */
    @JvmStatic
    external fun stop()

    @JvmStatic
    external fun isRunning(): Boolean

    /** Returns {tx_packets, tx_bytes, rx_packets, rx_bytes}: tx read from the tun, rx written. */
    @JvmStatic
    external fun stats(): LongArray

    /** TID of the worker thread, 0 before the first start. */
    @JvmStatic
    external fun workerTid(): Int

    /** The worker's effective CPU list after pinning. */
    @JvmStatic
    external fun workerAffinity(): String

    /**
     * Pins the calling thread to cpuList (if non-empty) and sets its name (if non-empty);
     * threads it creates afterwards inherit both. Returns the effective CPU list, or a string
     * starting with "error:".
     */
    @JvmStatic
    external fun prepareThread(cpuList: String, name: String): String

    @JvmStatic
    external fun gettid(): Int

    /** Lowest TID of this process whose name is name, other than exclude; 0 if none. */
    @JvmStatic
    external fun findThread(name: String, exclude: Int): Int

    /**
     * One line of key=value pairs for thread tid: utime, stime (clock ticks), processor,
     * nr_migrations (when readable), context switches, Cpus_allowed_list, and the process cpuset.
     */
    @JvmStatic
    external fun telemetry(tid: Int): String
}
