package dev.tunbench;

/**
 * JNI entry points of libhonkengine.so (crates/honk-android): the honk-netstack engine, plus thread
 * helpers (affinity, naming, /proc telemetry) that the hev path uses too. Logs go to logcat
 * under the tag HonkEngine.
 */
public final class HonkEngine {
    private HonkEngine() {
    }

    static {
        System.loadLibrary("honkengine");
    }

    /**
     * Starts the worker thread on the tun fd (the fd stays the caller's). Every TCP flow is
     * relayed to targetHost:targetPort; cpuList ("", "0-1", "0-2,7") pins the worker. Returns
     * false if it is already running or the setup failed.
     */
    public static native boolean start(int tunFd, int mtu, String targetHost, int targetPort,
            String cpuList);

    /** Stops the worker and waits for it. */
    public static native void stop();

    public static native boolean isRunning();

    /** Returns {tx_packets, tx_bytes, rx_packets, rx_bytes}: tx read from the tun, rx written. */
    public static native long[] stats();

    /** TID of the worker thread, 0 before the first start. */
    public static native int workerTid();

    /** The worker's effective CPU list after pinning. */
    public static native String workerAffinity();

    /**
     * Pins the calling thread to cpuList (if non-empty) and sets its name (if non-empty);
     * threads it creates afterwards inherit both. Returns the effective CPU list, or a string
     * starting with "error:".
     */
    public static native String prepareThread(String cpuList, String name);

    public static native int gettid();

    /** Lowest TID of this process whose name is name, other than exclude; 0 if none. */
    public static native int findThread(String name, int exclude);

    /**
     * One line of key=value pairs for thread tid: utime, stime (clock ticks), processor,
     * nr_migrations (when readable), context switches, Cpus_allowed_list, and the process cpuset.
     */
    public static native String telemetry(int tid);
}
