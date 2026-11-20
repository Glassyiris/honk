package dev.tunbench;

/** JNI entry points of hev-socks5-tunnel, registered by its JNI_OnLoad under this class name. */
public final class TProxyService {
    private TProxyService() {
    }

    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    public static native boolean TProxyStartService(String configPath, int fd);

    public static native boolean TProxyStopService();

    public static native boolean TProxyIsRunning();

    /** Returns {tx_packets, tx_bytes, rx_packets, rx_bytes}. */
    public static native long[] TProxyGetStats();
}
