package dev.tunbench

/** JNI entry points of hev-socks5-tunnel, registered by its JNI_OnLoad under this class name. */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int): Boolean

    @JvmStatic
    external fun TProxyStopService(): Boolean

    @JvmStatic
    external fun TProxyIsRunning(): Boolean

    /** Returns {tx_packets, tx_bytes, rx_packets, rx_bytes}. */
    @JvmStatic
    external fun TProxyGetStats(): LongArray
}
