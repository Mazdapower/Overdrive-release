package com.overdrive.app.netguard;

import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

/**
 * Process-wide outbound-network kill-switch for the "no-internet" build.
 *
 * <h2>Why this exists</h2>
 * OverDrive's dashcam pipeline and in-car UI communicate over <b>loopback</b>
 * (127.0.0.1) sockets: the app talks to the privileged CameraDaemon and loads
 * its local API over 127.0.0.1. Android gates <i>every</i> AF_INET socket -
 * including loopback - behind {@code android.permission.INTERNET}, so the
 * permission itself cannot be removed without breaking the dashcam.
 *
 * <h2>How it enforces</h2>
 * The guard installs a process-wide {@link ProxySelector} that:
 * <ul>
 *   <li>returns {@link Proxy#NO_PROXY} (direct) for loopback/localhost/file -
 *       so the dashcam IPC and local web API keep working, and</li>
 *   <li>returns a proxy pointing at a dead <b>loopback</b> port for every other
 *       host. The connection then fails immediately on-device; no packet ever
 *       leaves the head unit. The remote host is never contacted and the
 *       connection is indistinguishable from "proxy down".</li>
 * </ul>
 *
 * OkHttp (used by the updater, analytics, ABRP, weather, geocoding, community
 * and RoadSense clients) and the platform {@code HttpURLConnection} both honour
 * {@link ProxySelector#getDefault()}, so this covers the HTTP(S) surface without
 * needing the {@code SocketFactory.setDefault} hook that the Android public SDK
 * removed.
 *
 * <p>Networking that does not consult a {@code ProxySelector} (raw Paho MQTT,
 * Java-WebSocket, BYD Cloud) is additionally disabled at its feature entry
 * point. External executables (zrok, tailscaled, cloudflared, sing-box) run in
 * their own processes and are gated behind {@link #REMOTE_ACCESS_ENABLED}.
 */
public final class NoInternetGuard {

    private static final String TAG = "NoInternetGuard";

    /**
     * Master switch for remote-access features that would otherwise reach the
     * internet, including those that spawn external binaries in a separate
     * process (zrok / tailscale / cloudflared / sing-box / Telegram bot).
     * Hard-disabled in the no-internet build.
     */
    public static final boolean REMOTE_ACCESS_ENABLED = false;

    /** Discard port on loopback: closed on every Android device, so a proxy
     *  connection here is refused instantly and never leaves the device. */
    private static final int BLOCKED_PORT = 9;
    private static final String LOCAL = "127.0.0.1";

    private static final AtomicBoolean INSTALLED = new AtomicBoolean(false);

    private NoInternetGuard() {}

    /**
     * Idempotently install the outbound kill-switch for the current process.
     * Safe to call repeatedly and from any thread; never throws.
     */
    public static void install() {
        if (!INSTALLED.compareAndSet(false, true)) {
            return;
        }
        try {
            ProxySelector.setDefault(new BlockingProxySelector());
        } catch (Throwable t) {
            Log.w(TAG, "could not install blocking ProxySelector: " + t);
        }
    }

    // ==================== ADDRESS CLASSIFICATION ====================

    /** True when {@code addr} is loopback or any-local (i.e. on-device). */
    public static boolean isAllowedAddress(InetAddress addr) {
        if (addr == null) {
            return true; // unresolved / not-yet-bound: let the connect call decide
        }
        try {
            return addr.isLoopbackAddress() || addr.isAnyLocalAddress();
        } catch (Throwable t) {
            return false;
        }
    }

    /** True when {@code host} is a loopback literal or {@code localhost}. */
    public static boolean isAllowedHost(String host) {
        if (host == null) {
            return true;
        }
        String h = host.trim().toLowerCase();
        if (h.isEmpty()) {
            return true;
        }
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1");
    }

    /** True when the endpoint is loopback/local and therefore permitted. */
    public static boolean isAllowedEndpoint(SocketAddress endpoint) {
        if (endpoint == null) {
            return true;
        }
        if (!(endpoint instanceof InetSocketAddress)) {
            // Unknown address family (e.g. Unix domain socket) - local by nature.
            return true;
        }
        InetSocketAddress isa = (InetSocketAddress) endpoint;
        String host = isa.getHostString();
        if (isAllowedHost(host)) {
            return true;
        }
        InetAddress addr = isa.getAddress();
        if (addr == null) {
            return false; // unresolvable, non-local name -> refuse
        }
        // A literal IP (host string == textual address): allow loopback/any-local
        // literals such as 127.0.0.1 or a 0.0.0.0 connect. A *name* that merely
        // resolved to such an address (e.g. a DNS sinkhole to 0.0.0.0) is NOT
        // trusted, because reaching it required an internet DNS lookup.
        if (host != null && host.equalsIgnoreCase(addr.getHostAddress())) {
            return isAllowedAddress(addr);
        }
        return addr.isLoopbackAddress();
    }

    /** The (dead-loopback) proxy used to force a fast, on-device refusal. */
    public static Proxy blockedProxy() {
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(LOCAL, BLOCKED_PORT));
    }

    /**
     * A {@link SocketFactory} whose sockets refuse to connect anywhere but
     * loopback/local. Used to fail closed for clients that ignore the
     * {@link ProxySelector} (e.g. Paho MQTT via {@code MqttConnectOptions}).
     */
    public static SocketFactory blockingSocketFactory() {
        return new BlockingSocketFactory();
    }

    /**
     * TLS variant for Paho's SSL network module / BYD Cloud. Any attempt to
     * reach a non-local host throws before a handshake can begin.
     */
    public static SSLSocketFactory blockingSslSocketFactory(SSLSocketFactory delegate) {
        return new BlockingSslSocketFactory(delegate);
    }

    /** A {@link Socket} whose {@code connect()} refuses non-loopback targets. */
    static final class GuardedSocket extends Socket {
        @Override
        public void connect(SocketAddress endpoint) throws IOException {
            if (!isAllowedEndpoint(endpoint)) {
                throw new IOException("Blocked by NoInternetGuard: " + endpoint);
            }
            super.connect(endpoint);
        }

        @Override
        public void connect(SocketAddress endpoint, int timeout) throws IOException {
            if (!isAllowedEndpoint(endpoint)) {
                throw new IOException("Blocked by NoInternetGuard: " + endpoint);
            }
            super.connect(endpoint, timeout);
        }
    }

    /** {@link SocketFactory} yielding connect()-guarded sockets. */
    static final class BlockingSocketFactory extends SocketFactory {
        @Override
        public Socket createSocket() {
            return new GuardedSocket();
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            Socket s = new GuardedSocket();
            s.connect(new InetSocketAddress(host, port));
            return s;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                throws IOException {
            Socket s = new GuardedSocket();
            s.bind(new InetSocketAddress(localHost, localPort));
            s.connect(new InetSocketAddress(host, port));
            return s;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket s = new GuardedSocket();
            s.connect(new InetSocketAddress(host, port));
            return s;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                int localPort) throws IOException {
            Socket s = new GuardedSocket();
            s.bind(new InetSocketAddress(localAddress, localPort));
            s.connect(new InetSocketAddress(address, port));
            return s;
        }
    }

    /** {@link SSLSocketFactory} that refuses to open a TLS tunnel off-device. */
    static final class BlockingSslSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;

        BlockingSslSocketFactory(SSLSocketFactory delegate) {
            this.delegate = delegate;
        }

        private static void enforceHost(String host) throws IOException {
            if (!isAllowedHost(host)) {
                throw new IOException("Blocked by NoInternetGuard: " + host);
            }
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public Socket createSocket() throws IOException {
            // No destination yet; hand out a guarded raw socket. A subsequent
            // connect() to a non-local host is refused.
            return new GuardedSocket();
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose)
                throws IOException {
            enforceHost(host);
            return delegate.createSocket(s, host, port, autoClose);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            enforceHost(host);
            return delegate.createSocket(host, port);
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                throws IOException {
            enforceHost(host);
            return delegate.createSocket(host, port, localHost, localPort);
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            if (!isAllowedAddress(host)) {
                throw new IOException("Blocked by NoInternetGuard: " + host);
            }
            return delegate.createSocket(host, port);
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
                int localPort) throws IOException {
            if (!isAllowedAddress(address)) {
                throw new IOException("Blocked by NoInternetGuard: " + address);
            }
            return delegate.createSocket(address, port, localAddress, localPort);
        }
    }

    // ==================== PROXY SELECTOR ====================

    /**
     * Routes every non-local destination through a dead loopback port so the
     * connection fails on-device, while leaving loopback/local traffic direct.
     */
    static final class BlockingProxySelector extends ProxySelector {
        @Override
        public List<Proxy> select(URI uri) {
            if (uri == null) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            String scheme = uri.getScheme();
            if (scheme != null) {
                String s = scheme.toLowerCase();
                // Non-network schemes never leave the device.
                if (s.equals("file") || s.equals("jar") || s.equals("socket")) {
                    return Collections.singletonList(Proxy.NO_PROXY);
                }
            }
            if (isAllowedHost(uri.getHost())) {
                return Collections.singletonList(Proxy.NO_PROXY);
            }
            List<Proxy> blocked = new ArrayList<>(1);
            blocked.add(blockedProxy());
            return blocked;
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            // Nothing to recover - the refusal is intentional.
        }
    }
}
