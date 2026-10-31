package com.overdrive.app.netguard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.List;

/**
 * Verifies the address-classification rules underpinning the no-internet build:
 * loopback/local must be allowed (dashcam IPC + local UI), everything else
 * (i.e. the internet) must be redirected to an on-device dead end.
 */
public class NoInternetGuardTest {

    @Test
    public void loopbackHostsAreAllowed() throws Exception {
        assertTrue(NoInternetGuard.isAllowedHost("localhost"));
        assertTrue(NoInternetGuard.isAllowedHost("127.0.0.1"));
        assertTrue(NoInternetGuard.isAllowedHost("::1"));
        assertTrue(NoInternetGuard.isAllowedHost("  LOCALHOST  "));
        assertTrue(NoInternetGuard.isAllowedHost(null));
        assertTrue(NoInternetGuard.isAllowedHost(""));
    }

    @Test
    public void internetHostsAreBlocked() {
        assertFalse(NoInternetGuard.isAllowedHost("example.com"));
        assertFalse(NoInternetGuard.isAllowedHost("api.telegram.org"));
        assertFalse(NoInternetGuard.isAllowedHost("8.8.8.8"));
        assertFalse(NoInternetGuard.isAllowedHost("analytics-edge.yash321sri.workers.dev"));
    }

    @Test
    public void loopbackAddressesAreAllowed() throws Exception {
        assertTrue(NoInternetGuard.isAllowedAddress(InetAddress.getByName("127.0.0.1")));
        assertTrue(NoInternetGuard.isAllowedAddress(InetAddress.getByName("127.5.5.5")));
        assertTrue(NoInternetGuard.isAllowedAddress(InetAddress.getByName("::1")));
        assertTrue(NoInternetGuard.isAllowedAddress(InetAddress.getByName("0.0.0.0")));
    }

    @Test
    public void internetAddressesAreBlocked() throws Exception {
        assertFalse(NoInternetGuard.isAllowedAddress(InetAddress.getByName("8.8.8.8")));
        assertFalse(NoInternetGuard.isAllowedAddress(InetAddress.getByName("1.1.1.1")));
        assertFalse(NoInternetGuard.isAllowedAddress(InetAddress.getByName("2001:4860:4860::8888")));
    }

    @Test
    public void loopbackEndpointsAreAllowed() throws Exception {
        assertTrue(NoInternetGuard.isAllowedEndpoint(new InetSocketAddress("127.0.0.1", 19876)));
        assertTrue(NoInternetGuard.isAllowedEndpoint(new InetSocketAddress("localhost", 8080)));
    }

    @Test
    public void internetEndpointsAreBlocked() throws Exception {
        assertFalse(NoInternetGuard.isAllowedEndpoint(new InetSocketAddress("8.8.8.8", 443)));
        assertFalse(NoInternetGuard.isAllowedEndpoint(new InetSocketAddress("example.com", 443)));
    }

    @Test
    public void proxySelectorLeavesLocalTrafficDirect() {
        NoInternetGuard.BlockingProxySelector selector = new NoInternetGuard.BlockingProxySelector();

        List<Proxy> local = selector.select(URI.create("http://127.0.0.1:8080/api/status"));
        assertEquals(1, local.size());
        assertEquals(Proxy.NO_PROXY, local.get(0));

        List<Proxy> host = selector.select(URI.create("http://localhost:8080/"));
        assertEquals(Proxy.NO_PROXY, host.get(0));

        List<Proxy> file = selector.select(URI.create("file:///android_asset/web/index.html"));
        assertEquals(Proxy.NO_PROXY, file.get(0));
    }

    @Test
    public void proxySelectorDeadEndsInternetTraffic() {
        NoInternetGuard.BlockingProxySelector selector = new NoInternetGuard.BlockingProxySelector();

        List<Proxy> blocked = selector.select(URI.create("https://api.telegram.org/bot123/getMe"));
        assertEquals(1, blocked.size());
        Proxy p = blocked.get(0);
        assertNotEquals(Proxy.NO_PROXY, p);
        assertEquals(Proxy.Type.HTTP, p.type());
        assertEquals("127.0.0.1", ((InetSocketAddress) p.address()).getHostString());
        assertEquals(9, ((InetSocketAddress) p.address()).getPort());
    }

    @Test
    public void blockingSocketFactoryRefusesInternet() throws Exception {
        javax.net.SocketFactory f = NoInternetGuard.blockingSocketFactory();
        boolean blocked = false;
        try {
            f.createSocket("8.8.8.8", 443);
        } catch (java.io.IOException e) {
            blocked = true;
        }
        assertTrue("blockingSocketFactory must refuse an internet host", blocked);
    }

    @Test
    public void blockingSslSocketFactoryRefusesInternet() throws Exception {
        javax.net.ssl.SSLSocketFactory delegate =
                (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
        javax.net.ssl.SSLSocketFactory f = NoInternetGuard.blockingSslSocketFactory(delegate);
        boolean blocked = false;
        try {
            f.createSocket("api.telegram.org", 443);
        } catch (java.io.IOException e) {
            blocked = true;
        }
        assertTrue("blockingSslSocketFactory must refuse an internet host", blocked);
    }

    @Test
    public void remoteAccessMasterSwitchIsOff() {
        assertFalse(NoInternetGuard.REMOTE_ACCESS_ENABLED);
    }
}
