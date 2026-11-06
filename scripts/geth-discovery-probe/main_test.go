package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestProxyConnRouting checks exact payloads, reverse mapping, and unrelated endpoint rejection.
func TestProxyConnRouting(t *testing.T) {
	bind := func() *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	client, proxy := bind(), bind()
	remote := netip.MustParseAddrPort("127.0.0.1:19004")
	transport := &proxyConn{UDPConn: client, proxy: proxy.LocalAddr().(*net.UDPAddr).AddrPort(), remote: remote}
	payload := []byte{0, 255, 10}
	if _, err := transport.WriteToUDPAddrPort(payload, remote); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, from, err := proxy.ReadFromUDPAddrPort(buf[:])
	if err != nil || string(buf[:n]) != string(payload) {
		t.Fatalf("proxy receive: %x, %v", buf[:n], err)
	}
	if _, err := proxy.WriteToUDPAddrPort(payload, from); err != nil {
		t.Fatal(err)
	}
	n, from, err = transport.ReadFromUDPAddrPort(buf[:])
	if err != nil || from != remote || string(buf[:n]) != string(payload) {
		t.Fatalf("mapped response: %s %x %v", from, buf[:n], err)
	}
	if _, err := transport.WriteToUDPAddrPort(payload, transport.proxy); err == nil {
		t.Fatal("accepted unrelated destination")
	}
	stranger := bind()
	if _, err := stranger.WriteToUDPAddrPort(payload, client.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := transport.ReadFromUDPAddrPort(buf[:]); err == nil {
		t.Fatal("accepted unrelated source")
	}
}
