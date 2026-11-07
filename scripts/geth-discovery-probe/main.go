// This probe uses Geth's discv5 implementation to check Hightower's signed
// Fulu ENR, authenticated PING/PONG exchange, and FINDNODE/NODES response.
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

var forkID = []byte{1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255}

// main reports a failed independent discovery exchange with a nonzero exit.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: geth-discovery-probe <hightower-enr>")
		os.Exit(2)
	}
	if err := probe(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Geth discv5: ENR, PING/PONG, and FINDNODE/NODES passed")
}

// probe signs compatible fork fields so Hightower can authenticate Geth.
func probe(uri string) error {
	remote, err := enode.Parse(enode.ValidSchemes, uri)
	if err != nil {
		return fmt.Errorf("parse Hightower ENR: %w", err)
	}
	var remoteFork []byte
	if err := remote.Load(enr.WithEntry("eth2", &remoteFork)); err != nil || !bytes.Equal(remoteFork, forkID) {
		return fmt.Errorf("Hightower ENR has wrong Fulu fork: %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate Geth identity: %w", err)
	}
	db, err := enode.OpenDB("")
	if err != nil {
		return fmt.Errorf("open Geth node database: %w", err)
	}
	defer db.Close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("bind Geth discovery socket: %w", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	advertisedIP := net.IPv4(127, 0, 0, 1)
	var transport discover.UDPConn = conn
	if value := os.Getenv("HIGHTOWER_DISCOVERY_PROXY"); value != "" {
		proxy, err := netip.ParseAddrPort(value)
		if err != nil || !proxy.Addr().Is4() || !proxy.Addr().IsLoopback() || proxy.Port() == 0 {
			return fmt.Errorf("invalid loopback discovery proxy: %q", value)
		}
		source, err := netip.ParseAddrPort(os.Getenv("HIGHTOWER_DISCOVERY_SOURCE"))
		if err != nil || !source.Addr().Is4() || !source.Addr().IsLoopback() || source.Port() == 0 {
			return fmt.Errorf("invalid discovery proxy source")
		}
		remoteAddr, ok := remote.UDPEndpoint()
		if !ok || !remoteAddr.Addr().Is4() || !remoteAddr.Addr().IsLoopback() {
			return fmt.Errorf("diagnostic discovery peer must be loopback")
		}
		port = int(source.Port())
		advertisedIP = net.IP(source.Addr().AsSlice())
		transport = &proxyConn{UDPConn: conn, proxy: proxy, remote: remoteAddr}
	}
	local := enode.NewLocalNode(db, key)
	local.SetStaticIP(advertisedIP)
	local.Set(enr.UDP(port))
	local.Set(enr.TCP(9002))
	local.Set(enr.WithEntry("eth2", forkID))
	local.Set(enr.WithEntry("cgc", uint64(4)))
	local.Set(enr.WithEntry("nfd", []byte{0, 0, 0, 0}))
	service, err := discover.ListenV5(transport, local, discover.Config{PrivateKey: key})
	if err != nil {
		return fmt.Errorf("start Geth discovery: %w", err)
	}
	defer service.Close()
	pong, err := service.Ping(remote)
	if err != nil {
		return fmt.Errorf("Geth PING: %w", err)
	}
	if pong.ENRSeq != remote.Seq() || !pong.ToIP.Equal(advertisedIP) || pong.ToPort != uint16(port) {
		return fmt.Errorf("Geth PONG had wrong sequence or observed endpoint: %+v", pong)
	}
	resolved, err := service.RequestENR(remote)
	if err != nil {
		return fmt.Errorf("Geth FINDNODE: %w", err)
	}
	if resolved.ID() != remote.ID() || resolved.Seq() != remote.Seq() {
		return fmt.Errorf("Geth NODES returned a different peer")
	}
	return nil
}

// proxyConn changes socket destinations only; Geth still authenticates the signed remote ENR.
// Its own ENR advertises the proxy's dedicated upstream port, preserving Hightower's endpoint gate.
type proxyConn struct {
	*net.UDPConn
	proxy  netip.AddrPort
	remote netip.AddrPort
}

// WriteToUDPAddrPort routes only the configured verified peer through the diagnostic proxy.
func (c *proxyConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if addr != c.remote {
		return 0, fmt.Errorf("unexpected diagnostic destination: %s", addr)
	}
	return c.UDPConn.WriteToUDPAddrPort(b, c.proxy)
}

// ReadFromUDPAddrPort maps only proxy replies back to the original peer endpoint.
func (c *proxyConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := c.UDPConn.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, addr, err
	}
	if addr != c.proxy {
		return 0, addr, fmt.Errorf("unexpected diagnostic source: %s", addr)
	}
	return n, c.remote, nil
}
