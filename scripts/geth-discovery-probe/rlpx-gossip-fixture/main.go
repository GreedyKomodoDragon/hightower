// The eth/69 fixture checks a Zig peer's RLPx handshake, status, transaction
// hash announcement, and bounded pooled transaction response against Geth's
// production devp2p implementation. It serves one local peer and exits.
//
// Zig dial -> Geth RLPx/Status -> hash request -> transaction response
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
)

// main runs one eth/69 exchange and reports any wire mismatch.
func main() {
	listen := flag.String("listen", "127.0.0.1:0", "local TCP listener")
	flag.Parse()
	key, err := crypto.ToECDSA(bytes.Repeat([]byte{12}, 32))
	if err != nil {
		panic(err)
	}
	done := make(chan error, 1)
	server := &p2p.Server{Config: p2p.Config{
		PrivateKey: key, MaxPeers: 10, ListenAddr: *listen, NoDiscovery: true,
		Protocols: []p2p.Protocol{{Name: "eth", Version: eth.ETH69, Length: 18,
			Run: func(_ *p2p.Peer, rw p2p.MsgReadWriter) error {
				err := exchange(rw)
				done <- err
				return err
			}}},
	}}
	if err := server.Start(); err != nil {
		panic(err)
	}
	defer server.Stop()
	fmt.Println("ready")
	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("ok")
	case <-time.After(20 * time.Second):
		fmt.Fprintln(os.Stderr, "peer exchange timed out")
		os.Exit(1)
	}
}

// exchange verifies each expected eth/69 packet and replies with one hash query.
func exchange(rw p2p.MsgReadWriter) error {
	msg, err := rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != eth.StatusMsg {
		return fmt.Errorf("expected eth status, got %d", msg.Code)
	}
	var remote eth.StatusPacket
	if err := msg.Decode(&remote); err != nil {
		return err
	}
	genesis := common.Hash(bytes.Repeat([]byte{1}, 32))
	if remote.ProtocolVersion != eth.ETH69 || remote.NetworkID != 1 || remote.Genesis != genesis || remote.ForkID.Hash != [4]byte{2, 3, 4, 5} {
		return errors.New("incompatible Zig eth status")
	}
	local := eth.StatusPacket{ProtocolVersion: eth.ETH69, NetworkID: 1, Genesis: genesis, ForkID: forkid.ID{Hash: [4]byte{2, 3, 4, 5}}, EarliestBlock: 0, LatestBlock: 0, LatestBlockHash: genesis}
	if err := p2p.Send(rw, eth.StatusMsg, &local); err != nil {
		return err
	}
	msg, err = rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != eth.NewPooledTransactionHashesMsg {
		return fmt.Errorf("expected hash announcement, got %d", msg.Code)
	}
	var announced eth.NewPooledTransactionHashesPacket71
	if err := msg.Decode(&announced); err != nil {
		return err
	}
	if len(announced.Hashes) != 1 || len(announced.Types) != 1 || len(announced.Sizes) != 1 {
		return errors.New("invalid announcement shape")
	}
	request := eth.GetPooledTransactionsPacket{RequestId: 1, GetPooledTransactionsRequest: []common.Hash{announced.Hashes[0]}}
	if err := p2p.Send(rw, eth.GetPooledTransactionsMsg, &request); err != nil {
		return err
	}
	msg, err = rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != eth.PooledTransactionsMsg {
		return fmt.Errorf("expected pooled response, got %d", msg.Code)
	}
	var response eth.PooledTransactionsPacket
	if err := msg.Decode(&response); err != nil {
		return err
	}
	transactions, err := response.List.Items()
	if err != nil {
		return err
	}
	if response.RequestId != 1 || len(transactions) != 1 || transactions[0].Hash() != announced.Hashes[0] {
		return errors.New("wrong pooled transaction")
	}
	return nil
}
