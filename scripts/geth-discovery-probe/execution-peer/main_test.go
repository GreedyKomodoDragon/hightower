// These local message pipes preserve the eth/69 request ID and raw RLP shapes
// used against a reference peer without requiring a live TCP network.
package main

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// TestOsakaFixtureIdentity checks the pinned genesis against Geth's header.
func TestOsakaFixtureIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/engine/osaka-genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var genesis core.Genesis
	if err := json.Unmarshal(raw, &genesis); err != nil {
		t.Fatal(err)
	}
	want := common.HexToHash("0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f")
	if got := genesis.ToBlock().Hash(); got != want {
		t.Fatalf("fixture genesis hash: %s, want %s", got, want)
	}
}

// TestHeaderRequest checks bounded requests and rejects an unrelated header.
func TestHeaderRequest(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		local, remote := p2p.MsgPipe()
		header := &types.Header{Number: big.NewInt(7), GasLimit: 30_000_000}
		origin := eth.HashOrNumber{Hash: header.Hash()}
		if wrong {
			origin.Hash = common.Hash{1}
		}
		go func() {
			msg, err := remote.ReadMsg()
			if err != nil {
				return
			}
			var request eth.GetBlockHeadersPacket
			if err := msg.Decode(&request); err != nil || request.Amount != 1 || request.Origin.Hash != origin.Hash {
				return
			}
			var list rlp.RawList[*types.Header]
			if err := list.Append(header); err != nil {
				return
			}
			_ = p2p.Send(remote, eth.BlockHeadersMsg, &eth.BlockHeadersPacket{RequestId: request.RequestId, List: list})
		}()
		s := &session{rw: local}
		got, err := s.header(origin)
		if wrong && err == nil || !wrong && (err != nil || got.Hash() != header.Hash()) {
			t.Fatalf("wrong=%v: header=%v error=%v", wrong, got, err)
		}
		local.Close()
		remote.Close()
	}
}

// TestBodyRequest checks that a bounded eth body becomes four-field block RLP.
func TestBodyRequest(t *testing.T) {
	local, remote := p2p.MsgPipe()
	defer local.Close()
	defer remote.Close()
	header := &types.Header{Number: big.NewInt(1), GasLimit: 30_000_000}
	go func() {
		msg, err := remote.ReadMsg()
		if err != nil {
			return
		}
		var request eth.GetBlockBodiesPacket
		if err := msg.Decode(&request); err != nil || len(request.GetBlockBodiesRequest) != 1 || request.GetBlockBodiesRequest[0] != header.Hash() {
			return
		}
		withdrawals := new(rlp.RawList[*types.Withdrawal])
		body := eth.BlockBody{Withdrawals: withdrawals}
		var list rlp.RawList[eth.BlockBody]
		if err := list.Append(body); err != nil {
			return
		}
		_ = p2p.Send(remote, eth.BlockBodiesMsg, &eth.BlockBodiesPacket{RequestId: request.RequestId, List: list})
	}()
	s := &session{rw: local}
	encoded, err := s.body(header)
	if err != nil {
		t.Fatal(err)
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 {
		t.Fatalf("block has %d RLP fields, want 4", len(fields))
	}
}
