// These fixtures exercise complete account range verification without a peer.
package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/trie"
)

// TestVerifyAccountRange rejects a modified account even when its key is unchanged.
func TestVerifyAccountRange(t *testing.T) {
	account := types.StateAccount{Nonce: 3, Balance: types.NewEmptyStateAccount().Balance, Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes()}
	key := common.HexToHash("0x01")
	packet := &snap.AccountRangePacket{Accounts: []*snap.AccountData{{Hash: key, Body: types.SlimAccountRLP(account)}}}
	_, values, err := packet.Unpack()
	if err != nil {
		t.Fatal(err)
	}
	tr := trie.NewStackTrie(nil)
	if err := tr.Update(key[:], values[0]); err != nil {
		t.Fatal(err)
	}
	root := tr.Hash()
	if _, _, more, err := verifyAccountRange(root, common.Hash{}, packet); err != nil || more {
		t.Fatalf("valid range: more=%v err=%v", more, err)
	}
	packet.Accounts[0].Hash = common.HexToHash("0x02")
	if _, _, _, err := verifyAccountRange(root, common.Hash{}, packet); err == nil {
		t.Fatal("accepted modified account key")
	}
	packet.Accounts[0].Hash = key
	packet.Accounts[0].Body = []byte{0xff}
	if _, _, _, err := verifyAccountRange(root, common.Hash{}, packet); err == nil {
		t.Fatal("accepted malformed account body")
	}
}
