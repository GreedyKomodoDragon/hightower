// These fixtures exercise complete account range verification without a peer.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
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

// TestDownloadSnapshot uses a message-pipe reference peer to exercise the full checkpoint format.
func TestDownloadSnapshot(t *testing.T) {
	accountKey := common.HexToHash("0x11")
	slotKey := common.HexToHash("0x22")
	code := []byte{0x60, 0x00}
	slotValue, err := rlp.EncodeToBytes(uint64(9))
	if err != nil {
		t.Fatal(err)
	}
	storageTrie := trie.NewStackTrie(nil)
	if err := storageTrie.Update(slotKey[:], slotValue); err != nil {
		t.Fatal(err)
	}
	account := types.NewEmptyStateAccount()
	account.Nonce = 3
	account.Balance.SetUint64(42)
	account.Root = storageTrie.Hash()
	account.CodeHash = crypto.Keccak256(code)
	full, err := rlp.EncodeToBytes(account)
	if err != nil {
		t.Fatal(err)
	}
	accountTrie := trie.NewStackTrie(nil)
	if err := accountTrie.Update(accountKey[:], full); err != nil {
		t.Fatal(err)
	}
	local, remote := p2p.MsgPipe()
	defer local.Close()
	defer remote.Close()
	peerErrors := make(chan error, 1)
	go func() {
		for range 2 {
			for _, step := range []uint64{snap.GetAccountRangeMsg, snap.GetByteCodesMsg, snap.GetStorageRangesMsg} {
				msg, err := remote.ReadMsg()
				if err != nil {
					peerErrors <- err
					return
				}
				if msg.Code != step {
					peerErrors <- fmt.Errorf("request code %d, want %d", msg.Code, step)
					return
				}
				switch step {
				case snap.GetAccountRangeMsg:
					var req snap.GetAccountRangePacket
					if err = msg.Decode(&req); err == nil {
						err = p2p.Send(remote, snap.AccountRangeMsg, &snap.AccountRangePacket{ID: req.ID, Accounts: []*snap.AccountData{{Hash: accountKey, Body: types.SlimAccountRLP(*account)}}})
					}
				case snap.GetByteCodesMsg:
					var req snap.GetByteCodesPacket
					if err = msg.Decode(&req); err == nil {
						err = p2p.Send(remote, snap.ByteCodesMsg, &snap.ByteCodesPacket{ID: req.ID, Codes: [][]byte{code}})
					}
				case snap.GetStorageRangesMsg:
					var req snap.GetStorageRangesPacket
					if err = msg.Decode(&req); err == nil {
						err = p2p.Send(remote, snap.StorageRangesMsg, &snap.StorageRangesPacket{ID: req.ID, Slots: [][]*snap.StorageData{{{Hash: slotKey, Body: slotValue}}}})
					}
				}
				if err != nil {
					peerErrors <- err
					return
				}
			}
		}
		peerErrors <- nil
	}()
	path := filepath.Join(t.TempDir(), "state.bin")
	s := &snapSession{rw: local, root: accountTrie.Hash()}
	if err := s.downloadSnapshot(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(raw[:4]) != 1 || raw[4] != 2 || common.BytesToHash(raw[5:37]) != accountKey || binary.LittleEndian.Uint64(raw[37:45]) != 3 {
		t.Fatal("invalid downloaded account header")
	}
	if len(raw) != 4+1+32+8+32+4+len(code)+4+32+32 || binary.LittleEndian.Uint32(raw[77:81]) != uint32(len(code)) || binary.LittleEndian.Uint32(raw[83:87]) != 1 {
		t.Fatal("invalid downloaded code or storage count")
	}
	if err := s.downloadSnapshot(path); !os.IsExist(err) {
		t.Fatalf("existing checkpoint was replaceable: %v", err)
	}
	if err := <-peerErrors; err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unchanged) {
		t.Fatal("existing checkpoint changed")
	}
}

// TestVerifyStorageRange rejects a changed slot value under the same storage root.
func TestVerifyStorageRange(t *testing.T) {
	key := common.HexToHash("0x01")
	value := []byte{0x09}
	tr := trie.NewStackTrie(nil)
	if err := tr.Update(key[:], value); err != nil {
		t.Fatal(err)
	}
	packet := &snap.StorageRangesPacket{Slots: [][]*snap.StorageData{{{Hash: key, Body: value}}}}
	if _, more, err := verifyStorageRange(tr.Hash(), common.Hash{}, packet); err != nil || more {
		t.Fatalf("valid storage: more=%v err=%v", more, err)
	}
	packet.Slots[0][0].Body = []byte{0x0a}
	if _, _, err := verifyStorageRange(tr.Hash(), common.Hash{}, packet); err == nil {
		t.Fatal("accepted modified storage value")
	}
}

// TestDownloadSnapshotRejectsCorruptRange leaves no checkpoint after a bad peer response.
func TestDownloadSnapshotRejectsCorruptRange(t *testing.T) {
	local, remote := p2p.MsgPipe()
	defer local.Close()
	defer remote.Close()
	peerErrors := make(chan error, 1)
	go func() {
		msg, err := remote.ReadMsg()
		if err != nil {
			peerErrors <- err
			return
		}
		var req snap.GetAccountRangePacket
		if err := msg.Decode(&req); err != nil {
			peerErrors <- err
			return
		}
		peerErrors <- p2p.Send(remote, snap.AccountRangeMsg, &snap.AccountRangePacket{ID: req.ID})
	}()
	path := filepath.Join(t.TempDir(), "state.bin")
	s := &snapSession{rw: local, root: common.HexToHash("0x01")}
	if err := s.downloadSnapshot(path); err == nil {
		t.Fatal("accepted state range unrelated to trusted root")
	}
	if err := <-peerErrors; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt checkpoint was published: %v", err)
	}
}
