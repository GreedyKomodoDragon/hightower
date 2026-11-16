// SNAP account ranges carry hashed trie keys and slim account bodies. A range
// proof binds the decoded accounts to a trusted state root before any state is
// written. The first range starts at zero; later ranges resume after the last
// verified key, and an empty proof is valid only for a complete trie.
//
// trusted root -> range proof -> verified hashed accounts
package main

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// verifyAccountRange checks a SNAP response against the trusted state root.
// origin is the first requested hashed key; callers must advance it only after success.
func verifyAccountRange(root, origin common.Hash, packet *snap.AccountRangePacket) ([]common.Hash, [][]byte, bool, error) {
	if packet == nil {
		return nil, nil, false, fmt.Errorf("missing account range")
	}
	hashes, accounts, err := packet.Unpack()
	if err != nil {
		return nil, nil, false, err
	}
	keys := make([][]byte, len(hashes))
	for i, hash := range hashes {
		if hash.Cmp(origin) < 0 || i > 0 && hashes[i-1].Cmp(hash) >= 0 {
			return nil, nil, false, fmt.Errorf("unordered account range")
		}
		keys[i] = hash[:]
	}
	nodes := make(trienode.ProofList, len(packet.Proof))
	for i, node := range packet.Proof {
		nodes[i] = node
	}
	var first []byte
	var proofDB ethdb.KeyValueReader = nodes.Set()
	if len(nodes) == 0 && origin == (common.Hash{}) {
		proofDB = nil
	} else {
		first = origin[:]
	}
	more, err := trie.VerifyRangeProof(root, first, keys, accounts, proofDB)
	if err != nil {
		return nil, nil, false, fmt.Errorf("account range proof: %w", err)
	}
	return hashes, accounts, more, nil
}

// verifyStorageRange checks one account's hashed slots against its committed storage root.
func verifyStorageRange(root, origin common.Hash, packet *snap.StorageRangesPacket) ([]*snap.StorageData, bool, error) {
	if packet == nil || len(packet.Slots) != 1 {
		return nil, false, fmt.Errorf("missing storage range")
	}
	slots := packet.Slots[0]
	keys := make([][]byte, len(slots))
	values := make([][]byte, len(slots))
	for i, slot := range slots {
		if slot == nil || bytes.Compare(slot.Hash[:], origin[:]) < 0 || i > 0 && bytes.Compare(slots[i-1].Hash[:], slot.Hash[:]) >= 0 {
			return nil, false, fmt.Errorf("unordered storage range")
		}
		keys[i], values[i] = slot.Hash[:], slot.Body
	}
	nodes := make(trienode.ProofList, len(packet.Proof))
	for i, node := range packet.Proof {
		nodes[i] = node
	}
	var first []byte
	var proofDB ethdb.KeyValueReader = nodes.Set()
	if len(nodes) == 0 && origin == (common.Hash{}) {
		proofDB = nil
	} else {
		first = origin[:]
	}
	more, err := trie.VerifyRangeProof(root, first, keys, values, proofDB)
	if err != nil {
		return nil, false, fmt.Errorf("storage range proof: %w", err)
	}
	return slots, more, nil
}
