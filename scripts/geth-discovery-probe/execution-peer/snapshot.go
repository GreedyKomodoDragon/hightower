// SNAP downloads account, storage, and code data for one trusted execution
// header. Account and slot ranges are verified against their trie roots before
// being written. The checkpoint file is published only after all ranges and
// code hashes are checked; Hightower validates its final state root at startup.
//
// trusted header root -> account ranges -> storage/code -> checkpoint file
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

const snapshotRequestBytes = 512 * 1024
const maxCheckpointBytes = 512 * 1024 * 1024
const maxCheckpointCode = 24 * 1024

type snapshotWorker struct {
	genesis   *core.Genesis
	header    *types.Header
	path      string
	ready     chan struct{}
	started   chan struct{}
	done      chan struct{}
	result    chan error
	once      sync.Once
	startOnce sync.Once
}

// runSnapshot connects one trusted-chain peer and publishes a verified state file.
func runSnapshot(configPath string, peers []string) error {
	if len(peers) != 1 {
		return errors.New("SNAP checkpoint download requires one peer")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if cfg.CheckpointHeader == "" || cfg.CheckpointState == "" || cfg.CheckpointHash == "" {
		return errors.New("SNAP checkpoint requires header, state path, and trusted hash")
	}
	genesisBytes, err := os.ReadFile(cfg.Genesis)
	if err != nil {
		return err
	}
	var genesis core.Genesis
	if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
		return err
	}
	if genesis.Config == nil || genesis.Config.ChainID == nil || !genesis.Config.ChainID.IsUint64() {
		return errors.New("SNAP checkpoint requires a chain ID")
	}
	headerBytes, err := os.ReadFile(cfg.CheckpointHeader)
	if err != nil {
		return err
	}
	if len(headerBytes) > 16*1024 {
		return errors.New("checkpoint header exceeds 16 KiB")
	}
	header := new(types.Header)
	if err := rlp.DecodeBytes(headerBytes, header); err != nil {
		return err
	}
	if !strings.EqualFold(header.Hash().Hex(), cfg.CheckpointHash) || !header.Number.IsUint64() {
		return errors.New("checkpoint header does not match trusted hash or supported number")
	}
	node, err := enode.Parse(enode.ValidSchemes, peers[0])
	if err != nil {
		return err
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	w := &snapshotWorker{genesis: &genesis, header: header, path: cfg.CheckpointState, ready: make(chan struct{}), started: make(chan struct{}), done: make(chan struct{}), result: make(chan error, 1)}
	server := &p2p.Server{Config: p2p.Config{PrivateKey: key, MaxPeers: 1, ListenAddr: ":0", NoDiscovery: true, StaticNodes: []*enode.Node{node}, Protocols: []p2p.Protocol{
		{Name: "eth", Version: eth.ETH69, Length: 18, Run: w.eth},
		{Name: snap.ProtocolName, Version: snap.SNAP1, Length: 8, Run: w.snap},
		{Name: snap.ProtocolName, Version: snap.SNAP2, Length: 10, Run: w.snap},
	}}}
	if err := server.Start(); err != nil {
		return err
	}
	defer server.Stop()
	defer close(w.done)
	select {
	case err := <-w.result:
		return err
	case <-w.started:
	case <-time.After(30 * time.Second):
		return errors.New("SNAP peer did not connect")
	}
	return <-w.result
}

// eth validates the peer's execution chain identity before SNAP data is used.
func (w *snapshotWorker) eth(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	s := &session{worker: &worker{genesis: w.genesis, anchor: w.header}, peer: peer, rw: rw}
	if err := s.handshake(); err != nil {
		select {
		case w.result <- err:
		default:
		}
		return err
	}
	w.once.Do(func() { close(w.ready) })
	<-w.done
	return nil
}

// snap downloads a complete state only after eth/69 confirms the same chain.
func (w *snapshotWorker) snap(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	w.startOnce.Do(func() { close(w.started) })
	select {
	case <-w.ready:
	case <-w.done:
		return nil
	}
	s := &snapSession{rw: rw, peer: peer, root: w.header.Root}
	err := s.downloadSnapshot(w.path)
	select {
	case w.result <- err:
	default:
	}
	return err
}

type snapSession struct {
	rw     p2p.MsgReadWriter
	peer   *p2p.Peer
	root   common.Hash
	nextID uint64
}

type checkpointFile struct {
	file *os.File
	size int64
}

// put appends bounded checkpoint bytes and leaves the file unpublished on error.
func (w *checkpointFile) put(data []byte) error {
	if int64(len(data)) > maxCheckpointBytes-w.size {
		return errors.New("SNAP checkpoint exceeds 512 MiB")
	}
	n, err := w.file.Write(data)
	w.size += int64(n)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("short checkpoint write")
	}
	return nil
}

// putLE writes a fixed-width unsigned integer in the checkpoint format.
func (w *checkpointFile) putLE(value uint64, width int) error {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return w.put(encoded[:width])
}

// nextHash advances a hashed trie key; false means the key space is exhausted.
func nextHash(key *common.Hash) bool {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]++
		if key[i] != 0 {
			return true
		}
	}
	return false
}

// exchange sends one SNAP request and decodes only its matching response kind.
func (s *snapSession) exchange(code uint64, request any, replyCode uint64, reply any) error {
	if err := p2p.Send(s.rw, code, request); err != nil {
		return err
	}
	if s.peer != nil {
		timer := time.AfterFunc(requestTimeout, func() { s.peer.Disconnect(p2p.DiscReadTimeout) })
		defer timer.Stop()
	}
	msg, err := s.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > maxMessage {
		_ = msg.Discard()
		return errors.New("oversized SNAP response")
	}
	if msg.Code != replyCode {
		_ = msg.Discard()
		return fmt.Errorf("unexpected SNAP response %d", msg.Code)
	}
	return msg.Decode(reply)
}

// accounts retrieves and verifies one bounded account range from the trusted root.
func (s *snapSession) accounts(origin common.Hash) ([]common.Hash, [][]byte, bool, error) {
	s.nextID++
	id := s.nextID
	request := &snap.GetAccountRangePacket{ID: id, Root: s.root, Origin: origin, Limit: common.MaxHash, Bytes: snapshotRequestBytes}
	var packet snap.AccountRangePacket
	if err := s.exchange(snap.GetAccountRangeMsg, request, snap.AccountRangeMsg, &packet); err != nil {
		return nil, nil, false, err
	}
	if packet.ID != id {
		return nil, nil, false, errors.New("SNAP account response ID mismatch")
	}
	return verifyAccountRange(s.root, origin, &packet)
}

// code retrieves one bytecode and checks its claimed Keccak hash.
func (s *snapSession) code(hash common.Hash) ([]byte, error) {
	if hash == types.EmptyCodeHash {
		return nil, nil
	}
	s.nextID++
	id := s.nextID
	request := &snap.GetByteCodesPacket{ID: id, Hashes: []common.Hash{hash}, Bytes: snapshotRequestBytes}
	var packet snap.ByteCodesPacket
	if err := s.exchange(snap.GetByteCodesMsg, request, snap.ByteCodesMsg, &packet); err != nil {
		return nil, err
	}
	if packet.ID != id || len(packet.Codes) != 1 || len(packet.Codes[0]) > maxCheckpointCode || crypto.Keccak256Hash(packet.Codes[0]) != hash {
		return nil, errors.New("invalid SNAP bytecode")
	}
	return packet.Codes[0], nil
}

// storage retrieves one bounded range for an account and verifies its root.
func (s *snapSession) storage(account, root, origin common.Hash) ([]*snap.StorageData, bool, error) {
	s.nextID++
	id := s.nextID
	request := &snap.GetStorageRangesPacket{ID: id, Root: s.root, Accounts: []common.Hash{account}, Origin: origin[:], Limit: common.MaxHash[:], Bytes: snapshotRequestBytes}
	var packet snap.StorageRangesPacket
	if err := s.exchange(snap.GetStorageRangesMsg, request, snap.StorageRangesMsg, &packet); err != nil {
		return nil, false, err
	}
	if packet.ID != id {
		return nil, false, errors.New("SNAP storage response ID mismatch")
	}
	return verifyStorageRange(root, origin, &packet)
}

// writeAccount writes one verified account with all its code and storage slots.
func (s *snapSession) writeAccount(w *checkpointFile, key common.Hash, body []byte) error {
	var account types.StateAccount
	if err := rlp.DecodeBytes(body, &account); err != nil {
		return err
	}
	if account.Balance == nil || len(account.CodeHash) != common.HashLength {
		return errors.New("invalid SNAP account fields")
	}
	code, err := s.code(common.BytesToHash(account.CodeHash))
	if err != nil {
		return err
	}
	if err := w.put([]byte{2}); err != nil {
		return err
	}
	if err := w.put(key[:]); err != nil {
		return err
	}
	if err := w.putLE(account.Nonce, 8); err != nil {
		return err
	}
	balance := account.Balance.Bytes32()
	for i := 0; i < len(balance)/2; i++ {
		balance[i], balance[len(balance)-1-i] = balance[len(balance)-1-i], balance[i]
	}
	if err := w.put(balance[:]); err != nil {
		return err
	}
	if err := w.putLE(uint64(len(code)), 4); err != nil {
		return err
	}
	if err := w.put(code); err != nil {
		return err
	}
	slotsOffset := w.size
	if err := w.putLE(0, 4); err != nil {
		return err
	}
	var slots uint32
	if account.Root != types.EmptyRootHash {
		var origin common.Hash
		for {
			items, more, err := s.storage(key, account.Root, origin)
			if err != nil {
				return err
			}
			if len(items) == 0 && more {
				return errors.New("empty continuing SNAP storage range")
			}
			for _, item := range items {
				var value big.Int
				if err := rlp.DecodeBytes(item.Body, &value); err != nil || value.Sign() <= 0 || value.BitLen() > 256 {
					return errors.New("invalid SNAP storage value")
				}
				if slots == ^uint32(0) {
					return errors.New("too many SNAP storage slots")
				}
				slots++
				if err := w.put(item.Hash[:]); err != nil {
					return err
				}
				word := value.FillBytes(make([]byte, 32))
				for i := 0; i < len(word)/2; i++ {
					word[i], word[len(word)-1-i] = word[len(word)-1-i], word[i]
				}
				if err := w.put(word); err != nil {
					return err
				}
			}
			if !more {
				break
			}
			origin = items[len(items)-1].Hash
			if !nextHash(&origin) {
				return errors.New("SNAP storage range exceeds key space")
			}
		}
	}
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], slots)
	_, err = w.file.WriteAt(count[:], slotsOffset)
	return err
}

// downloadSnapshot writes a complete verified checkpoint to a temporary file.
func (s *snapSession) downloadSnapshot(path string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".hightower-snap-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	w := &checkpointFile{file: file}
	if err := w.putLE(0, 4); err != nil {
		return err
	}
	var count uint32
	var origin common.Hash
	for {
		keys, bodies, more, err := s.accounts(origin)
		if err != nil {
			return err
		}
		if len(keys) == 0 && more {
			return errors.New("empty continuing SNAP account range")
		}
		for i, key := range keys {
			if count == ^uint32(0) {
				return errors.New("too many SNAP accounts")
			}
			if err := s.writeAccount(w, key, bodies[i]); err != nil {
				return err
			}
			count++
		}
		if !more {
			break
		}
		origin = keys[len(keys)-1]
		if !nextHash(&origin) {
			return errors.New("SNAP account range exceeds key space")
		}
	}
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], count)
	if _, err := file.WriteAt(encoded[:], 0); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// A hard link publishes the completed file atomically and refuses an existing checkpoint.
	return os.Link(file.Name(), path)
}
