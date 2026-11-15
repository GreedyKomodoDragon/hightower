// Execution peers use devp2p discovery and the eth/69 capability to exchange
// headers and bodies. A trusted local checkpoint supplies the first complete
// post-state; every later block is submitted to Hightower for execution and
// root checks before durable storage. Requests use one hash or number at a
// time, at most two peers, and the protocol's 10 MiB message ceiling.
//
// checkpoint -> header -> body -> Hightower validation -> Engine fork choice
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

const maxMessage = 10 * 1024 * 1024
const requestTimeout = 10 * time.Second
const maxAncestry = 16

type config struct {
	Genesis          string `json:"genesis"`
	CheckpointHeader string `json:"checkpoint_header"`
	CheckpointHash   string `json:"checkpoint_hash"`
	JWTSecret        string `json:"jwt_secret"`
	EngineBind       string `json:"engine_bind"`
}

type api struct {
	url    string
	secret []byte
	client http.Client
}

type response struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type worker struct {
	api     *api
	genesis *core.Genesis
	anchor  *types.Header
	ctx     context.Context
}

type session struct {
	worker *worker
	peer   *p2p.Peer
	rw     p2p.MsgReadWriter
	remote eth.StatusPacket
	nextID uint64
	next   uint64
}

// main starts a bounded eth peer worker against the existing Engine listener.
func main() {
	configPath := flag.String("config", "", "execution service config")
	peerURI := flag.String("peer", "", "reference enode or ENR")
	flag.Parse()
	if *configPath == "" || *peerURI == "" {
		log.Fatal("usage: execution-peer --config service.json --peer enode://...")
	}
	if err := run(*configPath, *peerURI); err != nil {
		log.Fatal(err)
	}
}

// run loads the trusted chain identity and keeps one reference peer connected.
func run(configPath, peerURI string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	genesisBytes, err := os.ReadFile(cfg.Genesis)
	if err != nil {
		return err
	}
	var genesis core.Genesis
	if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
		return err
	}
	if genesis.Config == nil || genesis.Config.ChainID == nil || !genesis.Config.ChainID.IsUint64() || !strings.HasPrefix(cfg.EngineBind, "127.0.0.1:") {
		return errors.New("execution peer requires a chain ID and a loopback Engine listener")
	}
	anchor := genesis.ToBlock().Header()
	if cfg.CheckpointHeader != "" {
		rawHeader, err := os.ReadFile(cfg.CheckpointHeader)
		if err != nil {
			return err
		}
		anchor = new(types.Header)
		if err := rlp.DecodeBytes(rawHeader, anchor); err != nil {
			return err
		}
		if !strings.EqualFold(anchor.Hash().Hex(), cfg.CheckpointHash) {
			return errors.New("checkpoint header does not match trusted hash")
		}
	}
	if !anchor.Number.IsUint64() {
		return errors.New("checkpoint number exceeds supported range")
	}
	if anchor.Number.Uint64() == ^uint64(0) {
		return errors.New("checkpoint has no supported successor")
	}
	secretHex, err := os.ReadFile(cfg.JWTSecret)
	if err != nil {
		return err
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(secretHex)))
	if err != nil || len(secret) != 32 {
		return errors.New("invalid Engine JWT secret")
	}
	node, err := enode.Parse(enode.ValidSchemes, peerURI)
	if err != nil {
		return err
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	w := &worker{api: &api{url: "http://" + cfg.EngineBind, secret: secret, client: http.Client{Timeout: requestTimeout}}, genesis: &genesis, anchor: anchor, ctx: ctx}
	bootstrap := []*enode.Node(nil)
	discovery := false
	if endpoint, ok := node.UDPEndpoint(); ok && endpoint.Port() != 0 {
		bootstrap = []*enode.Node{node}
		discovery = true
	}
	server := &p2p.Server{Config: p2p.Config{
		PrivateKey: key, MaxPeers: 2, ListenAddr: ":0", DiscoveryV4: discovery, NoDiscovery: !discovery,
		BootstrapNodes: bootstrap, StaticNodes: []*enode.Node{node},
		Protocols: []p2p.Protocol{{Name: "eth", Version: eth.ETH69, Length: 18, Run: w.serve}},
	}}
	if err := server.Start(); err != nil {
		return err
	}
	defer server.Stop()
	<-ctx.Done()
	return nil
}

// serve checks the peer's chain identity, then imports bounded ascending ranges.
func (w *worker) serve(peer *p2p.Peer, rw p2p.MsgReadWriter) (runErr error) {
	defer func() {
		if runErr != nil {
			log.Printf("eth peer %s disconnected: %v", peer.ID(), runErr)
		}
	}()
	s := &session{worker: w, peer: peer, rw: rw, next: w.anchor.Number.Uint64() + 1}
	if err := s.handshake(); err != nil {
		return err
	}
	log.Printf("eth/69 peer %s connected at block %d", peer.ID(), s.remote.LatestBlock)
	var cursor string
	if err := w.api.call("hightower_executionSyncCursor", []any{}, &cursor); err != nil {
		return err
	}
	number, err := strconv.ParseUint(strings.TrimPrefix(cursor, "0x"), 16, 64)
	if err != nil || number == ^uint64(0) {
		return errors.New("invalid local execution sync cursor")
	}
	s.next = max(s.next, number+1)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.syncRound(); err != nil {
				return err
			}
		}
	}
}

// handshake exchanges eth/69 status and rejects a different genesis or fork.
func (s *session) handshake() error {
	w := s.worker
	status := eth.StatusPacket{
		ProtocolVersion: eth.ETH69,
		NetworkID:       w.genesis.Config.ChainID.Uint64(),
		Genesis:         w.genesis.ToBlock().Hash(),
		ForkID:          forkid.NewID(w.genesis.Config, w.genesis.ToBlock(), w.anchor.Number.Uint64(), w.anchor.Time),
		EarliestBlock:   w.anchor.Number.Uint64(),
		LatestBlock:     w.anchor.Number.Uint64(),
		LatestBlockHash: w.anchor.Hash(),
	}
	sent := make(chan error, 1)
	go func() { sent <- p2p.Send(s.rw, eth.StatusMsg, &status) }()
	msg, err := s.read()
	if err != nil {
		return err
	}
	if err := <-sent; err != nil {
		return err
	}
	if msg.Code != eth.StatusMsg {
		return fmt.Errorf("expected eth status, got %d", msg.Code)
	}
	if err := msg.Decode(&s.remote); err != nil {
		return err
	}
	if s.remote.ProtocolVersion != eth.ETH69 || s.remote.NetworkID != status.NetworkID || s.remote.Genesis != status.Genesis || s.remote.ForkID.Hash != status.ForkID.Hash || s.remote.LatestBlock < s.remote.EarliestBlock {
		return errors.New("incompatible eth peer status")
	}
	return nil
}

// read applies the eth message ceiling and disconnects an idle peer.
func (s *session) read() (p2p.Msg, error) {
	timer := time.AfterFunc(requestTimeout, func() { s.peer.Disconnect(p2p.DiscReadTimeout) })
	defer timer.Stop()
	msg, err := s.rw.ReadMsg()
	if err != nil {
		return msg, err
	}
	if msg.Size > maxMessage {
		return msg, errors.New("oversized eth message")
	}
	return msg, nil
}

// reply ignores at most 16 unrelated announcements and checks the request ID.
func (s *session) reply(code uint64, id uint64, result any) error {
	for range 16 {
		msg, err := s.read()
		if err != nil {
			return err
		}
		if msg.Code != code {
			if msg.Code == eth.BlockRangeUpdateMsg {
				var update eth.BlockRangeUpdatePacket
				if err := msg.Decode(&update); err != nil {
					return err
				}
				if update.LatestBlock < update.EarliestBlock {
					return errors.New("invalid peer block range")
				}
				s.remote.EarliestBlock = update.EarliestBlock
				s.remote.LatestBlock = update.LatestBlock
				s.remote.LatestBlockHash = update.LatestBlockHash
				continue
			}
			if err := msg.Discard(); err != nil {
				return err
			}
			continue
		}
		if err := msg.Decode(result); err != nil {
			return err
		}
		var got uint64
		switch packet := result.(type) {
		case *eth.BlockHeadersPacket:
			got = packet.RequestId
		case *eth.BlockBodiesPacket:
			got = packet.RequestId
		}
		if got != id {
			return errors.New("eth response ID mismatch")
		}
		return nil
	}
	return errors.New("too many unrelated eth messages")
}

// header requests exactly one peer header by hash or number.
func (s *session) header(origin eth.HashOrNumber) (*types.Header, error) {
	s.nextID++
	id := s.nextID
	packet := eth.GetBlockHeadersPacket{RequestId: id, GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{Origin: origin, Amount: 1}}
	if err := p2p.Send(s.rw, eth.GetBlockHeadersMsg, &packet); err != nil {
		return nil, err
	}
	var received eth.BlockHeadersPacket
	if err := s.reply(eth.BlockHeadersMsg, id, &received); err != nil {
		return nil, err
	}
	if received.List.Len() == 0 {
		return nil, nil
	}
	if received.List.Len() != 1 {
		return nil, errors.New("peer omitted requested header")
	}
	items, err := received.List.Items()
	if err != nil {
		return nil, err
	}
	header := items[0]
	if origin.Hash != (common.Hash{}) && header.Hash() != origin.Hash || origin.Hash == (common.Hash{}) && header.Number.Uint64() != origin.Number {
		return nil, errors.New("peer returned wrong header")
	}
	return header, nil
}

// body requests one block body and reassembles canonical block RLP.
func (s *session) body(header *types.Header) ([]byte, error) {
	s.nextID++
	id := s.nextID
	hash := header.Hash()
	packet := eth.GetBlockBodiesPacket{RequestId: id, GetBlockBodiesRequest: []common.Hash{hash}}
	if err := p2p.Send(s.rw, eth.GetBlockBodiesMsg, &packet); err != nil {
		return nil, err
	}
	var received eth.BlockBodiesPacket
	if err := s.reply(eth.BlockBodiesMsg, id, &received); err != nil {
		return nil, err
	}
	if received.List.Len() != 1 {
		return nil, errors.New("peer omitted requested body")
	}
	items, err := received.List.Items()
	if err != nil {
		return nil, err
	}
	body := items[0]
	if body.Withdrawals == nil || body.Uncles.Len() != 0 {
		return nil, errors.New("unsupported peer body")
	}
	encoded, err := rlp.EncodeToBytes([]any{header, body.Transactions, body.Uncles, body.Withdrawals})
	if len(encoded) > maxMessage {
		return nil, errors.New("peer block exceeds import limit")
	}
	return encoded, err
}

// syncRound acquires missing Engine ancestors, then advances from the anchor.
func (s *session) syncRound() error {
	var missing []common.Hash
	if err := s.worker.api.call("hightower_missingExecutionParents", []any{}, &missing); err != nil {
		return err
	}
	target := max(s.remote.LatestBlock, s.next-1+uint64(len(missing)))
	if err := s.worker.api.call("hightower_executionSyncProgress", []any{fmt.Sprintf("0x%x", s.next-1), fmt.Sprintf("0x%x", target)}, new(bool)); err != nil {
		return err
	}
	for _, hash := range missing {
		if err := s.fetchAncestors(hash); err != nil && !errors.Is(err, errDeepAncestry) {
			return err
		}
	}
	for range maxAncestry {
		header, err := s.header(eth.HashOrNumber{Number: s.next})
		if err != nil {
			return err
		}
		if header == nil {
			break
		}
		var known bool
		if err := s.worker.api.call("hightower_hasExecutionBlock", []any{header.Hash()}, &known); err != nil {
			return err
		}
		if !known {
			status, err := s.importHeader(header)
			if err != nil {
				return err
			}
			if status == "SYNCING" {
				if err := s.fetchAncestors(header.ParentHash); err != nil {
					return err
				}
				status, err = s.importHeader(header)
				if err != nil {
					return err
				}
			}
			if status != "VALID" {
				return errors.New("peer range has an unknown parent")
			}
		}
		s.next++
	}
	target = max(target, s.next-1)
	return s.worker.api.call("hightower_executionSyncProgress", []any{fmt.Sprintf("0x%x", s.next-1), fmt.Sprintf("0x%x", target)}, new(bool))
}

// fetchAncestors walks at most 16 hashes back to a validated parent.
func (s *session) fetchAncestors(target common.Hash) error {
	var pending []*types.Header
	current := target
	for range maxAncestry {
		var known bool
		if err := s.worker.api.call("hightower_hasExecutionBlock", []any{current}, &known); err != nil {
			return err
		}
		if known {
			for i := len(pending) - 1; i >= 0; i-- {
				status, err := s.importHeader(pending[i])
				if err != nil {
					return err
				}
				if status != "VALID" {
					return errors.New("peer ancestry did not connect")
				}
			}
			return nil
		}
		header, err := s.header(eth.HashOrNumber{Hash: current})
		if err != nil {
			return err
		}
		if header == nil {
			return errors.New("peer omitted missing parent header")
		}
		pending = append(pending, header)
		current = header.ParentHash
	}
	// shortcut: a branch more than 16 blocks from known state waits for forward range catch-up; add bounded cross-round branch state when deep forks must be followed.
	return errDeepAncestry
}

var errDeepAncestry = errors.New("peer ancestry exceeds 16-block round")

// importHeader fetches one body and asks Hightower to execute it durably.
func (s *session) importHeader(header *types.Header) (string, error) {
	block, err := s.body(header)
	if err != nil {
		return "", err
	}
	var status string
	err = s.worker.api.call("hightower_importExecutionBlock", []any{header.Hash(), "0x" + hex.EncodeToString(block)}, &status)
	return status, err
}

// call signs one structured Engine request and parses its result or error.
func (a *api) call(method string, params []any, out any) error {
	body, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"2.0", 1, method, params})
	if err != nil {
		return err
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claim, _ := json.Marshal(map[string]int64{"iat": time.Now().Unix()})
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claim)
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(message))
	token := message + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	request, err := http.NewRequest(http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Engine HTTP %d", resp.StatusCode)
	}
	limited, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}
	var parsed response
	if err := json.Unmarshal(limited, &parsed); err != nil {
		return err
	}
	if parsed.Error != nil {
		return fmt.Errorf("Engine %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	return json.Unmarshal(parsed.Result, out)
}
