// A blob transaction carries a KZG commitment to data supplied beside its
// execution payload. Fulu derives data columns from that blob for availability
// sampling. This command signs one blob transaction before slot 1 and waits
// for its receipt so the relay tests a non-empty column set. It supports one
// blob on the four-validator local devnet.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// main signs one blob transaction from the funded devnet account and waits for inclusion.
func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "execution JSON-RPC endpoint")
	keystorePath := flag.String("keystore", "", "Geth keystore file for the funded account")
	passwordPath := flag.String("password", "", "file containing the keystore password")
	to := flag.String("to", "0x0000000000000000000000000000000000000001", "transaction recipient")
	value := flag.Int64("value", 1, "wei to transfer")
	chainID := flag.Int64("chain-id", 1337, "execution chain ID")
	predeploys := flag.Bool("predeploys", false, "print Geth's system contract genesis allocations as JSON")
	flag.Parse()
	if *predeploys {
		contracts := map[common.Address][]byte{
			params.BeaconRootsAddress: params.BeaconRootsCode,
			params.HistoryStorageAddress: params.HistoryStorageCode,
			params.WithdrawalQueueAddress: params.WithdrawalQueueCode,
			params.ConsolidationQueueAddress: params.ConsolidationQueueCode,
			params.BuilderDepositAddress: params.BuilderDepositCode,
			params.BuilderExitAddress: params.BuilderExitCode,
			params.DeterministicFactoryAddress: params.DeterministicFactoryCode,
		}
		alloc := make(map[string]any, len(contracts))
		for address, code := range contracts {
			alloc[address.Hex()] = map[string]any{"nonce": 1, "code": "0x" + common.Bytes2Hex(code), "balance": "0"}
		}
		must(json.NewEncoder(os.Stdout).Encode(alloc))
		return
	}
	if *keystorePath == "" || *passwordPath == "" {
		fmt.Fprintln(os.Stderr, "blobtx: -keystore and -password are required")
		os.Exit(2)
	}

	password, err := os.ReadFile(*passwordPath)
	must(err)
	keyJSON, err := os.ReadFile(*keystorePath)
	must(err)
	key, err := keystore.DecryptKey(keyJSON, string(password))
	must(err)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	must(err)
	defer client.Close()

	nonce, err := client.PendingNonceAt(ctx, key.Address)
	must(err)
	head, err := client.HeaderByNumber(ctx, nil)
	must(err)
	gasTip, err := client.SuggestGasTipCap(ctx)
	must(err)
	gasFeeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), gasTip)
	maxBlobFee := big.NewInt(1_000_000_000)

	var blob kzg4844.Blob
	for i := 31; i < len(blob); i += 32 {
		blob[i] = byte((i / 32) % 251)
	}
	commitment, err := kzg4844.BlobToCommitment(&blob)
	must(err)
	proofs, err := kzg4844.ComputeCellProofs(&blob)
	must(err)
	sidecar := types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		proofs,
	)
	blobHash := common.Hash(kzg4844.CalcBlobHashV1(sha256.New(), &commitment))

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(big.NewInt(*chainID)),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(gasTip),
		GasFeeCap:  uint256.MustFromBig(gasFeeCap),
		Gas:        21_000,
		To:         common.HexToAddress(*to),
		Value:      uint256.NewInt(uint64(*value)),
		BlobFeeCap: uint256.MustFromBig(maxBlobFee),
		BlobHashes: []common.Hash{blobHash},
		Sidecar:    sidecar,
	})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(*chainID)), key.PrivateKey)
	must(err)
	must(client.SendTransaction(ctx, signed))

	for {
		receipt, err := client.TransactionReceipt(ctx, signed.Hash())
		if err == nil {
			result := map[string]any{
				"tx_hash":      signed.Hash().Hex(),
				"block_number": receipt.BlockNumber.Uint64(),
				"blob_hash":    blobHash.Hex(),
			}
			encoded, err := json.Marshal(result)
			must(err)
			fmt.Println(string(encoded))
			return
		}
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "blobtx: transaction %s was not mined: %v\n", signed.Hash(), ctx.Err())
			os.Exit(1)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// must exits when the local devnet cannot complete a required operation.
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "blobtx:", err)
		os.Exit(1)
	}
}
