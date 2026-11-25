// This fixture signs 300 small and four large independent eth/69 transactions.
// Each sender has nonce zero, so later pool entries can be selected by the
// payload builder while total network bytes also exceed one 3 MiB gossip page.
//
// deterministic key -> funded genesis address -> signed network transaction
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const smallCount = 300
const largeCount = 4
const largeDataBytes = 900_000

type entry struct {
	Address string `json:"address"`
	Raw     string `json:"raw"`
}

// main serializes deterministic signed transactions for the runtime test.
func main() {
	chainID := big.NewInt(1)
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")
	result := make([]entry, 0, smallCount+largeCount)
	for i := range smallCount + largeCount {
		var secret [32]byte
		binary.BigEndian.PutUint32(secret[28:], uint32(i+1))
		key, err := crypto.ToECDSA(secret[:])
		if err != nil {
			panic(err)
		}
		gas := uint64(21_000)
		var data []byte
		if i >= smallCount {
			gas = 10_000_000
			data = make([]byte, largeDataBytes)
		}
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: gas, To: &recipient, Data: data})
		signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), key)
		if err != nil {
			panic(err)
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			panic(err)
		}
		result = append(result, entry{Address: crypto.PubkeyToAddress(key.PublicKey).Hex(), Raw: "0x" + hex.EncodeToString(raw)})
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
