// Precompiles are native contracts selected by fork and address. Gas is charged
// before input validation; a failed call consumes its full call budget.
// London -> Cancun adds point evaluation -> Osaka reprices ModExp.
// Inputs stay below 512 bytes, apart from no external fixture data.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

type outcome struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
	GasUsed uint64 `json:"gas_used"`
}
type testCase struct {
	Seed    int64   `json:"seed"`
	Fork    string  `json:"fork"`
	Address uint8   `json:"address"`
	Input   string  `json:"input"`
	Gas     uint64  `json:"gas"`
	Geth    outcome `json:"geth"`
}

// validInput returns a small accepted input for each address.
func validInput(address byte) []byte {
	switch address {
	case 1:
		return make([]byte, 128)
	case 5:
		data := make([]byte, 99)
		data[31], data[63], data[95] = 1, 1, 1
		data[96], data[97], data[98] = 2, 3, 5
		return data
	case 6:
		return make([]byte, 128)
	case 7:
		return make([]byte, 96)
	case 8:
		return make([]byte, 192)
	case 9:
		return make([]byte, 213)
	case 10:
		data := make([]byte, 192)
		data[96], data[144] = 0xc0, 0xc0
		digest := sha256.Sum256(data[96:144])
		copy(data[:32], digest[:])
		data[0] = 1
		return data
	default:
		return []byte("hightower")
	}
}

// malformedInput returns a bounded invalid input for the contracts that validate structure.
func malformedInput(address byte) []byte {
	switch address {
	case 5:
		data := validInput(address)
		data[31] = 0xff
		return data
	case 6, 7:
		data := validInput(address)
		for i := range data {
			data[i] = 0xff
		}
		return data
	case 8:
		return []byte{0xff}
	case 9:
		data := validInput(address)
		data[212] = 2
		return data
	case 10:
		data := validInput(address)
		data[0] = 0
		return data
	default:
		return []byte{0xff}
	}
}

// reference applies Geth's fork-specific precompile and call-frame gas semantics.
func reference(p vm.PrecompiledContract, input []byte, gas uint64) outcome {
	cost := p.RequiredGas(input)
	if cost > gas {
		return outcome{GasUsed: gas}
	}
	output, err := p.Run(input)
	if err != nil {
		return outcome{GasUsed: gas}
	}
	return outcome{Success: true, Output: hex.EncodeToString(output), GasUsed: cost}
}

// main writes deterministic JSON cases for the Zig comparison runner.
func main() {
	seed := flag.Int64("seed", 114, "random seed")
	count := flag.Int("count", 2, "extra random inputs per fork and address")
	flag.Parse()
	if *count < 0 || *count > 100 {
		fmt.Fprintln(os.Stderr, "count must be 0..100")
		os.Exit(2)
	}
	rng := rand.New(rand.NewSource(*seed))
	cases := make([]testCase, 0)
	for _, fork := range []string{"london", "cancun", "osaka", "fulu"} {
		rules := params.Rules{IsBerlin: true, IsCancun: fork != "london", IsOsaka: fork == "osaka" || fork == "fulu"}
		contracts := vm.ActivePrecompiledContracts(rules)
		for address := byte(1); address <= 10; address++ {
			p := contracts[common.BytesToAddress([]byte{address})]
			if p == nil {
				continue
			}
			inputs := [][]byte{validInput(address), malformedInput(address)}
			for range *count {
				input := make([]byte, rng.Intn(257))
				rng.Read(input)
				if address == 5 {
					input = validInput(address)
					rng.Read(input[96:])
				}
				inputs = append(inputs, input)
			}
			for _, input := range inputs {
				cost := p.RequiredGas(input)
				budgets := []uint64{cost}
				if cost > 0 {
					budgets = append(budgets, cost-1)
				}
				for _, gas := range budgets {
					cases = append(cases, testCase{Seed: *seed, Fork: fork, Address: address, Input: hex.EncodeToString(input), Gas: gas, Geth: reference(p, input, gas)})
				}
			}
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(cases); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
