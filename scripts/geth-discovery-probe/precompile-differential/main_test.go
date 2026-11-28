// Precompile gas is charged before input validation. These cases assert that
// exact gas succeeds, one gas short fails, and malformed curve proofs fail.
// The tested addresses cover BN254 and point evaluation paths.
package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// TestReferenceBoundaries checks the oracle's exact and short gas behavior on critical paths.
func TestReferenceBoundaries(t *testing.T) {
	contracts := vm.ActivePrecompiledContracts(params.Rules{IsBerlin: true, IsCancun: true, IsOsaka: true})
	for _, address := range []byte{6, 8, 10} {
		p := contracts[common.BytesToAddress([]byte{address})]
		input := validInput(address)
		cost := p.RequiredGas(input)
		exact := reference(p, input, cost)
		if !exact.Success || exact.GasUsed != cost {
			t.Fatalf("address %d exact gas: %+v", address, exact)
		}
		short := reference(p, input, cost-1)
		if short.Success || short.GasUsed != cost-1 {
			t.Fatalf("address %d short gas: %+v", address, short)
		}
		invalidInput := malformedInput(address)
		invalid := reference(p, invalidInput, p.RequiredGas(invalidInput))
		if invalid.Success {
			t.Fatalf("address %d accepted malformed input", address)
		}
	}
}
