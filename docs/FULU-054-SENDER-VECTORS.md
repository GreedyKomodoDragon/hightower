# FULU-054 sender recovery vectors

[`sender_recovery_vectors.json`](../src/execution/fixtures/sender_recovery_vectors.json) pins raw signed transactions, their exact recovery parity, and sender addresses for types 2, 3, and 4. Tests decode the bytes and compare the recovered address, reject the wrong chain ID, and check that changing the parity changes the sender.

| Type | Oracle source |
| --- | --- |
| 2, dynamic fee | [`ethereum/tests` at `c67e485`](https://github.com/ethereum/tests/blob/c67e485/TransactionTests/ttEIP1559/GasLimitPriceProductOverflowtMinusOne.json), Cancun `sender` field. The complete upstream JSON has SHA-256 `f55540f177709ddca7bc2ce5687f7efa87ea40dcfded2ef1c3fe0a6a1faf326d`. |
| 3, blob | [`go-ethereum` v1.16.8](https://github.com/ethereum/go-ethereum/releases/tag/v1.16.8), signed with `types.NewCancunSigner`; `MarshalBinary`, `Sender`, and `RawSignatureValues` supplied the fixture fields. |
| 4, set code | The same go-ethereum release, signed with `types.NewPragueSigner`; its nonempty authorization list contains a `types.SignSetCode` authorization. |

The go-ethereum cases use chain ID 1 and the fixed test key `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`. Both contain a nonempty access list; the blob case contains a versioned hash. These are signature and sender vectors, not blob proof or authorization execution tests. The checked-in JSON has SHA-256 `2eedc1796cb962ffa0e1dcc3bac49f02e83a3fec402ac3b4decdcae4f701035f`.
