# FULU-059 execution fixture harness

## Summary

Adds an offline execution fixture test step for four transaction codec cases and explicitly reports the state and blockchain cases whose processors are not implemented.

The separate `zig build test-execution` step runs a fixed, offline bundle. Transaction cases verify the fixture checksum and oracle fields, decode `txbytes` with the execution RLP codec, and require byte-for-byte re-encoding for valid cases. Invalid cases pass only when the codec returns the expected error. The harness does not claim to verify transaction hashes, senders, intrinsic gas, or execution state.

## Pinned inputs

| Source | Revision | Fixture path in source | Checked-in file | SHA-256 |
| --- | --- | --- | --- | --- |
| [ethereum/tests](https://github.com/ethereum/tests) | `c67e485` | `TransactionTests/ttEIP2930/accessListStorage32Bytes.json` | [`accessListStorage32Bytes.json`](../src/execution/fixtures/accessListStorage32Bytes.json) | `02650cf49ea0034cf882a32e4ffcbb45b96ee5fd1e38d5c11e31f0f247ce966e` |
| [ethereum/tests](https://github.com/ethereum/tests) | `c67e485` | `TransactionTests/ttAddress/AddressLessThan20.json` | [`AddressLessThan20.json`](../src/execution/fixtures/AddressLessThan20.json) | `73e22320caea3169610f13b3abbfdc1240010b5d219877fbfe14826cc7113e7f` |
| [ethereum/tests](https://github.com/ethereum/tests) | `c67e485` | `TransactionTests/ttEIP1559/maxFeePerGas00prefix.json` | [`maxFeePerGas00prefix.json`](../src/execution/fixtures/maxFeePerGas00prefix.json) | `20389c8758b06db2509b4b854657cabe97b839bdff37e53e102b4118a65baaa6` |
| [execution-spec-tests](https://github.com/ethereum/execution-spec-tests) | `88e9fb8` (v5.4.0) | `src/ethereum_test_specs/tests/fixtures/tx_simple_type_0_shanghai.json` | [`tx_simple_type_0_shanghai.json`](../src/execution/fixtures/tx_simple_type_0_shanghai.json) | `57c9c3cd9086ea34f82befd3f88013cef7829d975450ae35055493001269e068` |
| [execution-spec-tests](https://github.com/ethereum/execution-spec-tests) | `88e9fb8` (v5.4.0) | `src/ethereum_test_specs/tests/fixtures/chainid_cancun_state_test_tx_type_0.json` | [`chainid_cancun_state_test_tx_type_0.json`](../src/execution/fixtures/chainid_cancun_state_test_tx_type_0.json) | `adbab28513ccf33a4e0c2bc79b19ebf341f93a64d75238d95cb4f6c8b9ce55a6` |
| [execution-spec-tests](https://github.com/ethereum/execution-spec-tests) | `88e9fb8` (v5.4.0) | `src/ethereum_test_specs/tests/fixtures/chainid_london_blockchain_test_tx_type_0.json` | [`chainid_london_blockchain_test_tx_type_0.json`](../src/execution/fixtures/chainid_london_blockchain_test_tx_type_0.json) | `934a836ca8a7d203d3e5388f7ea37a3a4a210954ecfb8b5f64b46ba79db57af3` |

## Acceptance criteria and evidence

| Issue #76 criterion | Evidence |
| --- | --- |
| Check in the six files at the pinned revisions without test-time downloads. | The table above records each source revision, source path, vendored file, and verified SHA-256. The files are compile-time embedded by [`fixtures.zig`](../src/execution/fixtures.zig). |
| Use a fixed manifest and reject checksum, JSON-field, format, or expectation failures. | Each manifest entry includes format, fork, expected outcome, and checksum. The dedicated tests cover checksum mismatch, malformed JSON, a missing expectation, and an unknown format; the runner also validates each format's expected source fields. |
| Decode and round-trip valid transactions; require the specified invalid-transaction errors without claiming unsupported checks. | `accessListStorage32Bytes` and `tx_simple_type_0_shanghai` decode and re-encode byte-for-byte. The short-address and leading-zero fee cases require `InvalidLength` and `NonCanonicalInteger`. Hashes, senders, and intrinsic gas remain unverified. |
| Add an independent execution fixture test step with explicit unsupported-case reporting. | `zig build test-execution` reports `4 passed, 2 skipped`. The Cancun state test names the missing state-transition processor; the London blockchain test names the missing blockchain-test processor. |

The two EELS state and blockchain fixtures are validated for their required oracle fields before they are reported skipped. They are not partial execution passes: their processors are tracked separately.

## Results

The pinned bundle contains four transaction cases and two unsupported execution cases. Expected outcomes are: two canonical round trips, one `InvalidLength`, one `NonCanonicalInteger`, one state-processor skip, and one blockchain-processor skip. The runner additionally exercises malformed JSON, missing expectations, unknown formats, and checksum mismatch through focused failure-path checks.

## Verification

- `zig fmt --check build.zig src`: passed.
- `zig build`: passed.
- `zig build test`: passed.
- `zig build test-execution`: passed; 4 fixture cases passed and 2 were reported skipped with named reasons.
- `git diff --check`: passed.

## Limits

This harness validates transaction envelope syntax and canonical RLP encoding only. It does not calculate transaction hashes, recover senders, compute intrinsic gas, apply state transitions, execute blocks, or validate blockchain fixture post-state.
