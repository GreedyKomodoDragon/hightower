# FULU-048 Receipts, logs, and logs bloom

## Summary

Execution receipt types already encode legacy receipts as RLP lists and typed receipts as a type byte followed by an RLP payload. The standalone `bloom_filter` module exposes the `BloomFilter` type for Ethereum's 2048-bit logs bloom. Execution code uses it to build and query blooms and computes a receipts trie root from ordered canonical receipt encodings.

The bloom hashes each log address and topic with Keccak-256 and sets three indexed bits. Log data is not part of the bloom. Bloom queries are probabilistic: a positive result may be a false positive. `receiptsRoot` owns temporary allocations for its computation and returns the ordered trie root.

## Pinned sample

The sample receipt root is taken from block 1 in `chainid_london_blockchain_test_tx_type_0.json`, pinned from `ethereum/execution-spec-tests` v5.4.0 commit [`88e9fb8`](https://github.com/ethereum/execution-spec-tests/commit/88e9fb8). Its existing checksum is:

| Fixture | SHA-256 |
| --- | --- |
| [`chainid_london_blockchain_test_tx_type_0.json`](../src/execution/fixtures/chainid_london_blockchain_test_tx_type_0.json) | `934a836ca8a7d203d3e5388f7ea37a3a4a210954ecfb8b5f64b46ba79db57af3` |

The test checks the root `c598f69a5674cae9337261b669970e24abc0b46e6d284372a239ec8ccbf20b0a` recorded by that fixture. The bloom bit mapping follows the [Ethereum Yellow Paper's 2048-bit bloom definition](https://ethereum.github.io/yellowpaper/paper.pdf). The known Keccak-256(`abc`) digest `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45` fixes the expected bloom bit positions independently of the query helper.

## Acceptance criteria and evidence

| Issue #85 criterion | Implementation evidence | Test evidence |
| --- | --- | --- |
| Bloom construction/query matches known vectors. | `bloom_filter.BloomFilter` provides `add` and `mayContain`; execution helpers build receipt and block blooms. | Tests assert exact Keccak vectors, empty-filter and empty-value behavior, binary and long inputs, duplicate/order-independent insertions, saturation false positives, log address/topic membership, data exclusion, and receipt aggregation. |
| Receipt encoding round-trips. | Existing codecs encode legacy and typed envelopes and decode all supported receipt tags. | Tests round-trip legacy, access-list, dynamic-fee, blob, and set-code receipts; malformed lengths and unknown tags are rejected. |
| Receipts root matches the trie root for a sample block. | `receiptsRoot` serializes each receipt and calls the ordered trie root helper. | A pinned London block receipt yields the fixture's expected `receiptTrie`. |

## Limits

The helpers do not execute transactions, generate receipts, verify that a supplied receipt bloom matches its logs during serialization, or implement JSON-RPC receipt responses (FULU-057). Callers constructing receipt payloads should set `logs_bloom` from `logsBloom(payload.logs)` before encoding.
