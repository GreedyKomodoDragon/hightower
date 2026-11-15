# Production execution service

Build with `zig build`, then start `zig-out/bin/hightower-execution --config path/to/config.json`. The service accepts an Osaka genesis JSON file in the format of [the local example](engine/osaka-genesis.json). Its `config.chainId` becomes the RPC chain ID. The binary loads account balances, nonces, code, and storage along with supported header fields; it rejects unrecognized account or header fields and does not enforce the example's pinned hash. Fork schedules beyond this Osaka-only entrypoint belong to #187.

The configuration is a JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `genesis` | Path to the Osaka genesis JSON file |
| `checkpoint_header` | Optional path to an RLP-encoded Osaka execution header |
| `checkpoint_state` | Optional path to a complete Hightower state checkpoint created by `State.checkpointBytes` |
| `checkpoint_hash` | Required with the two checkpoint paths: trusted `0x`-prefixed 32-byte hash of the header |
| `data_dir` | Exclusive execution database directory |
| `jwt_secret` | Path to a file containing 32 bytes as 64 hexadecimal characters |
| `trusted_setup` | Path to the KZG trusted setup file |
| `engine_bind` | IPv4 host and port for the authenticated Engine API, such as `127.0.0.1:8551` |
| `rpc_bind` | Separate IPv4 host and port for public execution JSON-RPC, such as `127.0.0.1:8545` |
| `transfer_contract` | Optional `0x`-prefixed 20-byte ERC-20 contract address |

The Engine listener requires the existing short-lived HS256 JWT on every request. Bind both listeners to loopback unless the deployment provides its own network access controls. Both HTTP handlers share one chain, state, transaction pool, and KZG setup. Startup verifies the starting header hash, persisted chain ID and fork, recovered canonical ancestry, and state and receipt roots before either listener opens. A changed starting header or chain ID requires a new data directory.

The three checkpoint fields must be supplied together. The operator must trust the checkpoint hash and its history; Hightower checks the RLP header against that hash and the complete state against the header's state root before opening the database. The genesis file still supplies the chain ID. This local checkpoint format requires full account addresses, storage keys, and code; it is not a SNAP download. Input is limited to a 16 KiB header and 512 MiB state file. Use a new data directory when changing the checkpoint. The database retains 4,096 finalized canonical blocks, aligned to 128-block state checkpoints, and cannot serve older pruned bodies or state. `zig build test` exercises the pinned Osaka genesis fixture through checkpoint loading, corrupt-state rejection, and the existing execution recovery tests.

The public RPC listener also serves unauthenticated `GET /health` (`200` when the durable identity record can be read, `503` after a durable choice write becomes uncertain or the storage read fails) and `GET /metrics` in Prometheus text format. Metrics report head, safe, and finalized block numbers, syncing state, pool entries and bytes, RPC requests and JSON-RPC errors, cumulative payload-build nanoseconds and failures, and the storage health flag. Credentials and hashes are not returned. Storage health performs a durable marker read; it does not perform a write probe.

## Execution peer catch-up

Build the optional worker with `cd scripts/geth-discovery-probe && go build -o ../../zig-out/bin/hightower-execution-peer ./execution-peer`. Start the execution service with a trusted checkpoint, then run `zig-out/bin/hightower-execution-peer --config path/to/config.json --peer enode://...` from the repository root. The worker reads the same genesis, checkpoint header, and JWT secret, and requires a loopback Engine listener. A peer with a discovery UDP endpoint is also used as a discovery bootstrap; a TCP-only record is used as a static peer. The worker speaks `eth/69`, admits at most two peers, requests one header or body per message, imports at most 16 sequential blocks per round, and rejects messages over 10 MiB. Hightower re-executes each block, checks its header and state commitments, and stores it durably before allowing Engine fork choice to select it. Peer import alone does not change the canonical head.

Unknown-parent Engine payloads return `SYNCING` and enter a queue of at most 32 payloads and 32 MiB. The worker asks for distinct missing parent hashes; after validated ancestors arrive, the Engine retries queued payloads in order. The queue is volatile, so an incomplete download may be fetched again after restart. The worker resumes from the durable canonical head when it is ahead of the anchor, avoiding pruned history. `eth_syncing` returns the worker's starting, current, and highest block while a recent report is behind its target; a stopped worker's report expires after ten seconds. The checkpoint state must already be complete. SNAP state acquisition is not implemented.

After `zig build` and building the Go worker, run `python3 scripts/test_execution_service.py --geth-bin /path/to/geth --peer-bin zig-out/bin/hightower-execution-peer` to build 18 local Geth blocks, submit the last to a fresh Hightower database before its parent, acquire the ancestry over multiple bounded `eth/69` rounds, compare canonical block data, and check restart. The Go message-pipe tests run with `cd scripts/geth-discovery-probe && go test ./...`.

## Finalized Transfer output

When `transfer_contract` is set, the service writes one newline-delimited JSON object to stdout for each successful canonical ERC-20 `Transfer(address,address,uint256)` log when its block becomes finalized. Each object has `id` (`0x` block hash followed by `:` and the decimal block log index), `contract`, `from`, `to`, `amount`, `block_hash`, `transaction_hash`, `block_number`, and `log_index`. `amount` is the raw, 32-byte hexadecimal uint256 from the log; no token decimals are assumed. `log_index` counts all logs in the block. A reverted transaction or orphaned branch produces no record.

The service stores a cursor after successfully writing every finalized block's events, including blocks without matching logs. On startup it catches up before opening listeners, and after every committed finality update it catches up before pruning. A failed output or cursor write leaves the block eligible for replay. After a crash, consumers may see the last block's records again and should deduplicate by `id`. A partially written line after an output failure should be discarded. There is one configured contract per data directory; changing it causes startup to fail. Enabling the stream after the needed finalized receipts have been pruned also fails explicitly. The existing execution retention policy keeps 4,096 finalized canonical blocks, rounded to a 128-block checkpoint floor, so an operator who disables the stream for long enough may lose the ability to resume it from that database.

Run `python3 scripts/test_execution_service.py` after `zig build` for a local two-listener test with health and metrics checks, finality output, recovery, invalid-storage startup, and the signed transaction fixture. On Linux it also limits the running process to zero file bytes, forces a durable commit failure, and checks for HTTP 503 plus a zero storage-health metric. To compare execution against pinned Geth v1.17.10, run `python3 scripts/test_execution_service.py --geth-bin /path/to/geth`. This opt-in mode feeds the same built payloads to both clients, including contract deployment, transfer, revert, restart, and a competing block reorg. It compares canonical hashes, state and receipt roots, gas, transaction receipts, logs, balances, and selected storage reads with block and transaction coordinates in mismatches. Hightower deliberately drops orphaned block-hash reads, reports `eth_syncing` as `false`, uses a fixed priority fee, and supports only the RPC methods listed below; these differ from Geth behavior.

## Public JSON-RPC and transaction pool

| RPC area | Methods | Support |
| --- | --- | --- |
| Chain and account reads | `eth_chainId`, `eth_blockNumber`, `eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_getTransactionCount` | Supported |
| Transactions and logs | `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockReceipts`, `eth_getLogs` | Supported |
| Calls and fees | `eth_call`, `eth_estimateGas`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_feeHistory` | Supported |
| Submission | `eth_sendRawTransaction` | Supported |
| Network and status | `net_version`, `web3_clientVersion`, `eth_syncing` | Supported |
| Tracing | `debug_traceTransaction` with `callTracer` | Supported for canonical transactions with an available parent pre-state |
| Other methods, including filters, subscriptions, other tracers, and personal account management | All unlisted methods | `-32601` method not found |

`eth_syncing` is `false` when no execution peer worker is actively catching up. Fee estimates use a fixed 1 gwei priority fee; fee-history rewards use the same estimate rather than a transaction-tip percentile.

Reads use only the selected canonical chain. `latest` and `pending` read the latest committed state; `safe` and `finalized` use their Engine fork-choice checkpoints, falling back to latest before a checkpoint is supplied; `earliest` uses genesis. Hexadecimal numbers select canonical blocks. `pending` transaction count advances only across contiguous sender nonces in the pool. Orphaned block hashes, transactions, receipts, and logs disappear from public reads. `eth_getBlockReceipts` returns `null` for an unknown block. Malformed parameters return `-32602`; a valid but unavailable state block returns `-32001`.

Calls and estimates accept contract creation requests with no `to`; they run initcode on a discarded state snapshot. A successful creation receipt contains the derived `contractAddress`. A reverted creation has status `0x0`, a null `contractAddress`, and no deployed code.

`debug_traceTransaction(hash, {"tracer":"callTracer"})` returns nested call frames with `type`, `from`, `to`, `value`, `input`, `output`, `gas`, and `gasUsed`; failed frames also have `error`. It replays system transitions and earlier transactions from the canonical block's parent state. Revert output retains its ABI-encoded bytes. Traces are computed on demand and are not stored. Unknown or orphaned transaction hashes return `-32000`, and unsupported tracer names return `-32602`. The trace stops with `-32005` after 1,024 frames, 1,000,000 opcode steps, two seconds, or a 1 MiB serialized response. A block at the retention floor needs its parent pre-state, so it may no longer be traceable after pruning.

`eth_sendRawTransaction` accepts signed legacy and EIP-2718 types 1 (access list), 2 (dynamic fee), 3 (blob), and 4 (set code) on supported forks. Blob submissions require a valid network sidecar and trusted KZG setup. A successfully submitted hash is pending and queryable through `eth_getTransactionByHash` with null block fields until canonical inclusion. Inclusion gives it a block position and receipt. A 10% bump in all applicable fee caps replaces a pending sender nonce; the old hash then returns `null`. A stale nonce, invalid signature or chain ID, insufficient balance, underpriced replacement, oversized transaction, invalid blob sidecar, or full pool is rejected with a named `-32000` error. Higher-tip entries may evict lower-tip entries. Entries already included or made stale by a canonical commit are pruned. On reorg, valid orphaned non-blob transactions are offered to the pool again; blob transactions are dropped because the included canonical record no longer retains their sidecars. Pending entries and counters are in memory and reset on restart.

The pool holds at most 4,096 entries and 64 MiB of encoded transactions plus sidecars. It records live entry count, owned bytes, evictions, replacements, and payload build failures internally. Metrics do not yet cover latency histograms, per-method RPC breakdowns, or direct disk I/O probes. JSON-RPC limits are 8 MiB per request, 20 requests per batch, 1,000 blocks or 10,000 returned logs per log query, and 128 blocks per fee-history query. These limits return a request or query error rather than a partial result.
