# Production execution service

Build with `zig build`, then start `zig-out/bin/hightower-execution --config path/to/config.json`. The service accepts an Osaka genesis JSON file in the format of [the local example](engine/osaka-genesis.json). Its `config.chainId` becomes the RPC chain ID. The binary uses that genesis header and account allocation; it does not enforce the example's pinned hash. Fork schedules beyond this Osaka-only entrypoint belong to #187.

The configuration is a JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `genesis` | Path to the Osaka genesis JSON file |
| `data_dir` | Exclusive execution database directory |
| `jwt_secret` | Path to a file containing 32 bytes as 64 hexadecimal characters |
| `trusted_setup` | Path to the KZG trusted setup file |
| `engine_bind` | IPv4 host and port for the authenticated Engine API, such as `127.0.0.1:8551` |
| `rpc_bind` | Separate IPv4 host and port for public execution JSON-RPC, such as `127.0.0.1:8545` |
| `transfer_contract` | Optional `0x`-prefixed 20-byte ERC-20 contract address |

The Engine listener requires the existing short-lived HS256 JWT on every request. Bind both listeners to loopback unless the deployment provides its own network access controls. Both HTTP handlers share one chain, state, transaction pool, and KZG setup. Startup verifies the genesis hash, persisted chain ID and fork, recovered canonical ancestry, and state and receipt roots before either listener opens. A changed genesis or chain ID requires a new data directory.

## Finalized Transfer output

When `transfer_contract` is set, the service writes one newline-delimited JSON object to stdout for each successful canonical ERC-20 `Transfer(address,address,uint256)` log when its block becomes finalized. Each object has `id` (`0x` block hash followed by `:` and the decimal block log index), `contract`, `from`, `to`, `amount`, `block_hash`, `transaction_hash`, `block_number`, and `log_index`. `amount` is the raw, 32-byte hexadecimal uint256 from the log; no token decimals are assumed. `log_index` counts all logs in the block. A reverted transaction or orphaned branch produces no record.

The service stores a cursor after successfully writing every finalized block's events, including blocks without matching logs. On startup it catches up before opening listeners, and after every committed finality update it catches up before pruning. A failed output or cursor write leaves the block eligible for replay. After a crash, consumers may see the last block's records again and should deduplicate by `id`. A partially written line after an output failure should be discarded. There is one configured contract per data directory; changing it causes startup to fail. Enabling the stream after the needed finalized receipts have been pruned also fails explicitly. The existing execution retention policy keeps 4,096 finalized canonical blocks, rounded to a 128-block checkpoint floor, so an operator who disables the stream for long enough may lose the ability to resume it from that database.

Run `python3 scripts/test_execution_service.py` after `zig build` for a local two-listener test with the signed token fixture, finality output, and recovery.
