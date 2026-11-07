# Local Fulu peer runtime

The runtime imports a single peer chain from an explicit trusted anchor. The
operator must obtain the raw SSZ `BeaconState` and matching `BeaconBlock` from
a trusted local producer or a separately verified checkpoint. Hightower checks
that their state roots match, but it cannot establish the history before the
anchor. Keep both files and the genesis, fork schedule, and execution client
for the same network. Do not use the bundled test fixture as a live anchor.

> [!WARNING]
> This JSON config is **not secure for handling secrets**. It stores the Engine
> JWT secret and node key as plaintext. Use only disposable local credentials.
> [FULU-072 (#175)](https://github.com/GreedyKomodoDragon/hightower/issues/175)
> tracks moving both values to environment-injected secrets.

Create a JSON config with these fields. The 32-byte `node_key` and
`engine_jwt_secret` are lowercase hex without `0x`; use different node keys
for two nodes and keep each key stable across restarts. The sample values below
are placeholders, not deployable secrets.

```json
{
  "listen_address": "127.0.0.1:5052",
  "anchor_state": "anchor-state.ssz",
  "anchor_block": "anchor-block.ssz",
  "bootstrap_enr": "",
  "node_key": "0000000000000000000000000000000000000000000000000000000000000001",
  "data_dir": "node-a-data",
  "trusted_setup": "trusted_setup.txt",
  "engine_url": "http://127.0.0.1:8551",
  "engine_jwt_secret": "0000000000000000000000000000000000000000000000000000000000000002"
}
```

Start the producer with `bootstrap_enr` empty, then copy the `local ENR`
printed in its log into the second node's `bootstrap_enr`. Give the second
node its own `listen_address`, `node_key`, `data_dir`, and local execution
client. Start each with `zig build run -- --config <path>`.

An existing config containing only `listen_address` still serves the bundled
test anchor through the read-only API. It does not join P2P or import blocks.

The Beacon API and `/metrics` use `listen_address`. The node requests at most
16 slots per round from its one active peer. It checks response order, parent
roots, selected KZG-proven columns, execution validity, and the full consensus
transition before atomically saving `fork-choice.bin`. The column store is
durable under `data_dir/columns`. On restart, the node loads both stores and
continues after the saved head. A disconnected or invalid peer leaves that
head intact. The local ENR advertises full 128-column custody for this small
two-node setup; the node needs a complete column set for blob-bearing blocks.

The current loop does not select another peer, reconcile a competing branch,
or backfill archival history. The snapshot format is bounded to 256 MiB and
4096 records per map. The advertised Fulu fork schedule currently assumes
the anchor is already in Fulu with the compiled blob schedule.

## Local verification

On 2026-11-07, the two-node test used the pinned Fulu anchor and two valid
successor blocks. The serving peer answered range requests; the importing
peer saved the first block, loaded its snapshot, imported the second, and
matched the serving peer's head and post-state root. Separate checks rejected
a conflicting replay, a tampered state root, and cancellation while retaining
the last accepted head. Existing network and column tests covered discovery,
block and attestation exchange, disconnect/reconnect, proof rejection, and
bounded sidecar serving.

Run the same checks with `zig build test-transition` and `zig build test`, then
repeat each command with `-Doptimize=ReleaseSafe`. The network tests need
permission to bind loopback TCP and UDP sockets. This local run used
`ZIG_GLOBAL_CACHE_DIR=.zig-global-cache` so Zig could write its cache inside
the repository sandbox. `bash scripts/test_runtime.sh` checks the compatible
read-only config and Beacon API health endpoint.
