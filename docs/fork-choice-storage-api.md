# Fork-choice recovery and Beacon API

`saveForkChoiceStore(allocator, io, dir, path, store)` writes a version 3
snapshot and appends subsequent changes to `<path>.log`. `loadForkChoiceStore`
returns a new, independently owned store; the caller must call `deinit`. The
caller must hold a stable store while saving or serving requests.

The file begins with ASCII `HTFC0003`, a little-endian 64-bit payload length,
and a SHA-256 checksum of the payload. The payload contains timing, four
checkpoints, proposer boost, the derived head, then length-prefixed maps of
blocks, post-states, checkpoint states, timeliness, validator latest messages,
equivocating indices, and unrealized justifications. Blocks and states use SSZ.
The format is local to Hightower and is not network wire SSZ. The snapshot is
limited to 8 GiB; map counts are bounded by that payload size rather than a
block-count retention cap. Only version 3 is accepted.

The log begins with `HTFLOG01`, the base snapshot checksum, and a checksum of
that header. Each `HTFREC01` frame contains one fork-choice commit's metadata
and only the changed map keys, including tombstones for finality-pruned data.
Every frame has a length and SHA-256 checksum and is synced before save returns.
The log is bounded to 8 GiB and is compacted into a synced atomic snapshot at
256 MiB. If a crash occurs after snapshot replacement but before log reset, the
old log's base checksum differs and startup ignores that stale generation.

Loading validates the snapshot and replays every matching log frame in order,
checking checksums, roots, references, and the selected head after each frame.
It rejects unsupported versions, truncated or oversized files, corrupt
checksums, malformed SSZ, inconsistent records, and never returns a partial
store. Fork choice retains the finalized anchor and descendants; when finality
advances, pruned blocks, states, votes, signatures, and checkpoints are written
as tombstones and removed during replay. Preserve failed files for diagnostics
and recover from a trusted chain anchor.

The standalone read-only service accepts a caller-supplied stable store plus
sync status and genesis fork version. The selected response shapes follow the
[Beacon API schemas at revision
`79b9b05e`](https://github.com/ethereum/beacon-APIs/tree/79b9b05e354da4f80d8f18879871af6f0068108d).
Import it as the `hightower_api` Zig module or through `hightower.api`. It
depends on the consensus module and implements:

| Endpoint | Returned data |
| --- | --- |
| `GET /eth/v1/node/health` | 200 ready, 206 syncing, or 503 unavailable |
| `GET /eth/v1/node/syncing` | Head slot, sync distance, sync and optimistic flags |
| `GET /eth/v1/beacon/genesis` | Genesis time, validators root, fork version |
| `GET /eth/v1/beacon/blocks/{block_id}/root` | Block root |
| `GET /eth/v1/beacon/states/{state_id}/root` | Post-state root |
| `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints` | State checkpoints |

Identifiers accept `head`, `finalized`, `genesis`, decimal slots, or a `0x` root;
state endpoints also accept `justified`. A block
root can select a noncanonical stored block. A state root can select a stored
noncanonical post-state. Slot lookup follows the current head and returns 404
for missed slots because this store only retains post-block states. Malformed
identifiers return 400, unknown data 404, and an unavailable store 503. Request
headers are capped at 8 KiB; request bodies are rejected. The API does not
expose complete signed blocks or arbitrary states because the fork-choice
store does not retain all data required by those endpoints.

The [Bruno collection](../tests/bruno/beacon-api/bruno.json) checks all six
endpoints over HTTP, including root identifiers, errors, syncing, and readiness. Run
`zig build api-test-server`, install `@usebruno/cli@4.3.0`, then run
`bash scripts/test_beacon_api.sh` from the repository root. The test server
loads the pinned fork-choice anchor fixture and listens only on loopback port
18080; it is not part of the node runtime.
