# Fork-choice recovery and Beacon API

`saveForkChoiceStore(allocator, io, dir, path, store)` writes the first local
snapshot format. `loadForkChoiceStore` returns a new, independently owned store;
the caller must call `deinit`. The caller must hold a stable store while saving
or serving requests. The node runtime in FULU-028 will own that coordination.

The file begins with ASCII `HTFC0001`, a little-endian 64-bit payload length,
and a SHA-256 checksum of the payload. The payload contains timing, four
checkpoints, proposer boost, the derived head, then length-prefixed maps of
blocks, post-states, checkpoint states, timeliness, validator latest messages,
equivocating indices, and unrealized justifications. Blocks and states use SSZ.
The format is local to Hightower and is not network wire SSZ. A file is limited
to 256 MiB and each map to 4096 entries.

Saving writes an atomic temporary file, syncs it, and replaces the destination.
An interrupted save leaves the prior destination loadable. Loading rejects an
unsupported header, truncated or oversized data, checksum failure, malformed
SSZ, duplicate records, invalid block and state roots, dangling references,
and a head different from the recorded head. Failure frees decoded records and
never returns a partial store. The caller should preserve a failed snapshot for
diagnostics and recover from an earlier backup or trusted chain anchor.

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
