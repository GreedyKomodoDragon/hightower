# Engine API implementation notes

The consensus boundary carries `headBlockHash`, `safeBlockHash`, and
`finalizedBlockHash` separately. Payload verdicts retain `latestValidHash`;
network and JSON-RPC failures remain errors. The authenticated client chooses
`newPayloadV4`, `forkchoiceUpdatedV3`, and `getPayloadV5` for Osaka/Fulu. Other
configured forks use V1–V4 according to their Engine API generation.

The server validates a payload on a copy of its parent's execution state and
stages it by hash. A valid forkchoice update commits the selected head before
processing payload attributes, including when those attributes return
`-38003`. An invalid forkchoice update leaves canonical state unchanged.
The builder uses the parent state, pool transactions,
and consensus withdrawals. Blob sidecars supply V1 blob proofs or Osaka V2
cell proofs; the existing KZG setup converts between the two formats.
Cancun and later execution runs the beacon-roots system call before user
transactions. Prague and later also stores the parent execution hash at that
point. Pool selection budgets the fork's blob limit as well as gas, leaving
transactions that do not fit pending.

The current in-memory chain fully validates direct children of its canonical
head. A malformed transaction returns `INVALID` with a known parent's hash as
`latestValidHash`; unknown ancestry returns `SYNCING`. A structurally valid
side-branch payload with known ancestry returns `ACCEPTED` pending execution.
Prague/Osaka deposit logs and withdrawal and consolidation queue outputs are
assembled in type order after transactions. The server compares those bytes
with `newPayloadV4` requests and includes them in builder output and the
requests hash. A deposit event from an address other than the hardcoded
mainnet deposit contract returns `SYNCING` until per-network deposit-contract
configuration is available. Synthetic chains without either request predeploy
retain empty-request behavior. Side-branch reorganization and persistence
belong with the execution chain storage work; this server does not report an
unvalidated request-bearing payload as `VALID`.

## Local checks

`zig build test --summary all` passes 236 tests and covers every supported
method generation's empty builder flow, JWT rejection, transport failure,
malformed requests and transactions, payload status distinctions, invalid
attributes, canonical head changes, and V1/V2 blob bundle conversion.

For Geth interoperability, CI tests v1.17.7 through v1.17.10 with pinned
image digests in [the workflow](../.github/workflows/ci.yml). The script
defaults to v1.17.7 and accepts a pinned image reference as its argument.
The [Osaka genesis](engine/osaka-genesis.json) comes from Geth's
`--dev dumpgenesis` output with `bogotaTime` removed; its system contracts are
needed for Osaka payload building. CI and local runs use the same command from
the repository root:

```sh
bash scripts/test_engine_interop.sh
```

Fresh-chain runs against all four pinned versions initialized the Osaka
genesis. Hightower computed
`0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f`
each time, and each probe reported:
`Osaka Engine API: Geth accepted Hightower payload and selected head`.
The original single-engine probe still accepts its three arguments.
It reported capability exchange, payload build and validation, and head
selection succeeded against the fixture server.

The status and error behavior follows the [Engine API payload validation and
forkchoice rules](https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md).
