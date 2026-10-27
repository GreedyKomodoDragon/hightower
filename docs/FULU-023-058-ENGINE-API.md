# Engine API implementation notes

The consensus boundary carries `headBlockHash`, `safeBlockHash`, and
`finalizedBlockHash` separately. Payload verdicts retain `latestValidHash`;
network and JSON-RPC failures remain errors. The authenticated client chooses
`newPayloadV4`, `forkchoiceUpdatedV3`, and `getPayloadV5` for Osaka/Fulu. Other
configured forks use V1–V4 according to their Engine API generation.

The server validates a payload on a copy of its parent's execution state and
stages it by hash. A forkchoice update prepares any requested build before it
commits a staged child. The builder uses the parent state, pool transactions,
and consensus withdrawals. Blob sidecars supply V1 blob proofs or Osaka V2
cell proofs; the existing KZG setup converts between the two formats.
Cancun and later execution runs the beacon-roots system call before user
transactions. Prague and later also stores the parent execution hash at that
point. Pool selection budgets the fork's blob limit as well as gas, leaving
transactions that do not fit pending.

The current in-memory chain accepts direct children of its canonical head.
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

`zig build test --summary all` passes 235 tests, including every supported
method generation's empty builder flow, JWT rejection, bad payload hashes,
canonical head changes, and V1/V2 blob bundle conversion. The dedicated
transition and execution fixture suites pass. Debug and ReleaseSafe builds
pass.

For Geth interoperability, use the pinned
`ethereum/client-go:v1.17.7` image (digest
`sha256:6e9669cca5359cdb2c5571198d51e78fc18128b56bff50a1f8422d1c2946fd64`).
The [Osaka genesis](engine/osaka-genesis.json) comes from Geth's
`--dev dumpgenesis` output with `bogotaTime` removed; its system contracts are
needed for Osaka payload building. From the repository root:

```sh
openssl rand -hex 32 > /tmp/hightower-engine-jwt.hex
docker run --rm -v "$PWD/docs/engine/osaka-genesis.json:/genesis.json:ro" -v /tmp/hightower-geth-data:/data ethereum/client-go:v1.17.7 --datadir /data init /genesis.json
docker run -d --rm --name hightower-geth-test -p 127.0.0.1:18545:8545 -p 127.0.0.1:18551:8551 -v /tmp/hightower-geth-data:/data -v /tmp/hightower-engine-jwt.hex:/jwt.hex:ro ethereum/client-go:v1.17.7 --datadir /data --networkid 1337 --http --http.addr 0.0.0.0 --http.api eth,net,web3 --authrpc.addr 0.0.0.0 --authrpc.vhosts '*' --authrpc.jwtsecret /jwt.hex --nodiscover --maxpeers 0
zig build engine-probe
./zig-out/bin/hightower-engine-probe http://127.0.0.1:18551 /tmp/hightower-engine-jwt.hex 0xd5bfe455af9e369a28ae13737769879f1ad8d2aa281ebfdbdf8529d48a20ae7f
docker stop hightower-geth-test
```

The probe completed capability exchange, `forkchoiceUpdatedV3`,
`getPayloadV5`, `newPayloadV4`, and head selection against Geth v1.17.7. It
completed the same sequence against `hightower-engine-test-server` over
authenticated HTTP. The temporary Geth test used a fresh JWT secret and
loopback ports.
