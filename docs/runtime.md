# Local Fulu peer runtime

The runtime imports one peer chain from a trusted Fulu anchor. Supply matching raw SSZ `BeaconState` and `BeaconBlock` files from a verified checkpoint, plus the same network's fork schedule and execution client. Hightower checks the anchor's state root but cannot establish its earlier history. The bundled fixture is only for the local test below.

Copy [runtime.example.json](runtime.example.json) and set its paths and addresses. Keep the JSON file free of credentials. A secret manager should inject `HIGHTOWER_NODE_KEY` and `HIGHTOWER_ENGINE_JWT_SECRET` into each node process. Each must be exactly 32 bytes encoded as 64 hex digits, without `0x`. Use a different node key per node and preserve it across restarts. The JWT secret must match that node's execution client's secret. The runtime rejects either former JSON field, even if its value is `null`; remove both fields when migrating an older config and rotate any credential that was committed or shared. Environment variables are an injection mechanism, not a complete secret-management system.

Start the serving node with `bootstrap_enr` empty. Copy its logged `local ENR` into the second node's `bootstrap_enr`. Give each node a separate `listen_address`, `data_dir`, node key, and local execution client. Start each under its secret-manager environment with:

```sh
zig build
./zig-out/bin/hightower --config path/to/node.json
```

A config with only `listen_address` still serves the bundled anchor through a read-only Beacon API; it does not join P2P or read credentials. The Beacon API and `/metrics` bind to `listen_address`.

The importer checks response order, parent roots, selected KZG-proven columns, the execution client's verdict, and the consensus transition before saving `fork-choice.bin`. It requests at most 16 slots per round from one active peer. The column store persists under `data_dir/columns`. Restart loads both stores, increments the durable `enr-sequence` for its new P2P ports, and continues after the saved head. A disconnected or invalid peer leaves that head intact. The local ENR advertises all 128 custody columns; blob-bearing blocks require a complete column set.

The loop does not select a replacement peer, reconcile competing branches, or backfill archival history. Snapshots are bounded to 256 MiB and 4096 records per map. The advertised fork schedule assumes an anchor already in Fulu with the compiled blob schedule.

## Reproducible two-node check

Run from the repository root on a machine that permits loopback TCP and UDP:

```sh
ZIG_GLOBAL_CACHE_DIR=.zig-global-cache zig build runtime-fixture engine-test-server
ZIG_GLOBAL_CACHE_DIR=.zig-global-cache zig build
python3 scripts/test_runtime_network.py
```

The script creates a temporary pinned Fulu anchor, a serving node snapshot with two valid successor blocks, two isolated Engine test servers, and two Hightower processes with distinct identities and data directories. Its fixed credentials are disposable test values. It checks startup rejection of missing, malformed, and legacy JSON credentials before any listener binds. It then waits for both Beacon API heads to equal the pinned slot-2 root, stops and restarts the importing node using its persisted directory, and checks the head again. Captured logs are checked for credential bytes. On 2026-11-07 the result was:

```text
two nodes converged at slot 2, head 0xd6ba53e69bd41b9e75c0650c6dc151bcf1133657c73c450e828076bba0dc6edd; target recovered after restart
```

The Engine test servers use an explicit fixture mode that accepts only the two pinned execution payload hashes. This establishes process-level transport, block exchange, consensus validation, fork-choice agreement, and durable recovery. It does **not** validate the pinned blocks under execution-layer state rules or demonstrate Hoodi interoperability; the ordinary local Engine server returns an unverified verdict for these synthetic payloads.

## Full local execution validation with Geth

This check needs Geth 1.17.10 and Prysm 7.3.1 binaries. Set `GETH_BIN` to the Geth executable and `PRYSM_BIN_DIR` to the directory containing `prysmctl`, `beacon-chain`, and `validator`. Then run from the repository root:

```sh
ZIG_GLOBAL_CACHE_DIR=.zig-global-cache zig build -Dpreset=mainnet -Doptimize=ReleaseSafe runtime-fixture p2p-interop-keys
ZIG_GLOBAL_CACHE_DIR=.zig-global-cache zig build -Dpreset=mainnet -Doptimize=ReleaseSafe
GETH_BIN=/path/to/geth PRYSM_BIN_DIR=/path/to/prysm/bin python3 scripts/test_runtime_geth.py
```

The script generates a four-validator Fulu genesis, runs Prysm to produce two signed blocks using Geth A, and seeds the first Hightower node by importing those blocks with `VALID` verdicts from Geth A. A second Hightower node receives the blocks over P2P and requires `VALID` from its own Geth B. The importer sends `forkchoiceUpdatedV3` after validation; the script checks both Beacon heads and both Geth canonical execution heads before and after restarting the second node. It also sends a corrupted payload directly to Geth B and requires an invalid verdict. All data and credentials are disposable and stored in a private temporary directory.

On 2026-11-08 this run converged at slot 2 with consensus root `0xedf464b9590072c542e22f4c3681a7778338ca151fefeef47adc940ebc5a9b94` and execution hash `0xb6eedf49b29cbb1b2c50f3799fa43e1196feafadc66d0a4bed7e6f3a7bc05806`; the target recovered after restart. These hashes vary with the generated genesis time. This is local execution validation on a synthetic Fulu network, not Hoodi interoperability. The mainnet-sized BeaconState currently needs a ReleaseSafe build and the runtime's larger worker stack on macOS.

Run `zig build test-transition`, `zig build test`, and both with `-Doptimize=ReleaseSafe` for the relevant Zig suites. Run `bash scripts/test_runtime.sh` for the read-only runtime smoke check.
