# Hightower roadmap and research guide

Hightower is an experimental Ethereum consensus client in Zig. SSZ and Merkle code are a useful base, but a Beacon node also needs fork-specific data structures, state transition, fork choice, cryptography, networking, persistence, and interfaces to an execution client.

This document is a practical reading order and a set of implementation targets. Protocol status below was checked on **11 October 2026**; fork status and network recommendations can change, so pin the upstream spec and config revision before coding against them.

## Recommendation

**Chosen target: Fulu, initially with the minimal preset.** The preset makes local fixtures and development smaller while exercising Fulu rules. This is a Fulu implementation plan, not a Phase 0 exercise. Pin the exact consensus-specs commit and matching test-vector release before writing protocol code.

Hoodi is a possible later integration network; it is a network choice, not a fork or preset. The upstream index currently lists Fulu as stable and Gloas/Heze as unstable. Recheck that status when updating the pinned revision.

## What is in this repository

- `src/ssz/` supports fixed and variable-size containers, lists, bitlists, and related types. Generated official SSZ cases exist, but unsupported vectors remain.
- `src/merkle/` handles chunking, hash-tree roots, list length mixing, and some progressive types. Its tests run from `zig build test`.
- `src/types/type.zig` contains generic SSZ wrappers; it does not define Beacon protocol types.
- `src/rlp/` implements part of the execution-layer encoding, but has no role in consensus-layer SSZ or the Engine API JSON-RPC boundary.
- There are no Beacon Chain data types, state transition, fork choice, BLS signatures, networking, persistence, Beacon API, or Engine API integration yet.

The README's historical implementation log still mentions old gaps. Use this section and the current source as the project status.

## Pick a target

These are three separate decisions: which fork's rules to implement, which preset supplies constants for tests, and which network to eventually interoperate with.

### Fork targets

| Target | Good for | Cost / limitation | Recommendation |
| --- | --- | --- | --- |
| [Phase 0](https://github.com/ethereum/consensus-specs/tree/master/specs/phase0) | Historical background for how the Beacon Chain began | Not this project's target and not current network compatibility | Read for context only |
| [Fulu](https://github.com/ethereum/consensus-specs/tree/master/specs/fulu) | This project's chosen consensus fork | Includes execution payload validation, blob/KZG and data-availability concerns, and proposer lookahead | **Chosen target** |
| [Gloas](https://github.com/ethereum/consensus-specs/tree/master/specs/gloas) / [Heze](https://github.com/ethereum/consensus-specs/tree/master/specs/heze) | Following work in progress and future protocol changes | Specs and test vectors can change; premature for a first compatibility target | Defer until stable |

Forks build on earlier forks, and each fork specification describes changes to the shared protocol. Read the target fork's files together with the prior fork specs it inherits; don't assume its `beacon-chain.md` is the whole protocol. Fulu is a demanding target: stage it by test suite and transition function, and use a mock execution-engine boundary in unit fixtures before connecting a real execution client.

### Presets and networks

| Choice | What it means | When to use it |
| --- | --- | --- |
| [Minimal preset](https://github.com/ethereum/consensus-specs/tree/master/presets/minimal) | Smaller protocol constants for test fixtures and development. It is not a separate fork or public network. | First implementation and fast conformance tests |
| [Mainnet preset and config](https://github.com/ethereum/consensus-specs/tree/master/presets/mainnet) / [mainnet config](https://github.com/ethereum/consensus-specs/blob/master/configs/mainnet.yaml) | Production-sized constants and mainnet network parameters | After minimal-preset coverage; required before claiming mainnet compatibility |
| [Hoodi](https://ethereum.org/developers/docs/networks/#hoodi) | Public test network recommended for protocol upgrades and validator testing | Later end-to-end interoperability; requires networking and an execution client |
| [Sepolia](https://ethereum.org/developers/docs/networks/#sepolia) | Public test network mainly aimed at application developers | Useful for application testing; less suitable as the first consensus protocol target |

Ethereum.org's [networks guide](https://ethereum.org/developers/docs/networks/) identifies Sepolia and Hoodi as the maintained public testnets and describes Hoodi as the place to test protocol upgrades and validators. That does not imply Hightower can join either network until its fork rules, networking, and execution-client interface are implemented.

## Fulu implementation plan

The pinned Fulu specification and test bundle are recorded in [`docs/FULU-SPEC-LOCK.md`](docs/FULU-SPEC-LOCK.md). Track implementation work in [GitHub Issues](https://github.com/GreedyKomodoDragon/hightower/issues).

The work is ordered so each stage has a concrete pass condition and produces something the following stage can use. Keep Fulu schema support complete while implementing behavior in slices: an incomplete `BeaconState` cannot produce a compatible state root.

### 0. Freeze the target

- Record the consensus-specs commit SHA, matching release test bundle, Fulu fork, and `minimal` preset in a small project note/config.
- Start with reference vectors for the selected fork/preset; don't track moving `master` as the implementation target.
- Write down explicitly unsupported test suites so skipped functionality stays visible.

**Exit:** the exact protocol revision and fixtures defining “Fulu support” are reproducible.

### 1. Establish the conformance harness and type inventory

- Inventory Fulu `BeaconState`, block/body/header, signed block, operation, and fork-choice types against current `src/types`, `src/ssz`, and `src/merkle` support.
- Add a fixture loader for the official test format and run existing SSZ/hash-tree-root suites before adding Beacon code.
- Classify unsupported vectors as required for Fulu state/block, needed later, or outside the initial scope.
- Keep vector files pinned; never mark an unimplemented case as a pass.

**Exit:** a checked-in inventory maps each Fulu field/type to implementation status and fixture coverage.

### 2. Complete required SSZ and hash-tree-root behavior

- Fill gaps identified by the inventory: likely composite collection limits and nested variable-size types; implement compatible unions or progressive forms only if Fulu schemas require them.
- Verify canonical offsets, bounds, trailing-byte rejection, bitlist handling, composite/basic packing, list length mix-in, and full state roots against upstream vectors.
- Defer generalized-index proofs unless a selected test or later feature needs them.

**Exit:** SSZ encode/decode and hash-tree-root vectors pass for the Fulu data types needed next.

### 3. Add the complete Fulu type schema

- Define all fields in Fulu `BeaconState`, `BeaconBlock`, `BeaconBlockBody`, `BeaconBlockHeader`, `SignedBeaconBlock`, and nested records in spec order and with exact list/vector limits.
- Include Fulu's `proposer_lookahead` and inherited Electra fields required by the complete state schema.
- Keep schema types, minimal/mainnet presets, and network fork configuration distinct.
- Decode upstream minimal-preset block and full-state fixtures and compare serialized bytes and roots.

**Exit:** complete Fulu fixtures round-trip and match expected roots, including a full state fixture.

### 4. Implement shared consensus helpers and cryptographic boundaries

- Implement epoch/slot arithmetic, active validator selection, seed calculation, shuffling, proposer and committee selection, fork/domain data, and attestation indexing as required by test dependencies.
- Add BLS12-381 verification behind a small interface and pass official BLS vectors before relying on signatures in block/operation processing.
- Implement Fulu proposer-lookahead calculation and epoch update from the Fulu spec.
- Keep validator private-key storage and signing outside the Beacon-node core for now.

**Exit:** helper, shuffling, proposer, and BLS suites used by later transition tests pass.

### 5. Implement slot and epoch state transition

- Implement slot advancement: per-slot block/state root updates, slot increment, and epoch processing at boundaries.
- Implement inherited epoch processing in spec order, then Fulu proposer-lookahead and pending-deposit/consolidation behavior.
- Start with small minimal-preset cases, then cover empty slots, epoch boundaries, and invalid cases.

**Exit:** Fulu `process_slots` and epoch-processing fixtures produce expected post-state roots across empty slots and epoch boundaries.

### 6. Implement block processing by operation group

Follow the order in Fulu `process_block` and use official operation/state-transition fixtures, implementing one group at a time:

1. Block header, proposer, and signature checks.
2. Withdrawals and execution-payload processing: header consistency, timestamp, `prev_randao`, blob commitment limits, and an execution-engine validity result.
3. RANDAO and `eth1_data` updates.
4. Operations in spec order: proposer slashings, attester slashings, attestations, voluntary exits, BLS-to-execution changes, then execution-request deposits, withdrawals, and consolidations. Fulu removes legacy deposits from Beacon block bodies.
5. Sync aggregate processing.

Use a deterministic execution-engine mock in isolated transition fixtures, then test real Engine API behavior in Step 8. Do not replace required validation with unconditional success in production paths.

**Exit:** selected Fulu block-processing suites pass, including rejected invalid blocks and expected post-state roots.

### 7. Implement Fulu fork choice

- Implement store initialization and time/tick, block, attestation, and required attester-slashing handlers.
- Include Fulu changes such as proposer-lookahead behavior and data-availability checks; test modified handlers against Fulu-specific vectors.
- Cover competing branches, late blocks, unknown parents, and finalization effects.

**Exit:** Fulu fork-choice vectors pass and a local competing-branch scenario selects the expected head.

### 8. Add persistence and the execution-client connection

- Persist blocks, states/checkpoints, and fork-choice data with recovery checks before networking introduces continuous untrusted input.
- Implement the Fulu-required [Engine API](https://github.com/ethereum/execution-apis/tree/main/src/engine) methods and payload-status handling. RLP encoding does not implement this JSON-RPC boundary.
- Test against a local execution client and cover valid, invalid, syncing, and unavailable payload responses.

**Exit:** restart preserves head and state; a local execution client can validate payloads through the required Fulu Engine API flow.

### 9. Add Fulu P2P, sync, and data availability

- Implement discovery and Fulu [P2P](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/p2p-interface.md): gossip topics, request/response, fork digest, block and sidecar retrieval.
- Add peer scoring, message validation, and resource limits before accepting network traffic.
- Implement the Fulu data-availability/PeerDAS path to the scope required by the node's advertised behavior; block gossip alone is not full Fulu support.
- Sync from a trusted checkpoint initially; validate imported blocks through transition and fork choice.

**Exit:** interoperate with other clients on a controlled Fulu setup and recover from disconnect/restart.

### 10. Expose Beacon API and try Hoodi

- Add the smallest useful [Beacon API](https://github.com/ethereum/beacon-APIs): health/sync status, head/finality, and block/state lookup.
- Use Hoodi's actual network configuration and genesis/checkpoint data; don't assume mainnet config or minimal-preset values apply to Hoodi.
- Run multi-client interoperability and sync checks before claiming Hoodi support. Add mainnet constants/config and repeat conformance separately before claiming mainnet support.

**Exit:** Hightower syncs and tracks the correct Fulu head on Hoodi with a paired execution client, and its API agrees with local consensus state.

## Reading order

### Learn the architecture first

1. [Ethereum consensus mechanisms](https://ethereum.org/developers/docs/consensus-mechanisms/) — how proof of stake, finality, and fork choice fit together.
2. [Proof of stake](https://ethereum.org/developers/docs/consensus-mechanisms/pos/) — slots, epochs, validators, and the duties the consensus client supports.
3. [Node architecture](https://ethereum.org/developers/docs/nodes-and-clients/node-architecture/) and [nodes and clients](https://ethereum.org/developers/docs/nodes-and-clients/) — division of work between consensus and execution clients.
4. [Block proposal](https://ethereum.org/developers/docs/consensus-mechanisms/pos/block-proposal/) and [attestations](https://ethereum.org/developers/docs/consensus-mechanisms/pos/attestations/) — the main Beacon block and voting flows.
5. [Rewards and penalties](https://ethereum.org/developers/docs/consensus-mechanisms/pos/rewards-and-penalties/) — useful once epoch processing and validator accounting are in scope.

## Concepts to keep straight

- **SSZ serialization** turns a typed value into bytes; **hash-tree-root** commits to a typed value. Both use schema details such as field order and list limits.
- **State transition** checks a block against a pre-state and computes the post-state. A valid transition does not by itself choose the chain head.
- **Fork choice** weighs valid blocks and attestations to select the head. It consumes state/block data and time events.
- **Fork** means a protocol upgrade such as Fulu. **Preset** means a set of constants such as minimal or mainnet. **Network** means a deployment such as Hoodi or mainnet.
- **Consensus client** handles Beacon consensus. **Execution client** executes transactions and validates execution payloads. The Engine API connects those clients; RLP is not that API.
- **Beacon node** serves consensus data and networking. A **validator client** holds validator keys and signs duties; keep validator key management out of the first Beacon-node milestone.

## Suggested checkpoints

1. **Can root a Fulu block:** decode an upstream minimal-preset block and match its SSZ bytes and root.
2. **Can root a Fulu state:** decode a complete upstream state fixture and match its hash-tree-root.
3. **Can advance empty slots:** pass `process_slots` and epoch-processing fixtures, including epoch boundaries.
4. **Can process a block locally:** pass block transition fixtures with signatures or execution checks stubbed only where the fixture explicitly permits it.
5. **Can choose a head:** pass fork-choice fixtures with competing branches and attestations.
6. **Can connect clients:** exchange fork-appropriate Engine API calls with an execution client.
7. **Can join Hoodi:** add P2P, sync, storage, Beacon API, correct network config, and cross-client validation.

Each checkpoint should have a runnable command and should identify its fork and preset. Avoid a single green test target that silently treats unsupported spec cases as success.

### Then use the normative specifications

1. [Consensus specs index](https://github.com/ethereum/consensus-specs) — fork status, rendered spec links, and reference tests.
2. [Fulu Beacon Chain spec](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/beacon-chain.md) — types, constants, state transition, and block processing.
3. [Fulu fork choice](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/fork-choice.md) — store and event handlers.
4. [Fulu fork logic](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/fork.md) — state upgrade and fork activation behavior.
5. [Fulu P2P interface](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/p2p-interface.md) — gossip and request/response protocol after the local core.
6. [SSZ specification](https://ethereum.github.io/consensus-specs/ssz/simple-serialize/) — serialization and hash-tree-root rules.
7. [Consensus-spec test format](https://github.com/ethereum/consensus-specs/blob/master/tests/formats/README.md) — how test directories encode fork, preset, runner, and expected outputs.

### Finally, wire the client boundaries

- [Networking layer overview](https://ethereum.org/developers/docs/networking-layer/) — execution and consensus networking stacks.
- [Beacon API repository](https://github.com/ethereum/beacon-APIs) — REST API exposed by Beacon nodes.
- [Engine API](https://github.com/ethereum/execution-apis/tree/main/src/engine) — consensus/execution client communication.
- [Run a node](https://ethereum.org/developers/docs/nodes-and-clients/run-a-node/) — operational view of running both client types and testnet nodes.
- [Ethereum networks](https://ethereum.org/developers/docs/networks/) — current network choices and their intended use.

## References and status checks

- [Consensus specs repository](https://github.com/ethereum/consensus-specs) — source of truth for stable and unstable fork labels; check before choosing a target.
- [Mainnet consensus config](https://github.com/ethereum/consensus-specs/blob/master/configs/mainnet.yaml) — network fork versions and activation epochs.
- [Hoodi network guide](https://ethereum.org/developers/docs/networks/#hoodi) — current testnet role and caveats.
- [Ethereum consensus clients](https://ethereum.org/developers/docs/nodes-and-clients/) — useful for comparing real implementations when a behavior in the specs is unclear.

When an upstream link uses `master`, resolve it to a commit SHA for any implementation work and store that SHA in the project. The links are convenient reading entry points; the pinned revision is the actual target.
