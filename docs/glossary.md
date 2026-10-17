# Ethereum Consensus Glossary

## What a block can contain

A Fulu consensus block has header information plus a body with validator, execution, and data-availability information:

```text
BeaconBlock
├── slot                 when it belongs in the chain
├── proposer_index       which validator proposed it
├── parent_root          reference to the previous block
├── state_root           commitment to the resulting consensus state
└── body
    ├── randao_reveal, eth1_data, graffiti
    ├── proposer/attester slashings
    ├── attestations, deposits, voluntary exits
    ├── sync aggregate
    ├── execution payload (transactions and execution data)
    ├── BLS-to-execution address changes
    ├── blob KZG commitments
    └── execution requests (deposits, withdrawals, consolidations)
```

This is a simplified view of the fields. Some lists can be empty, and the block's signature wraps the block message.

## Slots and missed blocks

Slots continue on a fixed schedule. A selected proposer may miss its slot; no block is added for that slot, and the next slot still begins on time with its own proposer.

```text
Time ───────────────────────────────────────────────────────▶

Slot:       0                 1                 2
Proposer:   Validator A       Validator B       Validator C
Result:     Block added       Missed slot       Block added
Chain:      [Block 0] ─────────────────────────▶ [Block 2]
```

| Term | Plain-language definition |
| --- | --- |
| Beacon chain | Ethereum's proof-of-stake consensus system, which tracks validators and agrees on the chain's history. |
| Bellatrix | An earlier Ethereum consensus upgrade whose inactivity penalty setting Fulu still uses. |
| Slot | A short time interval in which Ethereum may add a block. |
| Epoch | A group of slots. At an epoch boundary, the consensus system updates rewards, validator status, and other shared state. |
| Minimal preset | A small configuration used for tests. It uses fewer slots and validators than the regular network configuration. |
| Validator | A participant that helps Ethereum agree on blocks and receives rewards or penalties for its actions. |
| Beacon committee | A group of active validators assigned to attest during a particular slot. |
| Seed | A value derived from an epoch and shared randomness to select validator duties consistently. |
| Shuffle | The deterministic rearrangement of active validators used when assigning duties. |
| Checkpoint | A block reference at an epoch boundary, used when deciding which chain history is justified or finalized. |
| Fork choice | The rule a node uses to select one chain head when multiple valid branches exist. |
| Proposer boost | Temporary extra weight given to the first timely block seen in a slot, helping nodes converge on the same head. |
| Unrealized checkpoint | A justified or finalized checkpoint inferred from a block's state before that checkpoint has been processed at an epoch boundary. |
| Justification | A checkpoint gaining enough validator support to be treated as a strong candidate for finalization. |
| Finality | The point at which a checkpoint is considered settled and very difficult to reverse. |
| Participation flags | Per-validator markers recording whether the validator made required contributions during an epoch. |
| Inactivity score | A counter that increases when a validator misses important participation and affects its penalties. |
| Finality leak | A period when the chain has failed to finalize for long enough; validators that do not help restore finality receive stronger penalties. |
| Effective balance | The rounded and capped balance used to calculate a validator's influence and rewards. |
| Validator registry | The list of validators and their activation, exit, and withdrawal information. |
| Churn limit | The maximum amount of validator balance that may enter or leave active service in an epoch. |
| Deposit queue | Deposits waiting to be applied to validator balances and status. |
| Consolidation | Moving eligible balance from one validator to another under Ethereum's consolidation rules. |
| Consolidation queue | Consolidation requests waiting until their source validators can be processed. Requests are handled in order. |
| Slashing | A penalty for a validator's provably conflicting behavior, which can also affect its withdrawal and rewards. |
| RANDAO mix | A value updated by validator contributions and used as input when selecting validators for future duties. |
| Historical summary | A compact record that commits to older block and state history. |
| Sync committee | A group of validators selected to help light clients verify the recent chain. |
| Proposer lookahead | The planned sequence of validators expected to propose blocks in upcoming slots. |
| SSZ | Ethereum consensus's encoding and hashing format for structured data. |
| Signing domain | A 32-byte value that binds a signature to an operation type, network, and selected fork version. |
| Signing root | The SSZ hash of an object's root together with its signing domain; this is the message verified by consensus BLS signatures. |
| Fork version | Four bytes identifying a network's consensus rules at a particular upgrade. |
| Genesis validators root | The SSZ root of the initial validator registry, used to distinguish chains in signing domains. |
| ForkData | The SSZ container pairing a fork version with the genesis validators root. |
| SigningData | The SSZ container pairing an object root with a signing domain. |
| BLS12-381 | The elliptic-curve signature system Ethereum validators use, allowing signatures from multiple validators to be combined. |
| G1 and G2 | The two elliptic-curve groups used for Ethereum BLS public keys and signatures, respectively. |
| Subgroup check | A check that a decoded curve point belongs to the prime-order group required by the signature scheme. |
| Point at infinity | The identity element of an elliptic-curve group; Ethereum uses its signature encoding for an empty sync aggregate. |
| Proof of possession | A signature showing that a registrant controls the secret key corresponding to a public key, required before that key participates in fast aggregate verification. |
| Capella | The consensus upgrade that enabled withdrawals and whose fork version is retained for voluntary-exit signatures. |
| Deneb | The consensus upgrade that fixed voluntary-exit signing domains to the Capella version. |
| Voluntary exit | A signed request by a validator to stop participating in consensus. |
| BLS-to-execution change | A signed operation that replaces BLS withdrawal credentials with an execution-layer withdrawal address. |
