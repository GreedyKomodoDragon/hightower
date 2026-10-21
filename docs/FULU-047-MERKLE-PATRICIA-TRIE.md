# FULU-047 Merkle-Patricia trie

## Summary

The execution module now exposes an in-memory Ethereum Merkle-Patricia trie. It supports raw and secure keys, ordered transaction/receipt roots, and inclusion proofs. Each `Trie` owns copies of inserted keys and values; each returned `Proof` owns its encoded nodes and must be deinitialized. Empty values delete their key, matching Ethereum trie semantics. Node storage is rebuilt for each root or proof request; persistence and historical roots are outside this issue.

Secure tries Keccak-hash keys before converting them to nibbles. Ordered transaction and receipt tries use RLP-encoded zero-based indexes as keys through `orderedRoot`. Callers of generic `Trie` supply already encoded values, such as RLP account or storage values.

## Pinned vectors

Both files come from `ethereum/tests` commit [`c67e485`](https://github.com/ethereum/tests/commit/c67e485), under `TrieTests/`.

| Fixture | SHA-256 |
| --- | --- |
| [`trietest.json`](../src/execution/fixtures/trie/trietest.json) | `0ce5e1151210958edf47911b332fe188696d741f9f44b1a471ee62bc666c1f0f` |
| [`trietest_secureTrie.json`](../src/execution/fixtures/trie/trietest_secureTrie.json) | `98b76fd92fed69cb449d7a555cdb3eb397e7179614857de1289de2f63ac8e77a` |

## Acceptance criteria and evidence

| Issue #84 criterion | Implementation evidence | Test evidence |
| --- | --- | --- |
| Known trie root vectors match. | The complete pinned plain and secure `TrieTests` files are embedded in the execution tests. | `zig build test` checks every named case in both files against its expected root. |
| Empty trie, single entry, shared prefixes, and branch splitting are covered. | The builder handles empty roots, compact leaf/extension paths, and branch nodes with prefix values. | Tests check the canonical empty root and a single-entry proof; pinned `insert-middle-leaf`, `branch-value-update`, and `branchingTests` cases exercise prefix changes and branch construction. |
| Proof generation/verification for a leaf works. | `Trie.prove` returns owned nodes from the root to the included leaf; `verifyProof` checks the root and each inline or hashed child reference. | Tests verify a single leaf, a hashed child, and an inline child, and reject a changed proof and incorrect value. |

## Limits

The trie is in-memory and reconstructs nodes when computing roots or proofs. It has no persistent node database, deletion proofs, non-inclusion verification, or historical root retention. Secure-key collisions return `KeyCollision`; practical collision resistance relies on Keccak-256.
