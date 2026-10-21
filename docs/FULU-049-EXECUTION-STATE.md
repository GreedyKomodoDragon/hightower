# FULU-049 Execution state

The execution state module keeps accounts, per-account storage, and immutable code bytes in memory. `State.stateRoot()` rebuilds the secure account trie from each account's RLP fields in consensus order: nonce, balance, storage root, and code hash.

Storage slot keys are 32-byte big-endian words and are Keccak-hashed by the secure storage trie. Nonzero values are RLP-encoded integers; writing zero removes the slot. Code is stored by Keccak-256 hash. The empty code hash and empty storage root use Ethereum's canonical constants.

An absent account returns `null` from `getAccount`; nonce and balance return zero, storage reads return zero, and code reads return empty bytes. Explicit account deletion removes its storage from the state commitment. Empty-account clearing remains fork-specific and is left to block processing.

Snapshots are nested and must be committed or reverted in LIFO order. Mutations made with an active snapshot retain prior account values in the journal; reverting restores them, while committing the outermost snapshot discards the journal. Code bytes are content-addressed and retained until `State.deinit`, including when an account is deleted.

This is an in-memory execution model without persistent trie nodes or pruning. Account lookup is linear, and journal records copy an account's storage slots; indexed maps and slot-level undo are deferred until profiling justifies them.
