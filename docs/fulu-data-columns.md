# Fulu data columns

`consensus.DataColumns` provides the durable sidecar validation and availability boundary. The caller opens a `Store` with a database directory, genesis validators root, 32-byte discv5 node ID, and a custody group count of at least four. `Store.open` selects the pinned deterministic groups and refuses to reopen the database under a different network or identity. `Store.samples` selects at least eight groups and includes every custody group.

For a known block, call `Store.put(settings, sidecar, block, parent_state)` only after decoding bounded SSZ. It verifies the sidecar index and lengths, block header and proposer signature, commitment list and Merkle branch, and batched cell KZG proofs before retaining a serialized copy. Duplicate columns are rejected. The caller can pass `Store.check` as fork choice's `DataAvailabilityCheck.is_available` callback. A blobless block is immediately available; a blob-carrying block needs every selected column. Fork choice rejects unavailable blocks before changing canonical state.

`Store.get` returns an owned encoded sidecar for a custodied column and known block root; free it with the store allocator. `Store.serveByRoot` accepts at most 128 block identifiers and 16,384 requested columns; `Store.serveByRange` accepts at most 128 slots and a canonical-root callback from one fork-choice view. Both return only verified custodied sidecars. Range results are ordered by slot and column index and skip empty slots. Release response arrays with `Store.freeServed`. Call `Store.prune(current_slot)` as slots advance; a column remains through 4096 epochs after its block slot. Pruning uses durable batches and may leave physical disk reclamation until compaction.

The store persists verified sidecars and its slot index atomically. A restart restores the local availability and serving view without repeating KZG verification; on-disk records are checksummed and bound to the persisted network identity. It still does not fetch missing columns, backfill custody history, cap total retained disk bytes, or transmit peer responses. A fresh or incomplete node must backfill the 4096-epoch window before advertising full custody availability.

The pinned official v1.6.1 minimal fixture `tests/minimal/fulu/fork_choice/on_block/pyspec_tests/on_block_peerdas__ok/column_0xe1e7194a72a2dfd02669d91d83241624b6bd8a454aa0729fc5fd76337e350a5e.ssz_snappy` is copied to `src/consensus/fixtures/fulu_data_columns/valid.ssz_snappy` (SHA-256 `88995d1ab32e7720f0645e9cb1f0177cae1992218f8cf9889b129b209608c2d7`). Its block and anchor state are byte identical to the already pinned `fulu_fork_choice/availability` fixtures. The custody selection test uses the official `get_custody_groups_max_node_id_custody_group_count_is_4` vector.

The eight `sample_*.ssz_snappy` files in that directory are copied from the first block's columns in the same official `on_block_peerdas__ok` fixture. For node ID zero, the selected indices are 1, 17, 19, 42, 75, 87, 102, and 117. SHA-256 checksums:

| File | SHA-256 |
| --- | --- |
| `sample_01` | `7dc813ad668087d439e39ce6f9dfecd4e50e257af09c19ed484d85df0490c907` |
| `sample_17` | `9c5c6fa22a4e67e722cf325ff5148939b8b7222680469eaec83c5adc78835e9d` |
| `sample_19` | `cdfad13461fb5b66c0b2927ec54ed806b7e075bc98b17ae30c258ca831bde00f` |
| `sample_42` | `8b9f9c85f5bef330f4ae7ca48c3b9767d33614c4b2d58d63572004393e98b1d0` |
| `sample_75` | `605a8e3df345234d0969bf7c1b3389cf05d5f0c681d14bc71240645a1b96cb4f` |
| `sample_87` | `d5ee16ef66214a49faed7475901d73e11d0179a790474e3d5c74e237a5679ca4` |
| `sample_102` | `07de8b1484c67184af50134a06e6f84c598fe014cefbe278a67976e724ef599f` |
| `sample_117` | `6fab3fcf2b833e9b7f2c8b8c7b70bafdd087b659c332f795e73b5ad0e1ba2702` |
