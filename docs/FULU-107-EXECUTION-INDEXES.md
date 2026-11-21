# FULU-107 execution indexes

Execution records use a hash map for retained block hashes. Separate canonical hash, number, and transaction maps follow the selected path; ancestry follows parent hashes through the retained hash map. Reorg and recovery replace canonical indexes, and pruning rebuilds them after record compaction. These maps are derived in memory and do not change the durable format.

The Beacon API keeps the existing segment trie and handles one accepted connection at a time. The router tests cover route selection; the accept loop's serial behavior bounds active API requests at one.

## Benchmark

Run `zig build bench-execution-chain -Doptimize=ReleaseFast`. The benchmark builds 4,096 retained canonical blocks, then mixes block-number, block-hash, canonical-hash, transaction, and ancestry lookups. Each iteration performs four indexed map lookups; ancestry runs once per 100 iterations and returns at most 255 hashes.

Recorded on Apple Silicon with Zig 0.16.0, ReleaseFast: **0.13 μs per mixed lookup iteration** (1,000,000 iterations, 4,000,000 direct lookup checks). This is a local baseline, not a performance guarantee. Lookups are map-backed; hash-table operations remain expected O(1), with ancestry bounded by 255 parent steps.
