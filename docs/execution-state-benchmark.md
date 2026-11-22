# Execution state root cache benchmark

Run with:

```sh
zig build bench-execution-state -Doptimize=ReleaseFast
```

The benchmark imports 32 linked Shanghai blocks containing one withdrawal each, against a state with 512 accounts and 256 storage slots. It prepares a separate parent-state clone for each baseline import before timing; those clones have empty derived tries. The incremental path imports the same blocks into one live state. Both timed paths run header validation, block transitions, withdrawal crediting, and commitment checks; clone setup is outside both timings, and transaction execution is excluded because these blocks have no transactions.

Recorded on 2026-11-22 with Zig 0.16.0, macOS 15.5, arm64. Timings vary between runs; trie node counts are deterministic for this workload:

```text
512 account block imports (256 storage slots, 32 blocks)
full rebuild: 10.44 ms/block, 22080 trie nodes built
incremental: 0.52 ms/block, 814 trie nodes built
```
