# FULU-060 Beacon API router benchmark

Measured locally with Zig 0.16.0, `-O ReleaseFast`, on the repository's
Apple Silicon arm64 macOS target. Each case alternates between two runtime
paths so the compiler cannot reuse a constant lookup result. The benchmark ran
2,000,000 lookups per sample against the previous endpoint-by-endpoint matcher;
reported values are medians of five samples.

| Path | Trie latency | Trie throughput | Linear latency | Linear throughput | Lookup allocations |
| --- | ---: | ---: | ---: | ---: | ---: |
| Known literal paths | 3.67 ns | 272.36 M/s | 15.51 ns | 64.46 M/s | 0 |
| Parameterized paths | 57.90 ns | 17.27 M/s | 52.06 ns | 19.21 M/s | 0 |
| Unknown paths | 31.08 ns | 32.18 M/s | 64.63 ns | 15.47 M/s | 0 |

Run with `zig run src/api/router_bench.zig -O ReleaseFast -- <known-1> <known-2> <parameter-1> <parameter-2> <unknown-1> <unknown-2>`.
These are small local microbenchmarks; timings vary by machine and build. The
exact-route fast path is faster for known literals, parameter routes are close
to the former matcher, and unknown routes are faster. Lookup remains
allocation-free.
