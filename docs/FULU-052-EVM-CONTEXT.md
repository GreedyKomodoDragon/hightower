# FULU-052 EVM transaction context

The public [`evm.zig`](../src/execution/evm.zig) entry point re-exports the [machine](../src/execution/evm/machine.zig); its [unit tests](../src/execution/evm/tests.zig) live beside it.

`evm.Machine` owns one transaction's warm addresses and slots, original slot values, transient storage, refund counter, and logs. `configure` supplies the block and transaction environment plus access-list prewarming before the first frame. Each nested frame checkpoints state, logs, transient writes, refund changes, and newly warmed accesses. `emittedLogs` borrows the machine's committed logs for later receipt construction; `cappedRefund(gas_used)` applies the EIP-3529 one-fifth limit after execution.

Block hashes in `Environment.block_hashes` are newest first: element zero is the parent block. An in-window hash absent from the supplied history faults with `missing_context`; out-of-window queries return zero. Calls to reserved precompile addresses 1–17 fault with `unsupported_precompile` until FULU-053 implements them. Transaction fees and receipt assembly remain in FULU-055.

The EVM tests cover context opcodes, copy and return-data bounds, EIP-2929 access-list and warm/cold charges, EIP-150 forwarding and value stipend, all call modes and depth failure, log topics and rollback, static writes, nested value transfer, and capped refunds. The pinned [EIP-3529 storage vectors](FULU-050-051-EVM-FIXTURES.md) run under both `zig build test` and `zig build test-execution`.
