# EVM core fixture coverage

The [EVM fixture bundle](../src/execution/fixtures/evm_core.json) checks 21 published examples against the interpreter: all 17 SSTORE rows in [EIP-3529's reduced-refund table](https://eips.ethereum.org/EIPS/eip-3529#test-cases) and four [EIP-5656 MCOPY examples](https://eips.ethereum.org/EIPS/eip-5656#test-cases). It is run by both `zig build test` and `zig build test-execution` with no network access. The bundle's SHA-256 is `a069f36b21f56df89eb062a80ecf7ef0fe3777ee46f97663d0ea48a9e4dbc8c6`.

EIP-3529's table assumes the storage slot is warm. Each fixture starts a new transaction-scoped machine with a cold slot, so its expected gas adds the one-time 2,100 charge from [EIP-2929](https://eips.ethereum.org/EIPS/eip-2929#sstore-changes). The expected refund and final slot come from the published table. MCOPY vectors use the published pre/post memory images and copy charge; the fixture's total gas also includes the PUSH, MSTORE, memory expansion, and RETURN instructions used to set up and read the image.

The [unit tests](../src/execution/evm/tests.zig) exercise every implemented opcode, stack and depth limits, jumps into PUSH data, signed arithmetic, memory growth, frame rollback, transient isolation, and warm/cold reads. The published fixture bundle adds an independent oracle for storage metering and overlapping memory copies.

The [FULU-062/063 suite](FULU-062-063-EXECUTION-CONFORMANCE.md) now runs selected execution-specs state and London blockchain fixtures through the production transition path and asserts that the selected cases execute every FULU-050/051 opcode byte. This remains selected conformance coverage rather than full client conformance; unsupported precompiles and future-fork cases remain outside this suite.
