# FULU-062/063 execution conformance

The offline `zig build test-execution` suite pins selected fixtures from [execution-spec-tests v5.4.0](https://github.com/ethereum/execution-spec-tests/releases/tag/v5.4.0), commit `88e9fb8`. The `fixtures_stable.tar.gz` source archive has SHA-256 `92cf1b47ad12fb27163261fc3c1cea5df72439cab507983d06b56c94f8741909`. The [manifest](../src/execution/fixtures.zig) records each selected case's source archive path, SHA-256, fork, and expected outcome. `cNN` files contain one named upstream case each; their manifest comments give the exact upstream case key. All files are checked in, so tests make no network requests.

## Block acceptance and commitments

| Case | Oracle | Check |
| --- | --- | --- |
| `chainid_london_blockchain_test_tx_type_0` | Existing v5.4.0 fixture, SHA-256 `934a836ca8a7d203d3e5388f7ea37a3a4a210954ecfb8b5f64b46ba79db57af3` | London block accepted; raw RLP header and transactions, gas, state, transaction and receipt roots, final accounts, and last hash agree. |
| `london_invalid_base_fee` | `fixtures/blockchain_tests/london/validation/test_invalid_header.json`, London case only; SHA-256 `537ef2ebc3f2696a2e99ba838e5f6f17d9c14fba832f4e20839127e4300f9cff` | `BlockException.INVALID_BASEFEE_PER_GAS` maps to `InvalidBaseFee`; parent hash and state root remain intact. |

The valid fixture also drives a focused sequence: two malformed candidate headers are rejected, then the original valid block is accepted from the same parent and pre-state. Mutated oracle tests require malformed hashes, unknown forks, wrong header values, and unknown expected exceptions to fail. The archive contains no files named `blockchain_london_valid_filled.json` or `blockchain_london_invalid_filled.json`; the manifest uses the actual v5.4.0 paths above.

## Executed opcode coverage

The test-only collector records each opcode fetched by the EVM, including nested calls. The suite asserts that successfully executed upstream cases reach every FULU-050/051 opcode byte, plus SHA3: `00`, `01–0b`, `10–1d`, `20`, `50–5e`, `5f–9f`, `a0–a4`, `f3`, and `fd`. PUSH1/PUSH32, DUP1/DUP16, and SWAP1/SWAP16 are included with all intermediate widths. The assertion fails if a selected case stops reaching any of these bytes.

| Edge class | Pinned cases and oracle |
| --- | --- |
| Signed/unsigned arithmetic and shifts | `arithmetic`, `mod`, `smod`, `mulmod`, `signed_shifts`, `c06`, `c11`, `c12` compare complete post-state and logs hashes. |
| Stack faults and limits | `c28–c36` exercise SWAP underflow; `stack_overflow` exercises the 1,024-word limit. |
| Memory, jumps, and return behavior | `memory_oog`, `invalid_jump`, `c13`, `c21`, `c10`, `c23`, `mcopy_empty`, `sha3_dejavu`, `sha3_nonconst_v0`, `sha3_2016_32`, `sha3_neg1_2`, `sha3_nodata`, `mcopy_hash_forward`, `mcopy_hash_backward`, `mcopy_expansion_31`, and the [EIP-5656 MCOPY examples](FULU-050-051-EVM-FIXTURES.md) check SHA3 memory boundaries, out-of-gas expansion, invalid jumps, copying, REVERT, and overlap. |
| Storage and refunds | `c05`, `c07`, `tload_after_store`, `tload_transaction_begin`, `tload_call`, `tload_callcode`, `tload_delegatecall`, `tstore_subcall_revert`, and the [EIP-3529 SSTORE examples](FULU-050-051-EVM-FIXTURES.md) check warm/cold and original/current/dirty paths, capped refunds, transient reads across call contexts, and reverted transient writes. |
| Logs and call frames | `log1`, `log2`, `log4`, `c03`, `c24`, and `c25` compare full state and logs hashes. |

The state processor uses each fixture's raw transaction bytes, explicit Cancun or London fork, selected transaction indexes, sender, complete post-state, state root, and logs hash. Blockchain cases use the production `applyBlock` transition. Mismatches abort the suite.

## Remaining gaps

The suite now passes 93 pinned cases with no named skips; SHA3 and MCOPY cases compare the complete post-state, root, and logs oracle. A v5.4.0 MCOPY out-of-gas case uses a type-1 access-list transaction, which the current state fixture processor does not compare. Transient storage isolation between consecutive transactions remains untested by a selected upstream case. Deep recursive CALL coverage remains untested: the candidate from `stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json` exhausted the host stack during screening. The selected suite does not claim conformance for unsupported precompiles, contract creation, future forks, or every combination of operand values.
