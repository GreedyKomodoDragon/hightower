// Transaction fixtures check canonical envelopes. State fixtures select one
// fork and transaction index, then compare account fields, the state trie root,
// and the hash of ordered EVM logs. Invalid transactions leave pre-state intact.
//
// JSON -> selected transaction -> state transition -> oracle fields
// Blockchain fixtures apply ordered London blocks; a rejected block leaves the
// parent and its state in place for the next block. This runner supports London
// blocks with empty ommers and legacy transactions, and London/Cancun state cases.
// genesis -> accepted block -> rejected block (rollback) -> accepted block
const std = @import("std");
const execution = @import("execution");
const rlp = @import("rlp").decode;

const Format = enum { transaction, state, blockchain };
const Outcome = enum { valid, InvalidLength, NonCanonicalInteger, invalid_transaction, skip };

const Fixture = struct {
    name: []const u8,
    format: []const u8,
    fork: []const u8,
    expected: ?Outcome,
    skip_reason: ?[]const u8 = null,
    checksum: []const u8,
    bytes: []const u8,
};

const fixtures = [_]Fixture{
    .{ .name = "accessListStorage32Bytes", .format = "transaction", .fork = "Cancun", .expected = .valid, .checksum = "02650cf49ea0034cf882a32e4ffcbb45b96ee5fd1e38d5c11e31f0f247ce966e", .bytes = @embedFile("fixtures/accessListStorage32Bytes.json") },
    .{ .name = "AddressLessThan20", .format = "transaction", .fork = "Cancun", .expected = .InvalidLength, .checksum = "73e22320caea3169610f13b3abbfdc1240010b5d219877fbfe14826cc7113e7f", .bytes = @embedFile("fixtures/AddressLessThan20.json") },
    .{ .name = "maxFeePerGas00prefix", .format = "transaction", .fork = "Cancun", .expected = .NonCanonicalInteger, .checksum = "20389c8758b06db2509b4b854657cabe97b839bdff37e53e102b4118a65baaa6", .bytes = @embedFile("fixtures/maxFeePerGas00prefix.json") },
    .{ .name = "tx_simple_type_0_shanghai", .format = "transaction", .fork = "Shanghai", .expected = .valid, .checksum = "57c9c3cd9086ea34f82befd3f88013cef7829d975450ae35055493001269e068", .bytes = @embedFile("fixtures/tx_simple_type_0_shanghai.json") },
    .{ .name = "chainid_cancun_state_test_tx_type_0", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "adbab28513ccf33a4e0c2bc79b19ebf341f93a64d75238d95cb4f6c8b9ce55a6", .bytes = @embedFile("fixtures/chainid_cancun_state_test_tx_type_0.json") },
    .{ .name = "invalidTr", .format = "state", .fork = "Cancun", .expected = .invalid_transaction, .checksum = "2bce278411aaba2b37a18ee6ed04ae0925ece8e0326358edb0eba5b4157e2264", .bytes = @embedFile("fixtures/invalidTr.json") },
    .{ .name = "tload_after_store", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "22e07acc51344815b19410422cd26f3d65d3a23e15072f251476d68b4ffc3b25", .bytes = @embedFile("fixtures/tload_after_store.json") }, // fixtures/state_tests/cancun/eip1153_tstore/test_basic_tload_after_store.json
    .{ .name = "mcopy_empty", .format = "state", .fork = "Cancun", .expected = .skip, .skip_reason = "case executes SHA3 (0x20), which is not implemented", .checksum = "b9621cb125c4dffbfd287ba7286a078649f425da1b77fe1fccac25d3b0f1f3e1", .bytes = @embedFile("fixtures/mcopy_empty.json") }, // fixtures/state_tests/cancun/eip5656_mcopy/test_mcopy_on_empty_memory.json
    .{ .name = "signed_shifts", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "2e973b7e3c785bd995ff664c34d2e60fec263f2d0cc76f00e100e308cc1252a7", .bytes = @embedFile("fixtures/signed_shifts.json") }, // fixtures/state_tests/static/state_tests/stShift/shiftSignedCombinations.json
    .{ .name = "arithmetic", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "a5ad23fca72bbfa862407044ba7f4166c956b8851fb61e114ed3668fd4fea6c8", .bytes = @embedFile("fixtures/arithmetic.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmArithmeticTest/arith.json
    .{ .name = "mod", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "f3f0f69b8fbafc409a73888ded4b3d7495546d00af8b6fd209b1909e1c407a4e", .bytes = @embedFile("fixtures/mod.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmArithmeticTest/mod.json
    .{ .name = "smod", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "eb87584b20449ba1e821d183ae550f398369931ba0059472337fa0c0ff15795d", .bytes = @embedFile("fixtures/smod.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmArithmeticTest/smod.json
    .{ .name = "mulmod", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "b79b2c3d203e73c42a62f181ef0b0e6e36ec9cb21dd5e8f98350a6258ec03f89", .bytes = @embedFile("fixtures/mulmod.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmArithmeticTest/mulmod.json
    .{ .name = "log1", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "f3f3ff1f9af7bfa562155a0b8c81d7e90364c3d7ae4ea0b4aa1ee9c1800614c0", .bytes = @embedFile("fixtures/log1.json") }, // fixtures/state_tests/static/state_tests/stMemoryTest/log1_dejavu.json
    .{ .name = "log2", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "93ad24ce8d1428c6515d82b83ea3cb448d3ba3b2e5daddbd8d73efd86e993652", .bytes = @embedFile("fixtures/log2.json") }, // fixtures/state_tests/static/state_tests/stMemoryTest/log2_dejavu.json
    .{ .name = "log4", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "d7332e04b1d696945744b4772bdcd3e7b2f4aa6a191120b58845122ce904a847", .bytes = @embedFile("fixtures/log4.json") }, // fixtures/state_tests/static/state_tests/stLogTests/log4_emptyMem.json
    .{ .name = "push0", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "7a7a24b81f763eeb9dea5c21417e0b100a2e12490e487ad7cf52f7ce572bba54", .bytes = @embedFile("fixtures/push0.json") }, // fixtures/state_tests/shanghai/eip3855_push0/test_push0_contracts.json
    .{ .name = "stack_overflow", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "d78c1a4fd57e665f5abe23a9397da7ed4d168bbc84db182b02015e081388ba5c", .bytes = @embedFile("fixtures/stack_overflow.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_overflow.json
    .{ .name = "invalid_jump", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "5a46ab4ae897ea9652ddbf5c03524bd3b546e0c03bd309a9639c7e50df803c05", .bytes = @embedFile("fixtures/invalid_jump.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmIOandFlowOperations/jumpToPush.json
    .{ .name = "memory_oog", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "75b6276188c8a0953481b64c52808d5f86e2b7da456d8b9fa46f7effe20f93b7", .bytes = @embedFile("fixtures/memory_oog.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmIOandFlowOperations/mload.json
    .{ .name = "chainid_london_blockchain_test_tx_type_0", .format = "blockchain", .fork = "London", .expected = .valid, .checksum = "934a836ca8a7d203d3e5388f7ea37a3a4a210954ecfb8b5f64b46ba79db57af3", .bytes = @embedFile("fixtures/chainid_london_blockchain_test_tx_type_0.json") },
    .{ .name = "london_invalid_base_fee", .format = "blockchain", .fork = "London", .expected = .valid, .checksum = "537ef2ebc3f2696a2e99ba838e5f6f17d9c14fba832f4e20839127e4300f9cff", .bytes = @embedFile("fixtures/london_invalid_base_fee.json") }, // fixtures/blockchain_tests/london/validation/test_invalid_header.json
    .{ .name = "c00", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "b8cc11633bebdcd9841f160e58a251b043fb5ae78d4a149cad78d50e364a7a1f", .bytes = @embedFile("fixtures/candidates/c00.json") }, // fixtures/state_tests/static/state_tests/stSolidityTest/TestOverflow.json :: tests/static/state_tests/stSolidityTest/TestOverflowFiller.json::TestOverflow[fork_Cancun-state_test-]
    .{ .name = "c01", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "330c04a2823372bf660e158afd93b31efab598916e0912ed5ddd5453bfdd3602", .bytes = @embedFile("fixtures/candidates/c01.json") }, // fixtures/state_tests/static/state_tests/Shanghai/stEIP3651_warmcoinbase/coinbaseWarmAccountCallGas.json :: tests/static/state_tests/Shanghai/stEIP3651_warmcoinbase/coinbaseWarmAccountCallGasFiller.yml::coinbaseWarmAccountCallGas[fork_Cancun-state_test-d0]
    .{ .name = "c02", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "d9f5f7fb283010b69c15bdf555bb6fcbdfa01af1940f998871cc7fd6f768d5a3", .bytes = @embedFile("fixtures/candidates/c02.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmTests/envInfo.json :: tests/static/state_tests/VMTests/vmTests/envInfoFiller.yml::envInfo[fork_Cancun-state_test-address]
    .{ .name = "c03", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "2dd370aece518a170359b41be7bdbde07cd72c136a55804f2369184a8690edb3", .bytes = @embedFile("fixtures/candidates/c03.json") }, // fixtures/state_tests/static/state_tests/stStaticCall/static_log_Caller.json :: tests/static/state_tests/stStaticCall/static_log_CallerFiller.json::static_log_Caller[fork_Cancun-state_test-d0]
    .{ .name = "c05", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "65cdf24c4a3daac63afd9075bd8f835b09d2a1d543a4eaaaa681aa20bd8eefc0", .bytes = @embedFile("fixtures/candidates/c05.json") }, // fixtures/state_tests/static/state_tests/stSStoreTest/sstoreGas.json :: tests/static/state_tests/stSStoreTest/sstoreGasFiller.yml::sstoreGas[fork_Cancun-state_test-]
    .{ .name = "c06", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "e8802e6285035938c759990fbd0cc3e7572e8b5a8ac0f7b2a3050f0cbae0bf6c", .bytes = @embedFile("fixtures/candidates/c06.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmArithmeticTest/divByZero.json :: tests/static/state_tests/VMTests/vmArithmeticTest/divByZeroFiller.yml::divByZero[fork_Cancun-state_test-addmod_0_0_0-2]
    .{ .name = "c07", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "c7bd130370f5df64d92fdbb54a4d3b011df54a7149a710f99181d2aa42aacba9", .bytes = @embedFile("fixtures/candidates/c07.json") }, // fixtures/state_tests/cancun/eip1153_tstore/test_tload_after_tstore_is_zero.json :: tests/cancun/eip1153_tstore/test_tstorage.py::test_tload_after_tstore_is_zero[fork_Cancun-state_test]
    .{ .name = "c08", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "66089cc994e8ee0a216bcd2272ba92bd86ac9bde199519d26a14534bbd7b43c6", .bytes = @embedFile("fixtures/candidates/c08.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmTests/blockInfo.json :: tests/static/state_tests/VMTests/vmTests/blockInfoFiller.yml::blockInfo[fork_Cancun-state_test-coinbase]
    .{ .name = "c10", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "0dd8c4ed79996f1373597883dc770c92ba77b98aca9d600b9ae48cba7a64a111", .bytes = @embedFile("fixtures/candidates/c10.json") }, // fixtures/state_tests/static/state_tests/stRevertTest/RevertOpcodeReturn.json :: tests/static/state_tests/stRevertTest/RevertOpcodeReturnFiller.json::RevertOpcodeReturn[fork_Cancun-state_test-d0-g0]
    .{ .name = "c11", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "f09d20d2c2ccf24199d99176eff14f4ee20e9f2e1051cf9b21c0a1403476d434", .bytes = @embedFile("fixtures/candidates/c11.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmBitwiseLogicOperation/byte.json :: tests/static/state_tests/VMTests/vmBitwiseLogicOperation/byteFiller.yml::byte[fork_Cancun-state_test-byte_00_big]
    .{ .name = "c12", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "9e951d8b0779a0ab1310447f5f0a6c479fea0813d38ae36a912ec090754fd1f0", .bytes = @embedFile("fixtures/candidates/c12.json") }, // fixtures/state_tests/static/state_tests/VMTests/vmArithmeticTest/signextend.json :: tests/static/state_tests/VMTests/vmArithmeticTest/signextendFiller.yml::signextend[fork_Cancun-state_test-bit_is_not_set]
    .{ .name = "c13", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "6911480e51cf30f3ce5840f530f8d272bdc76ad5d061818fdf284fbc34f8b4b5", .bytes = @embedFile("fixtures/candidates/c13.json") }, // fixtures/state_tests/static/state_tests/stMemoryTest/memReturn.json :: tests/static/state_tests/stMemoryTest/memReturnFiller.json::memReturn[fork_Cancun-state_test-]
    .{ .name = "c15", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "feed8ff5f2f857c3723e82738531b134c0cbd9d4aacf16e1c249d5959c64abb5", .bytes = @embedFile("fixtures/candidates/c15.json") }, // fixtures/state_tests/static/state_tests/stSolidityTest/TestKeywords.json :: tests/static/state_tests/stSolidityTest/TestKeywordsFiller.json::TestKeywords[fork_Cancun-state_test-]
    .{ .name = "c16", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "e4f52085b615ecb590d0f348d16a88885b85ec79b46d7c8a96965d2838a165f4", .bytes = @embedFile("fixtures/candidates/c16.json") }, // fixtures/state_tests/static/state_tests/stBadOpcode/eip2315NotRemoved.json :: tests/static/state_tests/stBadOpcode/eip2315NotRemovedFiller.json::eip2315NotRemoved[fork_Cancun-state_test-]
    .{ .name = "c17", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "ff64f9442e1f837e63221ce59019122d49ed63ea19d6d1b5c205bcb0be5fc3c6", .bytes = @embedFile("fixtures/candidates/c17.json") }, // fixtures/state_tests/static/state_tests/stChainId/chainId.json :: tests/static/state_tests/stChainId/chainIdFiller.json::chainId[fork_Cancun-state_test-]
    .{ .name = "c18", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "da00311182f0d49653eeeb3d0ac26a0f3b34268d63a4f24e41061b1d3fbe5509", .bytes = @embedFile("fixtures/candidates/c18.json") }, // fixtures/state_tests/static/state_tests/stShift/sar11.json :: tests/static/state_tests/stShift/sar11Filler.json::sar11[fork_Cancun-state_test-]
    .{ .name = "c19", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "9528f897a74829931edfd700db40fdd83df7ebb265e73695fed136e60bb65f17", .bytes = @embedFile("fixtures/candidates/c19.json") }, // fixtures/state_tests/static/state_tests/stSelfBalance/selfBalance.json :: tests/static/state_tests/stSelfBalance/selfBalanceFiller.json::selfBalance[fork_Cancun-state_test-]
    .{ .name = "c20", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "532bb21829b1929b4f5a8aa5bf2db604f6fe27d3dc7d25874105755b3e55a6d9", .bytes = @embedFile("fixtures/candidates/c20.json") }, // fixtures/state_tests/static/state_tests/stSystemOperationsTest/balanceInputAddressTooBig.json :: tests/static/state_tests/stSystemOperationsTest/balanceInputAddressTooBigFiller.json::balanceInputAddressTooBig[fork_Cancun-state_test-]
    .{ .name = "c21", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "a678b3863adc12de89e15df955a6dd34b4ebc47c2b1eb5c1f733241f433ae047", .bytes = @embedFile("fixtures/candidates/c21.json") }, // fixtures/state_tests/static/state_tests/stReturnDataTest/returndatacopy_initial.json :: tests/static/state_tests/stReturnDataTest/returndatacopy_initialFiller.json::returndatacopy_initial[fork_Cancun-state_test-]
    .{ .name = "c23", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "c13bc61757c692e469938d52870bb0555bd1530c60b43f757ab5982e132525ee", .bytes = @embedFile("fixtures/candidates/c23.json") }, // fixtures/state_tests/static/state_tests/stStaticCall/static_callcode_checkPC.json :: tests/static/state_tests/stStaticCall/static_callcode_checkPCFiller.json::static_callcode_checkPC[fork_Cancun-state_test-]
    .{ .name = "c24", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "ddb8c3746aebcc5e11429ee33dc48eac73ac048f2e793d91032218b57e246fae", .bytes = @embedFile("fixtures/candidates/c24.json") }, // fixtures/state_tests/static/state_tests/stLogTests/log3_Caller.json :: tests/static/state_tests/stLogTests/log3_CallerFiller.json::log3_Caller[fork_Cancun-state_test-]
    .{ .name = "c25", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "319aa213196fd4f7fbd621eca8e6682c78b417f5c2a11ff603d2c151b1ab4dbf", .bytes = @embedFile("fixtures/candidates/c25.json") }, // fixtures/state_tests/static/state_tests/stStaticCall/static_makeMoney.json :: tests/static/state_tests/stStaticCall/static_makeMoneyFiller.json::static_makeMoney[fork_Cancun-state_test-]
    .{ .name = "c26", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "82012108c2a0d8bec79eb7ccf28f9d30c5f728cea25156bee9a9e0919a735a3e", .bytes = @embedFile("fixtures/candidates/c26.json") }, // fixtures/state_tests/static/state_tests/stArgsZeroOneBalance/sgtNonConst.json :: tests/static/state_tests/stArgsZeroOneBalance/sgtNonConstFiller.yml::sgtNonConst[fork_Cancun-state_test--v0]
    .{ .name = "c27", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "68bb409f35730d1c7c1becdac9223d3010f4e1228feae17b493c875b2696224f", .bytes = @embedFile("fixtures/candidates/c27.json") }, // fixtures/state_tests/static/state_tests/stArgsZeroOneBalance/xorNonConst.json :: tests/static/state_tests/stArgsZeroOneBalance/xorNonConstFiller.yml::xorNonConst[fork_Cancun-state_test--v0]
    .{ .name = "c28", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "4504e6f5f38c3af8a9aa886639748bbd2a759e83cacf52da393796eea6df4c1d", .bytes = @embedFile("fixtures/candidates/c28.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP10]
    .{ .name = "c29", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "4fe6c5106d6202e3fab351f0d3ad54112ceb61877e25efe33064620299ef1d0f", .bytes = @embedFile("fixtures/candidates/c29.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP11]
    .{ .name = "c30", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "46ac018aaae227a8b1b3285362a02a2b495050185f858878875c8b3769ad3485", .bytes = @embedFile("fixtures/candidates/c30.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP12]
    .{ .name = "c31", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "40eaa9a37f411ccfdc8fdfde195c605e7a53ec18d2cf1d42eafdde0c23771664", .bytes = @embedFile("fixtures/candidates/c31.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP13]
    .{ .name = "c32", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "c1663af2cc469980cbcf0c4122050a441d1a9843af28a1d48a2a20fb02061522", .bytes = @embedFile("fixtures/candidates/c32.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP14]
    .{ .name = "c33", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "e4d38df284597eaf472ce712a9ffc2bd8460757243af45b0e3d09f15e333c5e6", .bytes = @embedFile("fixtures/candidates/c33.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP15]
    .{ .name = "c34", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "efb2e9e907d52db2d3da3c5f77d0f0baa085fa5977566a372f0d99ab9e757c21", .bytes = @embedFile("fixtures/candidates/c34.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP16]
    .{ .name = "c35", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "6e5dce7c0aa6836ca853ed459ca8bd21e584081b69fdd5298b53b853f2ae8e26", .bytes = @embedFile("fixtures/candidates/c35.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP8]
    .{ .name = "c36", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "125ab4d5c6f271b059c7b6d7f0cbe5e04b1b62bbc16affaaec948e069c42d2fe", .bytes = @embedFile("fixtures/candidates/c36.json") }, // fixtures/state_tests/frontier/opcodes/test_stack_underflow.json :: tests/frontier/opcodes/test_swap.py::test_stack_underflow[fork_Cancun-state_test-SWAP9]
    .{ .name = "c37", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "b96fe9730e496d984077b566db5218a65e7ff63b81d967cae847793d933d0fd0", .bytes = @embedFile("fixtures/candidates/c37.json") }, // fixtures/state_tests/frontier/opcodes/test_dup.json :: tests/frontier/opcodes/test_dup.py::test_dup[fork_Cancun-evm_code_type_LEGACY-state_test-DUP11]
    .{ .name = "c38", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "6c866f02b96a97aa6c41064bcbb36c7da23463bb5288ac77a7bf3ca8575afe11", .bytes = @embedFile("fixtures/candidates/c38.json") }, // fixtures/state_tests/frontier/opcodes/test_dup.json :: tests/frontier/opcodes/test_dup.py::test_dup[fork_Cancun-evm_code_type_LEGACY-state_test-DUP12]
    .{ .name = "c39", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "a50061b98268864582aa6a1bb9c99a825ce539cbf50a5472f84098b618d460a1", .bytes = @embedFile("fixtures/candidates/c39.json") }, // fixtures/state_tests/frontier/opcodes/test_dup.json :: tests/frontier/opcodes/test_dup.py::test_dup[fork_Cancun-evm_code_type_LEGACY-state_test-DUP13]
    .{ .name = "c40", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "27a6704fae26dd05b704c048d92b85e3f423c75ebc1af10530760d23c7e446ae", .bytes = @embedFile("fixtures/candidates/c40.json") }, // fixtures/state_tests/frontier/opcodes/test_dup.json :: tests/frontier/opcodes/test_dup.py::test_dup[fork_Cancun-evm_code_type_LEGACY-state_test-DUP14]
    .{ .name = "c41", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "83e76a36ede2d8e4fec634c8d2e826707a3d482db3415602aab457ddbfef60ec", .bytes = @embedFile("fixtures/candidates/c41.json") }, // fixtures/state_tests/frontier/opcodes/test_dup.json :: tests/frontier/opcodes/test_dup.py::test_dup[fork_Cancun-evm_code_type_LEGACY-state_test-DUP15]
    .{ .name = "c42", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "e0800da2d469d4ac81e81f22f7183a90b04979a28e40ca993e80ea30c47ad028", .bytes = @embedFile("fixtures/candidates/c42.json") }, // fixtures/state_tests/frontier/opcodes/test_dup.json :: tests/frontier/opcodes/test_dup.py::test_dup[fork_Cancun-evm_code_type_LEGACY-state_test-DUP16]
    .{ .name = "push5", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "699dda4bce2e46a572afda6df123b2b08c9c9c7b33ec1cc1b8450102d998130b", .bytes = @embedFile("fixtures/candidates/push5.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH5]
    .{ .name = "push6", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "343dd984f89086fcb3848a15de0f37a98fb7019d86f8a5088d3262dde0312c8b", .bytes = @embedFile("fixtures/candidates/push6.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH6]
    .{ .name = "push7", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "2fcdeca0c8fa6096b923353bad8a67a38e99c3ad1c405aacef73d27c79aa8c33", .bytes = @embedFile("fixtures/candidates/push7.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH7]
    .{ .name = "push9", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "6bf5abef686b6670e8b5b8a58878f6765c557a4d3799afc9ca007c0c76c45df6", .bytes = @embedFile("fixtures/candidates/push9.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH9]
    .{ .name = "push10", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "42ff0ab626074f3f12063a85be5b8452def53ab68a06ad7daffe3b1d712629b2", .bytes = @embedFile("fixtures/candidates/push10.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH10]
    .{ .name = "push11", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "8afe66d30345ac7f93f4587e9424baa81350c5027516ae0519377a8aba905b50", .bytes = @embedFile("fixtures/candidates/push11.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH11]
    .{ .name = "push12", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "b56c9fbb03eabeee5f13408979daef72db2659bd175baea810245b00c48196a9", .bytes = @embedFile("fixtures/candidates/push12.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH12]
    .{ .name = "push18", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "66f0d70cbe1fa5bcadd9483ad648f8046613bf774d1d091fa1e6cb8fe20773cc", .bytes = @embedFile("fixtures/candidates/push18.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH18]
    .{ .name = "push22", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "cd025e27451c0805115b694fd17ce3cab150d1bff204dc88479e96521a39e56c", .bytes = @embedFile("fixtures/candidates/push22.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH22]
    .{ .name = "push23", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "268e3d1e34b8c2491e4263680166ce2b27b4795289628ab327778d8f16686d75", .bytes = @embedFile("fixtures/candidates/push23.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH23]
    .{ .name = "push24", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "3a58ad9e3cb9b2ac78d616b51226ab5b192bd91b3eec13b50897b05aafc42a0c", .bytes = @embedFile("fixtures/candidates/push24.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH24]
    .{ .name = "push25", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "193b99d057eb8359812b2ee1cc48063f53c101e7eb7392638de350b454c839fa", .bytes = @embedFile("fixtures/candidates/push25.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH25]
    .{ .name = "push26", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "5a11e34305d7779eb84719399fefea401881f11e39998cc26bafeb2c281c5773", .bytes = @embedFile("fixtures/candidates/push26.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH26]
    .{ .name = "push27", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "072e317a13fde329b2cb9674d05665b86852bce8b86cb99f81a6394255032249", .bytes = @embedFile("fixtures/candidates/push27.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH27]
    .{ .name = "push30", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "e9ae4cee19845a0c3283ef344b36bebbe92a764aae071764038a7144077940bf", .bytes = @embedFile("fixtures/candidates/push30.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH30]
    .{ .name = "push31", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "8cd8e242e8a4b35e51c098313856bd90c1f0f346c546de2d41534fd187f75975", .bytes = @embedFile("fixtures/candidates/push31.json") }, // fixtures/state_tests/frontier/opcodes/test_push.json :: tests/frontier/opcodes/test_push.py::test_push[fork_Cancun-state_test-PUSH31]
    .{ .name = "swap5", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "58912d395de2035eb03d44a76822229566edd7d2f68a098770944f82ca299540", .bytes = @embedFile("fixtures/candidates/swap5.json") }, // fixtures/state_tests/frontier/opcodes/test_swap.json :: tests/frontier/opcodes/test_swap.py::test_swap[fork_Cancun-state_test-SWAP5]
    .{ .name = "swap6", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "72690c599ff963d794971e675c985a28cfe5812f06e816c1a5cbc239c2c88931", .bytes = @embedFile("fixtures/candidates/swap6.json") }, // fixtures/state_tests/frontier/opcodes/test_swap.json :: tests/frontier/opcodes/test_swap.py::test_swap[fork_Cancun-state_test-SWAP6]
    .{ .name = "swap7", .format = "state", .fork = "Cancun", .expected = .valid, .checksum = "7f909d8568249c51b5d115a418fafd606d3df52476bdcd3900409b100c3bbb52", .bytes = @embedFile("fixtures/candidates/swap7.json") }, // fixtures/state_tests/frontier/opcodes/test_swap.json :: tests/frontier/opcodes/test_swap.py::test_swap[fork_Cancun-state_test-SWAP7]
};

const Counts = struct { passed: usize = 0, skipped: usize = 0 };

/// Checks a 64-character lowercase SHA-256 string against the fixture bytes.
fn checksumMatches(bytes: []const u8, expected: []const u8) bool {
    if (expected.len != 64) return false;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const digits = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        if (expected[i * 2] != digits[byte >> 4] or expected[i * 2 + 1] != digits[byte & 0x0f]) return false;
    }
    return true;
}

/// Returns a required object member or rejects malformed fixture structure.
fn member(value: std.json.Value, key: []const u8) error{MissingField}!std.json.Value {
    if (value != .object) return error.MissingField;
    return value.object.get(key) orelse error.MissingField;
}

/// Requires a non-empty JSON string at the selected member.
fn stringMember(value: std.json.Value, key: []const u8) error{MissingField}![]const u8 {
    const field = try member(value, key);
    if (field != .string or field.string.len == 0) return error.MissingField;
    return field.string;
}

/// Converts fixture hex data to bytes, rejecting prefixes, odd lengths, and bad digits.
fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len < 2 or !std.mem.startsWith(u8, hex, "0x") or (hex.len - 2) % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, (hex.len - 2) / 2);
    errdefer allocator.free(out);
    for (out, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[2 + i * 2 ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

/// Validates the source oracle fields and returns transaction bytes for transaction fixtures.
fn transactionBytes(allocator: std.mem.Allocator, root: std.json.Value, fixture: Fixture) ![]u8 {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const hex = try stringMember(test_value, "txbytes");
    const result = try member(test_value, "result");
    const fork_result = try member(result, fixture.fork);
    if (fixture.expected == .InvalidLength or fixture.expected == .NonCanonicalInteger) {
        const exception = try stringMember(fork_result, "exception");
        const expected_exception = if (fixture.expected == .InvalidLength) "TransactionException.ADDRESS_TOO_SHORT" else "TransactionException.RLP_LEADING_ZEROS_BASEFEE";
        if (!std.mem.eql(u8, exception, expected_exception)) return error.MissingExpectation;
    } else {
        _ = try member(fork_result, "intrinsicGas");
    }
    return decodeHex(allocator, hex);
}

/// Checks state and blockchain fixture oracle fields before a deliberate skip.
fn validateSkipped(root: std.json.Value, fixture: Fixture) !void {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const info = try member(test_value, "_info");
    const source_format = try stringMember(info, if (info == .object and info.object.contains("fixture_format")) "fixture_format" else "fixture-format");
    if (std.mem.eql(u8, fixture.format, "state")) {
        if (!std.mem.eql(u8, source_format, "state_test")) return error.MissingField;
        _ = try member(test_value, "transaction");
        _ = try member(try member(test_value, "post"), fixture.fork);
    } else {
        if (!std.mem.eql(u8, source_format, "blockchain_test")) return error.MissingField;
        _ = try member(test_value, "blocks");
        _ = try member(test_value, "postState");
        _ = try stringMember(test_value, "lastblockhash");
    }
}

/// Validates and runs one fixture, returning whether it passed or was skipped.
fn runFixture(allocator: std.mem.Allocator, fixture: Fixture, bytes: []const u8) !bool {
    if (fixture.expected == null) return error.MissingExpectation;
    if (!checksumMatches(bytes, fixture.checksum)) return error.ChecksumMismatch;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return error.MalformedJson;
    defer parsed.deinit();
    const format = std.meta.stringToEnum(Format, fixture.format) orelse return error.UnknownFormat;

    if (format == .state) {
        if (fixture.expected.? == .skip) {
            if (fixture.skip_reason == null) return error.MissingExpectation;
            try validateSkipped(parsed.value, fixture);
            return false;
        }
        return runStateFixture(allocator, parsed.value, fixture);
    }
    if (format == .blockchain) {
        if (fixture.expected.? == .skip) {
            if (fixture.skip_reason == null) return error.MissingExpectation;
            try validateSkipped(parsed.value, fixture);
            return false;
        }
        return runBlockchainFixture(allocator, parsed.value, fixture);
    }
    if (fixture.expected.? == .skip) return error.MissingExpectation;
    const raw = try transactionBytes(allocator, parsed.value, fixture);
    defer allocator.free(raw);
    var decoded = execution.parse(execution.Transaction, allocator, raw) catch |err| {
        const expected_error: ?anyerror = switch (fixture.expected.?) {
            .InvalidLength => error.InvalidLength,
            .NonCanonicalInteger => error.NonCanonicalInteger,
            else => null,
        };
        if (expected_error != null and err == expected_error.?) return true;
        std.debug.print("FAIL {s}: transaction decode returned {s}\n", .{ fixture.name, @errorName(err) });
        return err;
    };
    defer decoded.deinit();
    if (fixture.expected.? != .valid) return error.UnexpectedSuccess;
    const canonical = try execution.encode(allocator, decoded.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, raw, canonical)) return error.RoundTripMismatch;
    return true;
}

/// Runs the fixed manifest and counts validated cases and named processor skips.
pub fn run(allocator: std.mem.Allocator) !Counts {
    var counts: Counts = .{};
    for (fixtures) |fixture| {
        if (try runFixture(allocator, fixture, fixture.bytes)) {
            counts.passed += 1;
        } else {
            counts.skipped += 1;
            std.debug.print("SKIP {s}: {s}\n", .{ fixture.name, fixture.skip_reason.? });
        }
    }
    return counts;
}

test "pinned execution fixtures pass and unsupported processors are explicit" {
    var seen = [_]bool{false} ** 256;
    execution.evm.coverage.opcodes = &seen;
    defer execution.evm.coverage.opcodes = null;
    const counts = try run(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 79), counts.passed);
    try std.testing.expectEqual(@as(usize, 1), counts.skipped);
    std.debug.print("execution fixtures: {d} passed, {d} skipped\n", .{ counts.passed, counts.skipped });
    const core = [_]u8{ 0x00, 0xf3, 0xfd };
    for (core) |op| try std.testing.expect(seen[op]);
    for (0x01..0x0c) |op| try std.testing.expect(seen[op]);
    for (0x10..0x1e) |op| try std.testing.expect(seen[op]);
    for (0x50..0x9f + 1) |op| try std.testing.expect(seen[op]);
    for (0xa0..0xa5) |op| try std.testing.expect(seen[op]);
}

test "rejects checksum mismatch, malformed JSON, missing expectation, and unknown format" {
    try std.testing.expect(!checksumMatches("{}", "0000000000000000000000000000000000000000000000000000000000000000"));
    var fixture = fixtures[0];
    fixture.checksum = "0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.ChecksumMismatch, runFixture(std.testing.allocator, fixture, "{}"));

    fixture.checksum = "021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96";
    try std.testing.expectError(error.MalformedJson, runFixture(std.testing.allocator, fixture, "{"));

    fixture.expected = null;
    try std.testing.expectError(error.MissingExpectation, runFixture(std.testing.allocator, fixture, fixtures[0].bytes));

    fixture.expected = .valid;
    fixture.fork = "UnknownFork";
    fixture.checksum = fixtures[0].checksum;
    try std.testing.expectError(error.MissingField, runFixture(std.testing.allocator, fixture, fixtures[0].bytes));

    fixture.format = "future_format";
    fixture.fork = fixtures[0].fork;
    fixture.checksum = fixtures[0].checksum;
    try std.testing.expectError(error.UnknownFormat, runFixture(std.testing.allocator, fixture, fixtures[0].bytes));
}

test "blockchain fixture rejects malformed and mismatched oracles" {
    const allocator = std.testing.allocator;
    var valid = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[20].bytes, .{});
    defer valid.deinit();
    const case_value = valid.value.object.values()[0];
    const network = case_value.object.getPtr("network").?;
    network.* = .{ .string = "Paris" };
    try std.testing.expectError(error.UnsupportedFork, runBlockchainFixture(allocator, valid.value, fixtures[20]));
    network.* = .{ .string = "London" };
    const last_hash = case_value.object.getPtr("lastblockhash").?;
    const oracle_last = last_hash.*;
    last_hash.* = .{ .string = "0x00" };
    try std.testing.expectError(error.InvalidHex, runBlockchainFixture(allocator, valid.value, fixtures[20]));
    last_hash.* = oracle_last;
    const blocks = try member(case_value, "blocks");
    const header = try member(blocks.array.items[0], "blockHeader");
    header.object.getPtr("gasUsed").?.* = .{ .string = "0x00" };
    try std.testing.expectError(error.HeaderMismatch, runBlockchainFixture(allocator, valid.value, fixtures[20]));

    var invalid = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[21].bytes, .{});
    defer invalid.deinit();
    const invalid_case = invalid.value.object.values()[0];
    const invalid_blocks = try member(invalid_case, "blocks");
    invalid_blocks.array.items[0].object.getPtr("expectException").?.* = .{ .string = "BlockException.OTHER" };
    try std.testing.expectError(error.UnsupportedException, runBlockchainFixture(allocator, invalid.value, fixtures[21]));
}

test "two rejected London blocks leave the following valid block intact" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[20].bytes, .{});
    defer parsed.deinit();
    const case_value = parsed.value.object.values()[0];
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    try loadAccounts(allocator, &world, try member(case_value, "pre"));
    const parent = try londonHeader(allocator, try member(case_value, "genesisBlockHeader"));
    defer allocator.free(parent.extra_data);
    const blocks = try member(case_value, "blocks");
    const block = blocks.array.items[0];
    const header = try londonHeader(allocator, try member(block, "blockHeader"));
    defer allocator.free(header.extra_data);
    const txs = try londonBlockTransactions(allocator, block, block, header, 1);
    defer {
        for (txs) |tx| allocator.free(tx);
        allocator.free(txs);
    }
    const context: execution.transition.BlockContext = .{ .fork = .london, .parent_fork = .london, .chain_id = 1 };
    const before = try world.stateRoot();
    var bad_fee = header;
    bad_fee.base_fee_per_gas += 1;
    try std.testing.expectError(error.InvalidBaseFee, execution.transition.applyBlock(allocator, &world, context, parent, bad_fee, txs, &.{}));
    try std.testing.expectEqualSlices(u8, &before, &(try world.stateRoot()));
    var bad_parent = header;
    bad_parent.parent_hash = .{0} ** 32;
    try std.testing.expectError(error.InvalidParentHash, execution.transition.applyBlock(allocator, &world, context, parent, bad_parent, txs, &.{}));
    try std.testing.expectEqualSlices(u8, &before, &(try world.stateRoot()));
    var result = try execution.transition.applyBlock(allocator, &world, context, parent, header, txs, &.{});
    defer result.deinit();
    try checkAccounts(allocator, &world, try member(case_value, "postState"));
}

/// Parses a required 0x-prefixed fixture quantity without accepting omitted values.
fn quantity(value: std.json.Value) !u256 {
    if (value != .string or !std.mem.startsWith(u8, value.string, "0x") or value.string.len < 3) return error.InvalidQuantity;
    return std.fmt.parseInt(u256, value.string[2..], 16) catch error.InvalidQuantity;
}

/// Decodes a required fixed-size hash or address.
fn fixedHex(comptime N: usize, allocator: std.mem.Allocator, value: std.json.Value) ![N]u8 {
    if (value != .string) return error.InvalidHex;
    const bytes = try decodeHex(allocator, value.string);
    defer allocator.free(bytes);
    if (bytes.len != N) return error.InvalidHex;
    return bytes[0..N].*;
}

/// Loads each pre-account, including code and storage, into the execution state.
fn loadAccounts(allocator: std.mem.Allocator, world: *execution.state.State, accounts: std.json.Value) !void {
    if (accounts != .object) return error.MissingField;
    var it = accounts.object.iterator();
    while (it.next()) |entry| {
        const address = try fixedHex(20, allocator, .{ .string = entry.key_ptr.* });
        const item = entry.value_ptr.*;
        try world.createAccount(address);
        try world.setNonce(address, @intCast(try quantity(try member(item, "nonce"))));
        try world.setBalance(address, try quantity(try member(item, "balance")));
        const code = try decodeHex(allocator, try stringMember(item, "code"));
        defer allocator.free(code);
        _ = try world.setCode(address, code);
        const storage = try member(item, "storage");
        if (storage != .object) return error.MissingField;
        var slots = storage.object.iterator();
        while (slots.next()) |slot| try world.setStorage(address, try quantity(.{ .string = slot.key_ptr.* }), try quantity(slot.value_ptr.*));
    }
}

/// Compares every declared post-account field and rejects undeclared extra accounts.
fn checkAccounts(allocator: std.mem.Allocator, world: *execution.state.State, accounts: std.json.Value) !void {
    if (accounts != .object or world.accounts.items.len != accounts.object.count()) return error.StateMismatch;
    var it = accounts.object.iterator();
    while (it.next()) |entry| {
        const address = try fixedHex(20, allocator, .{ .string = entry.key_ptr.* });
        const item = entry.value_ptr.*;
        const account = (try world.getAccount(address)) orelse return error.StateMismatch;
        if (account.nonce != try quantity(try member(item, "nonce")) or account.balance != try quantity(try member(item, "balance"))) return error.StateMismatch;
        const code = try decodeHex(allocator, try stringMember(item, "code"));
        defer allocator.free(code);
        if (!std.mem.eql(u8, world.getCode(address), code)) return error.StateMismatch;
        const storage = try member(item, "storage");
        if (storage != .object) return error.MissingField;
        var slots = storage.object.iterator();
        while (slots.next()) |slot| {
            if (world.getStorage(address, try quantity(.{ .string = slot.key_ptr.* })) != try quantity(slot.value_ptr.*)) return error.StateMismatch;
        }
        for (world.accounts.items) |actual| {
            if (!std.mem.eql(u8, &actual.address, &address)) continue;
            if (actual.storage.items.len != storage.object.count()) return error.StateMismatch;
        }
    }
}

/// Returns the fixture field chosen by a required transaction index.
fn selectedValue(transaction: std.json.Value, indexes: std.json.Value, key: []const u8, field: []const u8) ![]const u8 {
    const index = try member(indexes, key);
    const values = try member(transaction, field);
    if (index != .integer or index.integer < 0 or values != .array or @as(usize, @intCast(index.integer)) >= values.array.items.len) return error.MissingExpectation;
    const selected = values.array.items[@intCast(index.integer)];
    if (selected != .string) return error.MissingExpectation;
    return selected.string;
}

/// Runs a selected fork outcome against transaction bytes, full state, root, and logs hash.
fn runStateFixture(allocator: std.mem.Allocator, root: std.json.Value, fixture: Fixture) !bool {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const info = try member(test_value, "_info");
    const format_name = if (info == .object and info.object.contains("fixture_format")) "fixture_format" else "fixture-format";
    if (!std.mem.eql(u8, try stringMember(info, format_name), "state_test")) return error.MissingField;
    const post = try member(try member(test_value, "post"), fixture.fork);
    if (post != .array or post.array.items.len != 1) return error.MissingExpectation;
    const expected = post.array.items[0];
    const indexes = try member(expected, "indexes");
    const transaction = try member(test_value, "transaction");
    const raw = try decodeHex(allocator, try stringMember(expected, "txbytes"));
    defer allocator.free(raw);
    var decoded = try execution.parse(execution.Transaction, allocator, raw);
    defer decoded.deinit();
    const selected_gas = try selectedValue(transaction, indexes, "gas", "gasLimit");
    const selected_data = try selectedValue(transaction, indexes, "data", "data");
    const selected_value = try selectedValue(transaction, indexes, "value", "value");
    const legacy = switch (decoded.value) {
        .legacy => |tx| tx,
        else => return error.TransactionMismatch,
    };
    const expected_to = try fixedHex(20, allocator, try member(transaction, "to"));
    const actual_to = legacy.to orelse return error.TransactionMismatch;
    const expected_data = try decodeHex(allocator, selected_data);
    defer allocator.free(expected_data);
    if (legacy.nonce != try quantity(try member(transaction, "nonce")) or
        legacy.gas_limit != try quantity(.{ .string = selected_gas }) or
        legacy.gas_price != try quantity(try member(transaction, "gasPrice")) or
        legacy.value != try quantity(.{ .string = selected_value }) or
        !std.mem.eql(u8, &actual_to, &expected_to) or
        !std.mem.eql(u8, legacy.data, expected_data)) return error.TransactionMismatch;
    const canonical = try execution.encode(allocator, decoded.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, raw, canonical)) return error.TransactionMismatch;
    const sender = try execution.recoverSender(allocator, decoded.value, try quantity(try member(try member(test_value, "config"), "chainid")));
    const expected_sender = try fixedHex(20, allocator, try member(transaction, "sender"));
    if (!std.mem.eql(u8, &sender, &expected_sender)) return error.TransactionMismatch;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    try loadAccounts(allocator, &world, try member(test_value, "pre"));
    const env = try member(test_value, "env");
    const config = try member(test_value, "config");
    const fork = if (std.mem.eql(u8, fixture.fork, "Cancun")) execution.transition.Fork.cancun else if (std.mem.eql(u8, fixture.fork, "London")) execution.transition.Fork.london else null orelse return error.UnsupportedFork;
    const context: execution.transition.Context = .{
        .fork = fork,
        .chain_id = try quantity(try member(config, "chainid")),
        .coinbase = try fixedHex(20, allocator, try member(env, "currentCoinbase")),
        .number = @intCast(try quantity(try member(env, "currentNumber"))),
        .timestamp = @intCast(try quantity(try member(env, "currentTimestamp"))),
        .gas_limit = @intCast(try quantity(try member(env, "currentGasLimit"))),
        .base_fee = try quantity(try member(env, "currentBaseFee")),
        .prev_randao = try fixedHex(32, allocator, try member(env, "currentRandom")),
        .blob_base_fee = if (fork == .london) null else try execution.transition.blobBaseFee(fork, @intCast(try quantity(try member(env, "currentExcessBlobGas")))),
    };
    if (fixture.expected == .invalid_transaction) {
        if (!std.mem.eql(u8, try stringMember(expected, "expectException"), "TransactionException.INTRINSIC_GAS_TOO_LOW")) return error.MissingExpectation;
        if (execution.transition.applyTransaction(allocator, &world, context, raw, context.gas_limit, 0)) |outcome| {
            var owned = outcome;
            owned.deinit();
            return error.UnexpectedSuccess;
        } else |err| {
            if (err != error.IntrinsicGasTooLow) return err;
        }
        try checkAccounts(allocator, &world, try member(expected, "state"));
        const expected_root = try fixedHex(32, allocator, try member(expected, "hash"));
        const actual_root = try world.stateRoot();
        if (!std.mem.eql(u8, &expected_root, &actual_root)) return error.StateRootMismatch;
        const empty_logs = try execution.encode(allocator, @as([]const execution.Log, &.{}));
        defer allocator.free(empty_logs);
        var logs_hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(empty_logs, &logs_hash, .{});
        const expected_logs = try fixedHex(32, allocator, try member(expected, "logs"));
        if (!std.mem.eql(u8, &expected_logs, &logs_hash)) return error.LogsHashMismatch;
    } else {
        if (expected == .object and expected.object.contains("expectException")) return error.MissingExpectation;
        var outcome = try execution.transition.applyTransaction(allocator, &world, context, raw, context.gas_limit, 0);
        defer outcome.deinit();
        try checkAccounts(allocator, &world, try member(expected, "state"));
        const root_hash = try fixedHex(32, allocator, try member(expected, "hash"));
        if (!std.mem.eql(u8, &root_hash, &(try world.stateRoot()))) return error.StateRootMismatch;
        const logs = switch (outcome.receipt) {
            inline else => |payload| payload.logs,
        };
        const encoded = try execution.encode(allocator, logs);
        defer allocator.free(encoded);
        var logs_hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(encoded, &logs_hash, .{});
        const expected_logs = try fixedHex(32, allocator, try member(expected, "logs"));
        if (!std.mem.eql(u8, &expected_logs, &logs_hash)) return error.LogsHashMismatch;
    }
    return true;
}

/// Reads the complete London header used by the pinned parent-hash oracle.
fn londonHeader(allocator: std.mem.Allocator, value: std.json.Value) !execution.Header {
    var header: execution.Header = std.mem.zeroes(execution.Header);
    header.parent_hash = try fixedHex(32, allocator, try member(value, "parentHash"));
    header.ommers_hash = try fixedHex(32, allocator, try member(value, "uncleHash"));
    header.fee_recipient = try fixedHex(20, allocator, try member(value, "coinbase"));
    header.state_root = try fixedHex(32, allocator, try member(value, "stateRoot"));
    header.transactions_root = try fixedHex(32, allocator, try member(value, "transactionsTrie"));
    header.receipts_root = try fixedHex(32, allocator, try member(value, "receiptTrie"));
    header.logs_bloom = try fixedHex(256, allocator, try member(value, "bloom"));
    header.difficulty = try quantity(try member(value, "difficulty"));
    header.number = @intCast(try quantity(try member(value, "number")));
    header.gas_limit = @intCast(try quantity(try member(value, "gasLimit")));
    header.gas_used = @intCast(try quantity(try member(value, "gasUsed")));
    header.timestamp = @intCast(try quantity(try member(value, "timestamp")));
    header.extra_data = try decodeHex(allocator, try stringMember(value, "extraData"));
    header.prev_randao = try fixedHex(32, allocator, try member(value, "mixHash"));
    header.nonce = try fixedHex(8, allocator, try member(value, "nonce"));
    header.base_fee_per_gas = try quantity(try member(value, "baseFeePerGas"));
    return header;
}

/// Returns one complete RLP item and rejects truncated or trailing block data.
fn rlpItem(bytes: []const u8) !struct { kind: rlp.Kind, header_len: usize, length: usize } {
    var reader: std.Io.Reader = .fixed(bytes);
    const header = try rlp.readHeader(&reader);
    const length = std.math.add(usize, header.header_len, header.payload_len) catch return error.MalformedRlp;
    if (length > bytes.len) return error.MalformedRlp;
    return .{ .kind = header.kind, .header_len = header.header_len, .length = length };
}

/// Compares the fixture's legacy transaction oracle with the transaction from raw block RLP.
fn checkLondonTransaction(allocator: std.mem.Allocator, raw: []const u8, oracle: std.json.Value, chain_id: u256) !void {
    var parsed = try execution.parse(execution.Transaction, allocator, raw);
    defer parsed.deinit();
    const tx = switch (parsed.value) {
        .legacy => |legacy| legacy,
        else => return error.UnsupportedTransaction,
    };
    const to = try fixedHex(20, allocator, try member(oracle, "to"));
    const data = try decodeHex(allocator, try stringMember(oracle, "data"));
    defer allocator.free(data);
    if (try quantity(try member(oracle, "type")) != 0 or
        tx.nonce != try quantity(try member(oracle, "nonce")) or
        tx.gas_price != try quantity(try member(oracle, "gasPrice")) or
        tx.gas_limit != try quantity(try member(oracle, "gasLimit")) or
        tx.value != try quantity(try member(oracle, "value")) or
        tx.v != try quantity(try member(oracle, "v")) or
        tx.r != try quantity(try member(oracle, "r")) or
        tx.s != try quantity(try member(oracle, "s")) or
        tx.to == null or !std.mem.eql(u8, &tx.to.?, &to) or
        !std.mem.eql(u8, tx.data, data)) return error.TransactionMismatch;
    const sender = try execution.recoverSender(allocator, parsed.value, chain_id);
    const oracle_sender = try fixedHex(20, allocator, try member(oracle, "sender"));
    if (!std.mem.eql(u8, &sender, &oracle_sender)) return error.TransactionMismatch;
}

/// Checks the raw block header against its JSON oracle and returns raw ordered transactions.
fn londonBlockTransactions(allocator: std.mem.Allocator, block: std.json.Value, decoded: std.json.Value, header: execution.Header, chain_id: u256) ![][]const u8 {
    const raw = try decodeHex(allocator, try stringMember(block, "rlp"));
    defer allocator.free(raw);
    const outer = try rlpItem(raw);
    if (outer.kind != .list or outer.length != raw.len) return error.MalformedRlp;
    const body = raw[outer.header_len..];
    const raw_header = try rlpItem(body);
    if (raw_header.kind != .list) return error.MalformedRlp;
    var actual_hash: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(body[0..raw_header.length], &actual_hash, .{});
    if (!std.mem.eql(u8, &actual_hash, &(try execution.transition.headerHash(allocator, .london, header)))) return error.HeaderMismatch;
    const tx_list = try rlpItem(body[raw_header.length..]);
    if (tx_list.kind != .list) return error.MalformedRlp;
    const tx_body = body[raw_header.length + tx_list.header_len ..][0 .. tx_list.length - tx_list.header_len];
    const ommers = try rlpItem(body[raw_header.length + tx_list.length ..]);
    if (ommers.kind != .list or ommers.length != 1 or body.len != raw_header.length + tx_list.length + ommers.length) return error.UnsupportedOmmers;
    const oracle_txs = try member(decoded, "transactions");
    if (oracle_txs != .array) return error.MissingField;
    const txs = try allocator.alloc([]const u8, oracle_txs.array.items.len);
    errdefer allocator.free(txs);
    var offset: usize = 0;
    for (txs, oracle_txs.array.items) |*tx, oracle| {
        if (offset >= tx_body.len) return error.TransactionMismatch;
        const item = try rlpItem(tx_body[offset..]);
        const encoded = tx_body[offset..][0..item.length];
        tx.* = try allocator.dupe(u8, if (item.kind == .list) encoded else encoded[item.header_len..]);
        errdefer allocator.free(tx.*);
        try checkLondonTransaction(allocator, tx.*, oracle, chain_id);
        offset += item.length;
    }
    if (offset != tx_body.len) return error.TransactionMismatch;
    return txs;
}

/// Executes one pinned London chain and checks each acceptance decision and final state.
fn runBlockchainFixture(allocator: std.mem.Allocator, root: std.json.Value, fixture: Fixture) !bool {
    const test_value = if (root == .object and root.object.count() == 1) root.object.values()[0] else return error.MissingField;
    const info = try member(test_value, "_info");
    const format_name = if (info == .object and info.object.contains("fixture_format")) "fixture_format" else "fixture-format";
    if (!std.mem.eql(u8, try stringMember(info, format_name), "blockchain_test")) return error.MissingField;
    if (!std.mem.eql(u8, try stringMember(test_value, "network"), fixture.fork) or !std.mem.eql(u8, try stringMember(try member(test_value, "config"), "network"), fixture.fork)) return error.UnsupportedFork;
    if (!std.mem.eql(u8, fixture.fork, "London")) return error.UnsupportedFork;
    const chain_id = try quantity(try member(try member(test_value, "config"), "chainid"));
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    try loadAccounts(allocator, &world, try member(test_value, "pre"));
    const genesis_json = try member(test_value, "genesisBlockHeader");
    var parent = try londonHeader(allocator, genesis_json);
    defer allocator.free(parent.extra_data);
    const genesis_hash = try fixedHex(32, allocator, try member(genesis_json, "hash"));
    if (!std.mem.eql(u8, &genesis_hash, &(try execution.transition.headerHash(allocator, .london, parent)))) return error.HeaderMismatch;
    if (!std.mem.eql(u8, &parent.state_root, &(try world.stateRoot()))) return error.StateRootMismatch;
    const genesis_rlp = try decodeHex(allocator, try stringMember(test_value, "genesisRLP"));
    defer allocator.free(genesis_rlp);
    const genesis_item = try rlpItem(genesis_rlp);
    if (genesis_item.kind != .list or genesis_item.length != genesis_rlp.len) return error.MalformedRlp;
    const genesis_body = genesis_rlp[genesis_item.header_len..];
    const genesis_header = try rlpItem(genesis_body);
    if (genesis_header.kind != .list) return error.MalformedRlp;
    var raw_genesis_hash: execution.Hash = undefined;
    std.crypto.hash.sha3.Keccak256.hash(genesis_body[0..genesis_header.length], &raw_genesis_hash, .{});
    if (!std.mem.eql(u8, &raw_genesis_hash, &genesis_hash)) return error.HeaderMismatch;
    const blocks = try member(test_value, "blocks");
    if (blocks != .array) return error.MissingField;
    var last_hash = genesis_hash;
    for (blocks.array.items) |block| {
        const invalid = block == .object and block.object.contains("expectException");
        const block_value = if (invalid) try member(block, "rlp_decoded") else block;
        const header_json = try member(block_value, "blockHeader");
        var header = try londonHeader(allocator, header_json);
        defer allocator.free(header.extra_data);
        const oracle_hash = try fixedHex(32, allocator, try member(header_json, "hash"));
        if (!std.mem.eql(u8, &oracle_hash, &(try execution.transition.headerHash(allocator, .london, header)))) return error.HeaderMismatch;
        const txs = try londonBlockTransactions(allocator, block, block_value, header, chain_id);
        defer {
            for (txs) |tx| allocator.free(tx);
            allocator.free(txs);
        }
        const uncles = try member(block_value, "uncleHeaders");
        if (uncles != .array or uncles.array.items.len != 0) return error.UnsupportedOmmers;
        if (try std.fmt.parseInt(u64, try stringMember(block_value, "blocknumber"), 10) != header.number) return error.BlockNumberMismatch;
        const context: execution.transition.BlockContext = .{ .fork = .london, .parent_fork = .london, .chain_id = chain_id };
        if (invalid) {
            const exception = try stringMember(block, "expectException");
            if (!std.mem.eql(u8, exception, "BlockException.INVALID_BASEFEE_PER_GAS")) return error.UnsupportedException;
            const before_root = try world.stateRoot();
            if (execution.transition.applyBlock(allocator, &world, context, parent, header, txs, &.{})) |result| {
                var owned = result;
                owned.deinit();
                return error.UnexpectedSuccess;
            } else |err| if (err != error.InvalidBaseFee) return err;
            if (!std.mem.eql(u8, &before_root, &(try world.stateRoot()))) return error.RollbackMismatch;
            if (!std.mem.eql(u8, &last_hash, &(try execution.transition.headerHash(allocator, .london, parent)))) return error.RollbackMismatch;
        } else {
            var result = try execution.transition.applyBlock(allocator, &world, context, parent, header, txs, &.{});
            defer result.deinit();
            if (result.gas_used != header.gas_used or !std.mem.eql(u8, &result.state_root, &header.state_root) or !std.mem.eql(u8, &result.transactions_root, &header.transactions_root) or !std.mem.eql(u8, &result.receipts_root, &header.receipts_root)) return error.CommitmentMismatch;
            const next_extra = try allocator.dupe(u8, header.extra_data);
            allocator.free(parent.extra_data);
            parent = header;
            parent.extra_data = next_extra;
            last_hash = oracle_hash;
        }
    }
    if (!std.mem.eql(u8, &last_hash, &(try fixedHex(32, allocator, try member(test_value, "lastblockhash"))))) return error.LastBlockHashMismatch;
    try checkAccounts(allocator, &world, try member(test_value, "postState"));
    return true;
}

/// Builds the pinned valid state fixture's pre-state and transaction input.
fn sampleTransaction(allocator: std.mem.Allocator, world: *execution.state.State) !struct { raw: []u8, context: execution.transition.Context } {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixtures[4].bytes, .{});
    defer parsed.deinit();
    const test_value = parsed.value.object.values()[0];
    try loadAccounts(allocator, world, try member(test_value, "pre"));
    const post = try member(try member(test_value, "post"), "Cancun");
    const raw = try decodeHex(allocator, try stringMember(post.array.items[0], "txbytes"));
    const env = try member(test_value, "env");
    return .{ .raw = raw, .context = .{
        .fork = .cancun,
        .chain_id = 1,
        .coinbase = try fixedHex(20, allocator, try member(env, "currentCoinbase")),
        .number = 1,
        .timestamp = 1000,
        .gas_limit = @intCast(try quantity(try member(env, "currentGasLimit"))),
        .base_fee = 7,
    } };
}

test "transaction prechecks preserve state and gas refund is capped" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const sender: execution.Address = try fixedHex(20, allocator, .{ .string = "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" });
    const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
    const root = try world.stateRoot();
    try world.setNonce(sender, 1);
    try std.testing.expectError(error.InvalidNonce, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try world.setNonce(sender, 0);
    try world.setBalance(sender, 0);
    try std.testing.expectError(error.InsufficientBalance, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try world.setBalance(sender, 1_000_000_000_000_000_000_000);
    try std.testing.expectError(error.BlockGasLimitExceeded, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, 99_999_999, 0));
    var expensive = sample.context;
    expensive.base_fee = 11;
    try std.testing.expectError(error.InvalidFee, execution.transition.applyTransaction(allocator, &world, expensive, sample.raw, sample.context.gas_limit, 0));
    try std.testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    const exact = try world.snapshot();
    var exact_outcome = try execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, 100_000_000, 0);
    exact_outcome.deinit();
    try world.revert(exact);
    try std.testing.expectEqualSlices(u8, &root, &(try world.stateRoot()));
    // Clearing an occupied slot earns a refund; the receipt remains owned after Machine.deinit.
    try world.setStorage(recipient, 1, 1);
    _ = try world.setCode(recipient, &.{ 0x60, 0, 0x60, 1, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0x00 });
    var outcome = try execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0);
    defer outcome.deinit();
    const payload = outcome.receipt.legacy;
    try std.testing.expectEqual(@as(u8, 1), payload.status);
    try std.testing.expectEqual(@as(usize, 1), payload.logs.len);
    try std.testing.expectEqualSlices(u8, &recipient, &payload.logs[0].address);
    try std.testing.expect(outcome.gas_used < 25_000);
    const after = try world.stateRoot();
    try world.setNonce(sender, 2);
    try std.testing.expectError(error.InvalidNonce, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try world.setNonce(sender, 1);
    try std.testing.expectEqualSlices(u8, &after, &(try world.stateRoot()));
}

test "block commitment failure rolls back transactions and withdrawals" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const original = try world.stateRoot();
    var parent: execution.Header = std.mem.zeroes(execution.Header);
    parent.gas_limit = sample.context.gas_limit;
    parent.base_fee_per_gas = 7;
    var header: execution.Header = std.mem.zeroes(execution.Header);
    header.parent_hash = try execution.transition.headerHash(allocator, .london, parent);
    header.number = 1;
    header.timestamp = 1000;
    header.gas_limit = parent.gas_limit;
    header.base_fee_per_gas = 7;
    header.gas_used = 0xa861;
    header.fee_recipient = sample.context.coinbase;
    header.parent_hash[0] ^= 1;
    try std.testing.expectError(error.InvalidParentHash, execution.transition.applyBlock(allocator, &world, .{ .fork = .london, .parent_fork = .london, .chain_id = 1 }, parent, header, &.{sample.raw}, &.{}));
    header.parent_hash[0] ^= 1;
    header.gas_limit = parent.gas_limit + parent.gas_limit / 1024;
    try std.testing.expectError(error.InvalidGasLimit, execution.transition.applyBlock(allocator, &world, .{ .fork = .london, .parent_fork = .london, .chain_id = 1 }, parent, header, &.{sample.raw}, &.{}));
    header.gas_limit = parent.gas_limit;
    header.base_fee_per_gas = 8;
    try std.testing.expectError(error.InvalidBaseFee, execution.transition.applyBlock(allocator, &world, .{ .fork = .london, .parent_fork = .london, .chain_id = 1 }, parent, header, &.{sample.raw}, &.{}));
    header.base_fee_per_gas = 7;
    try std.testing.expectError(error.InvalidCommitment, execution.transition.applyBlock(allocator, &world, .{ .fork = .london, .parent_fork = .london, .chain_id = 1 }, parent, header, &.{sample.raw}, &.{}));
    try std.testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    const destination: execution.Address = .{9} ** 20;
    const withdrawal: execution.Withdrawal = .{ .index = 0, .validator_index = 0, .address = destination, .amount = 3 };
    header.gas_used = 0;
    const empty = try execution.trie.orderedRoot(allocator, &.{});
    header.transactions_root = empty;
    header.receipts_root = empty;
    const withdrawal_bytes = try execution.encode(allocator, withdrawal);
    defer allocator.free(withdrawal_bytes);
    header.withdrawals_root = try execution.trie.orderedRoot(allocator, &.{withdrawal_bytes});
    const snapshot = try world.snapshot();
    try world.setBalance(destination, 3_000_000_000);
    header.state_root = try world.stateRoot();
    try world.revert(snapshot);
    header.parent_hash = try execution.transition.headerHash(allocator, .london, parent);
    var result = try execution.transition.applyBlock(allocator, &world, .{ .fork = .cancun, .parent_fork = .london, .chain_id = 1 }, parent, header, &.{}, &.{withdrawal});
    defer result.deinit();
    try std.testing.expectEqual(@as(u256, 3_000_000_000), world.getBalance(destination));
}

test "unsupported precompile nested in a transaction rolls back" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
    _ = try world.setCode(recipient, &.{ 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x60, 1, 0x61, 0xff, 0xff, 0xfa, 0x00 });
    const original = try world.stateRoot();
    try std.testing.expectError(error.UnsupportedExecution, execution.transition.applyTransaction(allocator, &world, sample.context, sample.raw, sample.context.gas_limit, 0));
    try std.testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
}

// The first hash is the parent; an older hash is supplied by the caller.
test "block BLOCKHASH reads provided ancestors and missing history is unsupported" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
    _ = try world.setCode(recipient, &.{ 0x60, 0, 0x40, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 });
    var parent: execution.Header = std.mem.zeroes(execution.Header);
    parent.number = 1;
    parent.gas_limit = sample.context.gas_limit;
    parent.base_fee_per_gas = 7;
    var header: execution.Header = std.mem.zeroes(execution.Header);
    header.parent_hash = try execution.transition.headerHash(allocator, .cancun, parent);
    header.number = 2;
    header.timestamp = 1000;
    header.gas_limit = parent.gas_limit;
    header.base_fee_per_gas = 7;
    header.fee_recipient = sample.context.coinbase;
    const older: execution.Hash = .{0x42} ** 32;
    var context = sample.context;
    context.number = 2;
    context.block_hashes = &.{ header.parent_hash, older };
    context.blob_base_fee = 1;
    const original = try world.stateRoot();
    var missing = context;
    missing.block_hashes = &.{header.parent_hash};
    try std.testing.expectError(error.UnsupportedExecution, execution.transition.applyTransaction(allocator, &world, missing, sample.raw, context.gas_limit, 0));
    try std.testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
    const snapshot = try world.snapshot();
    var outcome = try execution.transition.applyTransaction(allocator, &world, context, sample.raw, context.gas_limit, 0);
    defer outcome.deinit();
    try std.testing.expectEqualSlices(u8, &older, outcome.output);
    header.gas_used = outcome.gas_used;
    header.state_root = try world.stateRoot();
    header.transactions_root = try execution.trie.orderedRoot(allocator, &.{sample.raw});
    header.receipts_root = try execution.receiptsRoot(allocator, &.{outcome.receipt});
    header.logs_bloom = execution.receiptsBloom(&.{outcome.receipt});
    const empty = try execution.trie.orderedRoot(allocator, &.{});
    header.withdrawals_root = empty;
    try world.revert(snapshot);
    var result = try execution.transition.applyBlock(allocator, &world, .{ .fork = .cancun, .parent_fork = .cancun, .chain_id = 1, .older_hashes = &.{older} }, parent, header, &.{sample.raw}, &.{});
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, &header.state_root, &(try world.stateRoot()));
}

test "Cancun and Fulu blocks expose fork-specific blob base fees" {
    const allocator = std.testing.allocator;
    inline for (.{ .{ execution.transition.Fork.cancun, @as(u64, 393_216), @as(u256, 19) }, .{ execution.transition.Fork.fulu, @as(u64, 786_432), @as(u256, 7) } }) |case| {
        var world = execution.state.State.init(allocator);
        defer world.deinit();
        const sample = try sampleTransaction(allocator, &world);
        defer allocator.free(sample.raw);
        const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
        _ = try world.setCode(recipient, &.{ 0x4a, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3 });
        var parent: execution.Header = std.mem.zeroes(execution.Header);
        parent.number = 100;
        parent.gas_limit = sample.context.gas_limit;
        parent.gas_used = parent.gas_limit / 2;
        parent.base_fee_per_gas = 7;
        parent.excess_blob_gas = 10_000_000 + case[1];
        var header: execution.Header = std.mem.zeroes(execution.Header);
        header.parent_hash = try execution.transition.headerHash(allocator, case[0], parent);
        header.number = 101;
        header.timestamp = 1000;
        header.gas_limit = parent.gas_limit;
        header.base_fee_per_gas = 7;
        header.fee_recipient = sample.context.coinbase;
        header.excess_blob_gas = 10_000_000;
        header.excess_blob_gas += 1;
        try std.testing.expectError(error.InvalidExcessBlobGas, execution.transition.applyBlock(allocator, &world, .{ .fork = case[0], .parent_fork = case[0], .chain_id = 1 }, parent, header, &.{sample.raw}, &.{}));
        header.excess_blob_gas -= 1;
        const snapshot = try world.snapshot();
        var context = sample.context;
        context.fork = case[0];
        context.number = header.number;
        context.blob_base_fee = case[2];
        context.block_hashes = &.{header.parent_hash};
        var outcome = try execution.transition.applyTransaction(allocator, &world, context, sample.raw, context.gas_limit, 0);
        defer outcome.deinit();
        var fee_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &fee_bytes, case[2], .big);
        try std.testing.expectEqualSlices(u8, &fee_bytes, outcome.output);
        header.gas_used = outcome.gas_used;
        header.state_root = try world.stateRoot();
        header.transactions_root = try execution.trie.orderedRoot(allocator, &.{sample.raw});
        header.receipts_root = try execution.receiptsRoot(allocator, &.{outcome.receipt});
        header.logs_bloom = execution.receiptsBloom(&.{outcome.receipt});
        header.withdrawals_root = try execution.trie.orderedRoot(allocator, &.{});
        try world.revert(snapshot);
        var result = try execution.transition.applyBlock(allocator, &world, .{ .fork = case[0], .parent_fork = case[0], .chain_id = 1 }, parent, header, &.{sample.raw}, &.{});
        defer result.deinit();
        try std.testing.expectEqualSlices(u8, &header.state_root, &(try world.stateRoot()));
    }
}

test "missing BLOCKHASH context in a child call is unsupported" {
    const allocator = std.testing.allocator;
    var world = execution.state.State.init(allocator);
    defer world.deinit();
    const sample = try sampleTransaction(allocator, &world);
    defer allocator.free(sample.raw);
    const recipient: execution.Address = try fixedHex(20, allocator, .{ .string = "0x1000000000000000000000000000000000000000" });
    const child: execution.Address = .{0} ** 19 ++ .{0x21};
    _ = try world.setCode(recipient, &.{ 0x60, 96, 0x5f, 0x5f, 0x5f, 0x60, 0x21, 0x61, 0xff, 0xff, 0xfa, 0x00 });
    _ = try world.setCode(child, &.{ 0x60, 0, 0x40, 0x00 });
    var context = sample.context;
    context.number = 2;
    context.block_hashes = &.{.{3} ** 32};
    const original = try world.stateRoot();
    try std.testing.expectError(error.UnsupportedExecution, execution.transition.applyTransaction(allocator, &world, context, sample.raw, context.gas_limit, 0));
    try std.testing.expectEqualSlices(u8, &original, &(try world.stateRoot()));
}
