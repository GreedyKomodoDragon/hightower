const std = @import("std");
const testing = std.testing;
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");

fn expectSerializedFixture(comptime T: type, serialized: []const u8, expected_root_hex: []const u8) !void {
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    var reader: std.Io.Reader = .fixed(serialized);
    const decoded = try ssz.deserialize(testing.allocator, T, &reader);
    defer ssz.freeDecoded(testing.allocator, T, decoded);

    const root = try merkle.HashTreeRoot(testing.allocator, decoded);
    try testing.expectEqualSlices(u8, &expected_root, &root);

    const reserialized = try ssz.serializeAlloc(testing.allocator, decoded);
    defer testing.allocator.free(reserialized);
    try testing.expectEqualSlices(u8, serialized, reserialized);
}

test "Fulu block schemas match pinned ssz_nil fixtures" {
    try expectSerializedFixture(fulu.Attestation, @embedFile("fixtures/fulu_static/Attestation.ssz"), "6de084ea6894968e7e0448d73554cec064e04464b263ec8787a10c79b285b6a7");
    try expectSerializedFixture(fulu.AttestationData, @embedFile("fixtures/fulu_static/AttestationData.ssz"), "55551a653406335a1b48d33b48ec15c47899f94d20e1b95de26d4585f8cae0d5");
    try expectSerializedFixture(fulu.AttesterSlashing, @embedFile("fixtures/fulu_static/AttesterSlashing.ssz"), "a9b88e72a2c47a40115b399a87638f9af9939a61611d2a93e8ff3e04b1a05adc");
    try expectSerializedFixture(fulu.BLSToExecutionChange, @embedFile("fixtures/fulu_static/BLSToExecutionChange.ssz"), "f2edd7f5d3aeeeb9bb9318dabc2eb3f2a4eca53d779b29a7f922e211f9ae23f2");
    try expectSerializedFixture(fulu.BeaconBlock, @embedFile("fixtures/fulu_static/BeaconBlock.ssz"), "fe1e202b3fc788b7f7a0138efb9e740f3c1ef6692d665132047bc4ac1e7fae46");
    try expectSerializedFixture(fulu.BeaconBlockBody, @embedFile("fixtures/fulu_static/BeaconBlockBody.ssz"), "19e5733d43009445bd7ade8e912c2f56f86d1c463949950681fd59ddd1f082e9");
    try expectSerializedFixture(fulu.BeaconBlockHeader, @embedFile("fixtures/fulu_static/BeaconBlockHeader.ssz"), "a1657c154b2826eef214f92d505abcab7982c249c9e1f95066afdf7fe2e4d55e");
    try expectSerializedFixture(fulu.Checkpoint, @embedFile("fixtures/fulu_static/Checkpoint.ssz"), "dfc2397aa3e16228a80ed8ea3a8daf4fb60d070a7e6e443c8a4c376be89e3c40");
    try expectSerializedFixture(fulu.ConsolidationRequest, @embedFile("fixtures/fulu_static/ConsolidationRequest.ssz"), "e942254de1d7d9309d1ed166856b8fc2776a9ebbbed9be5909f37ab803697608");
    try expectSerializedFixture(fulu.Deposit, @embedFile("fixtures/fulu_static/Deposit.ssz"), "97ffc062d793b000dc52da16594e521cebe8025a3e633a32d09b0282823a0b49");
    try expectSerializedFixture(fulu.DepositData, @embedFile("fixtures/fulu_static/DepositData.ssz"), "96cdc199338d9450898476512c8ab43cc48efbac8141df0047d7100020162fe2");
    try expectSerializedFixture(fulu.DepositRequest, @embedFile("fixtures/fulu_static/DepositRequest.ssz"), "9c1668f6f10d245e58e93a0661d2fa6a12fea64a30a51414e8e8ffd894e8e7f1");
    try expectSerializedFixture(fulu.Eth1Data, @embedFile("fixtures/fulu_static/Eth1Data.ssz"), "9968f84e5015b9665d30815e99f8431b38564ee5c5431b858051ca1ea93ad1ad");
    try expectSerializedFixture(fulu.ExecutionPayload, @embedFile("fixtures/fulu_static/ExecutionPayload.ssz"), "075def883cd9d147e7ecc7499f4bc3bc33511d25e8f620b0a234cc15932a29d5");
    try expectSerializedFixture(fulu.ExecutionPayloadHeader, @embedFile("fixtures/fulu_static/ExecutionPayloadHeader.ssz"), "2b2a9259c4683bd01bc0c0ca26eae1e10ee6bd6a880d8eebb5c78f0abc8c14d5");
    try expectSerializedFixture(fulu.ExecutionRequests, @embedFile("fixtures/fulu_static/ExecutionRequests.ssz"), "85e253b40599d0df756be043ea6949e49a07e756deef72b3588a4b05362206b5");
    try expectSerializedFixture(fulu.Fork, @embedFile("fixtures/fulu_static/Fork.ssz"), "ba22f5c76c9bc32bebad2ab6d122da934c46407b79bc6b818875ca18501d54c2");
    try expectSerializedFixture(fulu.HistoricalSummary, @embedFile("fixtures/fulu_static/HistoricalSummary.ssz"), "f10affc7bf6d8f36d4536a6641ce68030b69296412049a6fe1f27e42e9c9fcf4");
    try expectSerializedFixture(fulu.IndexedAttestation, @embedFile("fixtures/fulu_static/IndexedAttestation.ssz"), "337264f05ad5bf235b8e22ed56d7e572b73b381f06407008203a783db316a8d2");
    try expectSerializedFixture(fulu.PendingConsolidation, @embedFile("fixtures/fulu_static/PendingConsolidation.ssz"), "647516d8c31dfa471b5167e88b0a60e1255e0a1d166c8b8c37f4d1239fbf59dd");
    try expectSerializedFixture(fulu.PendingDeposit, @embedFile("fixtures/fulu_static/PendingDeposit.ssz"), "7de87d0ea763b600795e658ab6c86d9949755876c0508b600c9a2412a691e92e");
    try expectSerializedFixture(fulu.PendingPartialWithdrawal, @embedFile("fixtures/fulu_static/PendingPartialWithdrawal.ssz"), "89a3344152f6ca1f5e6f96267bf052061532bec295b78fa32cfc6d973be5b694");
    try expectSerializedFixture(fulu.ProposerSlashing, @embedFile("fixtures/fulu_static/ProposerSlashing.ssz"), "e824124e7236ac2243342d24d19783caa831f98cccf34c59823b4cde6bf08a50");
    try expectSerializedFixture(fulu.SignedBLSToExecutionChange, @embedFile("fixtures/fulu_static/SignedBLSToExecutionChange.ssz"), "ba6d8347a9cdc994de1929832bfaf9e8cf595f1cd3304a9850d0f5a33fdffbe7");
    try expectSerializedFixture(fulu.SignedBeaconBlock, @embedFile("fixtures/fulu_static/SignedBeaconBlock.ssz"), "e25a8e05db535a57a95ca53824e131dee8d023c7fae26f908ab292d3878f3bc2");
    try expectSerializedFixture(fulu.SignedBeaconBlockHeader, @embedFile("fixtures/fulu_static/SignedBeaconBlockHeader.ssz"), "e1f0282ac55e8872ee7654420afd522fd754d1c1d6029ed1c5052048957340f0");
    try expectSerializedFixture(fulu.SignedVoluntaryExit, @embedFile("fixtures/fulu_static/SignedVoluntaryExit.ssz"), "788008e34e86780c2b907dfa9083aae3aba508bc766b9f62abba743c60c72874");
    try expectSerializedFixture(fulu.SyncAggregate, @embedFile("fixtures/fulu_static/SyncAggregate.ssz"), "3be21caa7e3f05f5f8635aeb3c0859c676b32cc3bbd0bece2d8cb3cf8c3feb51");
    try expectSerializedFixture(fulu.SyncCommittee, @embedFile("fixtures/fulu_static/SyncCommittee.ssz"), "516a8df6ad88dcb33b8fb056a304e2362e54f59186b78a91001790cadcba446c");
    try expectSerializedFixture(fulu.Validator, @embedFile("fixtures/fulu_static/Validator.ssz"), "45afc6a8166816b7e8ddcedc6fa0e9ed5df4423e089b2053dae3642461dc7abe");
    try expectSerializedFixture(fulu.VoluntaryExit, @embedFile("fixtures/fulu_static/VoluntaryExit.ssz"), "3eb4d4732f0f2c231ff2065c98fd20aaf12306760d0f40fbc1edf1071997405f");
    try expectSerializedFixture(fulu.Withdrawal, @embedFile("fixtures/fulu_static/Withdrawal.ssz"), "e962ee6393ee93fb747fc46bb58a2d8bf078f462cfa09f6f57d46232f00f252f");
    try expectSerializedFixture(fulu.WithdrawalRequest, @embedFile("fixtures/fulu_static/WithdrawalRequest.ssz"), "4f0d05a3640d5aadff725084d73b9f3831be2cad6ac1ff0eb6546e7a50a5ba01");
}

test "Fulu BeaconBlock matches pinned random fixtures" {
    try expectSerializedFixture(
        fulu.BeaconBlock,
        @embedFile("fixtures/fulu_static/BeaconBlock_random_case_7.ssz"),
        "5aa249c40fae6d424436e969716207f450d9e1284ac5009964c375a7377d08a8",
    );
    try expectSerializedFixture(
        fulu.BeaconBlock,
        @embedFile("fixtures/fulu_static/BeaconBlock_random_case_22.ssz"),
        "1934cedbde590d7bea2f78c7c675d376061db508ef146fd75a42cf7996a4575f",
    );
}

test "Fulu BeaconState matches pinned static fixtures" {
    try expectSerializedFixture(fulu.BeaconState, @embedFile("fixtures/fulu_static/BeaconState_ssz_nil.ssz"), "01320be217af530e3534c0522a51208f5aef449e3891f02755487012998ed143");
    try expectSerializedFixture(fulu.BeaconState, @embedFile("fixtures/fulu_static/BeaconState_ssz_zero.ssz"), "719e0056a623b67447f671cff7a5700c82467716d9934d7dea63a0e0c42f039f");
    try expectSerializedFixture(fulu.BeaconState, @embedFile("fixtures/fulu_static/BeaconState_ssz_one.ssz"), "0707081c5c0c9bae38f7a4cda1dfe877ca4ebb30582c23508f8b0b614ab3cb9e");
    try expectSerializedFixture(fulu.BeaconState, @embedFile("fixtures/fulu_static/BeaconState_ssz_random.ssz"), "26e29f8812013544d8423ebecf94340d55bca179ad51ffdf8fb3fc627635a2cd");
}
