// Fulu SSZ types use preset-sized vectors and bounded lists, and their roots
// commit to those dimensions. Check every pinned mainnet case against its
// root oracle and canonical byte encoding.
//
//   compressed official fixture -> decode -> root check -> byte-identical encode
const std = @import("std");
const testing = std.testing;
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const snappy = @import("snappy");

const Fixture = struct { bytes: []const u8, root: []const u8 };

/// Check one fixture and release its decoded state before the next case.
fn expectMainnetFixture(comptime T: type, fixture: Fixture) !void {
    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, fixture.root);
    const serialized = try snappy.decompress(testing.allocator, fixture.bytes);
    defer testing.allocator.free(serialized);
    var reader: std.Io.Reader = .fixed(serialized);
    const decoded = try ssz.deserialize(testing.allocator, T, &reader);
    defer ssz.freeDecoded(testing.allocator, T, decoded);
    const root = try merkle.HashTreeRoot(testing.allocator, decoded);
    try testing.expectEqualSlices(u8, &expected_root, &root);
    const reserialized = try ssz.serializeAlloc(testing.allocator, decoded);
    defer testing.allocator.free(reserialized);
    try testing.expectEqualSlices(u8, serialized, reserialized);
}

/// Check every pinned mainnet Fulu fixture for one schema.
fn expectMainnetFixtures(comptime T: type, fixtures: []const Fixture) !void {
    for (fixtures) |fixture| try expectMainnetFixture(T, fixture);
}

const aggregateAndProofFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AggregateAndProof/ssz_random/case_0/serialized.ssz_snappy"), .root = "d34e44a95bd052ad1ea798de7f8657d19267e65821f2ac83ef83f274ab84e08d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AggregateAndProof/ssz_random/case_1/serialized.ssz_snappy"), .root = "740cec3e0d961df749035a73fc4f5cbb3fc9db8f25097973e769b521fa497f5d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AggregateAndProof/ssz_random/case_2/serialized.ssz_snappy"), .root = "0be0281188c0342c3a134c5bf0cf37943f456859ca1fcadf6d6e4d2f04207b91" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AggregateAndProof/ssz_random/case_3/serialized.ssz_snappy"), .root = "9b0cade4458a2b6a8449eba2feb044c917707b797a659b24f612610d9626f858" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AggregateAndProof/ssz_random/case_4/serialized.ssz_snappy"), .root = "9f72a740c25e9079421add7ad2040ab555ddb69f4a641ab09afb5fe3e077bb5f" },
};

const attestationFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Attestation/ssz_random/case_0/serialized.ssz_snappy"), .root = "5be855e3214ab282b479c5ab439f71a7dad2b679a9ab120932cc3582053a1a83" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Attestation/ssz_random/case_1/serialized.ssz_snappy"), .root = "93233b33d296b3f8377c7698014b7d7ad4e8a4fc15d935c64a5c72fa07bf4b03" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Attestation/ssz_random/case_2/serialized.ssz_snappy"), .root = "b28e6a3bb75b844211649e2688e42c3f25feb93951a90568783c8480d35cf002" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Attestation/ssz_random/case_3/serialized.ssz_snappy"), .root = "b0fc8f2951c2c9dbc6019a54652afebe03e9d3ee2785fa5c2d8957c790e14662" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Attestation/ssz_random/case_4/serialized.ssz_snappy"), .root = "a36a93cf6d44f462705b4856b9b17ee353fd155eeb2f0a02345c9cbed078d714" },
};

const attestationDataFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttestationData/ssz_random/case_0/serialized.ssz_snappy"), .root = "32b90e17db088a6aa78afa8135d0279c7e720c59954b2ceae4c5d318489e39e5" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttestationData/ssz_random/case_1/serialized.ssz_snappy"), .root = "fbc34af414d587283b1b073b660a93dbc1db9287670c69560cb68a84ae8798b1" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttestationData/ssz_random/case_2/serialized.ssz_snappy"), .root = "56d82f9a8a57208d8c413737a450fb4bc5656fb9beb0b2a6c611d01855df6af8" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttestationData/ssz_random/case_3/serialized.ssz_snappy"), .root = "a18d5c8583a99f94a1c07fcee380e3ddb5b039b69b533e6d4cb101b0f4267607" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttestationData/ssz_random/case_4/serialized.ssz_snappy"), .root = "1510593271ede63ab374738a4ce78c7f554ba8933fa2c0b016fe7b58389930d1" },
};

const attesterSlashingFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttesterSlashing/ssz_random/case_0/serialized.ssz_snappy"), .root = "5706e96b91a90991f8aca8d201d5ba17598fee0e225faa588b5754ef70a151d3" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttesterSlashing/ssz_random/case_1/serialized.ssz_snappy"), .root = "ebb22ccb30b7a9cd91d6278ddb8727b9b1d6e388c2845ef848670b633ce6df94" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttesterSlashing/ssz_random/case_2/serialized.ssz_snappy"), .root = "c288a7bce1979105b81414e6ec8809e98decc90796e417f21df2dc8e219222c3" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttesterSlashing/ssz_random/case_3/serialized.ssz_snappy"), .root = "382a34c3692381714a89f55c1ca42ddcdd6ca7ab7bdcafb3c5a73b21d79273cb" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/AttesterSlashing/ssz_random/case_4/serialized.ssz_snappy"), .root = "bc2e97871dacb2390aa0bcd2a0ada18989ab3bb35ca2514e3770adf289cf3a45" },
};

const bLSToExecutionChangeFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BLSToExecutionChange/ssz_random/case_0/serialized.ssz_snappy"), .root = "cee9f638d870c42c932165aed7630da579924fe755e3b841ccb0d3834b86ca92" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BLSToExecutionChange/ssz_random/case_1/serialized.ssz_snappy"), .root = "e8bd733073d467916dea153e6ce89f4f92ea7b7efd9d90bf099d258940566a37" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BLSToExecutionChange/ssz_random/case_2/serialized.ssz_snappy"), .root = "988ff0892a76b58da2235065014fbdf2f2f052c0bcce22ffae401e2492f66b20" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BLSToExecutionChange/ssz_random/case_3/serialized.ssz_snappy"), .root = "85c9dbed9b32c003172c2f9a1cdb938f3d0d6935e7432d5318618a071fc7f38a" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BLSToExecutionChange/ssz_random/case_4/serialized.ssz_snappy"), .root = "0b3a03e4b4a69e4348cbd23d7c3e1481bbd9b8d75b9dfc1a1f3dbcccbe65ad54" },
};

const beaconBlockFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlock/ssz_random/case_0/serialized.ssz_snappy"), .root = "853653c6733c3275753665c3e1269f9f1fed274a67809dd9dec8245097f1aa7b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlock/ssz_random/case_1/serialized.ssz_snappy"), .root = "903868b8f39afdfd4fba2f7970d36ea37e40f8d4031501bca45e277002342dc4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlock/ssz_random/case_2/serialized.ssz_snappy"), .root = "d32d9bbc98d9e90dceaf923a61976bbfda51e015f5d611dc07baa37812670db7" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlock/ssz_random/case_3/serialized.ssz_snappy"), .root = "d553446dc899a4f533c616999659468cac7c429530a143d6877cdc74e9b63f27" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlock/ssz_random/case_4/serialized.ssz_snappy"), .root = "9012a2ed0832bad326bb37133acd61358656d71164dfa5c477bccd3a47a5a169" },
};

const beaconBlockBodyFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockBody/ssz_random/case_0/serialized.ssz_snappy"), .root = "759c9b9293844de48b86cf6bbf028adbb16e66ae6a503973ed8ecb6f77957b40" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockBody/ssz_random/case_1/serialized.ssz_snappy"), .root = "a07a5b85c8788769f924915a306f288ac040f2a2c8ddcba481b7586f082dc479" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockBody/ssz_random/case_2/serialized.ssz_snappy"), .root = "ead9f8c4d571bb9789062ff980790687fcbeb2b27bf48d93c2eb31f9e8fa81ba" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockBody/ssz_random/case_3/serialized.ssz_snappy"), .root = "3e296d7eb54ebac5a189061ea5d2893da7a6b6be4e42e49e5ecdeb16204215b6" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockBody/ssz_random/case_4/serialized.ssz_snappy"), .root = "a80b395e7459f547613654a46158097f45d3762d551c37d5b30e3d6df55d203b" },
};

const beaconBlockHeaderFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockHeader/ssz_random/case_0/serialized.ssz_snappy"), .root = "a2672769763d19c79dd7a584f37fd3391c0510c1fd6eba54ec0cd78748a84800" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockHeader/ssz_random/case_1/serialized.ssz_snappy"), .root = "c57d5786044bbb36e7278262e0c5f998284e892e3980949582b87a0539ec71c5" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockHeader/ssz_random/case_2/serialized.ssz_snappy"), .root = "61b2e967e8d7e64bdbf3619f16f6764eda1a9883dd94bb7fc079d3643f933b52" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockHeader/ssz_random/case_3/serialized.ssz_snappy"), .root = "7a3eef51172e7a551bd79b21476b5d35ad58db753d354a27a1ce6e1b3f99d3b7" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconBlockHeader/ssz_random/case_4/serialized.ssz_snappy"), .root = "bca7ed2c911fa206a325569cc8cdec66021b58071e7ed8abf559043096df2b38" },
};

const beaconStateFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconState/ssz_random/case_0/serialized.ssz_snappy"), .root = "cc7fb85ad35de0397582328dcaea541e21627920357b6ff37f9c01859ae12ee8" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconState/ssz_random/case_1/serialized.ssz_snappy"), .root = "1585e21fe40860cdbed0b7777add5bb72c1be257594352cbe6e40a91fe238200" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconState/ssz_random/case_2/serialized.ssz_snappy"), .root = "e396d480f7e0d0634750bbe3169c5a028417ad63d3866e72b6c7da0a7141c06a" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconState/ssz_random/case_3/serialized.ssz_snappy"), .root = "759c9be66d5029e72c9b77019c44825245aa2c71259489b01be55b4f9e146412" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/BeaconState/ssz_random/case_4/serialized.ssz_snappy"), .root = "2c1cee2dfbdd3b776db01038703d3b1d03f4f89fb37746f804d0e905eb417a94" },
};

const checkpointFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Checkpoint/ssz_random/case_0/serialized.ssz_snappy"), .root = "6d753282f74b9157acbb414dbcc9361d2095b302ec9a2970b379e1478129a97c" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Checkpoint/ssz_random/case_1/serialized.ssz_snappy"), .root = "ac984832a58c579064f408fda2fc591eb8fdc8a3bfd98d6347f51056af403d04" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Checkpoint/ssz_random/case_2/serialized.ssz_snappy"), .root = "ce82bba9e0cedc75122507b38fbd58b5ef4c1b4116009826928bbb22e2f7b893" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Checkpoint/ssz_random/case_3/serialized.ssz_snappy"), .root = "dc46e8dc5a975e92a50ceb2ddfe249a7854e128264ed91768a4efb98d71cc3ae" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Checkpoint/ssz_random/case_4/serialized.ssz_snappy"), .root = "0252dbb7ca22b0829f4d568e4498803117cb86b0b597357551ca1842b1d442eb" },
};

const consolidationRequestFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ConsolidationRequest/ssz_random/case_0/serialized.ssz_snappy"), .root = "5b3a102baf5e2658189b8db69f57fdec65fca7713ec6689172fe1a305741a81e" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ConsolidationRequest/ssz_random/case_1/serialized.ssz_snappy"), .root = "c8155c0bdc2cf01af9734f8a2947d8c07086b1f3fe13e4670cfe6db6327dd403" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ConsolidationRequest/ssz_random/case_2/serialized.ssz_snappy"), .root = "fc6948b1cb5a57926b3c6fa0834a027649a8219a0c50733e62a914222daca08c" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ConsolidationRequest/ssz_random/case_3/serialized.ssz_snappy"), .root = "c331060530c677896b873856b89f614d86fa63500165cd1ad211c4d6801703b4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ConsolidationRequest/ssz_random/case_4/serialized.ssz_snappy"), .root = "85bbaaba4f38328aa9c047d092e6b9f7fa5c7233ecd0e8da220cf7debdf6e0f5" },
};

const dataColumnSidecarFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DataColumnSidecar/ssz_random/case_0/serialized.ssz_snappy"), .root = "a7b236b45ea37fc2854b99b3299b306b1d2dd238250e1b10f39a89fdf1e229a6" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DataColumnSidecar/ssz_random/case_1/serialized.ssz_snappy"), .root = "73d3f9c1c561f3d68f05e942356f47c9d14295dbf4068550c7839b8078b47227" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DataColumnSidecar/ssz_random/case_2/serialized.ssz_snappy"), .root = "2105f170c6f0409f8611899d5d455b3593f7c589b81aa1985eb99c832f90e3dc" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DataColumnSidecar/ssz_random/case_3/serialized.ssz_snappy"), .root = "3b174aadc31469c54035fdd9f0a28e8cf09f8bcc33a18caa6b94c039ce4e8bb7" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DataColumnSidecar/ssz_random/case_4/serialized.ssz_snappy"), .root = "35f2cb1187278d9b8ab51bd8aa8ac2909c54fae46fdaac625ba62f221c2a034d" },
};

const depositFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Deposit/ssz_random/case_0/serialized.ssz_snappy"), .root = "ca5735a27105394c2ce6f09f5ccd6a0e5a7c63c427fd83c552a66475243e0c99" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Deposit/ssz_random/case_1/serialized.ssz_snappy"), .root = "9027469986285012ef1b855dff63b6251a58fafb29382bbaf54ad0934ada19dd" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Deposit/ssz_random/case_2/serialized.ssz_snappy"), .root = "c3597f564f60d4f411ce4749323b0d37ca6ba27e36c3ba3ecdd40139cdd9feeb" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Deposit/ssz_random/case_3/serialized.ssz_snappy"), .root = "818292a6e865e3c96de1246382ffff110eded1582e3162abf0752664a2f8c8c4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Deposit/ssz_random/case_4/serialized.ssz_snappy"), .root = "0351eef3ae9656055f5433b8676eef9af614969a213b7b58bfe4339b0999a218" },
};

const depositDataFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositData/ssz_random/case_0/serialized.ssz_snappy"), .root = "6208b4944917072435e2742a3c7b94d28f9be222da3e609ff9e2747c30533865" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositData/ssz_random/case_1/serialized.ssz_snappy"), .root = "b32275e5fb5f1c7b566d85b4818c4de64cccf1eee8d1aa9c5ba5e4a907aed6c2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositData/ssz_random/case_2/serialized.ssz_snappy"), .root = "651d9bfc6cd1251a5711aba1987641cb33dc514df72b021c089cb13916f9088d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositData/ssz_random/case_3/serialized.ssz_snappy"), .root = "4a6463f2c2eb875536cdacf63c0d65e54780bf217c64d92cf4b885319b9b1b08" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositData/ssz_random/case_4/serialized.ssz_snappy"), .root = "19f8baf250fd6118946a7a0d690ab30e07e1b6f5107cf3f85c8b86632ffb6d49" },
};

const depositRequestFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositRequest/ssz_random/case_0/serialized.ssz_snappy"), .root = "093f80385fe508aeb2f034ca209f6cef2b4f43f4738b2dcb090888d878e23e34" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositRequest/ssz_random/case_1/serialized.ssz_snappy"), .root = "00ee2872ec612a312848eac24761698c4c831e9e01b70274a3a7f7a17c67c5f1" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositRequest/ssz_random/case_2/serialized.ssz_snappy"), .root = "5314bde6a6035bf5e50c9df01257e53671b612059916a239f05b407d88cf55bf" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositRequest/ssz_random/case_3/serialized.ssz_snappy"), .root = "01ec29d76b4fc6012c556ffbd029a360ecb85a962f1e8a8d32f620dd479d2a29" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/DepositRequest/ssz_random/case_4/serialized.ssz_snappy"), .root = "6902e1689241a7e19b412acd5eef035d859b77be33cc0e6418cb6b3603421495" },
};

const eth1DataFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Eth1Data/ssz_random/case_0/serialized.ssz_snappy"), .root = "cb53901233f6a74469899d902b5bf9224633ff13cffcf6ba181eabaa6dd253bd" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Eth1Data/ssz_random/case_1/serialized.ssz_snappy"), .root = "a4d1c5d5703f5c1623c69f492f2bd2e332865b8832902ed789215ff91a10d4df" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Eth1Data/ssz_random/case_2/serialized.ssz_snappy"), .root = "a5e933a997e4661d89326d03655ca7dce6fe2082d32212ae0552120938e30e65" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Eth1Data/ssz_random/case_3/serialized.ssz_snappy"), .root = "b68e210d3e15bf216c233a6b3cb6df16c18f77b6f5679ec0aba5d0ee84e5cb37" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Eth1Data/ssz_random/case_4/serialized.ssz_snappy"), .root = "72913a4a53c48358125c4cf4400b7eb781d488cbb07873212ad68ce9d9699847" },
};

const executionPayloadFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayload/ssz_random/case_0/serialized.ssz_snappy"), .root = "ad492ef81f87cc7ecf397f145d13760f8cc519cddbaa5c36a77a1a42c466cff3" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayload/ssz_random/case_1/serialized.ssz_snappy"), .root = "d54b6fcc21357780a30ee2a6a129e9a019e8bf16f9c8b5a782fbc5493f144d17" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayload/ssz_random/case_2/serialized.ssz_snappy"), .root = "b26657a74fb3f60f2f0f6bc262be5c83cc2166b512e1207a4d997aa6406fae5f" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayload/ssz_random/case_3/serialized.ssz_snappy"), .root = "d3165264ff2daa0fc148e55f968efc00ac6759f081e1f0b66c415f7ea4528bde" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayload/ssz_random/case_4/serialized.ssz_snappy"), .root = "71471d637f767f5283d9125ea662e4f6b97beb4610240490fa074f1c06392375" },
};

const executionPayloadHeaderFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayloadHeader/ssz_random/case_0/serialized.ssz_snappy"), .root = "18de925788ca2214a51fafbaf9f23634949d20a07bf282852f919351fe353b06" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayloadHeader/ssz_random/case_1/serialized.ssz_snappy"), .root = "d9c6cae72cf2bc10b9472d2d987fe74947c00e05027eb510ef05e7438d89c7f4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayloadHeader/ssz_random/case_2/serialized.ssz_snappy"), .root = "380e5ffd0c428295a9616c65827a5ff0d2ffcca9b09913e2a75680c88a938b64" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayloadHeader/ssz_random/case_3/serialized.ssz_snappy"), .root = "ddc1e294e85cb7cc71662379a37172019ca43116d06fb4d043788ca5d9292931" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionPayloadHeader/ssz_random/case_4/serialized.ssz_snappy"), .root = "c1b79fb1f639ee1de4546dd8babe8608a009396c6a7527f498f806430a9d93a9" },
};

const executionRequestsFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionRequests/ssz_random/case_0/serialized.ssz_snappy"), .root = "1fc6e089542ff81b9520f7b0afd0a38ea54e4c8aba53dac2564f8da887d0e217" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionRequests/ssz_random/case_1/serialized.ssz_snappy"), .root = "3e9ebc73bda7f74065000a58c5217ce56917c9c55229c205dff034c6df9187f1" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionRequests/ssz_random/case_2/serialized.ssz_snappy"), .root = "1ae05e35bb763e94e4eb7aaaf86fe00fb367c9240cdb186c75e889f260e730d2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionRequests/ssz_random/case_3/serialized.ssz_snappy"), .root = "575767ae8134aa25b0717e4caf0c6ac7e8a7f34209eaac2ab32d2552f517e38d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ExecutionRequests/ssz_random/case_4/serialized.ssz_snappy"), .root = "703b81e41a1e3cd7dfe49415482862760b861394933594188330afb630a4040e" },
};

const forkFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Fork/ssz_random/case_0/serialized.ssz_snappy"), .root = "99729f17abf5296a79d713d1d38b4e274cd14b9f532aa715c3fc8162ad12570d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Fork/ssz_random/case_1/serialized.ssz_snappy"), .root = "53c7ec3598867f65e634428682544fa0c91e3410b94fd7caeeb708f53a3903aa" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Fork/ssz_random/case_2/serialized.ssz_snappy"), .root = "33214319f18b415a8333f6d1769d0a2c800b9fe6a259be4e3ebedfe7ede358d3" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Fork/ssz_random/case_3/serialized.ssz_snappy"), .root = "86b6628cfc7410a1faae9a09b3f04a9e8b5dd34e8cdad44d36dbf06f28d20623" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Fork/ssz_random/case_4/serialized.ssz_snappy"), .root = "839b3d0d4046211280b2694df507e40ad837c0fb14bf08fec1f2dd3525c141ab" },
};

const historicalSummaryFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/HistoricalSummary/ssz_random/case_0/serialized.ssz_snappy"), .root = "d71fc91ef5be8af2942a0a8045c8f6f9df8222f21e192eb1d3af57a43f097b0e" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/HistoricalSummary/ssz_random/case_1/serialized.ssz_snappy"), .root = "2c4d5ee638c9b7ac55812ec06ec479ef50b72be84f2105cdbadcaa77de8dd945" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/HistoricalSummary/ssz_random/case_2/serialized.ssz_snappy"), .root = "20c8f68ab23f4020d0d610615a1aba860369f17a1e98391c1e650bed365511c0" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/HistoricalSummary/ssz_random/case_3/serialized.ssz_snappy"), .root = "7ca3a7fe0e3db09b1e2a4650835569e2b985088f9a8c36d07d866a2b4d4b8b61" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/HistoricalSummary/ssz_random/case_4/serialized.ssz_snappy"), .root = "0893cfb5e42788dd8e9271e7cfa85e0d6acafa9faf63564458f9e72369234595" },
};

const indexedAttestationFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/IndexedAttestation/ssz_random/case_0/serialized.ssz_snappy"), .root = "230404687918aec8a9d73c2892720af103a113248195479137490176d0bf89f3" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/IndexedAttestation/ssz_random/case_1/serialized.ssz_snappy"), .root = "63f6eb24e89393253ba6860a1e0a5d2babcac7752ad98322533d8799b51eeaef" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/IndexedAttestation/ssz_random/case_2/serialized.ssz_snappy"), .root = "dceff138a3902d027bcf2165e94f559258939e08661618709be1b6e638d3334e" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/IndexedAttestation/ssz_random/case_3/serialized.ssz_snappy"), .root = "81cfb32f7e44c1e4cd93cf666b66cb2d673617822fd7b1e1e4690b9c1624ba5a" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/IndexedAttestation/ssz_random/case_4/serialized.ssz_snappy"), .root = "89d052c55f5321a7dab9656509e8b0e53d905b6977b631eee8fcbc7186e69bfb" },
};

const pendingConsolidationFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingConsolidation/ssz_random/case_0/serialized.ssz_snappy"), .root = "7d922bb5bb3e6ca5c4f178c2e053a8e334c519ee917157368d21490522e1cf3e" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingConsolidation/ssz_random/case_1/serialized.ssz_snappy"), .root = "6b59a263519a2ab5a138412ded23a30896dc36a28b5e244d2a74721f62c6d860" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingConsolidation/ssz_random/case_2/serialized.ssz_snappy"), .root = "fffebf230da7cbd5621ba01805f5b88dbb22d0a84ea38774bb2ed758d049d44f" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingConsolidation/ssz_random/case_3/serialized.ssz_snappy"), .root = "b55431518c0ede75cdc035e0858ee19d407ca6b57585e6f9a4534d7c1edbf7c0" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingConsolidation/ssz_random/case_4/serialized.ssz_snappy"), .root = "064156463f691fcaa72177d25bc87de45a52854966d93cda98c01b7034ddae41" },
};

const pendingDepositFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingDeposit/ssz_random/case_0/serialized.ssz_snappy"), .root = "1a95579e58f9494be8872eedc0e34c6f010c1154617910e6a34767ceee068eb2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingDeposit/ssz_random/case_1/serialized.ssz_snappy"), .root = "f164f6de392b414ea460d131e485d416271277d78eea5118fb1dfc81b97f445a" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingDeposit/ssz_random/case_2/serialized.ssz_snappy"), .root = "2d0fb78be3a8dffabdc130223a3a128fbca60afd37bbb5339b982da5c4b7f9b2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingDeposit/ssz_random/case_3/serialized.ssz_snappy"), .root = "31f63dd98e7fddbf81bfcb2d5d766cedd6cfb6cda7a285c9974ef47050ac596d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingDeposit/ssz_random/case_4/serialized.ssz_snappy"), .root = "4e42e02262e4b0a21ccd69d5182f00d33f66e3edaf465c3fd12b7f5f78be51d5" },
};

const pendingPartialWithdrawalFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingPartialWithdrawal/ssz_random/case_0/serialized.ssz_snappy"), .root = "fee5527172fd2af098adcdfa5d4108ffc52d19b4cb03fcdb186685a11147fe7b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingPartialWithdrawal/ssz_random/case_1/serialized.ssz_snappy"), .root = "d4c8a4e38ed4d4d09d3b74df1d825d244243218fa2ce1878eeb3d0356ec7fcab" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingPartialWithdrawal/ssz_random/case_2/serialized.ssz_snappy"), .root = "3548a86db6940952e5ab87b50e46cfbdb2324603ccfac73836834a87f160181a" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingPartialWithdrawal/ssz_random/case_3/serialized.ssz_snappy"), .root = "8ceb740b26a61041ea7dc2d6b1372686cf3381150bd9d9a19cfafeb9e0335c04" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/PendingPartialWithdrawal/ssz_random/case_4/serialized.ssz_snappy"), .root = "de460e5b596f11e6791d4b658544351a44e8bfc86b0952b8ac655354b399adad" },
};

const proposerSlashingFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ProposerSlashing/ssz_random/case_0/serialized.ssz_snappy"), .root = "07a2633957c0df517ea5d2c89982c720b1f295b84f6df8e3ee2ac612f6dff0f1" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ProposerSlashing/ssz_random/case_1/serialized.ssz_snappy"), .root = "c820906331888b7a1f97cb04d995873d09c6f5fdaa6b698dfbde7bc0e7eb9b86" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ProposerSlashing/ssz_random/case_2/serialized.ssz_snappy"), .root = "2b54b626948ef5bb036918b3e80058315ff308604a1d27e8cde0193e6f48b56d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ProposerSlashing/ssz_random/case_3/serialized.ssz_snappy"), .root = "d347f0d9c998c97d6ad3c57180fc65c0b1ea906287e52ccaf1b706c0b0b5d7d7" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/ProposerSlashing/ssz_random/case_4/serialized.ssz_snappy"), .root = "69daa65cb600d30a6509372144b6240847fa2f04dbabb0de82ea308880a154b4" },
};

const signedAggregateAndProofFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedAggregateAndProof/ssz_random/case_0/serialized.ssz_snappy"), .root = "14fec8e82a7156e90f8fba64a9bbdf2d28c37f7b5eba45d5429d13b56bafd130" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedAggregateAndProof/ssz_random/case_1/serialized.ssz_snappy"), .root = "f26d298dbecc57aa1773b1a366311997452770be122aace07508aab5d38b3f32" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedAggregateAndProof/ssz_random/case_2/serialized.ssz_snappy"), .root = "114dd0eb128251a813c508a2bcf8957b0b27487ccb1976ca9c6e4ec46ec8957b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedAggregateAndProof/ssz_random/case_3/serialized.ssz_snappy"), .root = "98f8b9f5516c61de3e771ba36d390806238d52f80ed77ebf67b5aa08955835bb" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedAggregateAndProof/ssz_random/case_4/serialized.ssz_snappy"), .root = "ea911aae97f2531acd1396a1f70032c3f2acb5580f3e96963d42ba6cc57b2f7e" },
};

const signedBLSToExecutionChangeFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBLSToExecutionChange/ssz_random/case_0/serialized.ssz_snappy"), .root = "a6e579609570a06c46111f0c3d0407a1cee12974e3a7ab8d5cb78e214db815ff" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBLSToExecutionChange/ssz_random/case_1/serialized.ssz_snappy"), .root = "1d98bc6732f7be562204d59c1ea8a398fe6fb24b43795a2036b8cba1c53c7aaf" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBLSToExecutionChange/ssz_random/case_2/serialized.ssz_snappy"), .root = "d43bab2d620767a5ac94dd25ca40b9450a3e33cbf7a2e797966e956209026865" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBLSToExecutionChange/ssz_random/case_3/serialized.ssz_snappy"), .root = "e2c9c6853ee7e293758a83a2c7ed1d46e75c21af4761f60878ecdb2a500beac2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBLSToExecutionChange/ssz_random/case_4/serialized.ssz_snappy"), .root = "ba6c1564e276c54f89fda9dda30f8ed02f56ef541f93980347abae25874e6983" },
};

const signedBeaconBlockFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlock/ssz_random/case_0/serialized.ssz_snappy"), .root = "7d9e987882a8fb67e7f0be2f22aa3d4c7f2a188775871640ded16774ec499ec6" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlock/ssz_random/case_1/serialized.ssz_snappy"), .root = "9cf4bb773314e4b0d87c8e9cbf6e7eb10edc7a1af82546626ede44dd65c24594" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlock/ssz_random/case_2/serialized.ssz_snappy"), .root = "d69b0e20fd3c1793511323ad921f6850b74b018b2caa706fe59bb723ee07b2fe" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlock/ssz_random/case_3/serialized.ssz_snappy"), .root = "a63fc64f28c3d8a37ccf71eebecb26abcffdd09608c5ab7737fdb507da818513" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlock/ssz_random/case_4/serialized.ssz_snappy"), .root = "73994cd3fc5bd6e6185cac8a2ea0798dfa83c4722d6f7d1686deab571aea066d" },
};

const signedBeaconBlockHeaderFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlockHeader/ssz_random/case_0/serialized.ssz_snappy"), .root = "068e91ae7d12b846acb2699e881c47ba01b81bd5a6d1644fbd404f80dc0c05c5" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlockHeader/ssz_random/case_1/serialized.ssz_snappy"), .root = "bbea9eace5402d3bd58aa78e668d3c41858f9d3acd38a0b02ebabd25e6e644df" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlockHeader/ssz_random/case_2/serialized.ssz_snappy"), .root = "c696f4e42999c85e4ac81572dd613f11ef51c19cfa4503d0372a53fe561e3366" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlockHeader/ssz_random/case_3/serialized.ssz_snappy"), .root = "fd762399fa1cac53dfc883018ef2ce0a12121ba971db465b559a9b2ba9380276" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedBeaconBlockHeader/ssz_random/case_4/serialized.ssz_snappy"), .root = "461945063313afaac2e7cf3af7be5376c9031700b4e4270355793d2480c026e8" },
};

const signedVoluntaryExitFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedVoluntaryExit/ssz_random/case_0/serialized.ssz_snappy"), .root = "41f269e84836014fad3bea9720042ca21b15ff3eae8489b5aae2ef0564187211" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedVoluntaryExit/ssz_random/case_1/serialized.ssz_snappy"), .root = "52e527c281e579558ddb97fa7b3eb7093b97c6ccf45abd75a7b28324b70aba54" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedVoluntaryExit/ssz_random/case_2/serialized.ssz_snappy"), .root = "a4289fe99018b130bc9eb4e057102bbf331cf1bd9751974ddb357b4cd5b925c1" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedVoluntaryExit/ssz_random/case_3/serialized.ssz_snappy"), .root = "3b5c55c8e77754cf7974bf85f27f087cb1bd5afe3c98e45f6c33c734ea798ca0" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SignedVoluntaryExit/ssz_random/case_4/serialized.ssz_snappy"), .root = "18452d9b493b77c629ac6472d0bb7c001c0d326385e6ec38e78a910556a6fa8d" },
};

const syncAggregateFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncAggregate/ssz_random/case_0/serialized.ssz_snappy"), .root = "a94d16491c1a75699d1bb7ed7e377968fd99d77c7713b2c1ae135f267b1070a6" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncAggregate/ssz_random/case_1/serialized.ssz_snappy"), .root = "91cad08b9ac8c2c28fb445eafca307f81bd4d2c67aafda76451aceadf362bde2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncAggregate/ssz_random/case_2/serialized.ssz_snappy"), .root = "f6aedf363e2a9d886cd21838a757c5d7907776e86fce794db64adbc9543b7af0" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncAggregate/ssz_random/case_3/serialized.ssz_snappy"), .root = "1aa19e490cffcf5ffe5c4f0ba06de1d78b8eca09078b80cc92774a8f38412e0d" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncAggregate/ssz_random/case_4/serialized.ssz_snappy"), .root = "d2aaf862a7e972dd71da762088b2d2c1f41711ff697b1a4a4e157c7de5d74447" },
};

const syncCommitteeFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncCommittee/ssz_random/case_0/serialized.ssz_snappy"), .root = "1d242d7c239b3f7bde8f7fbcd6acada32b630bc036697dfd667b340ed9aaa4bd" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncCommittee/ssz_random/case_1/serialized.ssz_snappy"), .root = "8007a1cdecfdf591e3c9f40e89ccfd134037fc847cca3ccf172b9517d872e3a6" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncCommittee/ssz_random/case_2/serialized.ssz_snappy"), .root = "206f1d9e2348262a28b5233b3c6e2e4806a17f8235b4b7e604782d7ac933b42b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncCommittee/ssz_random/case_3/serialized.ssz_snappy"), .root = "2715dfc9c76129aa3b83ecea55d01165fe23e294ce65ad4ec47fe484a7768a09" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/SyncCommittee/ssz_random/case_4/serialized.ssz_snappy"), .root = "31ea192dc0394111f7b1f0e7278b37e875ff2b53234e01b1876444949ffeb049" },
};

const validatorFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Validator/ssz_random/case_0/serialized.ssz_snappy"), .root = "0bbebba378260135dee1b978480369c73fa0a5df7063a7eba538e4b4ee252b6b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Validator/ssz_random/case_1/serialized.ssz_snappy"), .root = "28e8bb1df5efb73322be6055f3445d2d89f8ce16940fff128deb06069d3dff6b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Validator/ssz_random/case_2/serialized.ssz_snappy"), .root = "f527cb9c969d063c0f5bcb5a9491d7da76bf84e803b1a038ad63af50eab3d2e4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Validator/ssz_random/case_3/serialized.ssz_snappy"), .root = "ec96b9aa41c561def13b14cd55437509845c51c216ed5a4de9306d8cf86ed405" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Validator/ssz_random/case_4/serialized.ssz_snappy"), .root = "b42afb6cd20e0bfa4c429e9a3b29c478d7cb638500b93997225c624bb44d9129" },
};

const voluntaryExitFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/VoluntaryExit/ssz_random/case_0/serialized.ssz_snappy"), .root = "26d13bef7c4f7ae1b28767afcc0ade5bf56efd495ed5a63a1e1ba035d59a5ef0" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/VoluntaryExit/ssz_random/case_1/serialized.ssz_snappy"), .root = "fde30277470989d86b266290eec93407db6aa1c76f83e3269bddf7f9669ee1d4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/VoluntaryExit/ssz_random/case_2/serialized.ssz_snappy"), .root = "05b955daab02844b8ffac589942d56cbef85510e7b1fdce95bebf243bc617ef9" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/VoluntaryExit/ssz_random/case_3/serialized.ssz_snappy"), .root = "a0cf57a52cbe8faafb0a31c356c175ac6e5ff707545b6fa826f78686dec44995" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/VoluntaryExit/ssz_random/case_4/serialized.ssz_snappy"), .root = "4f4b395e957a4913e155abfcaf1c74c5e7803b37c8263253e1e482f3f4fc4c01" },
};

const withdrawalFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Withdrawal/ssz_random/case_0/serialized.ssz_snappy"), .root = "0ddeda0298ffe29153bb1429f2ef49aae45a3a1856b7b6f89d6c0c459c40dad2" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Withdrawal/ssz_random/case_1/serialized.ssz_snappy"), .root = "e6c8f8f2e5f6031523304762f43c6bd0bdf4362dfaefa911da6ab3867d1c9a92" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Withdrawal/ssz_random/case_2/serialized.ssz_snappy"), .root = "b66d1feb622a537a7a2c2c084943dff571253a4217353173e080fde35c72e6d4" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Withdrawal/ssz_random/case_3/serialized.ssz_snappy"), .root = "5826c9f3cd5eeff33919f52aa9010afeec586f716da8e2bc0b8f4229a5ab0643" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/Withdrawal/ssz_random/case_4/serialized.ssz_snappy"), .root = "8e54365c7a70efb90da8b79fd608c976402818aeb6b58d1eefb1dbdca1eb95a9" },
};

const withdrawalRequestFixtures = [_]Fixture{
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/WithdrawalRequest/ssz_random/case_0/serialized.ssz_snappy"), .root = "71b6dfd81b49e04aed0f6b42df7e28a9be09b7646a27546bb97fbfdc05f161a9" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/WithdrawalRequest/ssz_random/case_1/serialized.ssz_snappy"), .root = "98c2dd750b0e1858d74c22ace0b55d9fb69197454ef294d071c65972342278a1" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/WithdrawalRequest/ssz_random/case_2/serialized.ssz_snappy"), .root = "d8e94bdf393040b9e14bf26d76a305480f3434299ae058b652cfbc8e8f4b926b" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/WithdrawalRequest/ssz_random/case_3/serialized.ssz_snappy"), .root = "3d5fc5dde1ddfd33a06a0a5b4a6e857ca3532aada4cf57a6a558ecaeeebf5ed7" },
    .{ .bytes = @embedFile("fixtures/fulu_mainnet/ssz_static/WithdrawalRequest/ssz_random/case_4/serialized.ssz_snappy"), .root = "d062a8605b6f557a979ed13ee3cec7a4cd38b4825258f1084129adc5b130913e" },
};

test "mainnet AggregateAndProof fixtures" {
    try expectMainnetFixtures(fulu.AggregateAndProof, &aggregateAndProofFixtures);
}

test "mainnet Attestation fixtures" {
    try expectMainnetFixtures(fulu.Attestation, &attestationFixtures);
}

test "mainnet AttestationData fixtures" {
    try expectMainnetFixtures(fulu.AttestationData, &attestationDataFixtures);
}

test "mainnet AttesterSlashing fixtures" {
    try expectMainnetFixtures(fulu.AttesterSlashing, &attesterSlashingFixtures);
}

test "mainnet BLSToExecutionChange fixtures" {
    try expectMainnetFixtures(fulu.BLSToExecutionChange, &bLSToExecutionChangeFixtures);
}

test "mainnet BeaconBlock fixtures" {
    try expectMainnetFixtures(fulu.BeaconBlock, &beaconBlockFixtures);
}

test "mainnet BeaconBlockBody fixtures" {
    try expectMainnetFixtures(fulu.BeaconBlockBody, &beaconBlockBodyFixtures);
}

test "mainnet BeaconBlockHeader fixtures" {
    try expectMainnetFixtures(fulu.BeaconBlockHeader, &beaconBlockHeaderFixtures);
}

test "mainnet BeaconState fixtures" {
    var failure: ?anyerror = null;
    const worker = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 * 1024 }, struct {
        /// Hash the mainnet BeaconState vectors with a larger worker stack.
        fn run(result: *?anyerror) void {
            expectMainnetFixtures(fulu.BeaconState, &beaconStateFixtures) catch |err| {
                result.* = err;
            };
        }
    }.run, .{&failure});
    worker.join();
    if (failure) |err| return err;
}

test "mainnet Checkpoint fixtures" {
    try expectMainnetFixtures(fulu.Checkpoint, &checkpointFixtures);
}

test "mainnet ConsolidationRequest fixtures" {
    try expectMainnetFixtures(fulu.ConsolidationRequest, &consolidationRequestFixtures);
}

test "mainnet DataColumnSidecar fixtures" {
    try expectMainnetFixtures(fulu.DataColumnSidecar, &dataColumnSidecarFixtures);
}

test "mainnet Deposit fixtures" {
    try expectMainnetFixtures(fulu.Deposit, &depositFixtures);
}

test "mainnet DepositData fixtures" {
    try expectMainnetFixtures(fulu.DepositData, &depositDataFixtures);
}

test "mainnet DepositRequest fixtures" {
    try expectMainnetFixtures(fulu.DepositRequest, &depositRequestFixtures);
}

test "mainnet Eth1Data fixtures" {
    try expectMainnetFixtures(fulu.Eth1Data, &eth1DataFixtures);
}

test "mainnet ExecutionPayload fixtures" {
    try expectMainnetFixtures(fulu.ExecutionPayload, &executionPayloadFixtures);
}

test "mainnet ExecutionPayloadHeader fixtures" {
    try expectMainnetFixtures(fulu.ExecutionPayloadHeader, &executionPayloadHeaderFixtures);
}

test "mainnet ExecutionRequests fixtures" {
    try expectMainnetFixtures(fulu.ExecutionRequests, &executionRequestsFixtures);
}

test "mainnet Fork fixtures" {
    try expectMainnetFixtures(fulu.Fork, &forkFixtures);
}

test "mainnet HistoricalSummary fixtures" {
    try expectMainnetFixtures(fulu.HistoricalSummary, &historicalSummaryFixtures);
}

test "mainnet IndexedAttestation fixtures" {
    try expectMainnetFixtures(fulu.IndexedAttestation, &indexedAttestationFixtures);
}

test "mainnet PendingConsolidation fixtures" {
    try expectMainnetFixtures(fulu.PendingConsolidation, &pendingConsolidationFixtures);
}

test "mainnet PendingDeposit fixtures" {
    try expectMainnetFixtures(fulu.PendingDeposit, &pendingDepositFixtures);
}

test "mainnet PendingPartialWithdrawal fixtures" {
    try expectMainnetFixtures(fulu.PendingPartialWithdrawal, &pendingPartialWithdrawalFixtures);
}

test "mainnet ProposerSlashing fixtures" {
    try expectMainnetFixtures(fulu.ProposerSlashing, &proposerSlashingFixtures);
}

test "mainnet SignedAggregateAndProof fixtures" {
    try expectMainnetFixtures(fulu.SignedAggregateAndProof, &signedAggregateAndProofFixtures);
}

test "mainnet SignedBLSToExecutionChange fixtures" {
    try expectMainnetFixtures(fulu.SignedBLSToExecutionChange, &signedBLSToExecutionChangeFixtures);
}

test "mainnet SignedBeaconBlock fixtures" {
    try expectMainnetFixtures(fulu.SignedBeaconBlock, &signedBeaconBlockFixtures);
}

test "mainnet SignedBeaconBlockHeader fixtures" {
    try expectMainnetFixtures(fulu.SignedBeaconBlockHeader, &signedBeaconBlockHeaderFixtures);
}

test "mainnet SignedVoluntaryExit fixtures" {
    try expectMainnetFixtures(fulu.SignedVoluntaryExit, &signedVoluntaryExitFixtures);
}

test "mainnet SyncAggregate fixtures" {
    try expectMainnetFixtures(fulu.SyncAggregate, &syncAggregateFixtures);
}

test "mainnet SyncCommittee fixtures" {
    try expectMainnetFixtures(fulu.SyncCommittee, &syncCommitteeFixtures);
}

test "mainnet Validator fixtures" {
    try expectMainnetFixtures(fulu.Validator, &validatorFixtures);
}

test "mainnet VoluntaryExit fixtures" {
    try expectMainnetFixtures(fulu.VoluntaryExit, &voluntaryExitFixtures);
}

test "mainnet Withdrawal fixtures" {
    try expectMainnetFixtures(fulu.Withdrawal, &withdrawalFixtures);
}

test "mainnet WithdrawalRequest fixtures" {
    try expectMainnetFixtures(fulu.WithdrawalRequest, &withdrawalRequestFixtures);
}
