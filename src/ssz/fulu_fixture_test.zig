const std = @import("std");
const testing = std.testing;
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");

fn expectFixture(comptime T: type, value: T, expected_root_hex: []const u8) !void {
    const allocator = testing.allocator;

    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_root, expected_root_hex);

    const serialized = try ssz.serializeAlloc(allocator, value);
    defer allocator.free(serialized);

    var reader: std.Io.Reader = .fixed(serialized);
    const decoded = try ssz.deserialize(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, decoded);

    const reserialized = try ssz.serializeAlloc(allocator, decoded);
    defer allocator.free(reserialized);
    try testing.expectEqualSlices(u8, serialized, reserialized);

    const root = try merkle.HashTreeRoot(allocator, value);
    try testing.expectEqualSlices(u8, &expected_root, &root);
}

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

fn expectZeroFixture(comptime T: type, expected_root_hex: []const u8) !void {
    try expectFixture(T, std.mem.zeroes(T), expected_root_hex);
}

fn fixtureBytes(comptime T: type, hex: []const u8) T {
    var value: T = undefined;
    _ = std.fmt.hexToBytes(&value, hex) catch unreachable;
    return value;
}

fn fixtureBits(comptime length: usize, hex: []const u8) [length]bool {
    var bytes: [(length + 7) / 8]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;

    var bits: [length]bool = undefined;
    for (&bits, 0..) |*bit, index| {
        const mask = @as(u8, 1) << @as(u3, @intCast(index % 8));
        bit.* = bytes[index / 8] & mask != 0;
    }
    return bits;
}

test "Fulu shared types match pinned ssz_zero roots" {
    // Expected roots are from the corresponding ssz_static/<Type>/ssz_zero/case_0 fixture.
    try expectZeroFixture(fulu.Fork, "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71");
    try expectZeroFixture(fulu.BeaconBlockHeader, "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c");
    try expectZeroFixture(fulu.SignedBeaconBlockHeader, "75fbdb83b1dfa7d5cace569fb811348e77014d7ab517818a771c1a61d3303d83");
    try expectZeroFixture(fulu.Checkpoint, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    try expectZeroFixture(fulu.Eth1Data, "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71");
    try expectZeroFixture(fulu.Validator, "fa324a462bcb0f10c24c9e17c326a4e0ebad204feced523eccaf346c686f06ee");
    try expectZeroFixture(fulu.SyncCommittee, "e091a6d41e6945c26d6f833865068f9382ffe6bfac4738bf181bd88a6d11fe61");
    try expectZeroFixture(fulu.SyncAggregate, "b11b8bcf59425d6c99019cca1d2c2e47b51a2f74917a67ad132274f43e13ec43");
    try expectZeroFixture(fulu.HistoricalSummary, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    try expectZeroFixture(fulu.AttestationData, "01f278ee83d4e438cf8f563ce108974d64c029a20280ab8eca07741df7ee5290");
    try expectZeroFixture(fulu.PendingDeposit, "8e927f592f8df92c03613535a713c8f586ce4ee34ef0a353b90e09ae7dde7a60");
    try expectZeroFixture(fulu.PendingPartialWithdrawal, "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71");
    try expectZeroFixture(fulu.PendingConsolidation, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
}

test "Fulu SyncAggregate matches pinned ssz_nil case_0" {
    const value: fulu.SyncAggregate = .{
        .sync_committee_bits = .{ .data = fixtureBits(32, "afde4c46") },
        .sync_committee_signature = fixtureBytes(fulu.BLSSignature, "8ba03b38c3cb23c5085292e350b9f0f075de063ea61d50aec75cb1f632689785f8adb0d39db3524f5df15b9997082080a38c00a42654e45951fe0ac999edf00efd75dc391b9b8fd45d56fa401b737d22dba7a675a0ae2cdfc91d38c165c028fb"),
    };

    try expectFixture(
        fulu.SyncAggregate,
        value,
        "3be21caa7e3f05f5f8635aeb3c0859c676b32cc3bbd0bece2d8cb3cf8c3feb51",
    );
}

test "Fulu SyncCommittee matches pinned ssz_nil case_0" {
    const value: fulu.SyncCommittee = .{
        .pubkeys = .{
            fixtureBytes(fulu.BLSPubkey, "3da8970403cfe718f436b2acab75e36151e6a4ef611297cc7e296cc0fe3fb4f2914e3928910987fdc65332a3929d3434"),
            fixtureBytes(fulu.BLSPubkey, "82f39cf4ac38d8e624a09cb39acf63c34456e80556b84e11abcc848bb4b4ac11b9e818922691b7206b0c939452924ecc"),
            fixtureBytes(fulu.BLSPubkey, "b019533364f9639b8516d6addeccc6fa0bfdd261f084eac1d0beacac25f93dab5364f2833947a80f7048bd65e0ca3d31"),
            fixtureBytes(fulu.BLSPubkey, "0c68f6e89cfee10de2c70fbc651cb0d2520567be2471e7e12bcdb9cd4d3d40aee8b53c473c3ff473917aa7c1a0e49f22"),
            fixtureBytes(fulu.BLSPubkey, "0ac71788a569daef526374f7e494df9abf9c29d5d51a67810047aa04708a4ee140e29d9efcccb7c122497ca1e60b6705"),
            fixtureBytes(fulu.BLSPubkey, "cbf1e547f7ce857f0faadb21ff7c7852d654cd1c8209aa01e77eeb762d83894cc3317fd923dd9f01f59468ed0eb1faae"),
            fixtureBytes(fulu.BLSPubkey, "52de796570f3072cb542b3d2429cc22bc26173030ee3c92d212906434eabfa761407f27d36a6c5e059bd170c27fc16ba"),
            fixtureBytes(fulu.BLSPubkey, "cb9691cc272f8c7267f692efa47ef1fd091ba107feb6acdbde83cb812a92946aeee62b9337c868d151ddface35caa36a"),
            fixtureBytes(fulu.BLSPubkey, "a7f683f99bd25418e51224ec2d40028323657529ab01e2ca31549b2f92efc4daac3f39f35a25a6f37af97ef5ed724214"),
            fixtureBytes(fulu.BLSPubkey, "65d0c6e4100cacf49565a3ace2ee716acccce80f20d549e5db0c73848f08f7ccc4c1f17ef1fbc4f3903a01204647e59b"),
            fixtureBytes(fulu.BLSPubkey, "523610fe73d0d86ed3508f06a4697894efd463925b879c4cfb2322a0e5ae97f43939f5cdb565b211eab792ec34b40839"),
            fixtureBytes(fulu.BLSPubkey, "2b796a0d7bd2eda341d72c810141126af9904a6a28d3ad5284f84b9933f4529bc12d5f4fa760620eeeb9044a17eec5a2"),
            fixtureBytes(fulu.BLSPubkey, "f967f2231d542ff745ca0f11b555e3bb8a02e66255a60a5fc419a1e8852afaebeb6c825addaf27b5cd2632f79cf1aeb4"),
            fixtureBytes(fulu.BLSPubkey, "f7a8f492a41403b970e6fd43c005837951b455855ac2653c37fb3679064d7edd59ca2c5adfe32000f8e7a30281c8c801"),
            fixtureBytes(fulu.BLSPubkey, "6ab5a619610b8fa1c98ad3241ff44ac6b908b710f307c191bd175ba7c314298ef15a26aca16141783496720a22613539"),
            fixtureBytes(fulu.BLSPubkey, "0da5ad5037b46ae19127478622df393eb0a5f3e2ba4bd182e4bae727c20d7160ceec46e3e47f019ea8291ddc2bd1b2dc"),
            fixtureBytes(fulu.BLSPubkey, "b64a7f4c15b49f9d29916cabf8b92f54d7374faf979d56be76dad513fdd7438adc83f86c1cac91f28cb59f7819c753a9"),
            fixtureBytes(fulu.BLSPubkey, "fb9dae588adcd9a8a621fb92f0989e28be2c5c35fa20d2a77dffb5de6c4ade0f9f0b2243323ffbab3539925a7fdc4b0d"),
            fixtureBytes(fulu.BLSPubkey, "1f49dc8668f77910b37acf0f33493360820b3c3f7385ce0330a363509e1e417416b92313e87825b9323e5426c57ea974"),
            fixtureBytes(fulu.BLSPubkey, "cfc67313e2fdc68d877067bd960c99e8a99c55b7bf9eb6e291a061cd357a59a043a0519d4b850966e5c61b7e819d900a"),
            fixtureBytes(fulu.BLSPubkey, "c1c81d9eec7c63c1061d43ca85410c08a26928ab4ddef7124038d6a3a7223fe4c61d202564ae2d60e8b52331fc9d4ae2"),
            fixtureBytes(fulu.BLSPubkey, "be6106e60c2d2ceeee6cf987ce64c9a7a8da41dd16cb018ad40178aad54b1bfcc807de9ac765e56b6e60c16f432cca14"),
            fixtureBytes(fulu.BLSPubkey, "329e49e72a844f66a4bd7c46610882b5bb78045dc3d3dc2960e07906e66a36efcdd314260d6d781c3047433b5e292681"),
            fixtureBytes(fulu.BLSPubkey, "79f8f5e01a9cdccb3c8e825ec9fd8cbf54098957673a3efb10daa2cb9682a1b5123e4b41ed90c30cdb2b032c84ef91b8"),
            fixtureBytes(fulu.BLSPubkey, "ef154f2b19ecabb692cc2a60b514e688f5376fa021fc21ed0292f2f75c2437ee5bce83610c258933fb760a9f919a4171"),
            fixtureBytes(fulu.BLSPubkey, "675884707eb46c6552d75f412e6c013850a7e81c0d4b3f34da79649917a645705b71fc7e8d5490c593169614a6b00c70"),
            fixtureBytes(fulu.BLSPubkey, "d9de8db98a0c28a698d91375a63b4cbee5ebdd9ca080a005c6abafee3d5964fc66afb57cfa1e3686418d25022b8b6533"),
            fixtureBytes(fulu.BLSPubkey, "ce4edaaecad5c8d41e10bfa17b0fe05956417892da3f5815fa3888f7b1e652b9e736a4ad52b4ee9a6b889fd9b0a9aea9"),
            fixtureBytes(fulu.BLSPubkey, "95023cf00278331e26e9eb98b47cecd04f860de0b41355cde88118092ecd0d106fc7ce736fd1dcdd20148e2959029634"),
            fixtureBytes(fulu.BLSPubkey, "bb1129f65591a678306ad70cbb5eeaf86a93b98f2ad2ef68627bde172f0596a02aae08b552aaff017438ce52f7d6bd12"),
            fixtureBytes(fulu.BLSPubkey, "9db7186aef6815ba82d1557625fece19f3dda6f2b65785bdc4263cf5225202c530c9b3242c8910abbdb6dffa4d541ee4"),
            fixtureBytes(fulu.BLSPubkey, "b50631ba056cf10a34198424387c38eaeb4dd95bfc915952d9581e281b1418bd38389d3828dabe5fd903d3f96339474b"),
        },
        .aggregate_pubkey = fixtureBytes(fulu.BLSPubkey, "f60f90862dea1b090ecab6050b31beae9785235b48c759ab60250371a375d95808059554823b332d9d99a0b05ccba062"),
    };

    try expectFixture(
        fulu.SyncCommittee,
        value,
        "516a8df6ad88dcb33b8fb056a304e2362e54f59186b78a91001790cadcba446c",
    );
}

test "Fulu BeaconBlock matches pinned ssz_nil case_0" {
    const value: fulu.BeaconBlock = .{
        .slot = 7447784883850721481,
        .proposer_index = 15352176225027239194,
        .parent_root = fixtureBytes(fulu.Root, "082838dae4c2d7a764e891b94eaf8d5d2ed04bf3c97046d14a9f2e0a91487619"),
        .state_root = fixtureBytes(fulu.Root, "3b5443a9acc02e61126b630e5bf1a2696b754ff12de7b3256f9963d2f6736609"),
        .body = .{
            .randao_reveal = fixtureBytes(fulu.BLSSignature, "8de070c86946b122cf0ebc13b88e7086ca758ac94fa779b3428b061e5893a39fe76f0e1146306bb9346dcada3ea56a4526b1d58e5d6d450e8c26edf5608a58d4f584e079cfac12232f0fbe8a6f881cbcedc09147641f19ee7444e8f9bf111e9d"),
            .eth1_data = .{
                .deposit_root = fixtureBytes(fulu.Root, "5bd2bc43a69fa4d169028f3de3d3839edd9396d79a56e8295692b8afa3f134cb"),
                .deposit_count = 15042983915232323679,
                .block_hash = fixtureBytes(fulu.Hash32, "d2d51772cb64657e310f45bd95e8b674d54879bdb1647e25ce33447cecbb7bc4"),
            },
            .graffiti = fixtureBytes(fulu.Bytes32, "59ad89ba2ff2276907a0acc11bffc8e17964eb3611258bef1ce8c582ca16ab00"),
            .proposer_slashings = .{ .data = &.{} },
            .attester_slashings = .{ .data = &.{} },
            .attestations = .{ .data = &.{} },
            .deposits = .{ .data = &.{} },
            .voluntary_exits = .{ .data = &.{} },
            .sync_aggregate = .{
                .sync_committee_bits = .{ .data = fixtureBits(32, "ea59a572") },
                .sync_committee_signature = fixtureBytes(fulu.BLSSignature, "d24266239a4a80d3a3d64c71415b80a7226d024eb11e7509027a7291a93630e3597a057bb9d0faf50a802199bad4bee36f5456abb16e098cb6af879fc67a667e48341bedde32ec60a45ad3754942039f661322dda44ba97f62c1b960cdfbcb24"),
            },
            .execution_payload = .{
                .parent_hash = fixtureBytes(fulu.Hash32, "c7dbdf85f60e7b2a8097ea47e9d438b66faae29faab3c1218a3e26d3bfd1a1ca"),
                .fee_recipient = fixtureBytes(fulu.ExecutionAddress, "9c7b824f7464887cfda7df063875c2f8bce10dd2"),
                .state_root = fixtureBytes(fulu.Bytes32, "c3045c9a6a088beca68b5ad2c502e6cd791a72110111e5bace7b561c7bd0265e"),
                .receipts_root = fixtureBytes(fulu.Bytes32, "3685e332a7306519036d56bf6eb65cc034c3d1db74ec1f7c0d7ec2ceac0b5fd8"),
                .logs_bloom = fixtureBytes([256]u8, "3861eeb2ecc971d2ab75de4c6d8cb9d57d350101ce4d7cf561cd51e20c4cec07b96d64c2f8ea71b2fc45ff006a9926c56c48fd6ea43bbf3f550d5a290b290a851366e9912bf872c6ee8a3069e6d067f35887f9ce4156890e36fde7cdd6c60d7961c00cf328fb4e95341c387e105018c11b64a45e798cb0e976928eb1502801327ec8b2d0aacdc8ddfa4fa4a0bc55486eb887d9bd56dee7b49a822b772fe3b107742621c91f656307a61351874e60ab553c2d5d2373bd2c5b8b04008c09dfe707d64ee9cca1618ef8839c24ce7068629edc09a78413bae146d22061f3691dbe1e7b20062ff578a04df6711974fc7a6735ff689427f01d6aa87f5dfeb30c92cbd6"),
                .prev_randao = fixtureBytes(fulu.Bytes32, "ae05d428ecdcd507f200b1e1c7c9bd840ffbd950f74b622f43e592a2f419c939"),
                .block_number = 17253946581502809362,
                .gas_limit = 10399166554185282768,
                .gas_used = 4275734961893974723,
                .timestamp = 7290447872240149104,
                .extra_data = .{ .data = &.{} },
                .base_fee_per_gas = 17473930605183021798772288235702407435283459761638813267292825204306304072032,
                .block_hash = fixtureBytes(fulu.Hash32, "2040a194dfb99ca8289b213e29977850f1a4f064a561620b02fe1162c720ffb8"),
                .transactions = .{ .data = &.{} },
                .withdrawals = .{ .data = &.{} },
                .blob_gas_used = 5013045800169741497,
                .excess_blob_gas = 9766924727304548305,
            },
            .bls_to_execution_changes = .{ .data = &.{} },
            .blob_kzg_commitments = .{ .data = &.{} },
            .execution_requests = .{
                .deposits = .{ .data = &.{} },
                .withdrawals = .{ .data = &.{} },
                .consolidations = .{ .data = &.{} },
            },
        },
    };

    try expectFixture(
        fulu.BeaconBlock,
        value,
        "fe1e202b3fc788b7f7a0138efb9e740f3c1ef6692d665132047bc4ac1e7fae46",
    );
}

test "Fulu BeaconBlock matches pinned random cases" {
    // Raw SSZ extracted from the pinned consensus-specs v1.6.1 minimal Fulu fixtures.
    try expectSerializedFixture(
        fulu.BeaconBlock,
        @embedFile("fixtures/beacon_block_random_7.ssz"),
        "5aa249c40fae6d424436e969716207f450d9e1284ac5009964c375a7377d08a8",
    );
    try expectSerializedFixture(
        fulu.BeaconBlock,
        @embedFile("fixtures/beacon_block_random_22.ssz"),
        "1934cedbde590d7bea2f78c7c675d376061db508ef146fd75a42cf7996a4575f",
    );
}
