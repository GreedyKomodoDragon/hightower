const std = @import("std");
const testing = std.testing;
const desc_mod = @import("type_descriptor");
const types = @import("types");

test "descriptor classifies bool and uints" {
    try testing.expectEqual(desc_mod.Kind.Bool, desc_mod.SszType(bool).kind);
    try testing.expectEqual(@as(?usize, 1), desc_mod.SszType(bool).fixed_size);

    try testing.expectEqual(desc_mod.Kind.Uint8, desc_mod.SszType(u8).kind);
    try testing.expectEqual(desc_mod.Kind.Uint16, desc_mod.SszType(u16).kind);
    try testing.expectEqual(desc_mod.Kind.Uint32, desc_mod.SszType(u32).kind);
    try testing.expectEqual(desc_mod.Kind.Uint64, desc_mod.SszType(u64).kind);
    try testing.expectEqual(desc_mod.Kind.Uint128, desc_mod.SszType(u128).kind);
    try testing.expectEqual(desc_mod.Kind.Uint256, desc_mod.SszType(u256).kind);
    try testing.expectEqual(@as(?usize, 32), desc_mod.SszType(u256).fixed_size);
    try testing.expect(!desc_mod.SszType(u64).is_variable);
}

test "descriptor classifies arrays" {
    const fixed = desc_mod.SszType([32]u8);
    try testing.expectEqual(desc_mod.Kind.Array, fixed.kind);
    try testing.expectEqual(@as(?usize, 32), fixed.fixed_size);
    try testing.expect(!fixed.is_variable);
    try testing.expectEqual(@as(?type, u8), fixed.element);

    const vari = desc_mod.SszType([4]types.List(u16, 8));
    try testing.expectEqual(desc_mod.Kind.Array, vari.kind);
    try testing.expectEqual(@as(?usize, null), vari.fixed_size);
    try testing.expect(vari.is_variable);
}

test "descriptor classifies SSZ wrapper kinds" {
    const bv = desc_mod.SszType(types.BitVector(10));
    try testing.expectEqual(desc_mod.Kind.BitVector, bv.kind);
    try testing.expectEqual(@as(?usize, 2), bv.fixed_size);
    try testing.expectEqual(@as(?usize, 10), bv.bit_length);

    const bl = desc_mod.SszType(types.BitList(16));
    try testing.expectEqual(desc_mod.Kind.BitList, bl.kind);
    try testing.expect(bl.is_variable);
    try testing.expectEqual(@as(?usize, 16), bl.max_bits);

    const yv = desc_mod.SszType(types.ByteVector(48));
    try testing.expectEqual(desc_mod.Kind.ByteVector, yv.kind);
    try testing.expectEqual(@as(?usize, 48), yv.fixed_size);
    try testing.expectEqual(@as(?usize, 48), yv.byte_length);

    const yl = desc_mod.SszType(types.ByteList(512));
    try testing.expectEqual(desc_mod.Kind.ByteList, yl.kind);
    try testing.expect(yl.is_variable);
    try testing.expectEqual(@as(?usize, 512), yl.max_bytes);

    const li = desc_mod.SszType(types.List(u32, 16));
    try testing.expectEqual(desc_mod.Kind.List, li.kind);
    try testing.expect(li.is_variable);
    try testing.expectEqual(@as(?usize, null), li.fixed_size);
    try testing.expectEqual(@as(?usize, 16), li.max_length);
    try testing.expectEqual(@as(?type, u32), li.element);
}

test "descriptor classifies containers" {
    const Fixed = struct {
        a: u16,
        b: u64,
        c: bool,
    };
    const fixed = desc_mod.SszType(Fixed);
    try testing.expectEqual(desc_mod.Kind.Container, fixed.kind);
    try testing.expect(!fixed.is_variable);
    try testing.expectEqual(@as(?usize, 2 + 8 + 1), fixed.fixed_size);

    const Vari = struct {
        a: u16,
        xs: types.List(u32, 16),
    };
    const vari = desc_mod.SszType(Vari);
    try testing.expectEqual(desc_mod.Kind.Container, vari.kind);
    try testing.expect(vari.is_variable);
    try testing.expectEqual(@as(?usize, null), vari.fixed_size);
}

test "descriptor marks progressive containers distinctly" {
    const Prog = struct {
        pub const ssz_active_fields = [_]bool{ true, false, true };
        a: u16,
        b: u16,
    };
    const prog = desc_mod.SszType(Prog);
    try testing.expectEqual(desc_mod.Kind.ProgressiveContainer, prog.kind);
    // Progressive containers lay out bytes like plain containers:
    // all-fixed fields means fixed-size (only Merkleization differs).
    try testing.expect(!prog.is_variable);
    try testing.expectEqual(@as(?usize, 4), prog.fixed_size);

    const ProgVar = struct {
        pub const ssz_active_fields = [_]bool{true};
        xs: types.List(u32, 16),
    };
    const prog_var = desc_mod.SszType(ProgVar);
    try testing.expectEqual(desc_mod.Kind.ProgressiveContainer, prog_var.kind);
    try testing.expect(prog_var.is_variable);
}

test "descriptor helpers match legacy fixed.zig behavior" {
    try testing.expect(desc_mod.isFixedSize(u32));
    try testing.expect(desc_mod.isFixedSize([32]u8));
    try testing.expect(desc_mod.isFixedSize(types.ByteVector(4)));
    try testing.expect(!desc_mod.isFixedSize(types.List(u8, 8)));
    try testing.expect(!desc_mod.isFixedSize(types.BitList(8)));
    try testing.expectEqual(@as(usize, 4), desc_mod.fixedSize(u32));
    try testing.expectEqual(@as(usize, 32), desc_mod.fixedSize([32]u8));
}
