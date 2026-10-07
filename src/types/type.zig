// BitVector[N]
// - fixed number of bits
// - no delimiter bit
// - no length mix-in

// BitList[N]
// - variable current length
// - delimiter bit in serialization
// - current length mixed into hash_tree_root

pub fn BitList(comptime limit: usize) type {
    return struct {
        pub const ssz_kind = .bitlist;
        pub const max_bits = limit;

        data: []const bool,
    };
}

pub fn BitVector(comptime length: usize) type {
    return struct {
        pub const ssz_kind = .bitvector;
        pub const bit_length = length;

        data: [length]bool,
    };
}

pub fn ByteVector(comptime length: usize) type {
    return struct {
        pub const ssz_kind = .bytevector;
        pub const byte_length = length;

        data: [length]u8,
    };
}

pub fn ByteList(comptime limit: usize) type {
    return struct {
        pub const ssz_kind = .bytelist;
        pub const max_bytes = limit;

        data: []const u8,
    };
}

pub fn List(comptime Child: type, comptime limit: usize) type {
    return struct {
        pub const ssz_kind = .list;
        pub const Element = Child;
        pub const max_length = limit;

        data: []const Child,
    };
}
