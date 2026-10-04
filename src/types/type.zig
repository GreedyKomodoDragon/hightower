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
