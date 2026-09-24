pub fn BitList(comptime limit: usize) type {
    return struct {
        pub const ssz_kind = .bitlist;
        pub const max_bits = limit;

        data: []const bool,
    };
}
