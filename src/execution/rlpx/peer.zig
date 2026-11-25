// A devp2p execution session authenticates the ENR key with RLPx, negotiates
// eth/69 in Hello, and checks chain status before handling transaction gossip.
// Every frame is MAC checked, bounded, and decompressed only after its size
// header is checked. A session owns one TCP stream and one in-flight exchange.
//
// TCP -> auth/ack -> Hello -> eth Status -> bounded pool messages
const std = @import("std");
const rlp = @import("rlp");
const ecies = @import("ecies.zig");
const handshake = @import("handshake.zig");
const frame = @import("frame.zig");
const snappy = @import("snappy.zig");
const eth = @import("eth.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const handshake_timeout_ns: i96 = 5 * std.time.ns_per_s;
const connect_timeout_ms: u64 = 3000;
const idle_timeout_ms: i32 = 5000;
const send_timeout_seconds = 5;

pub const Message = struct {
    code: u8,
    body: []u8,

    /// Free the authenticated, decompressed frame body.
    pub fn deinit(self: Message, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }
};

pub const Peer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    framer: frame.Framer,
    remote: Ecdsa.PublicKey,
    compression: bool = false,

    /// Dial an already verified ENR endpoint and authenticate its static key.
    pub fn dial(allocator: std.mem.Allocator, io: std.Io, local: Ecdsa.KeyPair, remote: Ecdsa.PublicKey, address: std.Io.net.IpAddress, status: eth.Status) !Peer {
        const stream = try connectBounded(address);
        errdefer stream.close(io);
        try limitSendTime(stream);
        var nonce: [32]u8 = undefined;
        var iv: [16]u8 = undefined;
        io.random(&nonce);
        io.random(&iv);
        const started = try handshake.initiate(allocator, local, remote, Ecdsa.KeyPair.generate(io), nonce, iv, Ecdsa.KeyPair.generate(io));
        defer started.deinit(allocator);
        try writeAll(io, stream, started.auth);
        const ack = try readHandshake(allocator, io, stream);
        defer allocator.free(ack);
        const keys = try started.finish(allocator, ack);
        var peer = Peer{ .allocator = allocator, .io = io, .stream = stream, .framer = frame.Framer.init(keys), .remote = remote };
        try peer.exchangeHello(local.public_key);
        try peer.exchangeStatus(status);
        return peer;
    }

    /// Accept one authenticated remote identity; caller checks its discovered ENR.
    pub fn accept(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, local: Ecdsa.KeyPair, status: eth.Status) !Peer {
        errdefer stream.close(io);
        try limitSendTime(stream);
        const auth = try readHandshake(allocator, io, stream);
        defer allocator.free(auth);
        var nonce: [32]u8 = undefined;
        var iv: [16]u8 = undefined;
        io.random(&nonce);
        io.random(&iv);
        const replied = try handshake.accept(allocator, local, auth, Ecdsa.KeyPair.generate(io), nonce, iv, Ecdsa.KeyPair.generate(io));
        defer replied.deinit(allocator);
        try writeAll(io, stream, replied.ack);
        var peer = Peer{ .allocator = allocator, .io = io, .stream = stream, .framer = frame.Framer.init(replied.secrets), .remote = replied.remote };
        try peer.exchangeHello(local.public_key);
        try peer.exchangeStatus(status);
        return peer;
    }

    /// Close the stream after the owning session leaves its event loop.
    pub fn deinit(self: *Peer) void {
        self.stream.close(self.io);
    }

    /// Write one capability message, Snappy compressing all messages after Hello.
    pub fn send(self: *Peer, code: u8, body: []const u8) !void {
        const compressed = if (!self.compression or code == 0) try self.allocator.dupe(u8, body) else try snappy.encode(self.allocator, body);
        defer self.allocator.free(compressed);
        if (compressed.len + 1 > frame.max_frame_size) return error.FrameTooLarge;
        const message = try self.allocator.alloc(u8, 1 + compressed.len);
        defer self.allocator.free(message);
        message[0] = if (code == 0) 0x80 else code;
        @memcpy(message[1..], compressed);
        const wire = try self.framer.encode(self.allocator, message);
        defer self.allocator.free(wire);
        return writeAll(self.io, self.stream, wire);
    }

    /// Read one frame, yielding NoMessage only before consuming any header bytes.
    pub fn receive(self: *Peer, wait_ms: i32) !Message {
        var descriptors = [_]std.posix.pollfd{.{ .fd = self.stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        if (try std.posix.poll(&descriptors, wait_ms) == 0) return error.NoMessage;
        const deadline = now(self.io) + handshake_timeout_ns;
        var header: [32]u8 = undefined;
        try readExact(self.io, self.stream, &header, deadline);
        const length = try self.framer.decodeHeader(header);
        const encrypted = try self.allocator.alloc(u8, frame.Framer.bodySize(length));
        defer self.allocator.free(encrypted);
        try readExact(self.io, self.stream, encrypted, deadline);
        const plaintext = try self.framer.decodeBody(self.allocator, length, encrypted);
        defer self.allocator.free(plaintext);
        if (plaintext.len == 0) return error.EmptyMessage;
        const code: u8 = if (plaintext[0] == 0x80) 0 else plaintext[0];
        if (code >= 0x80) return error.InvalidMessageCode;
        const body = if (!self.compression or code == 0) try self.allocator.dupe(u8, plaintext[1..]) else try snappy.decode(self.allocator, plaintext[1..]);
        return .{ .code = code, .body = body };
    }

    /// Exchange devp2p Hello and check eth/69 support and authenticated identity.
    fn exchangeHello(self: *Peer, local: Ecdsa.PublicKey) !void {
        const body = try helloBody(self.allocator, local);
        defer self.allocator.free(body);
        try self.send(0, body);
        const message = try self.receive(idle_timeout_ms);
        defer message.deinit(self.allocator);
        if (message.code != 0) return error.ExpectedHello;
        try checkHello(self.allocator, message.body, self.remote);
        self.compression = true;
    }

    /// Exchange chain status and require the expected network, genesis, and fork.
    fn exchangeStatus(self: *Peer, local: eth.Status) !void {
        const encoded = try eth.encodeStatus(self.allocator, local);
        defer self.allocator.free(encoded);
        try self.send(eth.status_code, encoded);
        for (0..4) |_| {
            const message = try self.receive(idle_timeout_ms);
            defer message.deinit(self.allocator);
            if (message.code == 2) {
                try self.send(3, &.{0xc0});
                continue;
            }
            if (message.code != eth.status_code) return error.ExpectedStatus;
            const remote = try eth.decodeStatus(self.allocator, message.body);
            if (remote.network_id != local.network_id or !std.mem.eql(u8, &remote.genesis, &local.genesis) or !std.mem.eql(u8, &remote.fork_hash, &local.fork_hash)) return error.IncompatibleStatus;
            return;
        }
        return error.ExpectedStatus;
    }
};

/// Connect an IPv4 TCP socket within a fixed deadline, then restore blocking I/O.
fn connectBounded(address: std.Io.net.IpAddress) !std.Io.net.Stream {
    if (address != .ip4) return error.UnsupportedAddress;
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    var owned = true;
    defer {
        if (owned) _ = std.c.close(fd);
    }
    const original = std.c.fcntl(fd, std.posix.F.GETFL);
    if (original < 0) return error.SocketFailed;
    var flags: std.posix.O = @bitCast(@as(u32, @intCast(original)));
    flags.NONBLOCK = true;
    if (std.c.fcntl(fd, std.posix.F.SETFL, @as(c_int, @bitCast(flags))) < 0) return error.SocketFailed;
    const endpoint: std.posix.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, address.ip4.port), .addr = @bitCast(address.ip4.bytes) };
    switch (std.c.errno(std.c.connect(fd, @ptrCast(&endpoint), @sizeOf(@TypeOf(endpoint))))) {
        .SUCCESS => {},
        .INPROGRESS => {
            var descriptors = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
            if (try std.posix.poll(&descriptors, connect_timeout_ms) == 0) return error.Timeout;
            var socket_error: c_int = 0;
            var error_size: std.c.socklen_t = @sizeOf(c_int);
            if (std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, &socket_error, &error_size) < 0 or socket_error != 0) return error.ConnectFailed;
        },
        .CONNREFUSED => return error.ConnectionRefused,
        else => return error.ConnectFailed,
    }
    if (std.c.fcntl(fd, std.posix.F.SETFL, original) < 0) return error.SocketFailed;
    owned = false;
    return .{ .socket = .{ .handle = fd, .address = address } };
}

/// Bound writes so a nonreading peer cannot hold the single gossip loop indefinitely.
fn limitSendTime(stream: std.Io.net.Stream) !void {
    const timeout: std.posix.timeval = .{ .sec = send_timeout_seconds, .usec = 0 };
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
}

/// Build devp2p Hello with exactly one eth/69 capability.
fn helloBody(a: std.mem.Allocator, local: Ecdsa.PublicKey) ![]u8 {
    var payload = std.Io.Writer.Allocating.init(a);
    defer payload.deinit();
    try rlp.rlp(&payload.writer, @as(u8, 5));
    try rlp.rlp(&payload.writer, "Hightower/0.1");
    var capability = std.Io.Writer.Allocating.init(a);
    defer capability.deinit();
    try rlp.rlp(&capability.writer, "eth");
    try rlp.rlp(&capability.writer, @as(u8, 69));
    try rlp.encoding.encodeListHeader(&payload.writer, capability.written().len + 1);
    try rlp.encoding.encodeListHeader(&payload.writer, capability.written().len);
    try payload.writer.writeAll(capability.written());
    try rlp.rlp(&payload.writer, @as(u8, 0));
    const public = local.toUncompressedSec1();
    try rlp.rlp(&payload.writer, public[1..]);
    var result = std.Io.Writer.Allocating.init(a);
    defer result.deinit();
    try rlp.encoding.encodeListHeader(&result.writer, payload.written().len);
    try result.writer.writeAll(payload.written());
    return result.toOwnedSlice();
}

/// Verify Hello's identity and locate the mutually supported eth/69 capability.
fn checkHello(a: std.mem.Allocator, body: []const u8, expected: Ecdsa.PublicKey) !void {
    var parsed = try rlp.decode.decodeAll(a, body);
    defer parsed.deinit(a);
    if (parsed != .list or parsed.list.len < 5) return error.InvalidHello;
    const fields = parsed.list;
    if (fields[4] != .string or fields[4].string.len != 64) return error.InvalidHello;
    const public = expected.toUncompressedSec1();
    if (!std.mem.eql(u8, fields[4].string, public[1..])) return error.IdentityMismatch;
    if (fields[2] != .list) return error.InvalidHello;
    for (fields[2].list) |capability| {
        if (capability != .list or capability.list.len < 2 or capability.list[0] != .string or capability.list[1] != .string) continue;
        if (std.mem.eql(u8, capability.list[0].string, "eth") and capability.list[1].string.len == 1 and capability.list[1].string[0] == 69) return;
    }
    return error.NoEth69;
}

/// Read one bounded two-byte-length EIP-8 handshake packet.
fn readHandshake(a: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream) ![]u8 {
    const deadline = now(io) + handshake_timeout_ns;
    var prefix: [2]u8 = undefined;
    try readExact(io, stream, &prefix, deadline);
    const size = std.mem.readInt(u16, &prefix, .big);
    if (size < 113 or size + 2 > ecies.max_packet_size) return error.InvalidHandshakeSize;
    const packet = try a.alloc(u8, 2 + size);
    errdefer a.free(packet);
    @memcpy(packet[0..2], &prefix);
    try readExact(io, stream, packet[2..], deadline);
    return packet;
}

/// Read exactly one frame portion under a monotonic deadline.
fn readExact(io: std.Io, stream: std.Io.net.Stream, bytes: []u8, deadline: i96) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const remaining = deadline - now(io);
        if (remaining <= 0) return error.Timeout;
        const wait_ms: i32 = @intCast(@min(@divTrunc(remaining + std.time.ns_per_ms - 1, std.time.ns_per_ms), std.math.maxInt(i32)));
        var descriptors = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        if (try std.posix.poll(&descriptors, wait_ms) == 0) return error.Timeout;
        const count = try std.posix.read(stream.socket.handle, bytes[offset..]);
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

/// Flush a bounded packet to the TCP stream.
fn writeAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

/// Return monotonic time for handshake and frame deadlines.
fn now(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

test "Hello binds an eth/69 capability to the authenticated node key" {
    const a = std.testing.allocator;
    const local = try Ecdsa.KeyPair.generateDeterministic(.{1} ** 32);
    const other = try Ecdsa.KeyPair.generateDeterministic(.{2} ** 32);
    const body = try helloBody(a, local.public_key);
    defer a.free(body);
    try checkHello(a, body, local.public_key);
    try std.testing.expectError(error.IdentityMismatch, checkHello(a, body, other.public_key));
}

test "two Zig execution peers complete RLPx and eth/69 status" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alice = try Ecdsa.KeyPair.generateDeterministic(.{11} ** 32);
    const bob = try Ecdsa.KeyPair.generateDeterministic(.{12} ** 32);
    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const status = eth.Status{ .network_id = 1, .genesis = .{1} ** 32, .fork_hash = .{ 2, 3, 4, 5 }, .next_fork = 0, .earliest = 0, .latest = 0, .head = .{1} ** 32 };
    const Context = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        identity: Ecdsa.KeyPair,
        status: eth.Status,
        failure: ?anyerror = null,

        /// Accept one authenticated peer and answer a ping after status.
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.failure = err;
            };
        }

        /// Exchange one post-status message to exercise the encrypted stream.
        fn serve(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var peer = try Peer.accept(self.allocator, self.io, stream, self.identity, self.status);
            defer peer.deinit();
            const received = try peer.receive(idle_timeout_ms);
            defer received.deinit(self.allocator);
            if (received.code != 2) return error.ExpectedPing;
            try peer.send(3, &.{0xc0});
        }
    };
    var context = Context{ .io = io, .allocator = allocator, .listener = &listener, .identity = bob, .status = status };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    var peer = try Peer.dial(allocator, io, alice, bob.public_key, listener.socket.address, status);
    defer peer.deinit();
    try peer.send(2, &.{0xc0});
    const response = try peer.receive(idle_timeout_ms);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 3), response.code);
    thread.join();
    if (context.failure) |err| return err;
}
