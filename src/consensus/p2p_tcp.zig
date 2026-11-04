// A TCP peer first negotiates Noise XX, then authenticates the remote ENR
// identity before opening Yamux. The responder tries only discovered,
// signature-verified records; an identity proof must match one of them.
// Each Yamux frame is carried by an authenticated
// bounded Noise record, and reads have a caller-supplied deadline.
//
//   TCP -> /noise -> XX identity -> /yamux/1.0.0 -> bounded streams
// This IPv4 transport allows at most 16 KiB of stream data per Yamux frame.
const std = @import("std");
const enr = @import("enr.zig");
const discovery = @import("discv5_discovery.zig");
const multistream = @import("p2p_multistream.zig");
const noise = @import("p2p_noise_xx.zig");
const transport = @import("p2p_noise_transport.zig");
const yamux = @import("p2p_yamux.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const X25519 = std.crypto.dh.X25519;
const default_deadline_ns: i96 = 5 * std.time.ns_per_s;

pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    peer_id: [32]u8,
    cipher: transport.Transport,
    initiator: bool,

    pub const Received = struct {
        bytes: []u8,
        frame: yamux.Frame,

        /// Free the Noise plaintext after the Yamux payload has been consumed.
        pub fn deinit(self: Received, allocator: std.mem.Allocator) void {
            allocator.free(self.bytes);
        }
    };

    /// Dial only an authenticated discovery result at its signed TCP address.
    pub fn dial(allocator: std.mem.Allocator, io: std.Io, identity: Ecdsa.KeyPair, peers: *discovery.Service, peer_id: [32]u8) !Connection {
        const record = peers.discoveredRecord(peer_id) orelse return error.UnknownPeer;
        const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = record.ip, .port = record.tcp_port } };
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const deadline_at = now(io) + default_deadline_ns;
        try selectPlain(allocator, io, stream, .noise, true, deadline_at);
        const static = try freshKey(io);
        const ephemeral = try freshKey(io);
        var state = try noise.Initiator.init(identity, static, ephemeral, record);
        const first = try state.writeFirst();
        try writeAll(io, stream, first.slice());
        var second: [2050]u8 = undefined;
        try readNoiseFrame(io, stream, &second, deadline_at);
        try state.readSecond(second[0..frameLength(&second)]);
        const third = try state.writeThird();
        try writeAll(io, stream, third.frame.slice());
        var result = Connection{ .allocator = allocator, .io = io, .stream = stream, .peer_id = peer_id, .cipher = .init(third.keys), .initiator = true };
        try result.selectSecure(.yamux, true, deadline_at);
        return result;
    }

    /// Accept one TCP stream only after its Noise proof matches a discovered ENR.
    pub fn accept(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, identity: Ecdsa.KeyPair, peers: *discovery.Service) !Connection {
        errdefer stream.close(io);
        const deadline_at = now(io) + default_deadline_ns;
        try selectPlain(allocator, io, stream, .noise, false, deadline_at);
        var first: [2050]u8 = undefined;
        try readNoiseFrame(io, stream, &first, deadline_at);
        const static = try freshKey(io);
        const ephemeral = try freshKey(io);
        var selected: ?struct { id: [32]u8, keys: noise.TransportKeys } = null;
        var base: ?noise.Responder = null;
        for (peers.candidates.items.items) |candidate| {
            if (peers.discoveredRecord(candidate.node_id) == null) continue;
            base = try noise.Responder.init(identity, static, ephemeral, candidate);
            break;
        }
        var state = base orelse return error.UnknownPeer;
        try state.readFirst(first[0..frameLength(&first)]);
        const second = try state.writeSecond();
        try writeAll(io, stream, second.slice());
        var third: [2050]u8 = undefined;
        try readNoiseFrame(io, stream, &third, deadline_at);
        for (peers.candidates.items.items) |candidate| {
            if (peers.discoveredRecord(candidate.node_id) == null) continue;
            var attempt = state;
            attempt.remote = candidate;
            const keys = attempt.readThird(third[0..frameLength(&third)]) catch continue;
            selected = .{ .id = candidate.node_id, .keys = keys };
            break;
        }
        const authenticated = selected orelse return error.InvalidPeerIdentity;
        var result = Connection{ .allocator = allocator, .io = io, .stream = stream, .peer_id = authenticated.id, .cipher = .init(authenticated.keys), .initiator = false };
        try result.selectSecure(.yamux, false, deadline_at);
        return result;
    }

    /// Close this authenticated TCP connection and all of its logical streams.
    pub fn deinit(self: *Connection) void {
        self.stream.close(self.io);
    }

    /// Encrypt and write one bounded Yamux frame on this connection.
    pub fn send(self: *Connection, frame: yamux.Frame) !void {
        std.log.scoped(.p2p_transport).debug("send peer={x} stream={d} kind={s} syn={} ack={} fin={} rst={} len={d} prefix={x}", .{ self.peer_id[0..4], frame.stream_id, @tagName(frame.kind), frame.flags.syn, frame.flags.ack, frame.flags.fin, frame.flags.rst, frame.data.len, frame.data[0..@min(frame.data.len, 96)] });
        const bytes = try yamux.encode(self.allocator, frame);
        defer self.allocator.free(bytes);
        return self.sendRaw(bytes);
    }

    /// Read and authenticate one complete Yamux frame within the deadline.
    /// Ping frames are answered here so every stream loop sees only data,
    /// window, reset, and shutdown frames.
    pub fn receive(self: *Connection, deadline_ns: i96) !Received {
        while (true) {
            const bytes = try self.receiveRaw(deadline_ns);
            errdefer self.allocator.free(bytes);
            const frame = try yamux.decode(bytes);
            std.log.scoped(.p2p_transport).debug("recv peer={x} stream={d} kind={s} syn={} ack={} fin={} rst={} len={d} prefix={x}", .{ self.peer_id[0..4], frame.stream_id, @tagName(frame.kind), frame.flags.syn, frame.flags.ack, frame.flags.fin, frame.flags.rst, frame.data.len, frame.data[0..@min(frame.data.len, 96)] });
            switch (frame.kind) {
                .ping => {
                    self.allocator.free(bytes);
                    if (!frame.flags.ack) try self.send(.{ .kind = .ping, .flags = .{ .ack = true }, .stream_id = 0, .value = frame.value });
                    continue;
                },
                .go_away => {
                    self.allocator.free(bytes);
                    return error.GoAway;
                },
                else => return .{ .bytes = bytes, .frame = frame },
            }
        }
    }

    /// Return a monotonic deadline after the standard five-second request timeout.
    pub fn deadline(self: *const Connection) i96 {
        return now(self.io) + default_deadline_ns;
    }

    /// Encrypt a complete bounded application record before writing TCP bytes.
    fn sendRaw(self: *Connection, bytes: []const u8) !void {
        const encrypted = try self.cipher.encode(self.allocator, bytes);
        defer self.allocator.free(encrypted);
        return writeAll(self.io, self.stream, encrypted);
    }

    /// Read one clear length and its bounded ciphertext with one deadline.
    fn receiveRaw(self: *Connection, deadline_ns: i96) ![]u8 {
        var record_length: [transport.record_length_size]u8 = undefined;
        try readExact(self.io, self.stream, &record_length, deadline_ns);
        const length = try self.cipher.decodeLength(&record_length);
        const body = try self.allocator.alloc(u8, length);
        defer self.allocator.free(body);
        try readExact(self.io, self.stream, body, deadline_ns);
        return self.cipher.decodeBody(self.allocator, body);
    }

    /// Negotiate a secure application protocol before interpreting any frame.
    fn selectSecure(self: *Connection, protocol: multistream.Protocol, outgoing: bool, deadline_ns: i96) !void {
        if (outgoing) {
            const offer = try multistream.offer(self.allocator, protocol);
            defer self.allocator.free(offer);
            try self.sendRaw(offer);
            var state = multistream.Initiator{ .protocol = protocol };
            while (true) {
                const reply = try self.receiveRaw(deadline_ns);
                defer self.allocator.free(reply);
                var offset: usize = 0;
                while (offset < reply.len) {
                    const result = try state.feed(reply[offset..]);
                    offset += result.consumed;
                    if (result.selected) return;
                }
            }
        }
        var state = multistream.Responder{ .allowed = protocol };
        while (true) {
            const request = try self.receiveRaw(deadline_ns);
            defer self.allocator.free(request);
            var offset: usize = 0;
            while (offset < request.len) {
                const result = try state.feed(self.allocator, request[offset..]);
                offset += result.consumed;
                if (result.response) |reply| {
                    defer self.allocator.free(reply);
                    try self.sendRaw(reply);
                }
                if (result.selected != null) return;
            }
        }
    }
};

/// Negotiate an exact plaintext protocol before starting Noise XX.
fn selectPlain(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, protocol: multistream.Protocol, outgoing: bool, deadline_ns: i96) !void {
    if (outgoing) {
        const offer = try multistream.offer(allocator, protocol);
        defer allocator.free(offer);
        try writeAll(io, stream, offer);
        var state = multistream.Initiator{ .protocol = protocol };
        for (0..2) |_| {
            var line: [130]u8 = undefined;
            const size = try readLine(io, stream, &line, deadline_ns);
            const result = try state.feed(line[0..size]);
            if (result.selected) return;
        }
        return error.InvalidNegotiation;
    }
    var state = multistream.Responder{ .allowed = protocol };
    for (0..2) |_| {
        var line: [130]u8 = undefined;
        const size = try readLine(io, stream, &line, deadline_ns);
        const result = try state.feed(allocator, line[0..size]);
        if (result.response) |reply| {
            defer allocator.free(reply);
            try writeAll(io, stream, reply);
        }
        if (result.selected != null) return;
    }
    return error.InvalidNegotiation;
}

/// Read one bounded multistream line including its canonical varint prefix.
fn readLine(io: std.Io, stream: std.Io.net.Stream, output: *[130]u8, deadline_ns: i96) !usize {
    try readExact(io, stream, output[0..1], deadline_ns);
    const prefix: usize = if (output[0] & 0x80 == 0) 1 else 2;
    if (prefix == 2) try readExact(io, stream, output[1..2], deadline_ns);
    const length: usize = if (prefix == 1) output[0] else @as(usize, output[0] & 0x7f) | (@as(usize, output[1]) << 7);
    if (length == 0 or length > 128) return error.InvalidLength;
    try readExact(io, stream, output[prefix .. prefix + length], deadline_ns);
    return prefix + length;
}

/// Generate a fresh X25519 keypair from the I/O source's random bytes.
fn freshKey(io: std.Io) !X25519.KeyPair {
    var seed: [32]u8 = undefined;
    io.random(&seed);
    return X25519.KeyPair.generateDeterministic(seed);
}

/// Read one complete length-prefixed Noise XX handshake message.
fn readNoiseFrame(io: std.Io, stream: std.Io.net.Stream, output: *[2050]u8, deadline_ns: i96) !void {
    try readExact(io, stream, output[0..2], deadline_ns);
    const length = std.mem.readInt(u16, output[0..2], .big);
    if (length == 0 or length > 2048) return error.InvalidNoiseMessage;
    try readExact(io, stream, output[2 .. 2 + length], deadline_ns);
}

/// Return the full handshake frame length after its prefix has been read.
fn frameLength(bytes: *const [2050]u8) usize {
    return 2 + std.mem.readInt(u16, bytes[0..2], .big);
}

/// Read exactly the requested bytes, enforcing one monotonic deadline.
fn readExact(io: std.Io, stream: std.Io.net.Stream, output: []u8, deadline_ns: i96) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const left = deadline_ns - now(io);
        if (left <= 0) return error.Timeout;
        const wait_ms: i32 = @intCast(@min(@divTrunc(left + std.time.ns_per_ms - 1, std.time.ns_per_ms), std.math.maxInt(i32)));
        var descriptors = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        if (try std.posix.poll(&descriptors, wait_ms) == 0) return error.Timeout;
        const received = try std.posix.read(stream.socket.handle, output[offset..]);
        if (received == 0) return error.EndOfStream;
        offset += received;
    }
}

/// Write and flush all bytes in one bounded transport record.
fn writeAll(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

/// Return the monotonic nanoseconds used for connection deadlines.
fn now(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

test "two discovered nodes exchange authenticated Yamux frames over TCP" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key_a = try Ecdsa.KeyPair.generateDeterministic([_]u8{101} ** 32);
    const key_b = try Ecdsa.KeyPair.generateDeterministic([_]u8{102} ** 32);
    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = listener.socket.address.ip4.port, .fork_id = .{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    var a = try discovery.Service.init(allocator, io, key_a, local, 2);
    defer a.deinit();
    var b = try discovery.Service.init(allocator, io, key_b, local, 2);
    defer b.deinit();
    const b_uri = try b.localUri();
    defer allocator.free(b_uri);
    try a.addBootstrap(b_uri);
    try a.maintain();
    const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } };
    try b.step(timeout);
    try a.step(timeout);
    try b.step(timeout);
    try a.step(timeout);
    const Context = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        key: Ecdsa.KeyPair,
        peers: *discovery.Service,
        err: ?anyerror = null,

        /// Accept one peer and echo two independently numbered Yamux streams.
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        /// Authenticate the caller and answer each bounded frame on its stream.
        fn serve(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var connection = try Connection.accept(self.allocator, self.io, stream, self.key, self.peers);
            defer connection.deinit();
            for ([_]u32{ 1, 3 }) |id| {
                const received = try connection.receive(connection.deadline());
                defer received.deinit(self.allocator);
                if (received.frame.stream_id != id or !received.frame.flags.syn) return error.WrongStream;
                try connection.send(.{ .kind = .data, .flags = .{ .fin = true }, .stream_id = id, .data = received.frame.data });
            }
        }
    };
    var context = Context{ .io = io, .allocator = allocator, .listener = &listener, .key = key_b, .peers = &b };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    var connection = try Connection.dial(allocator, io, key_a, &a, b.local_record.node_id);
    defer connection.deinit();
    for ([_]u32{ 1, 3 }) |id| {
        try connection.send(.{ .kind = .data, .flags = .{ .syn = true }, .stream_id = id, .data = "hello" });
        const response = try connection.receive(connection.deadline());
        defer response.deinit(allocator);
        try std.testing.expectEqual(id, response.frame.stream_id);
        try std.testing.expect(response.frame.flags.fin);
        try std.testing.expectEqualStrings("hello", response.frame.data);
    }
    thread.join();
    if (context.err) |err| return err;
}
