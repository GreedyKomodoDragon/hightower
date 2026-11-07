// Local IPv4 diagnostics: a single poll loop owns sockets and recordings.
// TCP buffers apply backpressure; UDP sessions use distinct upstream sockets.
// Receive records precede forwarding records, whose offsets refer to the same
// payload file. TCP read chunks are not packet boundaries. At most 64 sessions
// retain two 65,535-byte buffers each; UDP sessions expire after 60 idle seconds.
const std = @import("std");
const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("poll.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("errno.h");
    @cInclude("sys/stat.h");
});
const max_sessions = 64;
var stopping = std.atomic.Value(bool).init(false);

/// Request shutdown; the poll loop wakes within 100 milliseconds.
fn stop(_: c_int) callconv(.c) void {
    stopping.store(true, .release);
}
/// Keep failed socket writes reportable instead of terminating on SIGPIPE.
fn ignoreSignal(_: c_int) callconv(.c) void {}
/// Return errno immediately after a failed C operation.
fn errno() c_int {
    return std.c._errno().*;
}
/// Recognize retryable nonblocking operations.
fn again() bool {
    const e = errno();
    return e == c.EAGAIN or e == c.EWOULDBLOCK or e == c.EINTR;
}
/// Parse a numeric IPv4 endpoint, using loopback when only a port is supplied.
fn address(text: []const u8) !c.struct_sockaddr_in {
    const split = std.mem.lastIndexOfScalar(u8, text, ':');
    const host = if (split) |i| text[0..i] else "127.0.0.1";
    const port = try std.fmt.parseInt(u16, if (split) |i| text[i + 1 ..] else text, 10);
    var result = std.mem.zeroes(c.struct_sockaddr_in);
    result.sin_family = c.AF_INET;
    result.sin_port = std.mem.nativeToBig(u16, port);
    var buf: [64]u8 = undefined;
    const host_z = try std.fmt.bufPrintZ(&buf, "{s}", .{host});
    if (c.inet_pton(c.AF_INET, host_z, &result.sin_addr) != 1) return error.InvalidAddress;
    return result;
}
/// Format a numeric endpoint without allocation.
fn endpoint(a: c.struct_sockaddr_in, buf: *[64]u8) []const u8 {
    const ip: [4]u8 = @bitCast(a.sin_addr.s_addr);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], std.mem.bigToNative(u16, a.sin_port) }) catch @panic("endpoint buffer is sized for IPv4 text");
}
/// Create a nonblocking socket; SIGPIPE is ignored process-wide.
fn socket(udp: bool) !c_int {
    const fd = c.socket(c.AF_INET, if (udp) c.SOCK_DGRAM else c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    if (udp) {
        const size: c_int = 131072;
        if (c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDBUF, &size, @sizeOf(c_int)) != 0) return error.SocketBufferFailed;
    }
    if (c.fcntl(fd, c.F_SETFL, @as(c_int, c.O_NONBLOCK)) < 0) return error.NonblockingFailed;
    return fd;
}
/// Bind an IPv4 socket without reusing another diagnostic listener's port.
fn bind(fd: c_int, a: *const c.struct_sockaddr_in) !void {
    if (c.bind(fd, @ptrCast(a), @sizeOf(c.struct_sockaddr_in)) < 0) return error.BindFailed;
}
/// Write all regular-file bytes or fail visibly; no buffered artifact is hidden.
fn write(fd: c_int, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (n < 0 and errno() == c.EINTR) continue;
        if (n <= 0) return error.RecordingFailed;
        offset += @intCast(n);
    }
}
const Recorder = struct {
    payload: c_int,
    metadata: c_int,
    offset: u64 = 0,
    io: std.Io,
    listen: c.struct_sockaddr_in,
    upstream: c.struct_sockaddr_in,

    /// Create private artifacts exclusively, preserving any previous capture.
    fn init(io: std.Io, path: []const u8, listen: c.struct_sockaddr_in, upstream: c.struct_sockaddr_in) !Recorder {
        const allocator = std.heap.page_allocator;
        const dir = try allocator.dupeZ(u8, path);
        defer allocator.free(dir);
        if (c.mkdir(dir, 0o700) != 0) return error.OutputDirectoryMustBeNew;
        const payload_path = try std.fmt.allocPrintSentinel(allocator, "{s}/payload.bin", .{path}, 0);
        defer allocator.free(payload_path);
        const metadata_path = try std.fmt.allocPrintSentinel(allocator, "{s}/events.jsonl", .{path}, 0);
        defer allocator.free(metadata_path);
        const payload = c.open(payload_path, c.O_WRONLY | c.O_CREAT | c.O_EXCL, @as(c_uint, 0o600));
        if (payload < 0) return error.RecordingFailed;
        errdefer _ = c.close(payload);
        const metadata = c.open(metadata_path, c.O_WRONLY | c.O_CREAT | c.O_EXCL, @as(c_uint, 0o600));
        if (metadata < 0) return error.RecordingFailed;
        return .{ .payload = payload, .metadata = metadata, .io = io, .listen = listen, .upstream = upstream };
    }
    /// Serialize one event; forward events reference received payload offsets.
    fn event(self: *Recorder, s: *const Session, direction: usize, kind: []const u8, offset: u64, length: usize, err: ?[]const u8) !void {
        var a: [64]u8 = undefined;
        var b: [64]u8 = undefined;
        var d: [64]u8 = undefined;
        var local: [64]u8 = undefined;
        const line = try std.json.Stringify.valueAlloc(std.heap.page_allocator, .{
            .timestamp_ns = std.Io.Clock.real.now(self.io).nanoseconds,
            .session = s.id,
            .direction = if (direction == 0) "client_to_upstream" else "upstream_to_client",
            .event = kind,
            .client = endpoint(s.client, &a),
            .listen = endpoint(self.listen, &b),
            .upstream = endpoint(self.upstream, &d),
            .upstream_local = endpoint(s.upstream_local, &local),
            .offset = offset,
            .length = length,
            .@"error" = err,
        }, .{});
        defer std.heap.page_allocator.free(line);
        try write(self.metadata, line);
        try write(self.metadata, "\n");
    }
    /// Persist bytes before any forwarding, including empty UDP datagrams.
    fn received(self: *Recorder, s: *Session, direction: usize) !void {
        const p = &s.pending[direction];
        p.offset = try self.record(s, direction, p.bytes[0..p.len]);
    }
    /// Retain even a datagram rejected because its session queue is full.
    fn record(self: *Recorder, s: *const Session, direction: usize, bytes: []const u8) !u64 {
        const offset = self.offset;
        try write(self.payload, bytes);
        self.offset += bytes.len;
        try self.event(s, direction, "received", offset, bytes.len, null);
        return offset;
    }
    /// Sync both artifacts; callers propagate failures to the exit status.
    fn flush(self: *Recorder) !void {
        if (c.fsync(self.payload) != 0 or c.fsync(self.metadata) != 0) return error.RecordingFailed;
    }
    /// Release artifact descriptors after the last flush attempt.
    fn deinit(self: *Recorder) void {
        _ = c.close(self.payload);
        _ = c.close(self.metadata);
    }
};
const Pending = struct {
    bytes: [65535]u8 = .{0} ** 65535,
    len: usize = 0,
    sent: usize = 0,
    offset: u64 = 0,
    active: bool = false,
    eof: bool = false,
};
const Session = struct {
    id: u64 = 0,
    fd: [2]c_int = .{ -1, -1 },
    client: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in),
    upstream_local: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in),
    pending: [2]Pending = .{ .{}, .{} },
    connecting: bool = false,
    touched: i96 = 0,
    /// Close owned sockets; UDP's shared listener is never owned by a session.
    fn close(self: *Session, udp: bool) void {
        if (!udp and self.fd[0] >= 0) _ = c.close(self.fd[0]);
        if (self.fd[1] >= 0) _ = c.close(self.fd[1]);
        self.id = 0;
    }
};
/// Connect a dedicated upstream socket, optionally binding a signed UDP port.
fn connect(s: *Session, udp: bool, upstream: *const c.struct_sockaddr_in, source: ?c.struct_sockaddr_in) !void {
    if (s.fd[1] < 0) {
        s.fd[1] = try socket(udp);
        if (source) |a| try bind(s.fd[1], &a);
    }
    if (c.connect(s.fd[1], @ptrCast(upstream), @sizeOf(c.struct_sockaddr_in)) != 0) {
        if (!udp and errno() == c.EINPROGRESS) {
            s.connecting = true;
        } else return error.UpstreamConnectFailed;
    }
    var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
    if (c.getsockname(s.fd[1], @ptrCast(&s.upstream_local), &length) != 0) return error.AddressFailed;
}
/// Record an OS failure before retiring only the affected session.
fn failed(r: *Recorder, s: *Session, udp: bool, direction: usize, reason: []const u8) !void {
    try r.event(s, direction, "error", 0, 0, reason);
    s.close(udp);
}
/// Drain one bounded buffer with partial-write accounting and TCP half-close.
fn forward(r: *Recorder, s: *Session, udp: bool, direction: usize) !void {
    const p = &s.pending[direction];
    if (!p.active) return;
    const n = if (udp and direction == 1)
        c.sendto(s.fd[0], p.bytes[p.sent..].ptr, p.len - p.sent, 0, @ptrCast(&s.client), @sizeOf(c.struct_sockaddr_in))
    else
        c.send(s.fd[1 - direction], p.bytes[p.sent..].ptr, p.len - p.sent, 0);
    if (n < 0) {
        if (again()) return;
        return failed(r, s, udp, direction, "send_failed");
    }
    const count: usize = @intCast(n);
    if ((udp and count != p.len) or (!udp and count == 0)) return failed(r, s, udp, direction, "short_send");
    try r.event(s, direction, "forwarded", p.offset + p.sent, count, null);
    p.sent += count;
    if (p.sent == p.len) {
        p.active = false;
        p.len = 0;
        p.sent = 0;
    }
}
/// Receive one TCP chunk or UDP datagram only when its forwarding slot is free.
fn receive(r: *Recorder, s: *Session, udp: bool, direction: usize) !void {
    const p = &s.pending[direction];
    if (p.active or p.eof) return;
    const n = c.recv(s.fd[direction], &p.bytes, p.bytes.len, 0);
    if (n < 0) {
        if (again()) return;
        return failed(r, s, udp, direction, "receive_failed");
    }
    if (!udp and n == 0) {
        p.eof = true;
        try r.event(s, direction, "eof", 0, 0, null);
        if (c.shutdown(s.fd[1 - direction], c.SHUT_WR) != 0) return failed(r, s, udp, direction, "half_close_failed");
        return;
    }
    p.len = @intCast(n);
    p.active = true;
    try r.received(s, direction);
}
/// Run the bounded single-owner event loop until SIGINT/SIGTERM or a recording error.
fn run(io: std.Io, udp: bool, listen: c.struct_sockaddr_in, upstream: c.struct_sockaddr_in, path: []const u8, source: ?c.struct_sockaddr_in) !void {
    const listener = try socket(udp);
    defer _ = c.close(listener);
    try bind(listener, &listen);
    if (!udp and c.listen(listener, 64) != 0) return error.ListenFailed;
    var actual = listen;
    var addr_len: c.socklen_t = @sizeOf(@TypeOf(actual));
    if (c.getsockname(listener, @ptrCast(&actual), &addr_len) != 0) return error.AddressFailed;
    var reserved_source: c_int = -1;
    defer if (reserved_source >= 0) {
        _ = c.close(reserved_source);
    };
    if (source) |a| {
        reserved_source = try socket(true);
        try bind(reserved_source, &a);
    }
    var r = try Recorder.init(io, path, actual, upstream);
    defer r.deinit();
    errdefer |err| {
        const failure = Session{};
        r.event(&failure, 0, "fatal", 0, 0, @errorName(err)) catch |event_err| std.log.err("best-effort operation failed: {s}", .{@errorName(event_err)});
        r.flush() catch |flush_err| std.log.err("best-effort operation failed: {s}", .{@errorName(flush_err)});
    }
    const sessions = try std.heap.page_allocator.alloc(Session, max_sessions);
    defer std.heap.page_allocator.free(sessions);
    for (sessions) |*s| s.* = .{};
    defer for (sessions) |*s| {
        if (s.id != 0) s.close(udp);
    };
    var next_id: u64 = 1;
    var marker = Session{};
    try r.event(&marker, 0, "ready", 0, 0, null);
    try r.flush();
    var ready_buf: [64]u8 = undefined;
    std.log.info("ready {s} {s}", .{ if (udp) "udp" else "tcp", endpoint(actual, &ready_buf) });
    loop: while (!stopping.load(.acquire)) {
        var polls: [1 + max_sessions * 2]c.struct_pollfd = undefined;
        polls[0] = .{ .fd = listener, .events = c.POLLIN, .revents = 0 };
        for (sessions, 0..) |*s, i| {
            for (0..2) |direction| {
                var events: c_short = 0;
                if (s.id != 0) {
                    if (!s.connecting and !s.pending[direction].active and !s.pending[direction].eof) events |= c.POLLIN;
                    if (s.pending[1 - direction].active or (direction == 1 and s.connecting)) events |= c.POLLOUT;
                }
                polls[1 + i * 2 + direction] = .{ .fd = if (s.id == 0 or events == 0 or (udp and direction == 0)) -1 else s.fd[direction], .events = events, .revents = 0 };
            }
        }
        const polled = c.poll(&polls, polls.len, 100);
        if (polled < 0) {
            if (errno() == c.EINTR) continue;
            return error.PollFailed;
        }
        const now = std.Io.Clock.awake.now(io).nanoseconds;
        for (sessions, 0..) |*s, i| {
            if (s.id == 0) continue;
            if ((udp or s.connecting) and now - s.touched > 60 * std.time.ns_per_s) {
                try failed(&r, s, udp, 0, "session_timeout");
                continue;
            }
            if (s.connecting) {
                if (polls[2 + i * 2].revents == 0) continue;
                var result: c_int = 0;
                var length: c.socklen_t = @sizeOf(c_int);
                if (c.getsockopt(s.fd[1], c.SOL_SOCKET, c.SO_ERROR, &result, &length) != 0 or result != 0) {
                    try failed(&r, s, udp, 0, "connect_failed");
                    continue;
                }
                s.connecting = false;
                try r.event(s, 0, "connected", 0, 0, null);
            }
            for (0..2) |direction| {
                if (s.id == 0) break;
                const events = polls[1 + i * 2 + direction].revents;
                if (events & (c.POLLERR | c.POLLNVAL) != 0) {
                    try failed(&r, s, udp, direction, "socket_error");
                    break;
                }
                if (events & (c.POLLIN | c.POLLHUP) != 0) {
                    try receive(&r, s, udp, direction);
                    s.touched = now;
                }
                if (s.id != 0) try forward(&r, s, udp, 1 - direction);
            }
            if (s.id != 0 and !udp and s.pending[0].eof and s.pending[1].eof) {
                try r.event(s, 0, "closed", 0, 0, null);
                s.close(udp);
            }
        }
        if (polls[0].revents & c.POLLIN == 0) continue;
        var client = std.mem.zeroes(c.struct_sockaddr_in);
        var length: c.socklen_t = @sizeOf(@TypeOf(client));
        var packet: [65535]u8 = undefined;
        const accepted = if (udp) c.recvfrom(listener, &packet, packet.len, 0, @ptrCast(&client), &length) else c.accept(listener, @ptrCast(&client), &length);
        if (accepted < 0) {
            if (again()) continue;
            return error.AcceptFailed;
        }
        var chosen: ?*Session = null;
        var recorded = false;
        if (udp) for (sessions) |*s| {
            if (s.id != 0 and s.client.sin_port == client.sin_port and s.client.sin_addr.s_addr == client.sin_addr.s_addr) {
                chosen = s;
                break;
            }
        };
        if (chosen == null) for (sessions[0..if (source != null) 1 else max_sessions]) |*s| {
            if (s.id == 0) {
                s.* = .{ .id = next_id, .client = client, .fd = .{ if (udp) listener else @intCast(accepted), -1 }, .touched = now };
                next_id += 1;
                chosen = s;
                if (!udp and c.fcntl(s.fd[0], c.F_SETFL, @as(c_int, c.O_NONBLOCK)) < 0) return error.NonblockingFailed;
                try r.event(s, 0, "accepted", 0, 0, null);
                if (reserved_source >= 0) {
                    s.fd[1] = reserved_source;
                    reserved_source = -1;
                }
                if (udp) {
                    const p = &s.pending[0];
                    p.len = @intCast(accepted);
                    p.active = true;
                    @memcpy(p.bytes[0..p.len], packet[0..p.len]);
                    try r.received(s, 0);
                    recorded = true;
                }
                connect(s, udp, &upstream, source) catch |err| {
                    try failed(&r, s, udp, 0, @errorName(err));
                    continue :loop;
                };
                break;
            }
        };
        if (chosen) |s| {
            if (udp) {
                const p = &s.pending[0];
                if (!recorded) {
                    if (p.active) {
                        _ = try r.record(s, 0, packet[0..@intCast(accepted)]);
                        return error.UdpBackpressureOverflow;
                    }
                    p.len = @intCast(accepted);
                    p.active = true;
                    @memcpy(p.bytes[0..p.len], packet[0..p.len]);
                    try r.received(s, 0);
                }
                try forward(&r, s, true, 0);
                s.touched = now;
            }
        } else {
            if (!udp) {
                _ = c.close(@intCast(accepted));
            }
            if (udp) {
                const dropped = Session{ .client = client };
                _ = try r.record(&dropped, 0, packet[0..@intCast(accepted)]);
            }
            return error.SessionCapacityExceeded;
        }
    }
    for (sessions) |*s| {
        if (s.id != 0) for (&s.pending, 0..) |*p, direction| {
            try r.event(s, direction, "shutdown", p.offset + p.sent, p.len - p.sent, null);
        };
    }
    try r.event(&marker, 0, "stopped", 0, 0, null);
    try r.flush();
}
/// Parse explicit destinations; bare ports default to loopback, output must be new.
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5 and args.len != 6) {
        std.log.info("usage: hightower-network-proxy tcp|udp LISTEN_IP:PORT UPSTREAM_IP:PORT NEW_OUTPUT_DIR [UDP_SOURCE_IP:PORT]", .{});
        return error.InvalidArguments;
    }
    const udp = std.mem.eql(u8, args[1], "udp");
    if (!udp and !std.mem.eql(u8, args[1], "tcp")) return error.InvalidProtocol;
    if (!udp and args.len == 6) return error.UdpSourceOnly;
    const upstream = try address(args[3]);
    if (upstream.sin_port == 0) return error.InvalidUpstreamPort;
    _ = c.signal(c.SIGPIPE, ignoreSignal);
    _ = c.signal(c.SIGINT, stop);
    _ = c.signal(c.SIGTERM, stop);
    try run(init.io, udp, try address(args[2]), upstream, args[4], if (args.len == 6) try address(args[5]) else null);
}

test "IPv4 endpoints default to loopback and reject invalid input" {
    const a = try address("19000");
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1:19000", endpoint(a, &buf));
    try std.testing.expectError(error.InvalidAddress, address("localhost:1"));
    try std.testing.expectError(error.Overflow, address("65536"));
}
