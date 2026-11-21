// Route patterns are installed once in a segment trie. Lookups allocate
// nothing, prefer a matching literal edge, and borrow named values from path.
const std = @import("std");
pub const max_path_length = 1024;

pub const Handler = enum(usize) { metrics, health, syncing, genesis, block_root, state_root, finality_checkpoints };
const Edge = struct { segment: []const u8, child: usize, parameter: bool };
const Terminal = struct { method: []const u8, handler: usize };
const ExactRoute = struct { method: []const u8, path: []const u8, handler: usize };
const Node = struct {
    edges: std.ArrayList(Edge) = .empty,
    terminals: std.ArrayList(Terminal) = .empty,
};
pub const Match = struct { handler: usize, parameter: ?[]const u8 = null };

pub const Router = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(Node) = .empty,
    exact_routes: std.ArrayList(ExactRoute) = .empty,

    /// Build the current Beacon API routes; additional routes can be registered before serving.
    pub fn init(allocator: std.mem.Allocator) !Router {
        var router = Router{ .allocator = allocator };
        errdefer router.deinit();
        try router.nodes.append(allocator, .{});
        try router.register("GET", "/eth/v1/node/health", @intFromEnum(Handler.health));
        try router.register("GET", "/eth/v1/node/syncing", @intFromEnum(Handler.syncing));
        try router.register("GET", "/eth/v1/beacon/genesis", @intFromEnum(Handler.genesis));
        try router.register("GET", "/eth/v1/beacon/blocks/{id}/root", @intFromEnum(Handler.block_root));
        try router.register("GET", "/eth/v1/beacon/states/{id}/root", @intFromEnum(Handler.state_root));
        try router.register("GET", "/eth/v1/beacon/states/{id}/finality_checkpoints", @intFromEnum(Handler.finality_checkpoints));
        try router.register("GET", "/metrics", @intFromEnum(Handler.metrics));
        return router;
    }

    /// Free all trie storage allocated during route registration.
    pub fn deinit(self: *Router) void {
        for (self.nodes.items) |*node| {
            node.edges.deinit(self.allocator);
            node.terminals.deinit(self.allocator);
        }
        self.nodes.deinit(self.allocator);
        self.exact_routes.deinit(self.allocator);
    }

    /// Register a method and path pattern; method and pattern must outlive the router.
    pub fn register(self: *Router, method: []const u8, pattern: []const u8, handler: usize) !void {
        if (method.len == 0 or pattern.len < 2 or pattern[0] != '/' or pattern[pattern.len - 1] == '/') return error.InvalidRoute;
        var node: usize = 0;
        var parameter_count: usize = 0;
        var segments = Segments.init(pattern);
        while (segments.next()) |segment| {
            if (segment.len == 0) return error.InvalidRoute;
            const parameter = segment.len > 2 and segment[0] == '{' and segment[segment.len - 1] == '}';
            if (parameter) parameter_count += 1;
            if (parameter_count > 1) return error.MultipleParameters;
            const key = if (parameter) "{}" else segment;
            var child: ?usize = null;
            for (self.nodes.items[node].edges.items) |edge| {
                if (edge.parameter == parameter and std.mem.eql(u8, edge.segment, key)) {
                    child = edge.child;
                    break;
                }
            }
            if (child) |index| {
                node = index;
                continue;
            }
            const index = self.nodes.items.len;
            try self.nodes.append(self.allocator, .{});
            try self.nodes.items[node].edges.append(self.allocator, .{ .segment = key, .child = index, .parameter = parameter });
            node = index;
        }
        for (self.nodes.items[node].terminals.items) |terminal| {
            if (std.mem.eql(u8, terminal.method, method)) return error.DuplicateRoute;
        }
        try self.nodes.items[node].terminals.append(self.allocator, .{ .method = method, .handler = handler });
        if (parameter_count == 0) try self.exact_routes.append(self.allocator, .{ .method = method, .path = pattern, .handler = handler });
    }

    /// Match method and path without allocation; captured identifiers borrow path bytes.
    pub fn match(self: *const Router, method: []const u8, path: []const u8) ?Match {
        if (path.len == 0 or path.len > max_path_length or path[0] != '/') return null;
        for (self.exact_routes.items) |route| {
            if (path.len == route.path.len and std.mem.eql(u8, route.method, method) and std.mem.eql(u8, route.path, path))
                return .{ .handler = route.handler };
        }
        return self.matchFrom(0, path, 1, method, null);
    }

    /// Walk unambiguous edges iteratively and backtrack only when literal and parameter edges overlap.
    fn matchFrom(self: *const Router, node_index: usize, path: []const u8, offset: usize, method: []const u8, parameter: ?[]const u8) ?Match {
        var node = node_index;
        var position = offset;
        var captured = parameter;
        while (true) {
            if (position == path.len + 1) {
                for (self.nodes.items[node].terminals.items) |terminal| {
                    if (std.mem.eql(u8, terminal.method, method)) return .{ .handler = terminal.handler, .parameter = captured };
                }
                return null;
            }
            if (position >= path.len) return null;
            const end = std.mem.indexOfScalarPos(u8, path, position, '/') orelse path.len;
            if (end == position) return null;
            const segment = path[position..end];
            const next = if (end == path.len) path.len + 1 else end + 1;
            var literal_child: ?usize = null;
            var named_child: ?usize = null;
            for (self.nodes.items[node].edges.items) |edge| {
                if (edge.parameter) {
                    named_child = edge.child;
                    continue;
                }
                if (std.mem.eql(u8, edge.segment, segment)) literal_child = edge.child;
            }
            if (literal_child) |child| {
                if (named_child) |named| {
                    if (self.matchFrom(child, path, next, method, captured)) |found| return found;
                    node = named;
                    captured = segment;
                } else {
                    node = child;
                }
                position = next;
                continue;
            }
            if (named_child) |child| {
                node = child;
                captured = segment;
                position = next;
                continue;
            }
            return null;
        }
    }
};

const Segments = struct {
    path: []const u8,
    offset: usize = 0,

    /// Start iterating route-pattern segments after the leading slash.
    fn init(path: []const u8) Segments {
        return .{ .path = path, .offset = 1 };
    }

    /// Return the next slash-delimited route segment.
    fn next(self: *Segments) ?[]const u8 {
        if (self.offset >= self.path.len) return null;
        const start = self.offset;
        const end = std.mem.indexOfScalarPos(u8, self.path, start, '/') orelse self.path.len;
        self.offset = end + 1;
        return self.path[start..end];
    }
};

test "router matches methods, prefers literals, and borrows parameters" {
    var router = try Router.init(std.testing.allocator);
    defer router.deinit();
    try router.register("GET", "/eth/v1/beacon/blocks/head/root", 98);
    try router.register("GET", "/eth/v1/beacon/blocks/root/other", 99);
    try router.register("POST", "/eth/v1/beacon/blocks/{id}/root", 100);
    try router.register("GET", "/eth/v1/beacon/blocks/root/extra", 101);

    const parameter = router.match("GET", "/eth/v1/beacon/blocks/tail/root").?;
    try std.testing.expectEqual(@as(usize, @intFromEnum(Handler.block_root)), parameter.handler);
    try std.testing.expectEqualStrings("tail", parameter.parameter.?);
    const literal = router.match("GET", "/eth/v1/beacon/blocks/head/root").?;
    try std.testing.expectEqual(@as(usize, 98), literal.handler);
    try std.testing.expect(literal.parameter == null);
    const fallback = router.match("GET", "/eth/v1/beacon/blocks/root/root").?;
    try std.testing.expectEqual(@as(usize, @intFromEnum(Handler.block_root)), fallback.handler);
    try std.testing.expectEqualStrings("root", fallback.parameter.?);
    try std.testing.expect(router.match("GET", "/eth/v1/beacon/blocks/root/root/") == null);
    const post = router.match("POST", "/eth/v1/beacon/blocks/head/root").?;
    try std.testing.expectEqual(@as(usize, 100), post.handler);
    try std.testing.expect(router.match("DELETE", "/metrics") == null);
    try std.testing.expect(router.match("GET", "/metrics/extra") == null);
    try std.testing.expect(router.match("GET", "/eth//v1/beacon/genesis") == null);
    try std.testing.expect(router.match("GET", "/eth/v1/beacon/states/x/unknown") == null);

    var storage: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var fixed_router = try Router.init(fixed.allocator());
    defer fixed_router.deinit();
    const used = fixed.end_index;
    _ = fixed_router.match("GET", "/eth/v1/beacon/states/justified/root");
    try std.testing.expectEqual(used, fixed.end_index);
}
