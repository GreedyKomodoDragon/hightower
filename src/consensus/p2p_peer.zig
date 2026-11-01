// A peer is admitted only after its signed discovery ENR, Noise identity,
// Status fork, and Metadata custody promise agree. Yamux keeps one negotiated
// gossip stream apart from bounded Req/Resp streams; incoming gossip reaches
// consensus callbacks only through P2PGossipSession's SSZ and fork gates.
//
//   discovered ENR -> Noise -> Status/Metadata -> gossip or request stream
// Control streams carry one response chunk; a request has a five-second read
// deadline, and gossip RPCs retain the existing 16 MiB limit.
const std = @import("std");
const discovery = @import("discv5_discovery.zig");
const tcp = @import("p2p_tcp.zig");
const yamux = @import("p2p_yamux.zig");
const multistream = @import("p2p_multistream.zig");
const control = @import("p2p_control.zig");
const gossip = @import("p2p_gossip.zig");
const gossip_session = @import("p2p_gossip_session.zig");
const wire = @import("p2p_wire.zig");
const requests = @import("p2p_requests.zig");
const columns = @import("data_columns.zig");
const ingress = @import("p2p_ingress.zig");
const fulu = @import("fulu");
const ssz = @import("ssz");
const merkle = @import("merkle");
const kzg = @import("execution").kzg;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

pub const Routes = struct {
    blocks: requests.BlockLookup,
    columns: *columns.Store,
    canonical: columns.CanonicalRoots,
};

pub const ResponseChunks = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(wire.ResponseChunk) = .empty,

    /// Release all decoded SSZ payloads returned by a bounded request.
    pub fn deinit(self: *ResponseChunks) void {
        for (self.items.items) |chunk| self.allocator.free(chunk.payload);
        self.items.deinit(self.allocator);
    }
};

pub const FetchedBlocks = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(fulu.SignedBeaconBlock) = .empty,

    /// Release decoded blocks after the caller has applied its consensus checks.
    pub fn deinit(self: *FetchedBlocks) void {
        for (self.items.items) |block| ssz.freeDecoded(self.allocator, fulu.SignedBeaconBlock, block);
        self.items.deinit(self.allocator);
    }
};

const ColumnScope = union(enum) {
    roots: requests.ByRootRequest,
    range: requests.ByRangeRequest,
};

pub const Peer = struct {
    allocator: std.mem.Allocator,
    connection: tcp.Connection,
    gossip_service: *gossip.Service,
    gossip_stream: ?gossip_session.Session = null,
    gossip_id: u32 = 5,
    next_stream_id: u32,
    local_status: control.Status,
    local_metadata: control.MetaData,
    remote_status: control.Status = undefined,
    remote_metadata: control.MetaData = undefined,
    routes: ?Routes = null,

    /// Dial a discovered ENR and complete both control exchanges before gossip.
    pub fn dial(allocator: std.mem.Allocator, io: std.Io, identity: Ecdsa.KeyPair, peers: *discovery.Service, service: *gossip.Service, status: control.Status, metadata: control.MetaData, peer_id: [32]u8) !Peer {
        var connection = try tcp.Connection.dial(allocator, io, identity, peers, peer_id);
        errdefer connection.deinit();
        var self = Peer{ .allocator = allocator, .connection = connection, .gossip_service = service, .next_stream_id = 7, .local_status = status, .local_metadata = metadata };
        const status_request = try control.encodeStatus(allocator, status);
        defer allocator.free(status_request);
        const status_response = try self.requestControl(1, .status, status_request);
        defer allocator.free(status_response);
        const status_chunk = try wire.decodeResponseChunk(allocator, .status, status_response, null, 92);
        defer allocator.free(status_chunk.payload);
        self.remote_status = try control.decodeStatusResponse(allocator, &status_chunk);
        try control.checkStatus(self.remote_status, status.fork_digest);
        try self.serveMetadata(2);
        const metadata_response = try self.requestControl(3, .metadata, &.{});
        defer allocator.free(metadata_response);
        const metadata_chunk = try wire.decodeResponseChunk(allocator, .metadata, metadata_response, null, 25);
        defer allocator.free(metadata_chunk.payload);
        self.remote_metadata = try control.decodeMetadataResponse(allocator, &metadata_chunk);
        try self.checkMetadata(peers);
        self.gossip_stream = try gossip_session.Session.init(allocator, service, peer_id, .initiator);
        errdefer self.gossip_stream.?.deinit();
        try self.openGossip();
        return self;
    }

    /// Accept a discovered peer and verify its Status and Metadata before gossip.
    pub fn accept(allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream, identity: Ecdsa.KeyPair, peers: *discovery.Service, service: *gossip.Service, status: control.Status, metadata: control.MetaData) !Peer {
        var connection = try tcp.Connection.accept(allocator, io, stream, identity, peers);
        errdefer connection.deinit();
        var self = Peer{ .allocator = allocator, .connection = connection, .gossip_service = service, .next_stream_id = 4, .local_status = status, .local_metadata = metadata };
        try self.serveStatus(1);
        const metadata_response = try self.requestControl(2, .metadata, &.{});
        defer allocator.free(metadata_response);
        const metadata_chunk = try wire.decodeResponseChunk(allocator, .metadata, metadata_response, null, 25);
        defer allocator.free(metadata_chunk.payload);
        self.remote_metadata = try control.decodeMetadataResponse(allocator, &metadata_chunk);
        try self.checkMetadata(peers);
        try self.serveMetadata(3);
        self.gossip_stream = try gossip_session.Session.init(allocator, service, self.connection.peer_id, .responder);
        errdefer self.gossip_stream.?.deinit();
        try self.acceptGossip();
        return self;
    }

    /// Close gossip and TCP while retaining the peer's invalid-message score.
    pub fn deinit(self: *Peer) void {
        if (self.gossip_stream) |*session| session.deinit();
        self.connection.deinit();
    }

    /// Install borrowed block and column views for serving later requests.
    pub fn setRoutes(self: *Peer, routes: Routes) void {
        self.routes = routes;
    }

    /// Compress one serialized SSZ object and publish it on the gossip stream.
    pub fn publish(self: *Peer, topic: []const u8, ssz_bytes: []const u8) !void {
        const encoded = try wire.encodeGossip(self.allocator, ssz_bytes, self.gossip_service.peers.config.max_encoded_size);
        defer self.allocator.free(encoded);
        const rpc = try gossip.encodePublish(self.allocator, topic, encoded);
        defer self.allocator.free(rpc);
        const frame = try gossip.encodeFrame(self.allocator, rpc);
        defer self.allocator.free(frame);
        var offset: usize = 0;
        const deadline_at = self.connection.deadline();
        while (offset < frame.len) {
            const end = @min(offset + yamux.max_data, frame.len);
            try self.connection.send(.{ .kind = .data, .stream_id = self.gossip_id, .data = frame[offset..end] });
            while (true) {
                const credit = try self.connection.receive(deadline_at);
                defer credit.deinit(self.allocator);
                if (try self.dispatchGossip(credit.frame)) continue;
                if (credit.frame.kind != .window_update or credit.frame.stream_id != self.gossip_id or credit.frame.value != end - offset) return error.InvalidWindowUpdate;
                break;
            }
            offset = end;
        }
    }

    /// Process one authenticated gossip frame and reject unexpected stream data.
    pub fn step(self: *Peer) !void {
        const received = try self.connection.receive(self.connection.deadline());
        defer received.deinit(self.allocator);
        if (received.frame.kind == .window_update) return;
        if (received.frame.kind != .data) return error.UnexpectedStream;
        if (received.frame.stream_id == self.gossip_id) {
            if (received.frame.flags.fin or received.frame.flags.syn) return error.UnexpectedStream;
            if (received.frame.data.len != 0) try self.connection.send(.{ .kind = .window_update, .stream_id = self.gossip_id, .value = @intCast(received.frame.data.len) });
            try self.feedGossip(received.frame.data);
            return;
        }
        if (!received.frame.flags.syn or received.frame.flags.fin) return error.UnexpectedStream;
        try self.serveRequest(received.frame);
    }

    /// Request one supported protocol and decode its bounded response chunks.
    pub fn requestChunks(self: *Peer, protocol: multistream.Protocol, encoded_request: []const u8, max_chunks: usize) !ResponseChunks {
        const wire_protocol = protocol.request() orelse return error.InvalidRequest;
        if (protocol == .status or protocol == .metadata or protocol == .ping or encoded_request.len > 256 * 1024 or max_chunks > columns.max_request_columns) return error.InvalidRequest;
        const id = self.next_stream_id;
        self.next_stream_id = try std.math.add(u32, id, 2);
        const deadline_at = self.connection.deadline();
        try self.offerRequest(id, protocol, deadline_at);
        try self.sendBytes(id, false, true, encoded_request);
        var decoder = wire.ResponseStream.init(self.allocator, wire_protocol, wire.max_payload_size);
        defer decoder.deinit();
        var result = ResponseChunks{ .allocator = self.allocator };
        errdefer result.deinit();
        var total: usize = 0;
        while (true) {
            const received = try self.connection.receive(deadline_at);
            defer received.deinit(self.allocator);
            if (received.frame.kind == .window_update) continue;
            if (try self.dispatchGossip(received.frame)) continue;
            if (received.frame.kind != .data or received.frame.stream_id != id or received.frame.flags.syn) return error.UnexpectedStream;
            if (received.frame.data.len > 16 * 1024 * 1024 - total) return error.PayloadTooLarge;
            total += received.frame.data.len;
            try decoder.append(received.frame.data);
            while (try decoder.next(null)) |chunk| {
                if (result.items.items.len == max_chunks) {
                    self.allocator.free(chunk.payload);
                    return error.TooManyResponses;
                }
                result.items.append(self.allocator, chunk) catch |err| {
                    self.allocator.free(chunk.payload);
                    return err;
                };
            }
            if (received.frame.data.len != 0) try self.connection.send(.{ .kind = .window_update, .stream_id = id, .value = @intCast(received.frame.data.len) });
            if (received.frame.flags.fin) {
                if (decoder.pending.items.len != 0) return error.IncompleteResponse;
                return result;
            }
        }
    }

    /// Fetch requested blocks and verify each fork digest, root, and uniqueness.
    pub fn fetchBlocksByRoot(self: *Peer, roots: []const fulu.Root) !FetchedBlocks {
        if (roots.len > columns.max_request_blocks) return error.InvalidRequest;
        const request_value = requests.BlockRootsRequest{ .data = roots };
        const encoded = try self.encodeRequest(request_value);
        defer self.allocator.free(encoded);
        var chunks = try self.requestChunks(.blocks_by_root, encoded, roots.len);
        defer chunks.deinit();
        var result = FetchedBlocks{ .allocator = self.allocator };
        errdefer result.deinit();
        for (chunks.items.items) |*chunk| {
            const block = try ingress.decodeBlockResponse(self.allocator, self.gossip_service.peers.config, chunk);
            errdefer ssz.freeDecoded(self.allocator, fulu.SignedBeaconBlock, block);
            const root = try merkle.HashTreeRoot(self.allocator, block.message);
            var requested = false;
            for (roots) |want| if (std.mem.eql(u8, &want, &root)) {
                requested = true;
                break;
            };
            if (!requested) return error.UnrequestedBlock;
            for (result.items.items) |earlier| {
                if (std.mem.eql(u8, &(try merkle.HashTreeRoot(self.allocator, earlier.message)), &root)) return error.DuplicateBlock;
            }
            try result.items.append(self.allocator, block);
        }
        return result;
    }

    /// Fetch blocks from a slot progression and check returned slot ordering.
    pub fn fetchBlocksByRange(self: *Peer, start_slot: u64, count: u64, stride: u64) !FetchedBlocks {
        if (count > columns.max_request_blocks or stride == 0) return error.InvalidRequest;
        if (count != 0) _ = try std.math.add(u64, start_slot, try std.math.mul(u64, count - 1, stride));
        const encoded = try self.encodeRequest(requests.BlockRangeRequest{ .start_slot = start_slot, .count = count, .step = stride });
        defer self.allocator.free(encoded);
        var chunks = try self.requestChunks(.blocks_by_range, encoded, @intCast(count));
        defer chunks.deinit();
        var result = FetchedBlocks{ .allocator = self.allocator };
        errdefer result.deinit();
        var previous: ?u64 = null;
        for (chunks.items.items) |*chunk| {
            const block = try ingress.decodeBlockResponse(self.allocator, self.gossip_service.peers.config, chunk);
            errdefer ssz.freeDecoded(self.allocator, fulu.SignedBeaconBlock, block);
            const slot = block.message.slot;
            if (slot < start_slot or (slot - start_slot) % stride != 0 or (slot - start_slot) / stride >= count or (previous != null and slot <= previous.?)) return error.UnrequestedBlock;
            previous = slot;
            try result.items.append(self.allocator, block);
        }
        return result;
    }

    /// Fetch selected columns by root, verify every response, then retain them.
    pub fn fetchColumnsByRoot(self: *Peer, identifiers: []const requests.ByRootIdentifier, store: *columns.Store, settings: *const kzg.Settings, lookup: ingress.ColumnLookup) !usize {
        if (identifiers.len > columns.max_request_blocks) return error.InvalidRequest;
        var total: usize = 0;
        for (identifiers) |identifier| {
            if (identifier.columns.data.len > columns.column_count or identifier.columns.data.len > columns.max_request_columns - total) return error.InvalidRequest;
            total += identifier.columns.data.len;
        }
        const value = requests.ByRootRequest{ .data = identifiers };
        const encoded = try self.encodeRequest(value);
        defer self.allocator.free(encoded);
        var chunks = try self.requestChunks(.columns_by_root, encoded, total);
        defer chunks.deinit();
        return self.retainColumns(&chunks, .{ .roots = value }, store, settings, lookup, null);
    }

    /// Fetch canonical columns by slot range and retain only verified samples.
    pub fn fetchColumnsByRange(self: *Peer, start_slot: u64, count: u64, indices: []const u64, canonical: columns.CanonicalRoots, store: *columns.Store, settings: *const kzg.Settings, lookup: ingress.ColumnLookup) !usize {
        if (count > columns.max_request_blocks or indices.len > columns.column_count or start_slot > std.math.maxInt(u64) - count) return error.InvalidRequest;
        const maximum = try std.math.mul(usize, @intCast(count), indices.len);
        if (maximum > columns.max_request_columns) return error.InvalidRequest;
        const value = requests.ByRangeRequest{ .start_slot = start_slot, .count = count, .columns = .{ .data = indices } };
        const encoded = try self.encodeRequest(value);
        defer self.allocator.free(encoded);
        var chunks = try self.requestChunks(.columns_by_range, encoded, maximum);
        defer chunks.deinit();
        return self.retainColumns(&chunks, .{ .range = value }, store, settings, lookup, canonical);
    }

    /// Check the complete response against request scope before any store write.
    fn retainColumns(self: *Peer, chunks: *ResponseChunks, scope: ColumnScope, store: *columns.Store, settings: *const kzg.Settings, lookup: ingress.ColumnLookup, canonical: ?columns.CanonicalRoots) !usize {
        var seen = std.AutoHashMap([40]u8, void).init(self.allocator);
        defer seen.deinit();
        var previous_slot: ?u64 = null;
        var previous_index: u64 = 0;
        const config = self.gossip_service.peers.config;
        for (chunks.items.items) |*chunk| {
            if (chunk.code != .success or chunk.fork_digest == null) return error.InvalidResponseCode;
            var reader: std.Io.Reader = .fixed(chunk.payload);
            const sidecar = try ssz.deserialize(self.allocator, fulu.DataColumnSidecar, &reader);
            defer ssz.freeDecoded(self.allocator, fulu.DataColumnSidecar, sidecar);
            const slot = sidecar.signed_block_header.message.slot;
            const digest = try config.digestAtSlot(slot);
            if (!std.mem.eql(u8, &digest, &chunk.fork_digest.?)) return error.InvalidForkContext;
            if (!store.samples.contains(sidecar.index)) return error.UnselectedColumn;
            const known = lookup.resolve(lookup.context, &sidecar.signed_block_header) orelse return error.UnknownBlock;
            const root = try columns.verify(self.allocator, settings, &sidecar, known.block, known.parent_state);
            const requested = switch (scope) {
                .roots => |value| blk: {
                    for (value.data) |identifier| {
                        if (!std.mem.eql(u8, &identifier.block_root, &root)) continue;
                        for (identifier.columns.data) |index| if (index == sidecar.index) break :blk true;
                    }
                    break :blk false;
                },
                .range => |value| blk: {
                    if (slot < value.start_slot or slot - value.start_slot >= value.count) break :blk false;
                    const expected_root = canonical.?.root_at_slot(canonical.?.context, slot) orelse break :blk false;
                    if (!std.mem.eql(u8, &root, &expected_root)) break :blk false;
                    for (value.columns.data) |index| if (index == sidecar.index) break :blk true;
                    break :blk false;
                },
            };
            if (!requested) return error.UnrequestedColumn;
            if (scope == .range) {
                if (previous_slot) |prior| {
                    if (slot < prior or (slot == prior and sidecar.index <= previous_index)) return error.InvalidResponseOrder;
                }
                previous_slot = slot;
                previous_index = sidecar.index;
            }
            var key: [40]u8 = undefined;
            @memcpy(key[0..32], &root);
            std.mem.writeInt(u64, key[32..40], sidecar.index, .big);
            if (seen.contains(key)) return error.DuplicateColumn;
            try seen.put(key, {});
        }
        for (chunks.items.items) |*chunk| {
            var reader: std.Io.Reader = .fixed(chunk.payload);
            const sidecar = try ssz.deserialize(self.allocator, fulu.DataColumnSidecar, &reader);
            defer ssz.freeDecoded(self.allocator, fulu.DataColumnSidecar, sidecar);
            const known = lookup.resolve(lookup.context, &sidecar.signed_block_header) orelse return error.UnknownBlock;
            try ingress.receiveColumnResponse(self.allocator, config, chunk, store, settings, known.block, known.parent_state);
        }
        return chunks.items.items.len;
    }

    /// Encode a bounded SSZ request in the existing Snappy wire framing.
    fn encodeRequest(self: *Peer, value: anytype) ![]u8 {
        const serialized = try ssz.serializeAlloc(self.allocator, value);
        defer self.allocator.free(serialized);
        return wire.encodePayload(self.allocator, serialized, wire.max_payload_size);
    }

    /// Send a bounded payload over one Yamux stream, marking its first and last frame.
    fn sendBytes(self: *Peer, id: u32, syn: bool, fin: bool, bytes: []const u8) !void {
        if (bytes.len == 0) return self.connection.send(.{ .kind = .data, .flags = .{ .syn = syn, .fin = fin }, .stream_id = id });
        var offset: usize = 0;
        while (offset < bytes.len) {
            const end = @min(offset + yamux.max_data, bytes.len);
            try self.connection.send(.{ .kind = .data, .flags = .{ .syn = syn and offset == 0, .fin = fin and end == bytes.len }, .stream_id = id, .data = bytes[offset..end] });
            offset = end;
        }
    }

    /// Read one frame for a control stream, skipping peer window updates.
    fn controlFrame(self: *Peer, id: u32, deadline_at: i96) !tcp.Connection.Received {
        while (true) {
            const received = try self.connection.receive(deadline_at);
            if (received.frame.kind == .window_update) {
                received.deinit(self.allocator);
                continue;
            }
            if (received.frame.kind != .data or received.frame.stream_id != id) {
                received.deinit(self.allocator);
                return error.UnexpectedStream;
            }
            return received;
        }
    }

    /// Negotiate one outbound request stream before sending its SSZ payload.
    fn offerRequest(self: *Peer, id: u32, protocol: multistream.Protocol, deadline_at: i96) !void {
        const offer = try multistream.offer(self.allocator, protocol);
        defer self.allocator.free(offer);
        try self.sendBytes(id, true, false, offer);
        var state = multistream.Initiator{ .protocol = protocol };
        while (true) {
            const received = try self.connection.receive(deadline_at);
            defer received.deinit(self.allocator);
            if (received.frame.kind == .window_update) continue;
            if (try self.dispatchGossip(received.frame)) continue;
            if (received.frame.kind != .data or received.frame.stream_id != id or received.frame.flags.fin) return error.InvalidNegotiation;
            const parsed = try state.feed(received.frame.data);
            if (parsed.consumed != received.frame.data.len) return error.InvalidNegotiation;
            if (parsed.selected) return;
        }
    }

    /// Decode one inbound request and serve retained blocks or verified columns.
    fn serveRequest(self: *Peer, opening: yamux.Frame) !void {
        const routes = self.routes orelse return error.ResourceUnavailable;
        const id = opening.stream_id;
        var selector = multistream.Responder{};
        var offset: usize = 0;
        var selected: ?multistream.Protocol = null;
        while (offset < opening.data.len) {
            const parsed = try selector.feed(self.allocator, opening.data[offset..]);
            offset += parsed.consumed;
            if (parsed.response) |reply| {
                defer self.allocator.free(reply);
                try self.sendBytes(id, false, false, reply);
            }
            if (parsed.selected) |protocol| selected = protocol;
        }
        const protocol = selected orelse return error.InvalidNegotiation;
        if (protocol != .blocks_by_root and protocol != .blocks_by_range and protocol != .columns_by_root and protocol != .columns_by_range) return error.InvalidRequest;
        var request_bytes: std.ArrayList(u8) = .empty;
        defer request_bytes.deinit(self.allocator);
        const deadline_at = self.connection.deadline();
        while (true) {
            const received = try self.connection.receive(deadline_at);
            defer received.deinit(self.allocator);
            if (received.frame.kind == .window_update) continue;
            if (try self.dispatchGossip(received.frame)) continue;
            if (received.frame.kind != .data or received.frame.stream_id != id or received.frame.flags.syn or received.frame.data.len > 256 * 1024 - request_bytes.items.len) return error.InvalidRequest;
            try request_bytes.appendSlice(self.allocator, received.frame.data);
            if (received.frame.flags.fin) break;
        }
        const config = self.gossip_service.peers.config;
        var response = switch (protocol) {
            .blocks_by_root => try requests.serveBlocksByRoot(self.allocator, config, request_bytes.items, routes.blocks),
            .blocks_by_range => try requests.serveBlocksByRange(self.allocator, config, request_bytes.items, routes.blocks),
            .columns_by_root => try requests.serveColumnsByRoot(self.allocator, config, request_bytes.items, routes.columns),
            .columns_by_range => try requests.serveColumnsByRange(self.allocator, config, request_bytes.items, routes.columns, routes.canonical),
            else => unreachable,
        };
        defer response.deinit();
        var total: usize = 0;
        for (response.items.items) |chunk| {
            if (chunk.len > 16 * 1024 * 1024 - total) break;
            total += chunk.len;
            var start: usize = 0;
            while (start < chunk.len) {
                const end = @min(start + yamux.max_data, chunk.len);
                try self.connection.send(.{ .kind = .data, .stream_id = id, .data = chunk[start..end] });
                while (true) {
                    const credit = try self.connection.receive(self.connection.deadline());
                    defer credit.deinit(self.allocator);
                    if (try self.dispatchGossip(credit.frame)) continue;
                    if (credit.frame.kind != .window_update or credit.frame.stream_id != id or credit.frame.value != end - start) return error.InvalidWindowUpdate;
                    break;
                }
                start = end;
            }
        }
        try self.connection.send(.{ .kind = .data, .flags = .{ .fin = true }, .stream_id = id });
    }

    /// Negotiate and perform one small Req/Resp control request on a new stream.
    fn requestControl(self: *Peer, id: u32, protocol: multistream.Protocol, request: []const u8) ![]u8 {
        const deadline_at = self.connection.deadline();
        const offer = try multistream.offer(self.allocator, protocol);
        defer self.allocator.free(offer);
        try self.sendBytes(id, true, false, offer);
        var selected = multistream.Initiator{ .protocol = protocol };
        while (true) {
            const received = try self.controlFrame(id, deadline_at);
            defer received.deinit(self.allocator);
            const parsed = try selected.feed(received.frame.data);
            if (parsed.consumed != received.frame.data.len) return error.InvalidNegotiation;
            if (parsed.selected) break;
        }
        try self.sendBytes(id, false, true, request);
        var response: std.ArrayList(u8) = .empty;
        errdefer response.deinit(self.allocator);
        while (true) {
            const received = try self.controlFrame(id, deadline_at);
            defer received.deinit(self.allocator);
            if (received.frame.data.len > 512 - response.items.len) return error.PayloadTooLarge;
            try response.appendSlice(self.allocator, received.frame.data);
            if (received.frame.flags.fin) return response.toOwnedSlice(self.allocator);
        }
    }

    /// Read one negotiated request, keeping its untrusted bytes below 512.
    fn readControl(self: *Peer, id: u32, protocol: multistream.Protocol) ![]u8 {
        const deadline_at = self.connection.deadline();
        const opening = try self.controlFrame(id, deadline_at);
        defer opening.deinit(self.allocator);
        if (!opening.frame.flags.syn) return error.InvalidNegotiation;
        var selected = multistream.Responder{ .allowed = protocol };
        var offset: usize = 0;
        while (offset < opening.frame.data.len) {
            const parsed = try selected.feed(self.allocator, opening.frame.data[offset..]);
            offset += parsed.consumed;
            if (parsed.response) |reply| {
                defer self.allocator.free(reply);
                try self.sendBytes(id, false, false, reply);
            }
            if (parsed.selected) |got| {
                if (got != protocol or offset != opening.frame.data.len) return error.InvalidNegotiation;
                break;
            }
        }
        if (selected.phase != .selected) return error.InvalidNegotiation;
        var request: std.ArrayList(u8) = .empty;
        errdefer request.deinit(self.allocator);
        while (true) {
            const received = try self.controlFrame(id, deadline_at);
            defer received.deinit(self.allocator);
            if (received.frame.flags.syn or received.frame.data.len > 512 - request.items.len) return error.InvalidRequest;
            try request.appendSlice(self.allocator, received.frame.data);
            if (received.frame.flags.fin) return request.toOwnedSlice(self.allocator);
        }
    }

    /// Verify and answer the first Status exchange on an authenticated stream.
    fn serveStatus(self: *Peer, id: u32) !void {
        const request = try self.readControl(id, .status);
        defer self.allocator.free(request);
        self.remote_status = try control.decodeStatus(self.allocator, request);
        try control.checkStatus(self.remote_status, self.local_status.fork_digest);
        const response = try control.encodeStatusResponse(self.allocator, self.local_status);
        defer self.allocator.free(response);
        try self.sendBytes(id, false, true, response);
    }

    /// Answer Metadata with the local custody promise after an empty request.
    fn serveMetadata(self: *Peer, id: u32) !void {
        const request = try self.readControl(id, .metadata);
        defer self.allocator.free(request);
        if (request.len != 0) return error.InvalidRequest;
        const response = try control.encodeMetadataResponse(self.allocator, self.local_metadata);
        defer self.allocator.free(response);
        try self.sendBytes(id, false, true, response);
    }

    /// Bind a decoded Metadata custody count to the signed discovery ENR.
    fn checkMetadata(self: *Peer, peers: *discovery.Service) !void {
        const record = peers.discoveredRecord(self.connection.peer_id) orelse return error.UnknownPeer;
        if (record.custody_group_count != self.remote_metadata.custody_group_count) return error.InvalidCustodyCount;
    }

    /// Open and select one gossip stream after both control exchanges pass.
    fn openGossip(self: *Peer) !void {
        const session = if (self.gossip_stream) |*value| value else return error.MissingGossipStream;
        const deadline_at = self.connection.deadline();
        const opening = try session.opening();
        defer self.allocator.free(opening);
        try self.sendBytes(self.gossip_id, true, false, opening);
        while (!session.selected) {
            const received = try self.controlFrame(self.gossip_id, deadline_at);
            defer received.deinit(self.allocator);
            try self.feedGossip(received.frame.data);
        }
        const subscription = try self.controlFrame(self.gossip_id, deadline_at);
        defer subscription.deinit(self.allocator);
        try self.feedGossip(subscription.frame.data);
    }

    /// Select an inbound gossip stream and consume its first subscription RPC.
    fn acceptGossip(self: *Peer) !void {
        const deadline_at = self.connection.deadline();
        const opening = try self.controlFrame(self.gossip_id, deadline_at);
        defer opening.deinit(self.allocator);
        if (!opening.frame.flags.syn) return error.InvalidNegotiation;
        try self.feedGossip(opening.frame.data);
        const subscription = try self.controlFrame(self.gossip_id, deadline_at);
        defer subscription.deinit(self.allocator);
        try self.feedGossip(subscription.frame.data);
    }

    /// Route negotiation output and later RPC bytes through the gossip gate.
    fn feedGossip(self: *Peer, bytes: []const u8) !void {
        const session = if (self.gossip_stream) |*value| value else return error.MissingGossipStream;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const result = try session.feed(bytes[offset..]);
            defer result.deinit(self.allocator);
            if (result.consumed == 0) return error.InvalidNegotiation;
            offset += result.consumed;
            if (result.reply) |reply| try self.sendBytes(self.gossip_id, false, false, reply);
            if (result.subscription) |subscription| try self.sendBytes(self.gossip_id, false, false, subscription);
        }
    }

    /// Deliver gossip interleaved with a request and replenish its Yamux window.
    fn dispatchGossip(self: *Peer, frame: yamux.Frame) !bool {
        if (frame.kind != .data or frame.stream_id != self.gossip_id) return false;
        if (frame.flags.syn or frame.flags.fin) return error.UnexpectedStream;
        if (frame.data.len != 0) try self.connection.send(.{ .kind = .window_update, .stream_id = self.gossip_id, .value = @intCast(frame.data.len) });
        try self.feedGossip(frame.data);
        return true;
    }
};

test "discovered peers exchange Status Metadata block and attestation over TCP" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const enr = @import("enr.zig");
    const fixture = @import("fixture_runner.zig");
    const key_a = try Ecdsa.KeyPair.generateDeterministic([_]u8{111} ** 32);
    const key_b = try Ecdsa.KeyPair.generateDeterministic([_]u8{112} ** 32);
    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 0, .tcp_port = listener.socket.address.ip4.port, .fork_id = .{ 1, 2, 3, 4, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    var local_b = local;
    local_b.custody_group_count = 128;
    var discovery_a = try discovery.Service.init(allocator, io, key_a, local, 2);
    defer discovery_a.deinit();
    var discovery_b = try discovery.Service.init(allocator, io, key_b, local_b, 2);
    defer discovery_b.deinit();
    const b_uri = try discovery_b.localUri();
    defer allocator.free(b_uri);
    try discovery_a.addBootstrap(b_uri);
    try discovery_a.maintain();
    const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } };
    try discovery_b.step(timeout);
    try discovery_a.step(timeout);
    try discovery_b.step(timeout);
    try discovery_a.step(timeout);

    const config = ingress.Config{ .genesis_validators_root = [_]u8{1} ** 32, .fulu_version = .{ 6, 0, 0, 0 }, .fulu_epoch = 0, .blob_schedule = &@import("helpers.zig").BLOB_SCHEDULE };
    const raw_block = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/availability/block.ssz_snappy"));
    defer allocator.free(raw_block);
    var block_reader: std.Io.Reader = .fixed(raw_block);
    const block = try ssz.deserialize(allocator, fulu.SignedBeaconBlock, &block_reader);
    defer ssz.freeDecoded(allocator, fulu.SignedBeaconBlock, block);
    const digest = try config.digestAtSlot(block.message.slot);
    const block_root = try merkle.HashTreeRoot(allocator, block.message);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var column_store = try columns.Store.open(allocator, io, tmp.dir, "columns", config.genesis_validators_root, discovery_b.local_record.node_id, 128);
    defer column_store.deinit();
    // shortcut: pinned sidecars cover the zero-ID sample set, use arbitrary-node vectors when available.
    var received_store = try columns.Store.open(allocator, io, tmp.dir, "received", config.genesis_validators_root, [_]u8{0} ** 32, 4);
    defer received_store.deinit();
    var parent_state = try fixture.decodeState(allocator, @embedFile("fixtures/fulu_fork_choice/availability/anchor_state.ssz_snappy"));
    defer ssz.freeDecoded(allocator, fulu.BeaconState, parent_state);
    var settings = try kzg.loadTrustedSetup("src/execution/trusted_setup.txt");
    defer settings.deinit();
    const sidecar_fixtures = [_][]const u8{
        @embedFile("fixtures/fulu_data_columns/sample_01.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_17.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_19.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_42.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_75.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_87.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_102.ssz_snappy"),
        @embedFile("fixtures/fulu_data_columns/sample_117.ssz_snappy"),
    };
    for (sidecar_fixtures) |compressed| {
        const raw = try fixture.decode(allocator, compressed);
        defer allocator.free(raw);
        var reader: std.Io.Reader = .fixed(raw);
        const sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &reader);
        defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, sidecar);
        try column_store.put(&settings, &sidecar, &block.message, &parent_state);
    }
    const raw_attestation = try fixture.decode(allocator, @embedFile("fixtures/fulu_fork_choice/slashing/attestation_0x5172be6898efefa589c2182765c8e7a74272ed2b0004d0577921a4808b364fcf.ssz_snappy"));
    defer allocator.free(raw_attestation);
    const Counts = struct { blocks: usize = 0, attestations: usize = 0 };
    var counts_a = Counts{};
    var counts_b = Counts{};
    const Validators = struct {
        /// Count a block only after SSZ, fork, and peer admission gates pass.
        fn acceptBlock(context: *anyopaque, _: *const fulu.SignedBeaconBlock) !void {
            const counts: *Counts = @ptrCast(@alignCast(context));
            counts.blocks += 1;
        }

        /// Count an attestation only after its consensus validation callback.
        fn attestation(context: *anyopaque, _: *const fulu.Attestation) !void {
            const counts: *Counts = @ptrCast(@alignCast(context));
            counts.attestations += 1;
        }

        /// Accept aggregate messages unused by this two-node test.
        fn aggregate(_: *anyopaque, _: *const fulu.SignedAggregateAndProof) !void {}
    };
    var service_a = try gossip.Service.init(allocator, config, digest, &.{3}, 1, 3, .{ .context = &counts_a, .validate = Validators.acceptBlock }, .{ .context = &counts_a, .validate = Validators.attestation }, .{ .context = &counts_a, .validate = Validators.aggregate }, null);
    defer service_a.deinit();
    var service_b = try gossip.Service.init(allocator, config, digest, &.{3}, 1, 3, .{ .context = &counts_b, .validate = Validators.acceptBlock }, .{ .context = &counts_b, .validate = Validators.attestation }, .{ .context = &counts_b, .validate = Validators.aggregate }, null);
    defer service_b.deinit();
    const status = control.Status{ .fork_digest = digest, .finalized_root = .{0} ** 32, .finalized_epoch = 0, .head_root = .{0} ** 32, .head_slot = block.message.slot, .earliest_available_slot = 0 };
    const metadata = control.MetaData{ .seq_number = 1, .attnets = .{ .data = [_]bool{false} ** 64 }, .syncnets = .{ .data = [_]bool{false} ** 4 }, .custody_group_count = 4 };
    var metadata_b = metadata;
    metadata_b.custody_group_count = 128;
    const Context = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *std.Io.net.Server,
        key: Ecdsa.KeyPair,
        peers: *discovery.Service,
        service: *gossip.Service,
        status: control.Status,
        metadata: control.MetaData,
        routes: Routes,
        err: ?anyerror = null,

        /// Accept and process one block and one attestation from the peer.
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        /// Keep the authenticated gossip connection alive for two messages.
        fn serve(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var peer = try Peer.accept(self.allocator, self.io, stream, self.key, self.peers, self.service, self.status, self.metadata);
            defer peer.deinit();
            peer.setRoutes(self.routes);
            try peer.step();
            try peer.step();
            try peer.step();
            try peer.step();
            try peer.step();
            try peer.step();
            try peer.step();
            const unfinished = try peer.connection.receive(peer.connection.deadline());
            unfinished.deinit(self.allocator);
        }
    };
    const Lookup = struct { block: *const fulu.SignedBeaconBlock, parent_state: *const fulu.BeaconState, root: fulu.Root };
    var lookup = Lookup{ .block = &block, .parent_state = &parent_state, .root = block_root };
    const get = struct {
        /// Return only the block matching the retained message root.
        fn byRoot(context: *anyopaque, root: fulu.Root) ?fulu.SignedBeaconBlock {
            const source: *Lookup = @ptrCast(@alignCast(context));
            return if (std.mem.eql(u8, &source.root, &root)) source.block.* else null;
        }

        /// Return the retained root at its exact slot.
        fn atSlot(context: *anyopaque, slot: u64) ?fulu.Root {
            const source: *Lookup = @ptrCast(@alignCast(context));
            return if (source.block.message.slot == slot) source.root else null;
        }
    };
    const routes = Routes{ .blocks = .{ .context = &lookup, .by_root = get.byRoot, .root_at_slot = get.atSlot }, .columns = &column_store, .canonical = .{ .context = &lookup, .root_at_slot = get.atSlot } };
    var context = Context{ .allocator = allocator, .io = io, .listener = &listener, .key = key_b, .peers = &discovery_b, .service = &service_b, .status = status, .metadata = metadata_b, .routes = routes };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&context});
    var peer_a = try Peer.dial(allocator, io, key_a, &discovery_a, &service_a, status, metadata, discovery_b.local_record.node_id);
    defer peer_a.deinit();
    try peer_a.publish(service_a.block_topic, raw_block);
    try peer_a.publish(service_a.attestation_topics[3].?, raw_attestation);
    var fetched = try peer_a.fetchBlocksByRoot(&.{block_root});
    defer fetched.deinit();
    try std.testing.expectEqual(@as(usize, 1), fetched.items.items.len);
    try std.testing.expectEqual(block_root, try merkle.HashTreeRoot(allocator, fetched.items.items[0].message));
    const unknown = requests.ByRootRequest{ .data = &.{.{ .block_root = [_]u8{0xff} ** 32, .columns = .{ .data = &.{1} } }} };
    const unknown_ssz = try ssz.serializeAlloc(allocator, unknown);
    defer allocator.free(unknown_ssz);
    const unknown_wire = try wire.encodePayload(allocator, unknown_ssz, wire.max_payload_size);
    defer allocator.free(unknown_wire);
    var empty_chunks = try peer_a.requestChunks(.columns_by_root, unknown_wire, 1);
    defer empty_chunks.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_chunks.items.items.len);
    try std.testing.expect(!try column_store.available(block_root, &block.message));
    var ranged = try peer_a.fetchBlocksByRange(block.message.slot, 1, 1);
    defer ranged.deinit();
    try std.testing.expectEqual(@as(usize, 1), ranged.items.items.len);
    const known = ingress.ColumnLookup{ .context = &lookup, .resolve = struct {
        /// Let the verified column gate match a sidecar to the known fixture block.
        fn resolve(ctx: *anyopaque, _: *const fulu.SignedBeaconBlockHeader) ?ingress.ColumnBlock {
            const source: *Lookup = @ptrCast(@alignCast(ctx));
            return .{ .block = &source.block.message, .parent_state = source.parent_state };
        }
    }.resolve };
    const first = [_]u64{ 1, 17, 19, 42 };
    const second = [_]u64{ 75, 87, 102, 117 };
    var invalid_chunks = ResponseChunks{ .allocator = allocator };
    defer invalid_chunks.deinit();
    try invalid_chunks.items.append(allocator, .{ .code = .success, .fork_digest = digest, .payload = try fixture.decode(allocator, sidecar_fixtures[0]) });
    const second_raw = try fixture.decode(allocator, sidecar_fixtures[1]);
    defer allocator.free(second_raw);
    var invalid_reader: std.Io.Reader = .fixed(second_raw);
    const invalid_sidecar = try ssz.deserialize(allocator, fulu.DataColumnSidecar, &invalid_reader);
    defer ssz.freeDecoded(allocator, fulu.DataColumnSidecar, invalid_sidecar);
    const bad_proofs = try allocator.dupe(fulu.KZGProof, invalid_sidecar.kzg_proofs.data);
    defer allocator.free(bad_proofs);
    bad_proofs[0][0] ^= 1;
    var altered_sidecar = invalid_sidecar;
    altered_sidecar.kzg_proofs = .{ .data = bad_proofs };
    try invalid_chunks.items.append(allocator, .{ .code = .success, .fork_digest = digest, .payload = try ssz.serializeAlloc(allocator, altered_sidecar) });
    const before_rejection = received_store.database.index.count();
    try std.testing.expectError(error.InvalidCellProof, peer_a.retainColumns(&invalid_chunks, .{ .roots = .{ .data = &.{.{ .block_root = block_root, .columns = .{ .data = &first } }} } }, &received_store, &settings, known, null));
    try std.testing.expectEqual(before_rejection, received_store.database.index.count());
    try std.testing.expectEqual(@as(usize, 4), try peer_a.fetchColumnsByRoot(&.{.{ .block_root = block_root, .columns = .{ .data = &first } }}, &received_store, &settings, known));
    try std.testing.expect(!try received_store.available(block_root, &block.message));
    try std.testing.expectEqual(@as(usize, 4), try peer_a.fetchColumnsByRange(block.message.slot, 1, &second, routes.canonical, &received_store, &settings, known));
    try std.testing.expect(try received_store.available(block_root, &block.message));
    try std.testing.expectError(error.EndOfStream, peer_a.fetchBlocksByRoot(&.{block_root}));
    thread.join();
    if (context.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), counts_b.blocks);
    try std.testing.expectEqual(@as(usize, 1), counts_b.attestations);
}
