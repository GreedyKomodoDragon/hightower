// RLPx authenticates execution peers, encrypts ordered devp2p frames, and
// carries eth/69 transaction messages after both peers check chain status.
// The package keeps handshake and wire limits beside their codecs.
//
// auth/ack -> encrypted Hello -> eth Status -> bounded pool messages
pub const peer = @import("peer.zig");
pub const eth = @import("eth.zig");
