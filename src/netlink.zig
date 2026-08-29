const std = @import("std");
const linux = std.os.linux;
const sys = @import("linux.zig");

const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFF_UP: u32 = 0x1;

const ifaddrmsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

fn ifla(field: linux.IFLA) u16 {
    return @intCast(@intFromEnum(field));
}

fn ifa(field: linux.IFA) u16 {
    return @intCast(@intFromEnum(field));
}

const Builder = struct {
    buf: [512]u8 = undefined,
    len: usize = 0,

    fn appendRaw(self: *Builder, bytes: []const u8) void {
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn pad(self: *Builder) void {
        while (self.len % 4 != 0) : (self.len += 1) self.buf[self.len] = 0;
    }

    fn appendStruct(self: *Builder, value: anytype) void {
        self.appendRaw(std.mem.asBytes(&value));
        self.pad();
    }

    fn beginAttr(self: *Builder, attr_type: u16) usize {
        const start = self.len;
        self.appendRaw(&[_]u8{ 0, 0, 0, 0 });
        std.mem.writeInt(u16, self.buf[start + 2 ..][0..2], attr_type, .little);
        return start;
    }

    fn endAttr(self: *Builder, start: usize) void {
        const attr_len: u16 = @intCast(self.len - start);
        std.mem.writeInt(u16, self.buf[start..][0..2], attr_len, .little);
        self.pad();
    }

    fn appendAttr(self: *Builder, attr_type: u16, data: []const u8) void {
        const start = self.beginAttr(attr_type);
        self.appendRaw(data);
        self.endAttr(start);
    }

    fn appendAttrZ(self: *Builder, attr_type: u16, str: []const u8) void {
        const start = self.beginAttr(attr_type);
        self.appendRaw(str);
        self.buf[self.len] = 0;
        self.len += 1;
        self.endAttr(start);
    }

    fn beginMessage(
        self: *Builder,
        msg_type: linux.NetlinkMessageType,
        flags: u16,
        seq: u32,
    ) void {
        self.appendStruct(linux.nlmsghdr{
            .len = 0,
            .type = msg_type,
            .flags = flags,
            .seq = seq,
            .pid = 0,
        });
    }

    fn finish(self: *Builder) []const u8 {
        std.mem.writeInt(u32, self.buf[0..4], @intCast(self.len), .little);
        return self.buf[0..self.len];
    }
};

fn emptyIfinfomsg() linux.ifinfomsg {
    return .{
        .family = 0,
        .__pad1 = 0,
        .type = 0,
        .index = 0,
        .flags = 0,
        .change = 0
    };
}

pub const NetlinkSocket = struct {
    fd: i32,
    seq: u32 = 1,

    pub fn open() !NetlinkSocket {
        return NetlinkSocket{ .fd = try sys.createNetlinkSocket() };
    }

    pub fn close(self: NetlinkSocket) void {
        sys.closeFd(self.fd);
    }

    fn nextSeq(self: *NetlinkSocket) u32 {
        const seq = self.seq;
        self.seq += 1;
        return seq;
    }

    fn request(self: *NetlinkSocket, msg: []const u8) !void {
        try sys.sendNetlink(self.fd, msg);

        var buf: [256]u8 = undefined;
        const n = try sys.recvNetlink(self.fd, &buf);
        if (n < @sizeOf(linux.nlmsghdr) + 4) return error.ShortNetlinkReply;

        const hdr = std.mem.bytesToValue(linux.nlmsghdr, buf[0..@sizeOf(linux.nlmsghdr)]);
        if (hdr.type != .ERROR) return error.UnexpectedNetlinkReply;

        const err_code = std.mem.bytesToValue(i32, buf[@sizeOf(linux.nlmsghdr)..][0..4]);
        if (err_code != 0) {
            std.log.err("netlink request failed: errno={d}", .{-err_code});
            return error.NetlinkRequestFailed;
        }
    }

    pub fn createVethPair(
        self: *NetlinkSocket,
        host_name: []const u8,
        peer_name: []const u8
    ) !void {
        var b: Builder =. {};
        b.beginMessage(.RTM_NEWLINK, linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_EXCL, self.nextSeq());
        b.appendStruct(emptyIfinfomsg());
        b.appendAttrZ(ifla(.IFNAME), host_name);

        const link_info  = b.beginAttr(ifla(.LINKINFO));
        b.appendAttrZ(IFLA_INFO_KIND, "veth");

        const info_data  = b.beginAttr(IFLA_INFO_DATA);
        const peer = b.beginAttr(VETH_INFO_PEER);
        b.appendStruct(emptyIfinfomsg());
        b.appendAttrZ(ifla(.IFNAME), peer_name);
        b.endAttr(peer);
        b.endAttr(info_data);
        b.endAttr(link_info);

        try self.request(b.finish());
    }

    pub fn moveToNetns(self: *NetlinkSocket, link_name: []const u8, target_pid: i32) !void {
        var b: Builder = .{}        ;
        b.beginMessage(.RTM_SETLINK, linux.NLM_F_REQUEST | linux.NLM_F_ACK, self.nextSeq());
        b.appendStruct(emptyIfinfomsg());
        b.appendAttrZ(ifla(.IFNAME), link_name);
        b.appendAttr(ifla(.NET_NS_PID), std.mem.asBytes(&@as(u32, @intCast(target_pid))));

        try self.request(b.finish());
    }

    pub fn setLinkUp(self: *NetlinkSocket, link_name: []const u8) !void {
        var b: Builder = .{};
        b.beginMessage(.RTM_SETLINK, linux.NLM_F_REQUEST | linux.NLM_F_ACK, self.nextSeq());
        b.appendStruct(linux.ifinfomsg{ .family = 0, .__pad1 = 0, .type = 0, .index = 0, .flags = IFF_UP, .change = IFF_UP });
        b.appendAttrZ(ifla(.IFNAME), link_name);

        try self.request(b.finish());
    }

    fn getLinkIndex(self: *NetlinkSocket, link_name: []const u8) !i32 {
        var b: Builder = .{};
        b.beginMessage(.RTM_GETLINK, linux.NLM_F_REQUEST, self.nextSeq());
        b.appendStruct(emptyIfinfomsg());
        b.appendAttrZ(ifla(.IFNAME), link_name);

        try sys.sendNetlink(self.fd, b.finish());

        var buf: [512]u8 = undefined;
        const n = try sys.recvNetlink(self.fd,  &buf);
        if (n < @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg)) return error.ShortNetlinkReply;

        const hdr = std.mem.bytesToValue(linux.nlmsghdr, buf[0..@sizeOf(linux.nlmsghdr)]);
        if (hdr.type == .ERROR) {
            const err_code = std.mem.bytesToValue(i32, buf[@sizeOf(linux.nlmsghdr)..][0..4]);
            std.log.err("RTM_GETLINK for {s} failed: errno={d}", .{ link_name, -err_code });
            return error.NetlinkRequestFailed;
        }
        if (hdr.type != .RTM_NEWLINK) return error.UnexpectedNetlinkReply;

        const info_start = @sizeOf(linux.nlmsghdr);
        const info = std.mem.bytesToValue(linux.ifinfomsg, buf[info_start..][0..@sizeOf(linux.ifinfomsg)]);
        
        return info.index;
    }


    pub fn addAddress(
        self: *NetlinkSocket,
        link_name: []const u8,
        addr: [4]u8,
        prefix_len: u8
    ) !void {
        const index = try self.getLinkIndex(link_name);

        var b: Builder = .{};
        b.beginMessage(.RTM_NEWADDR, linux.NLM_F_REQUEST | linux.NLM_F_ACK | linux.NLM_F_CREATE | linux.NLM_F_REPLACE, self.nextSeq());
        b.appendStruct(ifaddrmsg{
            .family = linux.AF.INET,
            .prefixlen = prefix_len,
            .flags = 0,
            .scope = 0,
            .index = @intCast(index)
        });
        b.appendAttr(ifa(.LOCAL), &addr);
        b.appendAttr(ifa(.ADDRESS), &addr);

        try self.request(b.finish());        
    }
};