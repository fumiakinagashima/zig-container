const std = @import("std");
const linux = std.os.linux;
const sys = @import("linux.zig");

const KEEP_CAPS = [_]u8 {
    linux.CAP.CHOWN,
    linux.CAP.DAC_OVERRIDE,
    linux.CAP.FOWNER,
    linux.CAP.FSETID,
    linux.CAP.KILL,
    linux.CAP.SETGID,
    linux.CAP.SETUID,
    linux.CAP.SETPCAP,
    linux.CAP.NET_BIND_SERVICE,
    linux.CAP.NET_RAW,
    linux.CAP.SYS_CHROOT,
    linux.CAP.MKNOD,
    linux.CAP.AUDIT_WRITE,
    linux.CAP.SETFCAP,
};

const CAPABILITY_VERSION_3: u32 = 0x20080522;

fn keepMask() u64 {
    var mask: u64 = 0;
    for (KEEP_CAPS) |cap| mask |= @as(u64, 1) << @as(u6, @intCast(cap));
    return mask;
}

pub fn dropToMinimalSet() !void {
    const mask = keepMask();

    var cap: u8 = 0;
    while (cap <= linux.CAP.LAST_CAP) : (cap += 1) {
        if (mask & (@as(u64, 1) << @as(u6, @intCast(cap))) != 0) continue;
        try sys.prctl(@intFromEnum(linux.PR.CAPBSET_DROP), cap, 0, 0, 0);
    }

    var header = linux.cap_user_header_t{ .version = CAPABILITY_VERSION_3, .pid = 0 };
    const data = [2]linux.cap_user_data_t {
        .{ .effective = @truncate(mask), .permitted = @truncate(mask), .inheritable = 0 },
        .{ .effective = @truncate(mask >> 32), .permitted = @truncate(mask >> 32), .inheritable = 0 },
    };
    try sys.setCapabilities(&header, &data[0]);
}