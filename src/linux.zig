const std = @import("std");
const linux = std.os.linux;

pub const SyscallError = error {
    PermissionDenied,
    Unexpected,
};

fn check(comptime name: []const u8, rc: usize) SyscallError!void {
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        .PERM => return error.PermissionDenied,
        else => |err| {
            std.log.err(
                "{s} failed: errno={d} ({s})",
                .{name, @intFromEnum(err), @tagName(err)}
            );
            return error.Unexpected;
        },
    }
}

pub fn getUname() SyscallError!linux.utsname {
    var uts: linux.utsname = undefined;
    try check("uname", linux.uname(&uts));
    return uts;
}

pub fn setHostname(name: []const u8) SyscallError!void {
    const rc = linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
    try check("sethostname", rc);
}