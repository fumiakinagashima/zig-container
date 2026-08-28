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

pub const CLONE_NEWPID: u32 = 0x20000000;

pub fn cloneInNamespace(
    flags: u32,
    stack: []align(16) u8,
    func: *const fn (arg: usize) callconv(.c) u8,
    arg: usize,
) SyscallError!linux.pid_t {
    const stack_top = @intFromPtr(stack.ptr) + stack.len;
    const rc = linux.clone(
        func,
        stack_top,
        flags | @intFromEnum(linux.SIG.CHLD),
        arg,
        null,
        0,
        null,
    );
    try check("clone", rc);
    return @intCast(rc);
}

pub fn waitForChild(pid: linux.pid_t) SyscallError!u8 {
    var status: u32 = undefined;
    const rc = linux.waitpid(pid, &status, 0);
    try check("waitpid", rc);
    return linux.W.EXITSTATUS(status);
}

pub fn getPid() linux.pid_t {
    return linux.getpid();
}