const std = @import("std");
const linux = std.os.linux;

pub const SyscallError = error {
    PermissionDenied,
    NotFound,
    Unexpected,
};

fn check(comptime name: []const u8, rc: usize) SyscallError!void {
    switch (linux.errno(rc)) {
        .SUCCESS => return,
        .PERM => return error.PermissionDenied,
        .NOENT => return error.NotFound,
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
pub const CLONE_NEWUTS: u32 = 0x04000000;
pub const CLONE_NEWIPC: u32 = 0x08000000;

pub const IPC_CREAT: u32 = 0o1000;
pub const IPC_RMID: u32 = 0;

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

pub fn shmGet(key: i32, size: usize, flags: u32) SyscallError!i32 {
    const rc = linux.syscall3(.shmget, @intCast(key), size, flags);
    try check("shmget", rc);
    return @intCast(rc);
}

pub fn shmRemove(shmid: i32) SyscallError!void {
    const rc = linux.syscall3(.shmctl, @intCast(shmid), IPC_RMID, 0);
    try check("shmctl", rc);
}
