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
pub const CLONE_NEWNS: u32 = 0x00020000;
pub const CLONE_NEWNET: u32 = 0x40000000;

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

pub fn pivotRootInto(new_root: [*:0]const u8) SyscallError!void {
    try check("mount(private)", linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0));
    try check("mount(bind)", linux.mount(new_root, new_root, null, linux.MS.BIND | linux.MS.REC, 0));
    try check("chdir(new_root)", linux.chdir(new_root));
    try check("mkdir(put_old)", linux.mkdir("put_old", 0o700));
    try check("pivot_root", linux.pivot_root(".", "put_old"));
    try check("chdir(/)", linux.chdir("/"));
    try check("umount2(put_old)", linux.umount2("/put_old", linux.MNT.DETACH));
    try check("rmdir(put_old)", linux.rmdir("/put_old"));
}

pub fn mountProc() SyscallError!void {
    try check("mount(proc)", linux.mount("proc", "/proc", "proc", 0, 0));
}

pub fn execInto(
    path: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) SyscallError!void {
    try check("execve", linux.execve(path, argv, envp));
}

pub fn makeDir(path: [*:0]const u8, mode: u32) SyscallError!void {
    try check("mkdir", linux.mkdir(path, mode));
}

pub fn removeDir(path: [*:0]const u8) SyscallError!void {
    try check("rmdir", linux.rmdir(path));
}

pub fn writeFile(path: [*:0]const u8, data: []const u8) SyscallError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY }, 0)    ;
    try check("open", fd_rc);
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    try check("write", linux.write(fd, data.ptr, data.len));
}

pub fn readFd(fd: i32, buf: []u8) SyscallError!usize {
    const rc = linux.read(fd, buf.ptr, buf.len);
    try check("read", rc);
    return rc;
}

pub fn writeFd(fd: i32, data: []const u8) SyscallError!usize {
    const rc = linux.write(fd, data.ptr, data.len);
    try check("write", rc);
    return rc;
}

pub fn closeFd(fd: i32) void {
    _ = linux.close(fd);
}

pub fn createPipe() SyscallError![2]i32 {
    var fds: [2]i32 = undefined;
    try check("pipe2", linux.pipe2(&fds, .{}));
    return fds;
}

pub fn createNetlinkSocket() SyscallError!i32 {
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW, linux.NETLINK.ROUTE);
    try check("socket", rc);
    const fd: i32 = @intCast(rc);

    const addr = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    try check("bind", linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl)));
    
    return fd;
}

pub fn sendNetlink(fd: i32, data: []const u8) SyscallError!void {
    const dest = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    const rc = linux.sendto(fd, data.ptr, data.len, 0, @ptrCast(&dest), @sizeOf(linux.sockaddr.nl));
    try check("sendto", rc);
}

pub fn recvNetlink(fd: i32, buf: []u8) SyscallError!usize {
    const rc = linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
    try check("recvfrom", rc);
    return rc;
}

pub fn prctl(
    option: i32,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) SyscallError!void {
    try check("prctl", linux.prctl(option, arg2, arg3, arg4, arg5));
}

pub fn setCapabilities(
    hdrp: *linux.cap_user_header_t,
    datap: *const linux.cap_user_data_t,
) SyscallError!void {
    try check("capset", linux.capset(hdrp, datap));
}

pub fn installSeccompFilter(prog: *const anyopaque) SyscallError!void {
    try check("seccomp", linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, prog));
}

