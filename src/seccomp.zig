const std = @import("std");
const linux = std.os.linux;
const sys = @import("linux.zig");

const sock_filter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const sock_fprog = extern struct {
    len: u16,
    filter: [*]const sock_filter,
};

const BPF_LD_W_ABS: u16 = 0x00 | 0x00 | 0x20;
const BPF_JMP_JEQ_K: u16 = 0x05 | 0x10 | 0x00;
const BPF_RET_K: u16 = 0x06 | 0x00;
const EPERM: u32 = 1;

fn stmt(code: u16, k: u32) sock_filter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) sock_filter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

pub fn blockMount() !void {
    const nr_offset: u32 = @offsetOf(linux.SECCOMP.data, "nr");
    const mount_nr: u32 = @intFromEnum(linux.SYS.mount);

    const program = [_]sock_filter{
        stmt(BPF_LD_W_ABS, nr_offset),
        jump(BPF_JMP_JEQ_K, mount_nr, 0, 1),
        stmt(BPF_RET_K, linux.SECCOMP.RET.ERRNO | EPERM),
        stmt(BPF_RET_K, linux.SECCOMP.RET.ALLOW),
    };

    const prog = sock_fprog{ .len = program.len, .filter = &program };

    try sys.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    try sys.installSeccompFilter(&prog);
}
