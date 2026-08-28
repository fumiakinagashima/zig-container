const std = @import("std");
const sys = @import("linux.zig");

var child_stack: [1024 * 1024]u8 align(16) = undefined;

fn childMain(_: usize) callconv(.c) u8 {
    std.debug.print("[child] pid inside new PID namespace: {d}\n", .{sys.getPid()});
    return 0;
}

fn runInNewPidNamespace() !void {
    std.debug.print("[parent] pid: {d}\n", .{sys.getPid()});

    const child_pid = sys.cloneInNamespace(
        sys.CLONE_NEWPID,
        &child_stack,
        childMain,
        0,
    ) catch |err| {
        std.debug.print("clone failed (try running with sudo): {s}\n", .{@errorName(err)});
        return;
    };
    std.debug.print("[parent] child pid (as seen from parent's namespace): {d}\n", .{child_pid});
    const exit_status = try sys.waitForChild(child_pid);
    std.debug.print("[parent] child exited with status: {d}\n", .{exit_status});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    
    if (args.len < 2) {
        std.debug.print("usage: {s} <command>\n", .{args[0]});
        return;
    }

    if (std.mem.eql(u8, args[1], "run")) {
        try runInNewPidNamespace();
        return;
    }

    std.debug.print("command: {s}\n", .{args[1]});
}