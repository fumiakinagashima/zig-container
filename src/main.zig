const std = @import("std");
const sys = @import("linux.zig");

const SHM_KEY: i32 = 0x1234;

var child_stack: [1024 * 1024]u8 align(16) = undefined;

fn childMain(rootfs_ptr: usize) callconv(.c) u8 {
    std.debug.print("[child] pid inside new PID namespace: {d}\n", .{sys.getPid()});
    
    sys.setHostname("zig-container") catch |err| {
        std.debug.print("[child] setHostname failed: {s}\n", .{@errorName(err)});
        return 1;
    };

    const uts = sys.getUname() catch |err| {
        std.debug.print("[child] getUname failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    std.debug.print(
        "[child] hostname inside new UTS namespace: {s}\n",
        .{std.mem.sliceTo(&uts.nodename, 0)},
    );

    if (sys.shmGet(SHM_KEY, 4096, 0)) |found_shmid| {
        std.debug.print(
            "[child] unexpectedly found parent's shmid {d} (namespace isolation failed?)\n",
            .{found_shmid},
        );
    } else |err| {
        std.debug.print(
            "[child] shmget lookup for the same key failed as expected: {s} (this IPC namespace has no such segment)\n",
            .{ @errorName(err)},
        );
    }

    const rootfs: [*:0]const u8 = @ptrFromInt(rootfs_ptr);
    sys.pivotRootInto(rootfs) catch |err| {
        std.debug.print(
            "[child] pivot_root into {s} failed: {s}\n",
            .{std.mem.span(rootfs), @errorName(err)},
        );
        return 1;
    };
    std.debug.print("[child] pivot_root done, root filesystem is now {s}\n", .{std.mem.span(rootfs)});

    sys.mountProc() catch |err| {
        std.debug.print("[child] mounting /proc failed: {s}\n", .{@errorName(err)});
        return 1;
    };

    std.debug.print("[child] handing over to /bin/sh\n", .{});

    const shell_argv = [_:null]?[*:0]const u8{"/bin/sh"};
    const shell_envp = [_:null]?[*:0]const u8{"PATH=/bin"};
    sys.execInto("/bin/sh", &shell_argv, &shell_envp) catch |err| {
        std.debug.print("[child] execve failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    unreachable;
}

fn runInNewNamespace(rootfs: [:0]const u8) !void {
    std.debug.print("[parent] pid: {d}\n", .{sys.getPid()});

    const parent_shmid = try sys.shmGet(SHM_KEY, 4096, sys.IPC_CREAT | 0o600);
    std.debug.print(
        "[parent] shmget returned shmid {d} (visible host-wide)\n",
        .{parent_shmid},
    );

    const child_pid = sys.cloneInNamespace(
        sys.CLONE_NEWPID | sys.CLONE_NEWUTS | sys.CLONE_NEWIPC | sys.CLONE_NEWNS,
        &child_stack,
        childMain,
        @intFromPtr(rootfs.ptr),
    ) catch |err| {
        std.debug.print(
            "clone failed (try running with sudo): {s}\n",
            .{@errorName(err)}
        );
        return;
    };
    std.debug.print(
        "[parent] child pid (as seen from parent's namespace): {d}\n",
        .{child_pid},
    );

    const exit_status = try sys.waitForChild(child_pid);
    std.debug.print("[parent] child exited with status: {d}\n", .{exit_status});

    const uts = try sys.getUname();
    std.debug.print(
        "[parent] hostname on host: {s}\n",
        .{std.mem.sliceTo(&uts.nodename, 0)},
    );

    try sys.shmRemove(parent_shmid);
    std.debug.print("[parent] removed shmid {d}\n", .{parent_shmid});

}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    
    if (args.len < 3 or !std.mem.eql(u8, args[1], "run")) {
        std.debug.print("usage: {s} run <rootfs-path>\n", .{args[0]});
        return;
    }

    try runInNewNamespace(args[2]);
}