const std = @import("std");
const sys = @import("linux.zig");
const Cgroup = @import("cgroup.zig").Cgroup;
const Netlink = @import("netlink.zig").NetlinkSocket;
const capabilities = @import("capabilities.zig");
const seccomp = @import("seccomp.zig");
const oci_config = @import("oci_config.zig");

const SHM_KEY: i32 = 0x1234;
const HOST_VETH_ADDR = [4]u8{ 10, 200, 0, 1 };
const CONTAINER_VETH_ADDR = [4]u8{ 10, 200, 0, 2 };
const VETH_PREFIX_LEN: u8 = 24;

const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 100 * 1024 * 1024;
const DEFAULT_CPU_QUOTA_US: u64 = 50_000;
const DEFAULT_CPU_PERIOD_US: u64 = 100_000;

var child_stack: [1024 * 1024]u8 align(16) = undefined;

const ChildContext = struct {
    rootfs: [*:0]const u8,
    sync_read_fd: i32,
    peer_veth_name: [*:0]const u8,
    hostname: []const u8,
    cwd: [*:0]const u8,
    program: [*:0]const u8,
    argv: [:null]const ?[*:0]const u8,
    envp: [:null]const ?[*:0]const u8,
};

fn buildCStringArray(
    allocator: std.mem.Allocator,
    items: [][]const u8,
) ![:null]?[*:0]const u8 {
    const array = try allocator.allocSentinel(?[*:0]const u8, items.len, null);
    for (items, 0..) |item, i| {
        array[i] = try allocator.dupeZ(u8, item);
    }
    return array;
}

fn childMain(ctx_ptr: usize) callconv(.c) u8 {
    const ctx: *const ChildContext = @ptrFromInt(ctx_ptr);

    std.debug.print("[child] pid inside new PID namespace: {d}\n", .{sys.getPid()});
    
    sys.setHostname(ctx.hostname) catch |err| {
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

    var sync_byte: [1]u8 = undefined;
    _ = sys.readFd(ctx.sync_read_fd, &sync_byte) catch |err| {
        std.debug.print(
            "[child] waiting for network setup failed: {s}\n",
            .{@errorName(err),
        });
        return 1;
    };
    sys.closeFd(ctx.sync_read_fd);

    const peer_name = std.mem.span(ctx.peer_veth_name);

    var netlink = Netlink.open() catch |err| {
        std.debug.print("[child] netlink open failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer netlink.close();

    netlink.setLinkUp(peer_name) catch |err| {
        std.debug.print(
            "[child] bringing up {s} failed: {s}\n",
            .{ peer_name, @errorName(err)},
        );
        return 1;
    };
    netlink.addAddress(peer_name, CONTAINER_VETH_ADDR, VETH_PREFIX_LEN) catch |err| {
        std.debug.print("[child] assigning address to {s} failed: {s}\n", .{ peer_name, @errorName(err) });
        return 1;
    };
    netlink.setLinkUp("lo") catch |err| {
        std.debug.print(
            "[child] bringing up lo failed: {s}\n",
            .{@errorName(err)},
        );
        return 1;
    };
    std.debug.print(
        "[child] {s} = {d}.{d}.{d}.{d}/{d}, lo up\n",
        .{
            peer_name,
            CONTAINER_VETH_ADDR[0],
            CONTAINER_VETH_ADDR[1],
            CONTAINER_VETH_ADDR[2],
            CONTAINER_VETH_ADDR[3],
            VETH_PREFIX_LEN,
        }
    );

    const rootfs = ctx.rootfs;
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

    sys.changeDir(ctx.cwd) catch |err| {
        std.debug.print(
            "[child] chdir to {s} failed: {s}\n",
            .{ std.mem.span(ctx.cwd), @errorName(err) }
        );
        return 1;
    };

    capabilities.dropToMinimalSet() catch |err| {
        std.debug.print("[child] dropping capabilities failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    std.debug.print("[child] capabilities reduced to Docker-default set\n", .{});

    seccomp.blockMount() catch |err| {
        std.debug.print("[child] installing seccomp filter failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    std.debug.print("[child] seccomp filter installed (mount blocked)\n", .{});

    std.debug.print("[child] handing over to {s}\n", .{std.mem.span(ctx.program)});
    sys.execInto(ctx.program, ctx.argv, ctx.envp) catch |err| {
        std.debug.print("[child] execve failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    unreachable;
}

fn setupHostNetwork(host_name: []const u8, peer_name: []const u8, child_pid: i32) !void {
    var netlink = try Netlink.open();
    defer netlink.close();

    try netlink.createVethPair(host_name, peer_name);
    try netlink.moveToNetns(peer_name, child_pid);
    try netlink.setLinkUp(host_name);
    try netlink.addAddress(host_name, HOST_VETH_ADDR, VETH_PREFIX_LEN);
}

fn runInNewNamespace(allocator: std.mem.Allocator, bundle_dir: []const u8) !void {
    std.debug.print("[parent] pid: {d}\n", .{sys.getPid()});

    const config = try oci_config.loadFromBundle(allocator, bundle_dir);
    if (config.process.args.len == 0) return error.EmptyProcessArgs;

    const rootfs = try oci_config.resolveRootfsPath(allocator, bundle_dir, config);
    const argv = try buildCStringArray(allocator, config.process.args);
    const envp = try buildCStringArray(allocator, config.process.env);
    const cwd = try std.fmt.allocPrintSentinel(allocator, "{s}", .{config.process.cwd}, 0);
    const program = argv[0].?;

    std.debug.print(
        "[parent] loaded bundle: rootfs={s}, process={s}, hostname={s}\n",
        .{ rootfs, program, config.hostname },
    );

    const cgroup_name = try std.fmt.allocPrint(allocator, "zigcon-{d}", .{sys.getPid()});
    const cgroup = try Cgroup.create(allocator, cgroup_name);
    defer cgroup.destroy();

    const memory_limit = config.linux.resources.memory.limit orelse DEFAULT_MEMORY_LIMIT_BYTES;
    const cpu_quota = config.linux.resources.cpu.quota orelse DEFAULT_CPU_QUOTA_US;
    const cpu_period = config.linux.resources.cpu.period orelse DEFAULT_CPU_PERIOD_US;
    try cgroup.setMemoryMax(memory_limit);
    try cgroup.setCpuMax(cpu_quota, cpu_period);
    std.debug.print(
        "[parent] created cgroup {s} (memory<={d}MiB, cpu<={d}%)\n",
        .{cgroup.path, memory_limit / 1024 / 1024, cpu_quota * 100 / cpu_period },
    );

    const parent_shmid = try sys.shmGet(SHM_KEY, 4096, sys.IPC_CREAT | 0o600);
    std.debug.print(
        "[parent] shmget returned shmid {d} (visible host-wide)\n",
        .{parent_shmid},
    );

    const host_veth_name = try std.fmt.allocPrintSentinel(allocator, "veth-h{d}", .{sys.getPid()}, 0);
    const peer_veth_name = try std.fmt.allocPrintSentinel(allocator, "veth-c{d}", .{sys.getPid()}, 0);
    const sync_pipe = try sys.createPipe();

    var child_ctx = ChildContext{
        .rootfs = rootfs.ptr,
        .sync_read_fd = sync_pipe[0],
        .peer_veth_name = peer_veth_name.ptr,
        .hostname = config.hostname,
        .cwd = cwd.ptr,
        .program = program,
        .argv = argv,
        .envp = envp,
    };

    const child_pid = sys.cloneInNamespace(
        sys.CLONE_NEWPID | sys.CLONE_NEWUTS | sys.CLONE_NEWIPC | sys.CLONE_NEWNS | sys.CLONE_NEWNET,
        &child_stack,
        childMain,
        @intFromPtr(&child_ctx),
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

    setupHostNetwork(host_veth_name, peer_veth_name, child_pid) catch |err| {
        std.debug.print(
            "[parent] network setup failed: {s}\n",
            .{@errorName(err)},
        );
    };
    std.debug.print(
        "[parent] host veth {s} = {d}.{d}.{d}.{d}/{d}, peer {s} moved into child's netns\n",
        .{
            host_veth_name, 
            HOST_VETH_ADDR[0],
            HOST_VETH_ADDR[1],
            HOST_VETH_ADDR[2],
            HOST_VETH_ADDR[3],
            VETH_PREFIX_LEN,
            peer_veth_name,
        },
    );

    _ = try sys.writeFd(sync_pipe[1], "x");
    sys.closeFd(sync_pipe[1]);

    try cgroup.addProcess(child_pid);
    std.debug.print("[parent] moved child pid {d} into cgroup {s}\n", .{child_pid, cgroup.path});

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
        std.debug.print("usage: {s} run <bundle-dir>\n", .{args[0]});
        return;
    }

    try runInNewNamespace(allocator, args[2]);
}