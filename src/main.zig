const std = @import("std");
const sys = @import("linux.zig");
const Cgroup = @import("cgroup.zig").Cgroup;
const CGROUP_ROOT = @import("cgroup.zig").cgroup_root;
const Netlink = @import("netlink.zig").NetlinkSocket;
const capabilities = @import("capabilities.zig");
const seccomp = @import("seccomp.zig");
const oci_config = @import("oci_config.zig");
const oci_registry = @import("oci_registry.zig");
const oci_image = @import("oci_image.zig");
const lifecycle = @import("lifecycle.zig");

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
    ready_write_fd: ?i32 = null,
    exec_fifo_path: ?[*:0]const u8 = null,
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

const DevNode = struct {
    path: [*:0]const u8,
    major: u32,
    minor: u32,
};
const DEV_NODES = [_]DevNode {
    .{ .path = "/dev/null", .major = 1, .minor = 3 },
    .{ .path = "/dev/zero", .major = 1, .minor = 5 },
    .{ .path = "/dev/full", .major = 1, .minor = 7 },
    .{ .path = "/dev/random", .major = 1, .minor = 8 },
    .{ .path = "/dev/urandom", .major = 1, .minor = 9 },
    .{ .path = "/dev/tty", .major = 5, .minor = 0 },
};

fn setupMinimalDev() !void {
    try sys.mountTmpfs("/dev");
    for (DEV_NODES) |node| {
        try sys.makeCharDevice(node.path, 0o666, node.major, node.minor);
    }
}

fn childMain(ctx_ptr: usize) callconv(.c) u8 {
    const ctx: *const ChildContext = @ptrFromInt(ctx_ptr);

    if (ctx.exec_fifo_path != null) {
        sys.newSession() catch |err| {
            std.debug.print("[child] setsid failed: {s}\n", .{@errorName(err)});
            return 1;
        };
    }

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

    var exec_fifo_path_fd: ?i32 = null;
    if (ctx.exec_fifo_path) |fifo_path| {
        exec_fifo_path_fd = sys.openPath(fifo_path) catch |err| {
            std.debug.print("[child] opening exec fifo path failed: {s}\n", .{@errorName(err)});
            return 1;
        };
    }

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

    setupMinimalDev() catch |err| {
        std.debug.print("[child] setting up /dev failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    std.debug.print("[child] minimal /dev populated (null, zero, full, random, urandom, tty)\n", .{});

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

    if (ctx.ready_write_fd) |fd| {
        _ = sys.writeFd(fd, "x") catch |err| {
            std.debug.print("[child] signaling ready failed: {s}\n", .{@errorName(err)});
            return 1;
        };
        sys.closeFd(fd);
    }

    if (ctx.exec_fifo_path != null) {
        sys.detachStdio() catch |err| {
            std.debug.print("[child] detaching stdio failed: {s}\n", .{@errorName(err)});
            return 1;
        };
    }

    if (exec_fifo_path_fd) |path_fd| {
        std.debug.print("[child] waiting for start signal on exec fifo\n", .{});

        var proc_fd_path_buf: [32]u8 = undefined;
        const proc_fd_path = std.fmt.bufPrintZ(&proc_fd_path_buf, "/proc/self/fd/{d}", .{path_fd}) catch unreachable;

        const fifo_fd = sys.openForReading(proc_fd_path) catch |err| {
            std.debug.print("[child] opening exec fifo failed: {s}\n", .{@errorName(err)});
            return 1;
        };
        sys.closeFd(path_fd);
        
        var start_byte: [1]u8 = undefined;
        _ = sys.readFd(fifo_fd, &start_byte) catch |err| {
            std.debug.print("[child] reading exec fifo failed: {s}\n", .{@errorName(err)});
            return 1;
        };
        sys.closeFd(fifo_fd);
    }

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

fn createContainer(
    allocator: std.mem.Allocator,
    io: std.Io,
    id: []const u8,
    bundle_dir: []const u8,
) !void {
    if (id.len > 9) return error.ContainerIdTooLong;

    const config = try oci_config.loadFromBundle(allocator, bundle_dir);
    if (config.process.args.len == 0) return error.EmptyProcessArgs;

    const rootfs = try oci_config.resolveRootfsPath(allocator, bundle_dir, config);
    const argv = try buildCStringArray(allocator, config.process.args);
    const envp = try buildCStringArray(allocator, config.process.env);
    const cwd = try std.fmt.allocPrintSentinel(allocator, "{s}", .{config.process.cwd}, 0);
    const program = argv[0].?;

    std.debug.print(
        "[parent] creating container {s}: rootfs={s}, process={s}\n",
        .{ id, rootfs, program },
    );

    const state_dir = try lifecycle.stateDir(allocator, id);
    const state_dir_handle = try std.Io.Dir.cwd().createDirPathOpen(io, state_dir, .{});
    state_dir_handle.close(io);

    const exec_fifo_path = try lifecycle.execFifoPath(allocator, id);
    try sys.makeFifo(exec_fifo_path, 0o600);

    const cgroup_name = try std.fmt.allocPrint(allocator, "zigcon-{s}", .{id});
    const cgroup = try Cgroup.create(allocator, cgroup_name);
    const memory_limit = config.linux.resources.memory.limit orelse DEFAULT_MEMORY_LIMIT_BYTES;
    const cpu_quota = config.linux.resources.cpu.quota orelse DEFAULT_CPU_QUOTA_US;
    const cpu_period = config.linux.resources.cpu.period orelse DEFAULT_CPU_PERIOD_US;
    try cgroup.setMemoryMax(memory_limit);
    try cgroup.setCpuMax(cpu_quota, cpu_period);

    const host_veth_name = try std.fmt.allocPrintSentinel(allocator, "veth-h{s}", .{id}, 0);
    const peer_veth_name = try std.fmt.allocPrintSentinel(allocator, "veth-c{s}", .{id}, 0);
    const sync_pipe = try sys.createPipe();
    const ready_pipe = try sys.createPipe();

    var child_ctx = ChildContext{
        .rootfs = rootfs.ptr,
        .sync_read_fd = sync_pipe[0],
        .peer_veth_name = peer_veth_name.ptr,
        .hostname = config.hostname,
        .cwd = cwd.ptr,
        .program = program,
        .argv = argv,
        .envp = envp,
        .ready_write_fd = ready_pipe[1],
        .exec_fifo_path = exec_fifo_path.ptr,
    };

    const child_pid = try sys.cloneInNamespace(
        sys.CLONE_NEWPID | sys.CLONE_NEWUTS | sys.CLONE_NEWIPC | sys.CLONE_NEWNS | sys.CLONE_NEWNET,
        &child_stack,
        childMain,
        @intFromPtr(&child_ctx),
    );
    std.debug.print("[parent] child pid: {d}\n", .{child_pid});

    sys.closeFd(sync_pipe[0]);
    sys.closeFd(ready_pipe[1]);

    try setupHostNetwork(host_veth_name, peer_veth_name, child_pid);

    _ = try sys.writeFd(sync_pipe[1], "x");
    sys.closeFd(sync_pipe[1]);

    try cgroup.addProcess(child_pid);

    var ready_byte: [1]u8 = undefined;
    const ready_len = try sys.readFd(ready_pipe[0], &ready_byte);
    sys.closeFd(ready_pipe[0]);
    if (ready_len == 0) return error.ContainerInitFailed;

    try lifecycle.save(allocator, io, .{
        .id = id,
        .pid = child_pid,
        .bundle = bundle_dir,
        .status = .created,
    });
    std.debug.print("[parent] container {s} created (pid={d})\n", .{ id, child_pid });
}   

fn startContainer(
    allocator: std.mem.Allocator,
    io: std.Io,
    id: []const u8
) !void {
    var state = try lifecycle.load(allocator, io, id);
    if (state.status != .created) return error.ContainerNotCreated;

    const exec_fifo_path = try lifecycle.execFifoPath(allocator, id);
    const fifo_fd = try sys.openForWriting(exec_fifo_path);
    _ = try sys.writeFd(fifo_fd, "x");
    sys.closeFd(fifo_fd);

    state.status = .running;
    try lifecycle.save(allocator, io, state);
    std.debug.print("[parent] container {s} started\n", .{id});
}

fn killContainer(
    allocator: std.mem.Allocator,
    io: std.Io,
    id: []const u8,
    signal: u32
) !void {
    const state = try lifecycle.load(allocator, io, id);
    try sys.sendSignal(state.pid, signal);
    std.debug.print(
        "[parent] sent signal {d} to container {s} (pid={d})\n",
        .{ signal, id, state.pid }
    );
}

fn stateContainer(
    allocator: std.mem.Allocator,
    io: std.Io,
    id: []const u8
) !void {
    var state = try lifecycle.load(allocator, io, id);
    if (!sys.processExists(state.pid)) state.status = .stopped;

    std.debug.print(
        "id={s} pid={d} bundle={s} status={s}\n",
        .{ state.id, state.pid, state.bundle, @tagName(state.status) },
    );
}

fn deleteContainer(
    allocator: std.mem.Allocator,
    io: std.Io,
    id: []const u8
) !void {
    const state = try lifecycle.load(allocator, io, id);
    if (sys.processExists(state.pid)) return error.ContainerStillRunning;

    const cgroup_path = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}/zigcon-{s}",
        .{CGROUP_ROOT, id},
        0,
    );
    (Cgroup{ .allocator = allocator, .path = cgroup_path }).destroy();
    
    const state_dir = try lifecycle.stateDir(allocator, id);
    try std.Io.Dir.cwd().deleteTree(io, state_dir);

    std.debug.print("[parent] container {s} deleted\n", .{id});
}

fn pullImage(
    allocator: std.mem.Allocator,
    io: std.Io,
    image_ref: []const u8
) !void {
    const sep = std.mem.lastIndexOfScalar(u8, image_ref, ':') orelse return error.InvalidImageRef;
    const repository = image_ref[0..sep];
    const reference = image_ref[sep + 1 ..];

    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    const session = try oci_registry.Session.open(allocator, &client, repository);
    const manifest = try session.pullManifest(reference);
    std.debug.print(
        "config: {s} ({d} bytes, {s})\n",
        .{ manifest.config.digest, manifest.config.size, manifest.config.mediaType },
    );

    const bundle_dir = try std.fmt.allocPrint(allocator, "pulled/{s}", .{repository});
    const rootfs_path = try std.fmt.allocPrint(allocator, "{s}/rootfs", .{bundle_dir});
    const rootfs_dir = try std.Io.Dir.cwd().createDirPathOpen(io, rootfs_path, .{});
    defer rootfs_dir.close(io);

    for (manifest.layers, 0..) |layer, i| {
        const blob = try session.pullBlob(layer.digest);
        try oci_image.extractLayer(io, rootfs_dir, layer, blob);
        std.debug.print(
            "layer[{d}]: {s} extracted ({d} bytes, {s})\n",
            .{ i, layer.digest, blob.len, layer.mediaType },
        );
    }
    const config_blob = try session.pullBlob(manifest.config.digest);
    try oci_image.writeBundleConfig(allocator, io, bundle_dir, config_blob);
    std.debug.print("bundle ready: {s}\n", .{bundle_dir});
}

const USAGE = "usage: {s} run <bundle-dir> | pull <repository>:<reference> | create <id> <bundle-dir> | start <id> | kill <id> [signal] | state <id> | delete <id>\n";

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    
    if (args.len < 3) {
        std.debug.print(USAGE, .{args[0]});
        return;
    }

    if (std.mem.eql(u8, args[1], "run")) {
        return runInNewNamespace(allocator, args[2]);
    }
    if (std.mem.eql(u8, args[1], "pull")) {
        return pullImage(allocator, init.io, args[2]);
    }
    if (std.mem.eql(u8, args[1], "create")) {
        if (args.len < 4) {
            std.debug.print(USAGE, .{args[0]});
            return;
        }
        return createContainer(allocator, init.io, args[2], args[3]);
    }
    if (std.mem.eql(u8, args[1], "start")) {
        return startContainer(allocator, init.io, args[2]);
    }
    if (std.mem.eql(u8, args[1], "kill")) {
        const signal: u32 = if (args.len >= 4) try std.fmt.parseInt(u32, args[3], 10) else 15;
        return killContainer(allocator, init.io, args[2], signal);
    }
    if (std.mem.eql(u8, args[1], "state")) {
        return stateContainer(allocator, init.io, args[2]);
    }
    if (std.mem.eql(u8, args[1], "delete")) {
        return deleteContainer(allocator, init.io, args[2]);
    }

    std.debug.print(USAGE, .{args[0]});
}