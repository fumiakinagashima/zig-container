const std = @import("std");

const REGISTRY_HOST = "registry-1.docker.io";
const MANIFEST_ACCEPT = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
const MANIFEST_MAX_SIZE = 4 * 1024 * 1024;
const BLOB_MAX_SIZE = 128 * 1024 * 1024;

pub const Descriptor = struct {
    mediaType: []const u8,
    digest: []const u8,
    size: u64,
};

pub const Manifest = struct {
    schemaVersion: u32,
    mediaType: []const u8 = "",
    config: Descriptor,
    layers: []Descriptor,
};

const Platform = struct {
    architecture: []const u8,
    os: []const u8,
};

const IndexEntry = struct {
    mediaType: []const u8,
    digest: []const u8,
    size: u64,
    platform: ?Platform = null,
};

const ManifestIndex = struct {
    manifests: []IndexEntry,
};

const TokenResponse = struct {
    token: []const u8,
};

const Challenge = struct {
    realm: []const u8,
    service: []const u8,
};

const HttpResult = struct {
    status: std.http.Status,
    content_type: []const u8,
    body: []const u8,
};

fn httpGet(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    url: []const u8,
    extra_headers: []const std.http.Header,
    max_size: usize,
) !HttpResult {
    const uri = try std.Uri.parse(url);
    var req = try client.request(.GET, uri, .{ .extra_headers = extra_headers });
    defer req.deinit();

    try req.sendBodiless();

    var redirect_buffer: [8192]u8 = undefined;
    var response = try req.receiveHead(&redirect_buffer);

    var content_type: []const u8 = "";
    var it = response.head.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
            content_type = try allocator.dupe(u8, header.value);
        }
    }

    var transfer_buffer: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buffer);
    const body = try body_reader.allocRemaining(allocator, .limited(max_size));

    return .{ .status = response.head.status, .content_type = content_type, .body = body };
}

fn parseChallenge(allocator: std.mem.Allocator, header_value: []const u8) !Challenge {
    var realm: []const u8 = "";
    var service: []const u8 = "";

    const prefix = "Bearer ";
    if (!std.mem.startsWith(u8, header_value, prefix)) return error.UnsupportedAuthScheme;

    var it = std.mem.splitScalar(u8, header_value[prefix.len..], ',');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = std.mem.trim(u8, pair[0..eq], " ");
        const value = std.mem.trim(u8, pair[eq + 1 ..], " \"");
        if (std.mem.eql(u8, key, "realm")) realm = try allocator.dupe(u8, value);
        if (std.mem.eql(u8, key, "service")) service = try allocator.dupe(u8, value);
    }
    if (realm.len == 0 or service.len == 0) return error.InvalidChallenge;
    return .{ .realm = realm, .service = service };
}

fn discoverChallenge(allocator: std.mem.Allocator, client: *std.http.Client) !Challenge {
    const url = try std.fmt.allocPrint(allocator, "https://{s}/v2/", .{REGISTRY_HOST});
    const uri = try std.Uri.parse(url);
    var req = try client.request(.GET, uri, .{});
    defer req.deinit();
    try req.sendBodiless();

    var redirect_buffer: [8192]u8 = undefined;
    var response = try req.receiveHead(&redirect_buffer);

    var it = response.head.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) {
            return try parseChallenge(allocator, header.value);
        }
    }
    return error.NoAuthChallenge;
}

fn fetchToken(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    challenge: Challenge,
    repository: []const u8,
) ![]const u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}?service={s}&scope=repository:{s}:pull",
        .{ challenge.realm, challenge.service, repository },
    );
    const result = try httpGet(allocator, client, url, &.{}, MANIFEST_MAX_SIZE);
    if (result.status != .ok) return error.TokenRequestFailed;

    const parsed = try std.json.parseFromSliceLeaky(
        TokenResponse,
        allocator,
        result.body,
        .{ .ignore_unknown_fields = true }
    );
    return parsed.token;
}

fn fetchManifestRaw(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    repository: []const u8,
    reference: []const u8,
    token: []const u8,
) !HttpResult {
    const url= try std.fmt.allocPrint(
        allocator,
        "https://{s}/v2/{s}/manifests/{s}",
        .{ REGISTRY_HOST, repository, reference },
    );
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    const result = try httpGet(allocator, client, url, &.{
        .{ .name = "Authorization", .value = auth_header },
        .{ .name = "Accept", .value = MANIFEST_ACCEPT },
    }, MANIFEST_MAX_SIZE);
    if (result.status != .ok) return error.ManifestRequestFailed;
    return result;
}

fn isIndexMediaType(media_type: []const u8) bool {
    return std.mem.eql(u8, media_type, "application/vnd.oci.image.index.v1+json") or
        std.mem.eql(u8, media_type, "application/vnd.docker.distribution.manifest.list.v2+json");
}

fn selectPlatform(index: ManifestIndex) !IndexEntry {
    for (index.manifests) |entry| {
        const platform = entry.platform orelse continue;
        if (std.mem.eql(u8, platform.architecture, "amd64") and std.mem.eql(u8, platform.os, "linux")) {
            return entry;
        }
    }
    return error.NoMatchingPlatform;
}

fn verifyDigest(body: []const u8, digest: []const u8) !void {
    const prefix = "sha256:";
    if (!std.mem.startsWith(u8, digest, prefix)) return error.UnsupportDigestAlgorithm;

    var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &hash, .{});
    const actual_hex = std.fmt.bytesToHex(hash, .lower);

    if (!std.mem.eql(u8, &actual_hex, digest[prefix.len..])) return error.DigestMismatch;
}

pub const Session = struct {
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    repository: []const u8,
    token: []const u8,

    pub fn open(
        allocator: std.mem.Allocator,
        client: *std.http.Client,
        repository: []const u8,
    ) !Session {
        const challenge = try discoverChallenge(allocator, client);
        const token = try fetchToken(allocator, client, challenge, repository);
        return .{ .allocator = allocator, .client = client, .repository = repository, .token = token };
    }

    pub fn pullManifest(self: Session, reference: []const u8) !Manifest {
        var result = try fetchManifestRaw(self.allocator, self.client, self.repository, reference, self.token);

        if (isIndexMediaType(result.content_type)) {
            const index = try std.json.parseFromSliceLeaky(
                ManifestIndex,
                self.allocator,
                result.body,
                .{ .ignore_unknown_fields = true },
            );
            const entry = try selectPlatform(index);
            result = try fetchManifestRaw(self.allocator, self.client, self.repository, entry.digest, self.token);
            try verifyDigest(result.body, entry.digest);
        }

        return try std.json.parseFromSliceLeaky(
            Manifest,
            self.allocator,
            result.body,
            .{ .ignore_unknown_fields = true },
        );
    }

    pub fn pullBlob(self: Session, digest: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "https://{s}/v2/{s}/blobs/{s}",
            .{ REGISTRY_HOST, self.repository, digest },
        );
        const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.token});
        const result = try httpGet(
            self.allocator,
            self.client,
            url,
            &.{ .{ .name = "Authorization", .value= auth_header }, },
            BLOB_MAX_SIZE
        );
        if (result.status != .ok) return error.BlobRequestFailed;

        try verifyDigest(result.body, digest);
        
        return result.body;
    }
};
