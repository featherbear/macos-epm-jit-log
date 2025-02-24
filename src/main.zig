const std = @import("std");

const ChildProcess = std.process.Child;

const LogStream = struct { eventMessage: []const u8, subsystem: []const u8, processID: c_int, timestamp: []const u8 };

const AppEvent = struct { timeMs: i64, type: []const u8, waitTimeMs: i64 = -1 };

const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

var allocatorBacking = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = allocatorBacking.allocator();

const List = struct {
    mutex: std.Thread.Mutex,
    list: std.ArrayList(i64),
    const Self = @This();

    pub fn add(self: *Self, reqStartTimeMs: i64) std.mem.Allocator.Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.list.append(reqStartTimeMs);
    }

    pub fn popEarliest(self: *Self) i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return requests.list.swapRemove(0);
    }

    pub fn remove(self: *Self, reqStartTimeMs: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.list.items, 0..) |num, i| {
            if (num == reqStartTimeMs) {
                _ = self.list.swapRemove(i);
                return;
            }
        }
    }

    pub fn contains(self: *Self, reqStartTimeMs: i64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.list.items) |num| {
            if (num == reqStartTimeMs) {
                return true;
            }
        }

        return false;
    }
};
var requests = List{ .mutex = std.Thread.Mutex{}, .list = std.ArrayList(i64).init(allocator) };
var grants = List{ .mutex = std.Thread.Mutex{}, .list = std.ArrayList(i64).init(allocator) };

pub fn emitEvent(event: AppEvent) !void {
    if (event.waitTimeMs != -1) {
        try stdout.print("{d},{s},{d}\n", .{ event.timeMs, event.type, event.waitTimeMs });
    } else {
        try stdout.print("{d},{s}\n", .{ event.timeMs, event.type });
    }
}

fn grantMonitor(grantStartTimeMs: i64) !void {
    const waitMinutes = 60;
    const thresholdHours = 2;
    const giveUpHours = 24;

    try grants.add(grantStartTimeMs);
    std.time.sleep(thresholdHours * std.time.ns_per_hour);

    while (true) {
        if (grants.contains(grantStartTimeMs)) {
            const now = std.time.milliTimestamp();

            if ((now - grantStartTimeMs) > giveUpHours * std.time.ms_per_hour) {
                grants.remove(grantStartTimeMs);
                try emitEvent(AppEvent{ .timeMs = now, .type = "revokeStopTracking" });
                return;
            }

            try emitEvent(AppEvent{ .timeMs = now, .type = "revokePending" });
        }

        std.time.sleep(waitMinutes * std.time.ns_per_min);
    }
}

fn requestMonitor(reqStartTimeMs: i64) !void {
    const waitMinutes = 5;
    const thresholdSeconds = 120;
    const giveUpMinutes = 120;

    try requests.add(reqStartTimeMs);
    std.time.sleep(thresholdSeconds * std.time.ns_per_s);

    while (true) {
        if (requests.contains(reqStartTimeMs)) {
            const now = std.time.milliTimestamp();

            if ((now - reqStartTimeMs) > giveUpMinutes * std.time.ms_per_min) {
                requests.remove(reqStartTimeMs);
                try emitEvent(AppEvent{ .timeMs = now, .type = "requestStopTracking" });
                return;
            }

            try emitEvent(AppEvent{ .timeMs = now, .type = "requestPending" });
        }

        std.time.sleep(waitMinutes * std.time.ns_per_min);
    }
}

pub fn main() !void {
    const predicate = "subsystem == 'com.cyberark.CyberArkEPM' AND ((formatString == 'Requested administrative privileges') OR (eventMessage ENDSWITH \" 'admin' group\" AND (formatString BEGINSWITH 'ac_%llu: Did add ' OR formatString BEGINSWITH 'ac_%llu: Did remove ')))";

    var proc = ChildProcess.init(&[_][]const u8{ "/usr/bin/log", "stream", "--style", "ndjson", "--info", "--predicate", predicate }, allocator);
    proc.stdout_behavior = ChildProcess.StdIo.Pipe;
    proc.stderr_behavior = ChildProcess.StdIo.Ignore;
    try proc.spawn();

    // The max I've seen is around 5400 bytes
    var buffer: [8192]u8 = undefined;

    const reader = proc.stdout.?.reader();

    // Skip the first line: "Filtering the log data using ..."
    _ = try reader.readUntilDelimiter(&buffer, '\n');

    try stderr.print("Observing events...\n", .{});

    while (true) {
        const bytesRead = (try reader.readUntilDelimiter(&buffer, '\n')).len;
        const parsed = try std.json.parseFromSlice(LogStream, allocator, buffer[0..bytesRead], .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const now = std.time.milliTimestamp();

        var evtObject = AppEvent{ .timeMs = now, .type = undefined };

        if (std.mem.startsWith(u8, parsed.value.eventMessage, "Requested")) {
            evtObject.type = "request";

            _ = try std.Thread.spawn(.{}, requestMonitor, .{now});
        } else if (std.mem.indexOf(u8, parsed.value.eventMessage, " Did add ") != null) {
            evtObject.type = "grant";

            const reqStartTimeMs = requests.popEarliest();
            evtObject.waitTimeMs = now - reqStartTimeMs;

            _ = try std.Thread.spawn(.{}, grantMonitor, .{now});
        } else if (std.mem.indexOf(u8, parsed.value.eventMessage, " Did remove ") != null) {
            // TODO: maybe skip this log?
            // When a user is added, they are first removed - thanks alot CyberArk.
            // if (reqStartTimeMs > 0) {
            //     continue;
            // }
            evtObject.type = "revoke";

            const grantStartTimeMs = grants.popEarliest();
            evtObject.waitTimeMs = now - grantStartTimeMs;
        } else {
            try stderr.print("Unexpected message at {s}: {s}...\n", .{ parsed.value.timestamp, parsed.value.eventMessage });
            continue;
        }

        try emitEvent(evtObject);
    }
}
