const std = @import("std");
const ctime = @cImport({
    @cInclude("time.h");
});

const ChildProcess = std.process.Child;

const LogStream = struct { eventMessage: []const u8, subsystem: []const u8, processID: c_int, timestamp: []const u8 };

const AppEvent = struct { timeMs: i64, type: []const u8, hasDelta: bool, delta: i64 };

const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

pub fn emitEvent(event: AppEvent) !void {
    if (event.hasDelta) {
        try stdout.print("{d},{s},{d}\n", .{ event.timeMs, event.type, event.delta });
    } else {
        try stdout.print("{d},{s}\n", .{ event.timeMs, event.type });
    }
}
var reqStartTimeMs: i64 = 0;

fn deltaMonitor() !void {
    const waitSeconds = 10;
    const thresholdSeconds = 120;

    while (true) {
        std.time.sleep(waitSeconds * std.time.ns_per_s);

        if (reqStartTimeMs > 0) {
            const now = std.time.milliTimestamp();
            const delta = now - reqStartTimeMs;

            if (delta > thresholdSeconds * std.time.ms_per_s) {
                try emitEvent(AppEvent{ .timeMs = now, .type = "requestPending", .hasDelta = true, .delta = delta });
            }
        }
    }
}

pub fn main() !void {
    var allocatorBacking = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = allocatorBacking.allocator();

    const filter = "subsystem == 'com.cyberark.CyberArkEPM' AND ((formatString == 'Requested administrative privileges') OR (eventMessage ENDSWITH \" 'admin' group\" AND (formatString BEGINSWITH 'ac_%llu: Did add ' OR formatString BEGINSWITH 'ac_%llu: Did remove ')))";

    var proc = ChildProcess.init(&[_][]const u8{ "/usr/bin/log", "stream", "--style", "ndjson", "--info", "--predicate", filter }, allocator);
    proc.stdout_behavior = ChildProcess.StdIo.Pipe;
    proc.stderr_behavior = ChildProcess.StdIo.Ignore;
    try proc.spawn();

    // The max I've seen is around 5400 bytes
    var buffer: [8192]u8 = undefined;

    const reader = proc.stdout.?.reader();

    // Skip the first line: "Filtering the log data using ..."
    _ = try reader.readUntilDelimiter(&buffer, '\n');

    try stderr.print("Observing events...\n", .{});

    _ = try std.Thread.spawn(.{}, deltaMonitor, .{});

    while (true) {
        const bytesRead = (try reader.readUntilDelimiter(&buffer, '\n')).len;
        const parsed = try std.json.parseFromSlice(LogStream, allocator, buffer[0..bytesRead], .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        const now = std.time.milliTimestamp();

        var evtObject = AppEvent{ .timeMs = now, .type = undefined, .hasDelta = false, .delta = 0 };

        if (std.mem.startsWith(u8, parsed.value.eventMessage, "Requested")) {
            evtObject.type = "request";

            // There is another outstanding request, show the interval between requests
            if (reqStartTimeMs > 0) {
                evtObject.hasDelta = true;
                evtObject.delta = now - reqStartTimeMs;
            }

            reqStartTimeMs = now;
        } else if (std.mem.indexOf(u8, parsed.value.eventMessage, " Did add ") != null) {
            evtObject.type = "grant";

            if (reqStartTimeMs > 0) {
                evtObject.hasDelta = true;
                evtObject.delta = now - reqStartTimeMs;
            }
            reqStartTimeMs = 0;
        } else if (std.mem.indexOf(u8, parsed.value.eventMessage, " Did remove ") != null) {
            // TODO: maybe skip this log?
            // When a user is added, they are first removed - thanks alot CyberArk.
            // if (reqStartTimeMs > 0) {
            //     continue;
            // }
            evtObject.type = "revoke";
        } else {
            try stderr.print("Unexpected message at {s}: {s}...\n", .{ parsed.value.timestamp, parsed.value.eventMessage });
            continue;
        }

        try emitEvent(evtObject);
    }
}
