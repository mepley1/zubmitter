//! Zig 0.14.0-dev.2634+b36ea592b
//! Submit abuse report to AbuseIPDB HTTP API.
//! Also supports the clear-address endpoint (delete all reports for given IP).
//! Usage: zubmit-report <action: submit|delete> <ip_addr> <categories> <comment>
//! Example (submission): zubmit-report submit "127.0.0.1" "15,23"  "Malicious activity"
//! Example (clear reports): zubmit-report delete "127.0.0.1"
//! Configure API key in `app.conf`; file must contain valid JSON.

const std = @import("std");
const http = std.http;
const Allocator = std.mem.Allocator;
const Request = http.Client.Request;
const print = std.debug.print;

// Define API endpoints
const API_URL: []const u8 = "https://api.abuseipdb.com/api/v2/report";
const API_URL_CLEAR: []const u8 = "https://api.abuseipdb.com/api/v2/clear-address";
const CONFIG_FILE_PATH: []const u8 = "./app.conf";

const HELP_MSG: []const u8 =
    \\
    \\Usage: zubmit <action:submit|delete> <ip_addr> <categories> | <comment>
    \\Example: zubmit submit "127.0.0.1" "15,21" "Malicious activity"
    \\Example: zubmit delete "127.0.0.1"
    \\Available actions:
    \\ - submit (REPORT endpoint)
    \\ - delete (CLEAR-ADDRESS endpoint)
    \\
;

/// Improper usage of program
const UserError = error{
    MissingParams,
    //InvalidParams,
    InvalidJSON,
    InvalidConfig,
    //MissingConfig,
    InvalidRegex,
};

/// For errors returned by API endpoint due to user error.
/// Unused right now.
const ApiUserError = error{
    TooManyRequests,
    Unauthorized,
    UnprocessableEntity,
    Something,
};

/// Holds report params. Returned by getCliArgs()
const ReportParams = struct {
    ip: [*:0]u8,
    categories: [*:0]u8,
    comment: ?[*:0]u8 = null,
};

/// Program config
const ConfigData = struct {
    key: []u8,
    default_comment: ?[]u8 = null,
    //default_comment: ?[]u8,
};

// Some types representing API response data.

/// For parsing errors returned by API
const ApiResponseErrors = struct {
    errors: []struct {
        detail: []const u8,
        status: u16,
        source: ?struct {
            parameter: ?[]const u8 = null,
        } = null,
    },
};

/// Api response may include different datas from various endpoints
const ApiResponse = struct {
    data: struct {
        ipAddress: ?[]const u8 = null,
        abuseConfidenceScore: ?u8 = null,
        numReportsDeleted: ?u8 = null,
    },
};

/// Categories accepted by API endpoint
const Categories = enum(u8) {
    dnsCompromise = 1,
    dnsPoisoning = 2,
    fraudOrders = 3,
    ddosAttack = 4,
    ftpBruteForce = 5,
    pingOfDeath = 6,
    phishing = 7,
    fraudVoip = 8,
    openProxy = 9,
    webSpam = 10,
    emailSpam = 11,
    blogSpam = 12,
    vpnIp = 13,
    portScan = 14,
    hacking = 15,
    sqlInjection = 16,
    spoofing = 17,
    bruteForce = 18,
    badWebBot = 19,
    exploitedHost = 20,
    webAppAttack = 21,
    ssh = 22,
    iotTargeted = 23,

    /// Return category # from name
    //pub fn catNum(self: Categories) u8 {
    pub fn catNum(self: @This()) u8 {
        return @intFromEnum(self);
    }
};

/// Print some feedback text, along with the help msg.
fn printErrHelp(msg: [:0]const u8) void {
    print("\n{s}", .{msg});
    print("\n{s}", .{HELP_MSG});
    return;
}

/// Print a horizontal line of length n, alternating colors each char.
fn printHorizontalLine(allocator: Allocator, len: u8) !void {
    print("\n", .{});
    for (1..len + 1) |pos| {
        if (pos % 2 == 0) {
            try printStyled(allocator, .magenta, "=");
        } else {
            try printStyled(allocator, .cyan, "-");
        }
    }
    return;
}

const Style = enum {
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bold,
    underline,
    blink,
};

/// Print msg to stderr in given color/style.
/// Usage: `try printStyled(alloc, .blue, "some text")`;
fn printStyled(alloc: Allocator, color: Style, msg: []const u8) !void {
    const esc: []const u8 = "\u{001b}";
    const reset: []const u8 = "[0m";

    const colCode = switch (color) {
        .black => "[30m",
        .red => "[31m",
        .green => "[32m",
        .yellow => "[33m",
        .blue => "[34m",
        .magenta => "[35m",
        .cyan => "[36m",
        .white => "[37m",
        .bold => "[1m",
        .underline => "[4m",
        .blink => "[5m",
    };

    const msg_colored = try std.fmt.allocPrint(alloc, "{s}{s}{s}{s}{s}", .{ esc, colCode, msg, esc, reset });
    defer alloc.free(msg_colored);
    try std.testing.expect(msg_colored.len == esc.len + colCode.len + msg.len + esc.len + reset.len);

    print("{s}", .{msg_colored});

    return;
}

/// Print the intro/title text to stderr
fn printIntroMsg(allocator: Allocator) !void {
    try printHorizontalLine(allocator, 34);
    try printStyled(allocator, .cyan, "\n AbuseIPDB report submission tool");
    try printStyled(allocator, .cyan, "\n             by rogueAutomaton();");
    try printHorizontalLine(allocator, 34);
    return;
}

// Utility functions

/// Allowed actions for 1st cli arg
const Action = enum { submit, delete };

/// Read first CL argument passed (action). Return an int representing which action to take.
fn getIntendedAction(alloc: Allocator) !?Action {
    const argc: usize = std.os.argv.len;
    if (argc < 2) {
        printErrHelp("Error: No action specified");
        return null;
    }

    const arg1 = try std.fmt.allocPrint(alloc, "{s}", .{std.os.argv[1]});
    defer alloc.free(arg1);

    // TODO: Rewrite this as a switch to simplify adding additional actions.
    if (std.mem.eql(u8, arg1, "submit")) {
        return Action.submit;
    } else if (std.mem.eql(u8, arg1, "delete")) {
        return Action.delete;
    } else {
        printErrHelp("Invalid action.");
        return null;
    }
}

fn getIntendedActionAlloc(alloc: Allocator) !?Action {
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len <= 1) {
        printErrHelp("Error: No action specified");
        return null;
    }

    const arg1 = try std.fmt.allocPrint(alloc, "{s}", .{args[1]});
    defer alloc.free(arg1);

    // TODO: Rewrite this as a switch to simplify adding additional actions.
    if (std.mem.eql(u8, arg1, "submit")) {
        return Action.submit;
    } else if (std.mem.eql(u8, arg1, "delete")) {
        return Action.delete;
    } else {
        printErrHelp("Invalid action.");
        return null;
    }
}

/// Validate number of cli args given is >= given minimum. If not, print help text and quit.
fn validateNumArgs(min: u4) bool {
    const argc = std.os.argv.len;
    if (argc >= min) {
        return true;
    } else {
        var buf: [128]u8 = undefined;
        const msg: [:0]const u8 = std.fmt.bufPrintZ(&buf, "\u{001b}[31mMissing required args!\u{001b}[0m {d} required, {d} given.", .{ min, argc - 1 }) catch unreachable;
        printErrHelp(msg);
        return false;
    }
}

/// Validate an IP address (either v4/v6).
fn validateIpAddr(addr: []const u8) bool {
    _ = std.net.Address.resolveIp(addr, 0) catch {
        return false;
    };
    return true;
}

/// Read command line args (excluding action), and return as a ReportParams struct.
/// Linux only.
/// TODO: Make Windows-compatible.
fn getCliArgs() ReportParams {
    const argc: usize = std.os.argv.len; // Get # of args passed (including #0)

    const values = ReportParams{
        .ip = std.os.argv[2],
        .categories = if (argc >= 4) std.os.argv[3] else @constCast("15"),
        .comment = if (argc >= 5) std.os.argv[4] else null,
    };

    return values;
}

/// Take a ReportParams and change the comment
fn addDefaultComment(params: *ReportParams, new_cmt: [:0]u8) bool {
    if (params.*.comment) |val| {
        _ = val;
        return false;
    } else {
        params.*.comment = new_cmt;
        return true;
    }
}

/// Read and parse config file, return config values as a ConfigData struct.
/// File must be in same dir as command is being run from.
fn readConfigFile(allocator: Allocator) !ConfigData {
    const cwd = std.fs.cwd();
    const handle = cwd.openFile(CONFIG_FILE_PATH, .{
        .mode = .read_only,
    }) catch |err| {
        print("\nError opening config file: {}\n", .{err});
        return err;
    };
    defer handle.close();

    // Read file
    const file_bytes = try handle.readToEndAlloc(allocator, 512);
    defer allocator.free(file_bytes);
    const config_file_data = file_bytes[0..];

    //Parse JSON
    const parsed = std.json.parseFromSlice(ConfigData, allocator, config_file_data, .{
        .ignore_unknown_fields = true,
    }) catch {
        return UserError.InvalidJSON;
    };
    defer parsed.deinit();
    const value = parsed.value;

    // Dupe the values to avoid seg fault
    const config_data = ConfigData{
        .key = try allocator.dupe(u8, value.key),
        .default_comment = try allocator.dupe(u8, value.default_comment.?),
    };

    std.testing.expect(config_data.key.len == 80) catch {
        print("\nInvalid API key. A valid key should be exactly 80 bytes long; found {d}.", .{config_data.key.len});
        return UserError.InvalidConfig;
    };

    return config_data;
}

// HTTP Client functions

/// Parse + print errors in submission response.
fn parseResponseErrors(allocator: Allocator, req: *Request) !void {
    var rdr = req.reader();

    // Read (allocator)
    const resp_body: []const u8 = try rdr.readAllAlloc(allocator, 1024 * 4);
    defer allocator.free(resp_body);

    // To read to a buffer instead of alloc:
    //var buff: [1024]u8 = undefined;
    //const num_bytes_read = try rdr.readAll(&buff);
    //const resp_body = buff[0..num_bytes_read];

    // Parse response JSON
    const parsed = try std.json.parseFromSlice(ApiResponseErrors, allocator, resp_body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const value: ApiResponseErrors = parsed.value;

    if (value.errors.len > 0) {
        print("\nReceived error(s):", .{});
        for (value.errors, 0..) |erro, i| {
            print("\n- Error #{d}:", .{i});
            print("\n-- Detail: {s}\n-- Status: {d}\n-- Source: {s}", .{ erro.detail, erro.status, erro.source.?.parameter.? });
        }
    } else {
        print("\nNo error info found in response.", .{});
    }
    return;
}

/// Send a DELETE request to API_URL_CLEAR, to delete all reports for given ip addr.
/// Return true if successful, else false.
fn deleteReportsForAddr(alloc: Allocator, api_key: []const u8, ip_addr: [*:0]u8) !bool {
    const query_str: []const u8 = "?ipAddress=";

    // Concatenate endpoint uri + query str + ip:
    const uri_no_ip: []const u8 = API_URL_CLEAR ++ query_str;
    const uri_complete = try std.fmt.allocPrint(alloc, "{s}{s}", .{ uri_no_ip, ip_addr });
    defer alloc.free(uri_complete);

    const uri = try std.Uri.parse(uri_complete);

    // Initialize client
    var client = http.Client{ .allocator = alloc };
    defer client.deinit();

    // Server headers buffer
    print("\nOpening connection ...", .{});
    var buf: [1024]u8 = undefined;
    var req = try client.open(.DELETE, uri, .{
        .server_header_buffer = &buf,
        .extra_headers = &.{
            .{ .name = "key", .value = api_key },
            .{ .name = "accept", .value = "application/json" },
        },
    });
    defer req.deinit();

    // Send request
    print("\n- Send headers ...", .{});
    try req.send();
    print("\n- Finish request ...", .{});
    try req.finish();
    print("\nWaiting for response ...\n", .{});
    try req.wait();

    // check for 200 ok
    std.testing.expectEqual(.ok, req.response.status) catch {
        try parseResponseErrors(alloc, &req);
        return false;
    };

    // read response
    var rdr = req.reader();
    const resp_body = try rdr.readAllAlloc(alloc, 1024 * 4);
    defer alloc.free(resp_body);
    //print("\nResponse body (unformatted):\n{s}\n", .{resp_body});

    // Parse response
    const parsed = try std.json.parseFromSlice(ApiResponse, alloc, resp_body, .{});
    defer parsed.deinit();

    const value: ApiResponse = parsed.value;

    print("\nNumber of reports deleted: {d}", .{value.data.numReportsDeleted.?});

    return true;
}

/// Submit a report to API REPORT endpoint. Return true if successful, else false.
fn submitReport(allocator: Allocator, api_key: []const u8, params: ReportParams) !bool {
    // Params were read from cli args
    const report_params = params;

    // Jsonify report params
    const report_params_json = try std.json.stringifyAlloc(allocator, report_params, .{ .whitespace = .minified });
    defer allocator.free(report_params_json);

    // Set up http client
    var client = http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(API_URL);
    const payload: []const u8 = report_params_json;
    //print("\nReport body: {s}", .{payload});

    // BEGIN CHUNK BEING MOVED

    // Instantiate the request + add headers required by API endpoint
    //print("\nOpening connection ...", .{});
    //var buf: [1024]u8 = undefined;
    //var req = try client.open(.POST, uri, .{
    //.server_header_buffer = &buf,
    //.extra_headers = &.{
    //    .{ .name = "key", .value = api_key },
    //    .{ .name = "accept", .value = "application/json" },
    //},
    //});
    //defer req.deinit();
    //req.transfer_encoding = .{ .content_length = payload.len };
    //req.headers.content_type = .{ .override = "application/json" };

    // Send request on the wire
    //print("\nSending request to API ...", .{});
    //print("\n- Send headers ...", .{});
    //try req.send();
    //print("\n- Send body ...", .{});
    //var wtr = req.writer();
    //try wtr.writeAll(payload);
    //try req.finish();
    //print("\nWaiting for response ...\n", .{});
    //try req.wait();

    // Check for 200 ok
    //std.testing.expectEqual(.ok, req.response.status) catch {
    //    try parseResponseErrors(allocator, &req);
    //    return false;
    //};

    // Read response body
    //var rdr = req.reader();
    //const resp_body = try rdr.readAllAlloc(allocator, 1024 * 4);
    //defer allocator.free(resp_body);

    // END CHUNK BEING MOVED

    // TEST - MOVING ABOVE CHUNK TO A FUNCTION
    //const resp_body = try openConnection(allocator, &client, uri, payload, api_key);
    const resp_body = openConnection(allocator, &client, uri, payload, api_key) catch {
        return false;
    };
    defer allocator.free(resp_body);

    // END TEST

    // Parse response JSON + print it
    // Reference: https://cookbook.ziglang.cc/10-01-json.html
    const parsed = try std.json.parseFromSlice(ApiResponse, allocator, resp_body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const value: ApiResponse = parsed.value;
    print("\nParsed response:", .{});
    print("\nipAddress: {s}", .{value.data.ipAddress.?});
    print("\nabuseConfidenceScore: {u}", .{value.data.abuseConfidenceScore.?});

    return true;
}

fn openConnection(allocator: Allocator, client: *http.Client, uri: std.Uri, payload: []const u8, api_key: []const u8) ![]const u8 {
    print("\nOpening connection ...", .{});
    var buf: [1024]u8 = undefined;
    var req = try client.open(.POST, uri, .{
        .server_header_buffer = &buf,
        .extra_headers = &.{
            .{ .name = "key", .value = api_key },
            .{ .name = "accept", .value = "application/json" },
        },
    });
    defer req.deinit();
    req.transfer_encoding = .{ .content_length = payload.len };
    req.headers.content_type = .{ .override = "application/json" };

    // Send request on the wire
    print("\nSending request to API ...", .{});
    print("\n- Send headers ...", .{});
    try req.send();
    print("\n- Send body ...", .{});
    var wtr = req.writer();
    try wtr.writeAll(payload);
    try req.finish();
    print("\nWaiting for response ...\n", .{});
    try req.wait();

    // Check for 200 ok
    std.testing.expectEqual(.ok, req.response.status) catch {
        try parseResponseErrors(allocator, &req);
        //return false;
        return ApiUserError.Something;
    };

    // Read response body
    var rdr = req.reader();
    const resp_body: []const u8 = try rdr.readAllAlloc(allocator, 1024 * 4);
    defer allocator.free(resp_body);

    //return resp_body;
    const x: []const u8 = try allocator.dupe(u8, resp_body);
    return x;
}

/// Main loop.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    _ = gpa.detectLeaks();
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try printIntroMsg(allocator);

    // Read and set config
    const APP_CONFIG = readConfigFile(allocator) catch |err| {
        try printStyled(allocator, .red, "\nError parsing config! Check that config file contains valid JSON.");
        print("\n{}\n", .{err});
        return err;
    };
    // These two values are duped in readConfigFile() and still need freed:
    defer allocator.free(APP_CONFIG.key);
    defer allocator.free(APP_CONFIG.default_comment.?);

    // Read action arg (1st CLI arg) and set const accordingly.
    //const action = try getIntendedAction(allocator);
    const action: ?Action = try getIntendedActionAlloc(allocator);
    if (action == null) {
        return;
    }

    // Validate enough args received for chosen action
    const min_args: u4 = if (action == .submit) 4 else 3; // change first val back to 5 if not adding default comment
    const enuf_args = validateNumArgs(min_args);
    if (!enuf_args) {
        //return UserError.MissingParams;
        return;
    }

    // Read passed args
    var params: ReportParams = getCliArgs();

    // Validate IP
    const ip_str = std.mem.span(params.ip);
    const ip_is_valid = validateIpAddr(ip_str);
    if (!ip_is_valid) {
        try printStyled(allocator, .red, "\nInvalid IP address.\n");
        return;
    }

    // add default comment if none passed:
    if (action.? == .submit) {
        const def_cmt_z = try allocator.dupeZ(u8, APP_CONFIG.default_comment.?); //testing
        defer allocator.free(def_cmt_z);
        const changed = addDefaultComment(&params, def_cmt_z);
        if (changed) {
            print("\nNo comment given. Using default. \n", .{});
        }
    }

    print("\nParams:", .{});
    print("\n  IP: {s}", .{params.ip});
    if (action.? == .submit) {
        print("\n  Categories: {s}", .{params.categories});
        print("\n  Comment: {s}", .{params.comment.?});
    }

    // Either submit a report, or clear reports, based on which action chosen.
    const successful: bool = switch (action.?) {
        .submit => try submitReport(allocator, APP_CONFIG.key, params),
        .delete => try deleteReportsForAddr(allocator, APP_CONFIG.key, params.ip),
        //else => false,
    };

    // Print a success/fail text and exit.
    if (successful == true) {
        try printStyled(allocator, .green, "\nFinished.\n");
        return;
    } else {
        try printStyled(allocator, .red, "\n\u{001b}[1mFailure.\u{001b}[0m\n");
        return;
    }
}

// Some tests - far from complete but whatever

/// This is for testing, see tests.
var X_TESTS_PASSED: u8 = 0; // # passed of tracked tests

var tests_pass_msg: []const u8 = undefined;

test "set test message" {
    tests_pass_msg = "\nTests passed (tracked): ";
}

test "print args vy argv" {
    const argc = std.os.argv.len;
    print("\n # args: {d}", .{argc});
    const args = std.os.argv;
    for (args) |arg| {
        print("\n- arg: {s}", .{arg});
    }
}

test "validate an ip address input is valid" {
    var x: bool = undefined;
    // v4 good
    x = validateIpAddr("10.0.0.255");
    try std.testing.expect(x);
    // v4 bad
    x = validateIpAddr("10.0.0.256");
    try std.testing.expectEqual(false, x);
    // v6 good
    x = validateIpAddr("2001:db8::1");
    try std.testing.expect(x);
    // v6 bad
    x = validateIpAddr("2001:db8::g");
    try std.testing.expectEqual(false, x);
}

test "category numbers" {
    try std.testing.expectEqual(@as(u8, 15), Categories.hacking.catNum());
}

test "user error - invalid/no action" {
    const x = try getIntendedAction(std.testing.allocator);
    try std.testing.expectEqual(null, x);
}

test "get null action (argsAlloc)" {
    const x = try getIntendedActionAlloc(std.testing.allocator);
    try std.testing.expectEqual(null, x);
}

test "validate num of cli args" {
    try std.testing.expect(validateNumArgs(1));
    try std.testing.expect(validateNumArgs(8) == false);
}

test "add default comment to params" {
    var talloc = std.testing.allocator;
    const a = try talloc.dupeZ(u8, "0");
    defer talloc.free(a);
    var b = ReportParams{ .ip = a, .categories = a };
    try std.testing.expectEqual(null, b.comment); //null comment (optional)
    // Now add a comment value
    const c = try talloc.dupeZ(u8, "test");
    defer talloc.free(c);
    const d: bool = addDefaultComment(&b, c);

    try std.testing.expectEqual(c, b.comment.?[0..4]);
    try std.testing.expectEqualSlices(u8, c, b.comment.?[0..c.len]);
    try std.testing.expect(d);
}

test "read config" {
    const x = try readConfigFile(std.testing.allocator);
    defer std.testing.allocator.free(x.key);
    defer std.testing.allocator.free(x.default_comment.?);
    try std.testing.expectEqual(80, x.key.len);
    try std.testing.expect(x.default_comment != null);
}

test "join strings (not really necessary, just testing similar method)" {
    const slices = [_][]const u8{ "one", "two", "three" };
    const x = try std.mem.join(std.testing.allocator, " ", &slices);
    defer std.testing.allocator.free(x);
    try std.testing.expectEqualStrings("one two three", x);
}

test "escape codes" {
    const x = try printStyled(std.testing.allocator, .magenta, "\nTest: This text should Magenta colored\n");
    try std.testing.expect(@TypeOf(x) == void);
}
