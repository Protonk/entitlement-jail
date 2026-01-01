import Foundation
import Darwin
import Security

// Stable, C-callable trace markers for external instrumentation tools.
@_cdecl("pw_probe_fs_op")
@inline(never)
@_optimize(none)
public func pw_probe_fs_op_marker() {}

@_cdecl("pw_probe_fs_op_wait")
@inline(never)
@_optimize(none)
public func pw_probe_fs_op_wait_marker() {}

@_cdecl("pw_probe_net_op")
@inline(never)
@_optimize(none)
public func pw_probe_net_op_marker() {}

@_cdecl("pw_probe_dlopen_external")
@inline(never)
@_optimize(none)
public func pw_probe_dlopen_external_marker() {}

@_cdecl("pw_probe_jit_map_jit")
@inline(never)
@_optimize(none)
public func pw_probe_jit_map_jit_marker() {}

@_cdecl("pw_probe_jit_rwx_legacy")
@inline(never)
@_optimize(none)
public func pw_probe_jit_rwx_legacy_marker() {}

@_cdecl("pw_probe_sandbox_check")
@inline(never)
@_optimize(none)
public func pw_probe_sandbox_check_marker() {}

@_cdecl("pw_probe_sandbox_extension")
@inline(never)
@_optimize(none)
public func pw_probe_sandbox_extension_marker() {}

@_cdecl("pw_probe_inherit_child")
@inline(never)
@_optimize(none)
public func pw_probe_inherit_child_marker() {}

private enum InheritChildCapabilityTransport {
    case rightsBus
    case eventBus
}

private enum InheritChildCapabilityType: String {
    case fileFd = "file_fd"
    case dirFd = "dir_fd"
    case socketFd = "socket_fd"
    case bookmark = "bookmark"
}

private struct InheritChildCapabilityPlan {
    var id: Int32
    var type: InheritChildCapabilityType
    var notes: String
    var transport: InheritChildCapabilityTransport
}

private struct InheritChildScenarioPlan {
    var id: String
    var capabilities: [InheritChildCapabilityPlan]
    var usesSandboxExtension: Bool
    var spawnGrandchild: Bool
    var notes: String
}

private let inheritChildScenarioCatalog: [String: InheritChildScenarioPlan] = {
    let filePlan = InheritChildCapabilityPlan(
        id: InheritChildCapabilityId.fileFd.rawValue,
        type: .fileFd,
        notes: "op=read",
        transport: .rightsBus
    )
    let dirPlan = InheritChildCapabilityPlan(
        id: InheritChildCapabilityId.dirFd.rawValue,
        type: .dirFd,
        notes: "op=openat",
        transport: .rightsBus
    )
    let socketPlan = InheritChildCapabilityPlan(
        id: InheritChildCapabilityId.socketFd.rawValue,
        type: .socketFd,
        notes: "op=sendrecv",
        transport: .rightsBus
    )
    let bookmarkPlan = InheritChildCapabilityPlan(
        id: InheritChildCapabilityId.bookmark.rawValue,
        type: .bookmark,
        notes: "op=bookmark_access",
        transport: .eventBus
    )
    return [
        "dynamic_extension": InheritChildScenarioPlan(
            id: "dynamic_extension",
            capabilities: [filePlan],
            usesSandboxExtension: true,
            spawnGrandchild: false,
            notes: "sandbox extension + file_fd ferry"
        ),
        "matrix_basic": InheritChildScenarioPlan(
            id: "matrix_basic",
            capabilities: [filePlan, dirPlan, socketPlan],
            usesSandboxExtension: false,
            spawnGrandchild: false,
            notes: "file_fd + dir_fd + socket_fd"
        ),
        "bookmark_ferry": InheritChildScenarioPlan(
            id: "bookmark_ferry",
            capabilities: [bookmarkPlan],
            usesSandboxExtension: false,
            spawnGrandchild: false,
            notes: "bookmark payload ferry + access attempt"
        ),
        "lineage_basic": InheritChildScenarioPlan(
            id: "lineage_basic",
            capabilities: [],
            usesSandboxExtension: false,
            spawnGrandchild: true,
            notes: "child spawns grandchild and re-ferries event bus"
        ),
        "inherit_bad_entitlements": InheritChildScenarioPlan(
            id: "inherit_bad_entitlements",
            capabilities: [],
            usesSandboxExtension: false,
            spawnGrandchild: false,
            notes: "spawn intentionally mis-entitled child to force abort"
        ),
    ]
}()

private let inheritChildScenarioList = inheritChildScenarioCatalog.keys.sorted()
private let inheritChildScenarioListString = inheritChildScenarioList.joined(separator: "|")

public enum InProcessProbeCore {
    public typealias ProbeEventSink = (_ event: String, _ childPid: Int?, _ runId: String?, _ message: String?) -> Void

    public static func run(_ req: RunProbeRequest, eventSink: ProbeEventSink? = nil) -> RunProbeResponse {
        var req = req
        if req.correlation_id == nil {
            req.correlation_id = UUID().uuidString
        }
        let enableSignpostsOverride = req.enable_signposts

        let runBody: () -> RunProbeResponse = {
            PWTraceContext.set(
                correlationId: req.correlation_id,
                planId: req.plan_id,
                rowId: req.row_id,
                probeId: req.probe_id
            )
            defer { PWTraceContext.clear() }

            let started = Date()
            let span = PWSignpostSpan(
                category: PWSignposts.categoryXpcService,
                name: "run_probe",
                label: "probe_id=\(req.probe_id)",
                correlationId: req.correlation_id
            )
            defer { span.end() }

            var response: RunProbeResponse
            guard validateProbeId(req.probe_id) else {
                response = RunProbeResponse(
                    rc: 2,
                    stdout: "",
                    stderr: "invalid probe_id: \(req.probe_id)",
                    normalized_outcome: "bad_request",
                    errno: nil,
                    error: nil,
                    details: baseDetails([
                        "probe_family": "bad_request",
                        "probe_id": req.probe_id,
                    ]),
                    layer_attribution: nil
                )
                let ended = Date()
                return decorate(response, req: req, started: started, ended: ended)
            }

            let args = Argv(req.argv)
            if args.has("--help") || args.has("-h") {
                response = probeHelpResponse(probeId: req.probe_id)
                let ended = Date()
                return decorate(response, req: req, started: started, ended: ended)
            }

            switch req.probe_id {
            case "probe_catalog":
                response = probeCatalog()
            case "world_shape":
                response = probeWorldShape()
            case "network_tcp_connect":
                response = probeNetworkTCPConnect(argv: req.argv)
            case "downloads_rw":
                response = probeDownloadsReadWrite(argv: req.argv)
            case "fs_op":
                response = probeFsOp(argv: req.argv)
            case "fs_op_wait":
                response = probeFsOpWait(argv: req.argv)
            case "net_op":
                response = probeNetOp(argv: req.argv)
            case "dlopen_external":
                response = probeDlopenExternal(argv: req.argv)
            case "jit_map_jit":
                response = probeJitMapJit(argv: req.argv)
            case "jit_rwx_legacy":
                response = probeJitRwxLegacy(argv: req.argv)
            case "bookmark_op":
                response = probeBookmarkOp(argv: req.argv)
            case "bookmark_make":
                response = probeBookmarkMake(argv: req.argv)
            case "bookmark_roundtrip":
                response = probeBookmarkRoundtrip(argv: req.argv)
            case "capabilities_snapshot":
                response = probeCapabilitiesSnapshot()
            case "sandbox_check":
                response = probeSandboxCheck(argv: req.argv)
            case "sandbox_extension":
                response = probeSandboxExtension(argv: req.argv)
            case "inherit_child":
                response = probeInheritChild(argv: req.argv, eventSink: eventSink)
            case "userdefaults_op":
                response = probeUserDefaultsOp(argv: req.argv)
            case "fs_xattr":
                response = probeFsXattr(argv: req.argv)
            case "fs_coordinated_op":
                response = probeFsCoordinatedOp(argv: req.argv)
            default:
                response = unknownProbeResponse(req.probe_id)
            }

            let ended = Date()
            return decorate(response, req: req, started: started, ended: ended)
        }

        if let enableSignpostsOverride {
            return PWSignposts.withEnabled(enableSignpostsOverride) {
                runBody()
            }
        }

        return runBody()
    }

    // MARK: - Common metadata

    private static func decorate(_ response: RunProbeResponse, req: RunProbeRequest, started: Date, ended: Date) -> RunProbeResponse {
        var response = response
        let correlationId = req.correlation_id ?? response.correlation_id ?? UUID().uuidString

        response.plan_id = req.plan_id ?? response.plan_id
        response.row_id = req.row_id ?? response.row_id
        response.correlation_id = correlationId
        response.probe_id = req.probe_id
        response.argv = req.argv
        response.service_bundle_id = Bundle.main.bundleIdentifier ?? response.service_bundle_id
        response.service_name = Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String ?? response.service_name
        response.service_version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? response.service_version
        response.service_build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? response.service_build
        response.started_at_iso8601 = iso8601(started)
        response.ended_at_iso8601 = iso8601(ended)
        response.thread_id = threadIdString()
        response.schema_version = 1

        var details = response.details ?? [:]
        details["correlation_id"] = correlationId
        response.details = details

        return response
    }

    private static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private static func threadIdString() -> String {
        let tid = pthread_mach_thread_np(pthread_self())
        return "\(tid)"
    }

	    private static func baseDetails(_ extra: [String: String] = [:]) -> [String: String] {
	        let pid = getpid()
	        var out: [String: String] = [
	            "bundle_id": Bundle.main.bundleIdentifier ?? "",
	            "process_name": ProcessInfo.processInfo.processName,
	            "pid": "\(pid)",
	            "service_pid": "\(pid)",
	            "probe_pid": "\(pid)",
	            "home_dir": FileManager.default.homeDirectoryForCurrentUser.path,
	            "tmp_dir": FileManager.default.temporaryDirectory.path,
	            "cwd": FileManager.default.currentDirectoryPath,
	        ]
	        for (k, v) in extra {
	            out[k] = v
        }
        return out
    }

    // MARK: - Probe catalog + help

    private struct ProbeSpec: Codable {
        var probe_id: String
        var summary: String
        var usage: String
        var required_args: [String]
        var optional_args: [String]
        var examples: [String]
        var entitlement_hints: [String]
        var notes: [String]
    }

    private struct TraceSymbolSpec: Codable {
        var probe_id: String
        var symbols: [String]
    }

    private struct ProbeCatalog: Codable {
        var schema_version: Int
        var generated_at_iso8601: String
        var probes: [ProbeSpec]
        var trace_symbols: [TraceSymbolSpec]
    }

    private static let probeSpecs: [ProbeSpec] = [
        ProbeSpec(
            probe_id: "probe_catalog",
            summary: "emit a JSON catalog of available probes",
            usage: "probe_catalog",
            required_args: [],
            optional_args: [],
            examples: [
                "probe_catalog"
            ],
            entitlement_hints: ["none (observer)"],
            notes: [
                "Outputs JSON in RunProbeResponse.stdout.",
                "Use <probe-id> --help for per-probe usage."
            ]
        ),
        ProbeSpec(
            probe_id: "world_shape",
            summary: "report containerization and world shape metadata",
            usage: "world_shape",
            required_args: [],
            optional_args: [],
            examples: [
                "world_shape"
            ],
            entitlement_hints: ["none (observer)"],
            notes: [
                "Reports HOME/TMP/CWD and containerization signals."
            ]
        ),
        ProbeSpec(
            probe_id: "network_tcp_connect",
            summary: "attempt a TCP connect to an IPv4 host:port",
            usage: "network_tcp_connect --host <ipv4> --port <1..65535>",
            required_args: [
                "--host <ipv4>",
                "--port <1..65535>"
            ],
            optional_args: [],
            examples: [
                "network_tcp_connect --host 1.1.1.1 --port 443"
            ],
            entitlement_hints: ["com.apple.security.network.client"],
            notes: []
        ),
        ProbeSpec(
            probe_id: "downloads_rw",
            summary: "read/write/remove a file under Downloads/policy-witness-harness",
            usage: "downloads_rw [--name <file-name>]",
            required_args: [],
	            optional_args: [
                "--name <file-name>"
            ],
            examples: [
                "downloads_rw",
                "downloads_rw --name demo.txt"
            ],
            entitlement_hints: ["com.apple.security.files.downloads.read-write"],
            notes: [
                "Writes under Downloads/policy-witness-harness."
            ]
        ),
        ProbeSpec(
            probe_id: "fs_op",
            summary: "parameterized filesystem operations",
            usage: """
fs_op --op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>
      (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
      [--target <base|harness_dir|run_dir|specimen_file>] [--name <file-name>]
      [--to <path>|--to-path <path>|--to-name <file-name>] [--max-entries <n>] [--allow-unsafe-path] [--no-cleanup]
""",
            required_args: [
                "--op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>",
                "--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>"
            ],
            optional_args: [
                "--target <base|harness_dir|run_dir|specimen_file>",
                "--name <file-name>",
                "--to <path> | --to-path <path> | --to-name <file-name>",
                "--max-entries <n>",
                "--allow-unsafe-path",
                "--no-cleanup"
            ],
            examples: [
                "fs_op --op stat --path-class downloads",
                "fs_op --op create --path-class tmp --target run_dir"
            ],
            entitlement_hints: ["path-dependent (file access entitlements)"],
            notes: [
                "Destructive direct-path ops are refused unless you use --path-class/--target (or a path under */policy-witness-harness/*) or set --allow-unsafe-path.",
                "Use --no-cleanup to keep harness artifacts after rename/truncate for update_file_by_fileid experiments."
            ]
        ),
        ProbeSpec(
            probe_id: "fs_op_wait",
            summary: "wait for a trigger, then run fs_op",
            usage: """
fs_op_wait --op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>
          (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
          [--target <base|harness_dir|run_dir|specimen_file>] [--name <file-name>]
          [--to <path>|--to-path <path>|--to-name <file-name>] [--max-entries <n>] [--allow-unsafe-path] [--no-cleanup]
          (--wait-fifo <path> | --wait-exists <path>) [--wait-timeout-ms <n>] [--wait-interval-ms <n>]
""",
            required_args: [
                "--op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>",
                "--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>",
                "--wait-fifo <path> | --wait-exists <path>"
            ],
            optional_args: [
                "--target <base|harness_dir|run_dir|specimen_file>",
                "--name <file-name>",
                "--to <path> | --to-path <path> | --to-name <file-name>",
                "--max-entries <n>",
                "--allow-unsafe-path",
                "--no-cleanup",
                "--wait-timeout-ms <n>",
                "--wait-interval-ms <n>"
            ],
            examples: [
                "fs_op_wait --op open_read --path-class tmp --wait-fifo /tmp/pw-wait.fifo",
                "fs_op_wait --op stat --path /tmp/target --wait-exists /tmp/trigger --wait-timeout-ms 60000"
            ],
            entitlement_hints: ["path-dependent (file access entitlements)"],
            notes: [
                "Blocks until the wait trigger is satisfied, then runs fs_op.",
                "--wait-interval-ms is only used with --wait-exists."
            ]
        ),
        ProbeSpec(
            probe_id: "net_op",
            summary: "parameterized network operations",
            usage: "net_op --op <getaddrinfo|tcp_connect|udp_send> --host <host> [--port <1..65535>] [--numeric]",
            required_args: [
                "--op <getaddrinfo|tcp_connect|udp_send>",
                "--host <host>"
            ],
            optional_args: [
                "--port <1..65535>",
                "--numeric"
            ],
            examples: [
                "net_op --op getaddrinfo --host example.com",
                "net_op --op tcp_connect --host 127.0.0.1 --port 80"
            ],
            entitlement_hints: ["com.apple.security.network.client"],
            notes: [
                "--port is required for tcp_connect and udp_send."
            ]
        ),
        ProbeSpec(
            probe_id: "dlopen_external",
            summary: "dlopen a signed dylib by absolute path",
            usage: "dlopen_external --path <abs> (or set PW_DLOPEN_PATH)",
            required_args: [
                "--path <abs> (or PW_DLOPEN_PATH)"
            ],
            optional_args: [],
            examples: [
                "dlopen_external --path /path/to/testdylib.dylib"
            ],
            entitlement_hints: [
                "com.apple.security.cs.disable-library-validation",
                "com.apple.security.cs.allow-dyld-environment-variables (if you rely on DYLD_*)"
            ],
            notes: [
                "Executes dylib initializers; this is not a passive probe.",
                "Use a signed dylib (see tests/fixtures/TestDylib)."
            ]
        ),
        ProbeSpec(
            probe_id: "jit_map_jit",
            summary: "attempt mmap with MAP_JIT",
            usage: "jit_map_jit [--size <bytes>]",
            required_args: [],
            optional_args: [
                "--size <bytes> (default: 16384)"
            ],
            examples: [
                "jit_map_jit",
                "jit_map_jit --size 65536"
            ],
            entitlement_hints: ["com.apple.security.cs.allow-jit"],
            notes: [
                "Reports errno on MAP_JIT failure."
            ]
        ),
        ProbeSpec(
            probe_id: "jit_rwx_legacy",
            summary: "attempt mmap with RWX permissions (legacy)",
            usage: "jit_rwx_legacy [--size <bytes>]",
            required_args: [],
            optional_args: [
                "--size <bytes> (default: 16384)"
            ],
            examples: [
                "jit_rwx_legacy",
                "jit_rwx_legacy --size 65536"
            ],
            entitlement_hints: ["com.apple.security.cs.allow-unsigned-executable-memory"],
            notes: [
                "Reports errno on RWX mmap failure."
            ]
        ),
        ProbeSpec(
            probe_id: "bookmark_op",
            summary: "resolve a bookmark token and run a filesystem op against it",
            usage: """
bookmark_op --bookmark-b64 <base64> | --bookmark-path <path>
            [--relative <rel>] [--op <fs_op-op>] [--allow-unsafe-path]
""",
            required_args: [
                "--bookmark-b64 <base64> | --bookmark-path <path>"
            ],
            optional_args: [
                "--relative <rel>",
                "--op <fs_op-op> (default: stat)",
                "--allow-unsafe-path"
            ],
            examples: [
                "bookmark_op --bookmark-b64 <b64> --op stat",
                "bookmark_op --bookmark-path /tmp/token.txt --op open_read --relative file.txt"
            ],
            entitlement_hints: [
                "com.apple.security.files.bookmarks.app-scope",
                "com.apple.security.files.user-selected.read-only",
                "com.apple.security.files.user-selected.read-write"
            ],
            notes: [
                "Uses ScopedBookmarksAgent IPC for security-scoped bookmarks.",
                "Treat bookmark tokens as scoped to the creating code identity (bundle id/team id); resolving under a different profile/service may fail even if entitlements are present."
            ]
        ),
        ProbeSpec(
            probe_id: "bookmark_make",
            summary: "create a security-scoped bookmark token for a path",
            usage: "bookmark_make --path <abs> [--no-security-scope] [--read-only] [--allow-missing]",
            required_args: [
                "--path <abs>"
            ],
            optional_args: [
                "--no-security-scope",
                "--read-only",
                "--allow-missing"
            ],
            examples: [
                "bookmark_make --path /Users/me/Downloads",
                "bookmark_make --path /Users/me/Downloads --read-only"
            ],
            entitlement_hints: [
                "com.apple.security.files.bookmarks.app-scope",
                "com.apple.security.files.user-selected.read-only",
                "com.apple.security.files.user-selected.read-write"
            ],
            notes: [
                "Security-scoped bookmarks use ScopedBookmarksAgent IPC.",
                "Bookmark tokens are not expected to be portable across service identities; prefer make+resolve within the same profile/service."
            ]
        ),
        ProbeSpec(
            probe_id: "bookmark_roundtrip",
            summary: "create a bookmark token and immediately resolve + run a filesystem op",
            usage: "bookmark_roundtrip --path <abs> [--op <fs_op-op>] [--relative <rel>] [--no-security-scope] [--read-only] [--allow-missing] [--allow-unsafe-path]",
            required_args: [
                "--path <abs>"
            ],
            optional_args: [
                "--op <fs_op-op> (default: stat)",
                "--relative <rel>",
                "--no-security-scope",
                "--read-only",
                "--allow-missing",
                "--allow-unsafe-path"
            ],
            examples: [
                "bookmark_roundtrip --path /Users/me/Downloads --op stat",
                "bookmark_roundtrip --path /Users/me/Downloads --op open_read --relative file.txt"
            ],
            entitlement_hints: [
                "com.apple.security.files.bookmarks.app-scope",
                "com.apple.security.files.user-selected.read-only",
                "com.apple.security.files.user-selected.read-write"
            ],
            notes: [
                "Returns the bookmark token in stdout and the fs_op result in details.",
                "This is the most deterministic bookmark workflow because create+resolve happen under the same service identity."
            ]
        ),
        ProbeSpec(
            probe_id: "capabilities_snapshot",
            summary: "report entitlements and resolved standard directories",
            usage: "capabilities_snapshot",
            required_args: [],
            optional_args: [],
            examples: [
                "capabilities_snapshot"
            ],
            entitlement_hints: ["none (observer)"],
            notes: [
                "Includes entitlement presence booleans and standard directory paths."
            ]
        ),
        ProbeSpec(
            probe_id: "sandbox_check",
            summary: "call sandbox_check() in libsystem_sandbox (hook calibration)",
            usage: "sandbox_check --operation <sandbox-op> [--path <abs>] [--repeat <n>]",
            required_args: [
                "--operation <sandbox-op>"
            ],
            optional_args: [
                "--path <abs>",
                "--repeat <n> (default: 1)"
            ],
            examples: [
                "sandbox_check --operation file-read-data",
                "sandbox_check --operation file-read-data --path /etc/hosts",
                "sandbox_check --operation mach-lookup --repeat 10"
            ],
            entitlement_hints: ["none (observer / instrumentation target)"],
            notes: [
                "This does not perform the operation; it only calls sandbox_check() so attach/hook tooling can observe libsystem_sandbox activity.",
                "If --path is provided, the probe passes a guessed filter type for a path argument; treat the return code as informational, not authoritative."
            ]
        ),
	        ProbeSpec(
	            probe_id: "sandbox_extension",
	            summary: "issue/consume/release sandbox file extensions",
	            usage: """
	sandbox_extension --op issue_file --class <extension-class>
	                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
	                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--flags <int>] [--create] [--allow-unsafe-path] [--introspect]
	sandbox_extension --op issue_file_to_pid --pid <int|self> --class <extension-class>
	                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
	                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--flags <int>] [--create] [--allow-unsafe-path] [--introspect]
	sandbox_extension --op issue_extension
	                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
	                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--create] [--allow-unsafe-path] [--introspect]
	sandbox_extension --op issue_fs_extension [--flags <int>]
	                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
	                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--create] [--allow-unsafe-path] [--introspect]
		sandbox_extension --op issue_fs_rw_extension
		                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
		                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
		                 [--create] [--allow-unsafe-path] [--introspect]
		sandbox_extension --op consume --token <token> [--token-format <full|prefix>]
		                 [--call-symbol <symbol>] [--call-variant <handle_one_arg|one_arg|two_arg|token_second|token_and_ptr|auto>] [--flags <int>] [--introspect]
		sandbox_extension --op release [--handle <i64>] [--token <token> --token-format <full|prefix>]
		                 [--call-symbol <symbol>] [--call-variant <handle_one_arg|one_arg|two_arg|token_and_ptr|auto>] [--flags <int>] [--introspect]
		sandbox_extension --op release_file --token <token> [--token-format <full|prefix>]
		                 [--introspect]
	sandbox_extension --op update_file (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
	                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--flags <int>] [--allow-unsafe-path] [--introspect]
		sandbox_extension --op update_file_rename_delta --class <extension-class>
		                 --path <abs> --new-path <abs>
		                 [--flags <int>] [--selector <u64>] [--allow-unsafe-path]
		                 [--wait-for-external-rename] [--wait-timeout-ms <n>] [--wait-interval-ms <n>]
		                 [--no-cleanup] [--introspect]
		sandbox_extension --op update_file_by_fileid --token <token> (--file-id <u64> | --path <abs>)
		                 [--flags <int>] [--selector <u64>] [--call-variant <token_fileid|fileid_token|fileid_ptr_token|token_ptr_fileid|fileid_ptr_selector|payload_ptr_selector|auto>] [--introspect]
		sandbox_extension --op update_file_by_fileid_sweep --class <extension-class>
		                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
		                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--flags <int>] [--create] [--allow-unsafe-path]
	                 [--selectors <u64,u64,...>] [--include-token-fields] [--no-cleanup] [--introspect]
	sandbox_extension --op update_file_by_fileid_delta --class <extension-class>
	                 (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
	                 [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
	                 [--flags <int>] [--selector <u64>] [--create] [--allow-unsafe-path]
	                 [--payload <u64> | --payload-source <st_dev|st_ino|handle_low32|handle_high32|handle_xor32>]
	                 [--sandbox-op <sandbox-op>] [--skip-update] [--no-cleanup]
	                 [--wait-for-external-replace] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--introspect]
""",
		            required_args: [
		                "--op <issue_file|issue_file_to_pid|issue_extension|issue_fs_extension|issue_fs_rw_extension|consume|release|release_file|update_file|update_file_rename_delta|update_file_by_fileid|update_file_by_fileid_sweep|update_file_by_fileid_delta>"
		            ],
		            optional_args: [
		                "--class <extension-class> (required for issue_file/issue_file_to_pid/update_file_rename_delta/update_file_by_fileid_delta)",
		                "--pid <int|self> (required for issue_file_to_pid)",
		                "--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches> (required for issue_file/issue_file_to_pid/issue_*/update_file/update_file_by_fileid_delta)",
		                "--new-path <abs> (required for update_file_rename_delta)",
		                "--file-id <u64> (required for update_file_by_fileid unless --path is provided)",
		                "--selector <u64> (update_file_by_fileid selectors; default: 2 for update_file_by_fileid_delta/update_file_rename_delta)",
		                "--selectors <u64,u64,...> (default: 0,1,2; update_file_by_fileid_sweep)",
		                "--payload <u64> (update_file_by_fileid_delta; overrides --payload-source)",
		                "--payload-source <st_dev|st_ino|handle_low32|handle_high32|handle_xor32> (default: st_dev; update_file_by_fileid_delta)",
		                "--sandbox-op <sandbox-op> (default: file-read-data; update_file_by_fileid_delta sandbox_check oracle)",
		                "--skip-update (update_file_by_fileid_delta control arm: measure without calling update)",
		                "--no-cleanup (update_file_by_fileid_delta/update_file_rename_delta: do not call sandbox_extension_release(handle))",
		                "--wait-for-external-replace (update_file_by_fileid_delta: wait for inode change instead of doing an in-sandbox replace)",
		                "--wait-for-external-rename (update_file_rename_delta: wait for a host-side rename from --path to --new-path)",
		                "--wait-timeout-ms <n> (default: 30000; update_file_by_fileid_delta/update_file_rename_delta)",
		                "--wait-interval-ms <n> (default: 50; update_file_by_fileid_delta/update_file_rename_delta)",
		                "--include-token-fields (update_file_by_fileid_sweep: parse numeric token segments as candidate payloads)",
		                "--target <base|harness_dir|run_dir|specimen_file> (default: specimen_file)",
		                "--name <filename>",
	                "--flags <int> (default: 0; issue_file/issue_fs_extension/update_file/update_file_by_fileid/update_file_by_fileid_delta or consume/release with two_arg)",
	                "--create (create a harness file/dir for issue_file/update_file_by_fileid_delta if missing)",
	                "--allow-unsafe-path",
	                "--introspect (emit symbol presence + image path in details)",
	                "--token <token> (required for consume/release_file/update_file_by_fileid; optional for release)",
	                "--handle <i64> (preferred for release; from a prior consume)",
	                "--token-format <full|prefix> (default: full; consume/release/update_file_by_fileid)",
	                "--call-symbol <symbol> (override consume/release symbol; advanced)",
	                "--call-variant <handle_one_arg|one_arg|two_arg|token_second|token_and_ptr|token_fileid|fileid_token|fileid_ptr_token|token_ptr_fileid|fileid_ptr_selector|payload_ptr_selector|auto> (default: auto; consume/release/update_file_by_fileid)"
	            ],
		            examples: [
		                "sandbox_extension --op issue_file --class com.apple.app-sandbox.read --path /etc/hosts --allow-unsafe-path",
		                "sandbox_extension --op issue_file --class com.apple.app-sandbox.read --path-class tmp --target specimen_file --name pw_extension.txt --create",
		                "sandbox_extension --op issue_file_to_pid --pid self --class com.apple.app-sandbox.read --path /etc/hosts --allow-unsafe-path",
		                "sandbox_extension --op issue_extension --path-class tmp --target specimen_file --name pw_extension.txt --create",
		                "sandbox_extension --op issue_fs_extension --flags 8 --path /etc/hosts --allow-unsafe-path",
		                "sandbox_extension --op consume --token <token> --token-format full",
		                "sandbox_extension --op consume --token <token> --call-variant token_second --call-symbol sandbox_consume_extension",
		                "sandbox_extension --op consume --token <token> --call-variant token_and_ptr --call-symbol sandbox_consume_fs_extension",
		                "sandbox_extension --op release --handle <i64>",
		                "sandbox_extension --op release_file --token <token>",
		                "sandbox_extension --op update_file --path /etc/hosts --flags 0 --allow-unsafe-path",
		                "sandbox_extension --op update_file_rename_delta --class com.apple.app-sandbox.read --path /Users/me/Desktop/pw_old.txt --new-path /Users/me/Desktop/pw_new.txt --wait-for-external-rename --allow-unsafe-path",
		                "sandbox_extension --op update_file_by_fileid --token <token> --path /etc/hosts --flags 0",
		                "sandbox_extension --op update_file_by_fileid --token <token> --file-id <u64> --selector 2 --call-variant payload_ptr_selector",
		                "sandbox_extension --op update_file_by_fileid_sweep --class com.apple.app-sandbox.read --path-class tmp --target specimen_file --name pw_sweep.txt --create --selectors 0,1,2",
		                "sandbox_extension --op update_file_by_fileid_delta --class com.apple.app-sandbox.read --path-class tmp --target specimen_file --name pw_delta.txt --create --selector 2 --payload-source st_dev",
	                "sandbox_extension --op issue_file --class com.apple.app-sandbox.read --path /etc/hosts --allow-unsafe-path --introspect"
	            ],
            entitlement_hints: [
                "com.apple.security.temporary-exception.sbpl (allow file-issue-extension for extension class)"
            ],
		            notes: [
		                "issue_file returns the token in stdout and in details.token.",
		                "issue_file_to_pid issues a token scoped to another process via sandbox_extension_issue_file_to_process_by_pid.",
		                "issue_extension/issue_fs_extension/issue_fs_rw_extension are thin wrappers around sandbox_extension_issue_file.",
		                "Direct-path issuance outside */policy-witness-harness/* is refused unless you pass --allow-unsafe-path.",
		                "If consume/release fails with invalid-token style errors, try --token-format prefix (uses the substring before the first ';').",
		                "consume returns a (typically positive) i64 handle in stdout + details.consume_handle when sandbox_extension_consume(handle) is usable.",
		                "release prefers --handle from a prior consume; token-based release variants are supported for experimentation only.",
		                "Consume/release auto-tries common symbols/variants when --call-symbol is not set; use --call-symbol/--call-variant to pin behavior.",
		                "release_file calls sandbox_extension_release_file with the provided token only.",
		                "update_file passes path + flags into sandbox_extension_update_file; update_file_by_fileid is experimental and supports multiple ABI variants, including pointer-based forms.",
		                "update_file_rename_delta runs issue+consume on --path, waits for a host-side rename to --new-path, then compares update_file_by_fileid candidates vs update_file() for restoring access to --new-path.",
		                "update_file_rename_delta stops early with normalized_outcome=dest_preexisted if --new-path already exists at probe start.",
		                "payload_ptr_selector uses an 8-byte payload buffer + selector and forces field2 to 0 (Sonoma 14.4.1 ABI).",
		                "If update_file_by_fileid returns invalid-arg/Bad address, try --call-variant payload_ptr_selector and a selector of 0/1/2.",
		                "update_file_by_fileid_sweep issues+consumes a token and runs payload_ptr_selector across candidate payloads (stat + handle-derived; optionally token fields) and selectors.",
		                "update_file_by_fileid_delta runs an atomic replace and records open + sandbox_check transitions before/after the update call (use this to define a measurable access delta).",
		                "Wrapper symbols use specific variants: sandbox_consume_extension=token_second, sandbox_consume_fs_extension=token_and_ptr, sandbox_release_fs_extension=one_arg."
	            ]
        ),
        ProbeSpec(
            probe_id: "inherit_child",
            summary: "capability ferry matrix: parent acquires, child attempts acquire vs use",
            usage: """
inherit_child [--scenario <\(inheritChildScenarioListString)>]
              [--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>]
              [--target <base|harness_dir|run_dir|specimen_file>] [--name <filename>]
              [--create] [--allow-unsafe-path]
              [--stop-on-entry] [--stop-on-deny] [--stop-auto-resume]
              [--bookmark-move] [--bookmark-invalid] [--protocol-bad-cap-id]
""",
            required_args: [],
            optional_args: [
                "--scenario <\(inheritChildScenarioListString)> (default: dynamic_extension)",
                "--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>",
                "--target <base|harness_dir|run_dir|specimen_file> (default: specimen_file)",
                "--name <filename>",
                "--create (create a harness file/dir for the target if missing)",
                "--allow-unsafe-path",
                "--bookmark-move (bookmark_ferry only; move target after bookmark creation)",
                "--bookmark-invalid (bookmark_ferry only; send invalid bookmark payload bytes)",
                "--stop-on-entry (child raises SIGSTOP early for debugger attach)",
                "--stop-on-deny (child raises SIGSTOP on EPERM/EACCES)",
                "--stop-auto-resume (parent sends SIGCONT after child stop)",
                "--protocol-bad-cap-id (inject a bad cap_id for protocol tests)"
            ],
            examples: [
                "inherit_child --scenario dynamic_extension --path /private/var/db/launchd.db/com.apple.launchd/overrides.plist --allow-unsafe-path",
                "inherit_child --scenario matrix_basic --path-class tmp --target specimen_file --name pw_child.txt --create",
                "inherit_child --scenario bookmark_ferry --path-class documents --target specimen_file --name pw_child.txt --create",
                "inherit_child --scenario inherit_bad_entitlements"
            ],
            entitlement_hints: [
                "com.apple.security.temporary-exception.sbpl (needed for sandbox_extension issue_file in dynamic_extension)"
            ],
            notes: [
                "Spawns the bundled pw-inherit-child helper using posix_spawn and an event bus + rights bus (SCM_RIGHTS).",
                "Emits a structured witness payload under RunProbeResponse.witness.",
                "dynamic_extension uses sandbox extension issuance for parent-only acquisition; matrix_basic skips tokens.",
                "bookmark_ferry passes security-scoped bookmark bytes over the event bus; bookmark resolution is identity-sensitive, so the spawned helper must share the service bundle id.",
                "lineage_basic spawns a grandchild."
            ]
        ),
        ProbeSpec(
            probe_id: "userdefaults_op",
            summary: "read/write/remove/sync a UserDefaults key",
            usage: "userdefaults_op --op <read|write|remove|sync> [--key <k>] [--value <v>] [--suite <suite>]",
            required_args: [],
            optional_args: [
                "--op <read|write|remove|sync> (default: read)",
                "--key <k>",
                "--value <v>",
                "--suite <suite>"
            ],
            examples: [
                "userdefaults_op --op read --key example",
                "userdefaults_op --op write --key example --value 1"
            ],
            entitlement_hints: ["none (containerization evidence)"],
            notes: [
                "Useful for observing containerized preferences paths."
            ]
        ),
        ProbeSpec(
            probe_id: "fs_xattr",
            summary: "get/list/set/remove extended attributes",
            usage: "fs_xattr --op <get|list|set|remove> --path <abs> [--name <xattr>] [--value <v>] [--allow-write] [--allow-unsafe-path]",
            required_args: [
                "--op <get|list|set|remove>",
                "--path <abs>"
            ],
            optional_args: [
                "--name <xattr>",
                "--value <v>",
                "--allow-write",
                "--allow-unsafe-path"
            ],
            examples: [
                "fs_xattr --op get --path /tmp/file --name com.apple.quarantine",
                "fs_xattr --op list --path /tmp/file"
            ],
            entitlement_hints: ["path-dependent (file access entitlements)"],
            notes: [
                "xattr writes are refused outside harness paths unless --allow-write or --allow-unsafe-path is set."
            ]
        ),
        ProbeSpec(
            probe_id: "fs_coordinated_op",
            summary: "NSFileCoordinator mediated read/write",
            usage: "fs_coordinated_op --op <read|write> (--path <abs> | --path-class <...>) [--target <...>] [--allow-unsafe-path]",
            required_args: [
                "--op <read|write>",
                "--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>"
            ],
            optional_args: [
                "--target <base|harness_dir|run_dir|specimen_file>",
                "--allow-unsafe-path"
            ],
            examples: [
                "fs_coordinated_op --op read --path-class documents",
                "fs_coordinated_op --op write --path-class tmp --target run_dir"
            ],
            entitlement_hints: ["path-dependent (file access entitlements)"],
            notes: [
                "Coordinated writes to direct paths are refused unless you use --path-class/--target (or a path under */policy-witness-harness/*) or set --allow-unsafe-path."
            ]
        )
    ]

    private static let traceSymbols: [TraceSymbolSpec] = [
        TraceSymbolSpec(probe_id: "fs_op", symbols: ["pw_probe_fs_op"]),
        TraceSymbolSpec(probe_id: "fs_op_wait", symbols: ["pw_probe_fs_op_wait"]),
        TraceSymbolSpec(probe_id: "net_op", symbols: ["pw_probe_net_op"]),
        TraceSymbolSpec(probe_id: "dlopen_external", symbols: ["pw_probe_dlopen_external"]),
        TraceSymbolSpec(probe_id: "jit_map_jit", symbols: ["pw_probe_jit_map_jit"]),
        TraceSymbolSpec(probe_id: "jit_rwx_legacy", symbols: ["pw_probe_jit_rwx_legacy"]),
        TraceSymbolSpec(probe_id: "sandbox_check", symbols: ["pw_probe_sandbox_check"]),
        TraceSymbolSpec(probe_id: "sandbox_extension", symbols: ["pw_probe_sandbox_extension"]),
        TraceSymbolSpec(probe_id: "inherit_child", symbols: ["pw_probe_inherit_child"]),
    ]

    private static func probeSpec(for probeId: String) -> ProbeSpec? {
        probeSpecs.first { $0.probe_id == probeId }
    }

    private static func probeCatalog() -> RunProbeResponse {
        let catalog = ProbeCatalog(
            schema_version: 1,
            generated_at_iso8601: ISO8601DateFormatter().string(from: Date()),
            probes: probeSpecs,
            trace_symbols: traceSymbols
        )
        do {
            let data = try encodeJSON(catalog)
            let json = String(data: data, encoding: .utf8) ?? ""
            return RunProbeResponse(
                rc: 0,
                stdout: json,
                stderr: "",
                normalized_outcome: "ok",
                errno: nil,
                error: nil,
                details: baseDetails([
                    "probe_family": "probe_catalog",
                    "probe_count": "\(probeSpecs.count)"
                ]),
                layer_attribution: nil
            )
        } catch {
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "encode_failed",
                errno: nil,
                error: "\(error)",
                details: baseDetails([
                    "probe_family": "probe_catalog"
                ]),
                layer_attribution: nil
            )
        }
    }

    private static func probeHelpResponse(probeId: String) -> RunProbeResponse {
        guard let spec = probeSpec(for: probeId) else {
            return unknownProbeResponse(probeId)
        }
        let help = renderProbeHelp(spec)
        return RunProbeResponse(
            rc: 0,
            stdout: help,
            stderr: "",
            normalized_outcome: "help",
            errno: nil,
            error: nil,
            details: baseDetails([
                "probe_family": "probe_help",
                "probe_id": probeId
            ]),
            layer_attribution: nil
        )
    }

    private static func renderProbeHelp(_ spec: ProbeSpec) -> String {
        var lines: [String] = []
        lines.append("probe: \(spec.probe_id)")
        lines.append("summary: \(spec.summary)")

        if !spec.usage.isEmpty {
            lines.append("usage:")
            for line in spec.usage.split(separator: "\n", omittingEmptySubsequences: true) {
                lines.append("  \(line)")
            }
        }

        if !spec.required_args.isEmpty {
            lines.append("required args:")
            for arg in spec.required_args {
                lines.append("  \(arg)")
            }
        }

        if !spec.optional_args.isEmpty {
            lines.append("optional args:")
            for arg in spec.optional_args {
                lines.append("  \(arg)")
            }
        }

        if !spec.entitlement_hints.isEmpty {
            lines.append("entitlement hints:")
            for ent in spec.entitlement_hints {
                lines.append("  \(ent)")
            }
        }

        if !spec.examples.isEmpty {
            lines.append("examples:")
            for ex in spec.examples {
                lines.append("  \(ex)")
            }
        }

        if !spec.notes.isEmpty {
            lines.append("notes:")
            for note in spec.notes {
                lines.append("  \(note)")
            }
        }

        return lines.joined(separator: "\n")
    }

    private static func unknownProbeResponse(_ probeId: String) -> RunProbeResponse {
        RunProbeResponse(
            rc: 2,
            stdout: "",
            stderr: "unknown probe_id: \(probeId)",
            normalized_outcome: "unknown_probe",
            errno: nil,
            error: nil,
            details: baseDetails([
                "probe_family": "unknown_probe",
                "probe_id": probeId,
            ]),
            layer_attribution: nil
        )
    }

	    private static func probeWorldShape() -> RunProbeResponse {
	        let home = FileManager.default.homeDirectoryForCurrentUser.path
	        let tmp = FileManager.default.temporaryDirectory.path
	        let cwd = FileManager.default.currentDirectoryPath

	        let looksContainerized = home.contains("/Library/Containers/")
	        let worldShapeChange = looksContainerized ? "home_containerized" : nil

        let details = baseDetails([
            "home_dir": home,
            "tmp_dir": tmp,
            "cwd": cwd,
            "has_app_sandbox": entitlementBool("com.apple.security.app-sandbox") ? "true" : "false",
            "has_network_client": entitlementBool("com.apple.security.network.client") ? "true" : "false",
            "has_downloads_rw": entitlementBool("com.apple.security.files.downloads.read-write") ? "true" : "false",
            "has_user_selected_executable": entitlementBool("com.apple.security.files.user-selected.executable") ? "true" : "false",
        ])

        return RunProbeResponse(
            rc: 0,
            stdout: "",
            stderr: "",
            normalized_outcome: "ok",
            errno: nil,
            error: nil,
            details: details,
            layer_attribution: LayerAttribution(world_shape_change: worldShapeChange)
        )
    }

    private static func probeNetworkTCPConnect(argv: [String]) -> RunProbeResponse {
        let args = Argv(argv)
        guard let host = args.value("--host") else {
            return badRequest("missing required --host")
        }
        guard let portStr = args.value("--port"), let port = Int(portStr), (1...65535).contains(port) else {
            return badRequest("missing/invalid --port (expected 1..65535)")
        }

        let detailsBase = baseDetails([
            "host": host,
            "port": "\(port)",
        ])

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.stride)

        let ptonResult = host.withCString { cstr in
            inet_pton(AF_INET, cstr, &addr.sin_addr)
        }
        guard ptonResult == 1 else {
            return badRequest("invalid IPv4 address for --host: \(host)")
        }

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 {
            let e = errno
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "socket_failed",
                errno: Int(e),
                error: String(cString: strerror(e)),
                details: detailsBase,
                layer_attribution: nil
            )
        }
        defer { close(fd) }

        var addrCopy = addr
        let connectResult: Int32 = withUnsafePointer(to: &addrCopy) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                pw_connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }

        if connectResult == 0 {
            return RunProbeResponse(
                rc: 0,
                stdout: "",
                stderr: "",
                normalized_outcome: "ok",
                errno: nil,
                error: nil,
                details: detailsBase.merging(["connect": "ok"], uniquingKeysWith: { cur, _ in cur }),
                layer_attribution: nil
            )
        }

        let e = errno
        let outcome: String
        switch e {
        case EACCES, EPERM:
            outcome = "permission_error"
        case ECONNREFUSED:
            outcome = "connection_refused"
        case ETIMEDOUT:
            outcome = "timed_out"
        case EHOSTUNREACH, ENETUNREACH:
            outcome = "unreachable"
        default:
            outcome = "connect_failed"
        }

        return RunProbeResponse(
            rc: 1,
            stdout: "",
            stderr: "",
            normalized_outcome: outcome,
            errno: Int(e),
            error: String(cString: strerror(e)),
            details: detailsBase.merging(["connect": "failed"], uniquingKeysWith: { cur, _ in cur }),
            layer_attribution: nil
        )
    }

    private static func probeDownloadsReadWrite(argv: [String]) -> RunProbeResponse {
        let args = Argv(argv)
        let requestedName = args.value("--name")

        let detailsBase = baseDetails()

        guard let downloadsDir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first else {
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "downloads_dir_unavailable",
                errno: nil,
                error: "failed to resolve downloads directory",
                details: detailsBase,
                layer_attribution: nil
            )
        }

        let harnessDir = downloadsDir.appendingPathComponent("policy-witness-harness", isDirectory: true)
        let fileName = requestedName?.isEmpty == false ? requestedName! : "probe-\(UUID().uuidString).txt"
        let fileURL = harnessDir.appendingPathComponent(fileName, isDirectory: false)

        func opError(_ outcome: String, _ error: Error, op: String) -> RunProbeResponse {
            let e = extractErrno(error)
            let details: [String: String] = detailsBase.merging([
                "downloads_dir": downloadsDir.path,
                "target_dir": harnessDir.path,
                "file_path": fileURL.path,
                "failed_op": op,
            ], uniquingKeysWith: { cur, _ in cur })
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: outcome,
                errno: e,
                error: "\(error)",
                details: details,
                layer_attribution: nil
            )
        }

        do {
            try FileManager.default.createDirectory(at: harnessDir, withIntermediateDirectories: true, attributes: nil)
        } catch {
            let outcome = isPermissionError(error) ? "permission_error" : "mkdir_failed"
            return opError(outcome, error, op: "mkdir")
        }

        let payload = Data("policy-witness downloads_rw probe\n".utf8)
        do {
            try payload.write(to: fileURL, options: [.atomic])
        } catch {
            let outcome = isPermissionError(error) ? "permission_error" : "write_failed"
            return opError(outcome, error, op: "write")
        }

        do {
            _ = try Data(contentsOf: fileURL)
        } catch {
            let outcome = isPermissionError(error) ? "permission_error" : "read_failed"
            return opError(outcome, error, op: "read")
        }

        var cleanupError: String?
        do {
            try FileManager.default.removeItem(at: fileURL)
        } catch {
            cleanupError = "\(error)"
        }

        let details: [String: String] = detailsBase.merging([
            "downloads_dir": downloadsDir.path,
            "target_dir": harnessDir.path,
            "file_path": fileURL.path,
            "cleanup_error": cleanupError ?? "",
        ], uniquingKeysWith: { cur, _ in cur })

	        return RunProbeResponse(
	            rc: 0,
	            stdout: "",
	            stderr: "",
	            normalized_outcome: cleanupError == nil ? "ok" : "ok_cleanup_failed",
	            errno: nil,
	            error: cleanupError,
	            details: details,
	            layer_attribution: nil
	        )
	    }

	    // MARK: - fs_op (parameterized file system operations)

	    private enum FsOp: String, CaseIterable {
	        case stat
	        case open_read
	        case open_write
	        case create
	        case truncate
	        case rename
	        case unlink
	        case mkdir
	        case rmdir
	        case listdir
	        case readlink
	        case realpath
	    }

	    private enum FsTarget: String {
	        case path
	        case base
	        case harness_dir
	        case run_dir
	        case specimen_file
	    }

	    private struct FsResolvedTarget {
	        var path: String
	        var baseDir: String?
	        var harnessDir: String?
	        var runDir: String?
	        var cleanupRoots: [String]
	    }

        private struct WaitResult {
            var normalizedOutcome: String
            var errno: Int32?
            var error: String?
        }

        private struct WaitConfig {
            var mode: String
            var path: String
            var timeoutMs: Int?
            var intervalMs: Int
        }

        private static func performWait(_ config: WaitConfig) -> (WaitResult, [String: String]) {
            var details: [String: String] = [
                "wait_mode": config.mode,
                "wait_path": config.path,
            ]
            if let timeoutMs = config.timeoutMs { details["wait_timeout_ms"] = "\(timeoutMs)" }
            if config.mode == "exists" { details["wait_interval_ms"] = "\(config.intervalMs)" }

            let waitStartNs = DispatchTime.now().uptimeNanoseconds
            details["wait_started_at_ns"] = "\(waitStartNs)"

            let result: WaitResult
            if config.mode == "fifo" {
                result = waitForFifo(path: config.path, timeoutMs: config.timeoutMs)
            } else {
                result = waitForPathExists(path: config.path, timeoutMs: config.timeoutMs, intervalMs: config.intervalMs)
            }

            let waitEndNs = DispatchTime.now().uptimeNanoseconds
            details["wait_ended_at_ns"] = "\(waitEndNs)"
            details["wait_duration_ms"] = "\(Int((waitEndNs - waitStartNs) / 1_000_000))"
            return (result, details)
        }

	    // MARK: - fs_op_wait (delayed fs_op for attach)

	    private static func probeFsOpWait(argv: [String]) -> RunProbeResponse {
	        pw_probe_fs_op_wait_marker()
	        let args = Argv(argv)
	        let expectedOps = FsOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let opStr = args.value("--op"), FsOp(rawValue: opStr) != nil else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }

	        let directPath = args.value("--path")
	        let pathClass = args.value("--path-class")
	        if (directPath == nil) == (pathClass == nil) {
	            return badRequest("provide exactly one of --path or --path-class")
	        }

	        let waitFifo = args.value("--wait-fifo")
	        let waitExists = args.value("--wait-exists")
	        if (waitFifo == nil) == (waitExists == nil) {
	            return badRequest("provide exactly one of --wait-fifo or --wait-exists")
	        }

	        if let waitPath = waitFifo, !waitPath.hasPrefix("/") {
	            return badRequest("--wait-fifo must be an absolute path")
	        }
	        if let waitPath = waitExists, !waitPath.hasPrefix("/") {
	            return badRequest("--wait-exists must be an absolute path")
	        }

	        if waitFifo != nil, args.value("--wait-interval-ms") != nil {
	            return badRequest("--wait-interval-ms is only valid with --wait-exists")
	        }

	        let timeoutMs = args.intValue("--wait-timeout-ms")
	        if let timeoutMs, timeoutMs < 0 {
	            return badRequest("--wait-timeout-ms must be >= 0")
	        }

	        let intervalMs = args.intValue("--wait-interval-ms") ?? 200
	        if intervalMs < 1 {
	            return badRequest("--wait-interval-ms must be >= 1")
	        }

	        let waitPath = waitFifo ?? waitExists ?? ""
	        let waitMode = (waitFifo != nil) ? "fifo" : "exists"

	        let pid = getpid()
	        fputs("[probe] wait-ready pid=\(pid) wait_path=\(waitPath)\n", stderr)
	        fflush(stderr)

	        let config = WaitConfig(
	            mode: waitMode,
	            path: waitPath,
	            timeoutMs: timeoutMs,
	            intervalMs: intervalMs
	        )
	        let waitSpan = PWSignpostSpan(
	            category: PWSignposts.categoryXpcService,
	            name: "wait",
	            label: "fs_op_wait mode=\(waitMode)"
	        )
	        defer { waitSpan.end() }
	        let (waitResult, waitDetailsBase) = performWait(config)
	        var waitDetails = waitDetailsBase
	        waitDetails["probe_family"] = "fs_op_wait"

	        if waitResult.normalizedOutcome != "ok" {
	            let details = baseDetails(waitDetails.merging([
	                "op": opStr,
	                "path_mode": directPath != nil ? "direct_path" : "path_class",
	                "path_class": pathClass ?? "",
	                "path": directPath ?? "",
	            ], uniquingKeysWith: { cur, _ in cur }))
	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: waitResult.normalizedOutcome,
	                errno: waitResult.errno.map { Int($0) },
	                error: waitResult.error,
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        var response = probeFsOp(argv: argv)
	        var details = response.details ?? [:]
	        for (k, v) in waitDetails {
	            details[k] = v
	        }
	        response.details = details
	        return response
	    }

		    private static func waitForFifo(path: String, timeoutMs: Int?) -> WaitResult {
		        let lock = NSLock()
		        var openedFd: Int32 = -1
		        var openErrno: Int32?
		        let sema = DispatchSemaphore(value: 0)

	        DispatchQueue.global(qos: .userInitiated).async {
	            let fd = path.withCString { ptr in
	                pw_open(ptr, O_RDONLY, 0)
	            }
	            lock.lock()
	            if fd < 0 {
	                openErrno = errno
	            } else {
	                openedFd = fd
	            }
	            lock.unlock()
	            sema.signal()
	        }

	        let timedOut: Bool
	        if let timeoutMs {
	            timedOut = sema.wait(timeout: .now() + .milliseconds(timeoutMs)) == .timedOut
	        } else {
	            sema.wait()
	            timedOut = false
	        }

	        if timedOut {
	            let unblockFd = path.withCString { ptr in
	                pw_open(ptr, O_WRONLY | O_NONBLOCK, 0)
	            }
	            if unblockFd >= 0 {
	                close(unblockFd)
	            }
	            _ = sema.wait(timeout: .now() + .milliseconds(50))
	            return WaitResult(normalizedOutcome: "timeout", errno: nil, error: "wait timeout")
	        }

	        lock.lock()
	        let err = openErrno
	        let fd = openedFd
	        lock.unlock()

		        if let err {
		            return WaitResult(normalizedOutcome: "wait_failed", errno: err, error: String(cString: strerror(err)))
		        }
		        if fd >= 0 {
		            let maxWaitMs = min(200, timeoutMs ?? 200)
		            let currentFlags = fcntl(fd, F_GETFL)
		            if currentFlags >= 0, fcntl(fd, F_SETFL, currentFlags | O_NONBLOCK) >= 0 {
		                var b: UInt8 = 0
		                var attempts = 0
		                while attempts < maxWaitMs {
		                    let n = Darwin.read(fd, &b, 1)
		                    if n > 0 || n == 0 {
		                        break
		                    }
		                    let e = errno
		                    if e == EINTR {
		                        continue
		                    }
		                    if e == EAGAIN || e == EWOULDBLOCK {
		                        usleep(1000)
		                        attempts += 1
		                        continue
		                    }
		                    break
		                }
		            } else {
		                usleep(useconds_t(maxWaitMs * 1000))
		            }
		            close(fd)
		            return WaitResult(normalizedOutcome: "ok", errno: nil, error: nil)
		        }
		        return WaitResult(normalizedOutcome: "wait_failed", errno: nil, error: "wait failed")
		    }

	    private static func waitForPathExists(path: String, timeoutMs: Int?, intervalMs: Int) -> WaitResult {
	        if FileManager.default.fileExists(atPath: path) {
	            return WaitResult(normalizedOutcome: "ok", errno: nil, error: nil)
	        }
	        if let timeoutMs, timeoutMs <= 0 {
	            return WaitResult(normalizedOutcome: "timeout", errno: nil, error: "wait timeout")
	        }

	        let start = DispatchTime.now().uptimeNanoseconds
	        while true {
	            if let timeoutMs {
	                let now = DispatchTime.now().uptimeNanoseconds
	                let elapsedMs = (now - start) / 1_000_000
	                if elapsedMs >= UInt64(timeoutMs) {
	                    return WaitResult(normalizedOutcome: "timeout", errno: nil, error: "wait timeout")
	                }
	                let remainingMs = Int(UInt64(timeoutMs) - elapsedMs)
	                let sleepMs = max(1, min(intervalMs, remainingMs))
	                usleep(useconds_t(sleepMs * 1000))
	            } else {
	                usleep(useconds_t(intervalMs * 1000))
	            }

	            if FileManager.default.fileExists(atPath: path) {
	                return WaitResult(normalizedOutcome: "ok", errno: nil, error: nil)
	            }
	        }
	    }

	    private static func probeFsOp(argv: [String]) -> RunProbeResponse {
	        pw_probe_fs_op_marker()
	        let args = Argv(argv)
	        let expectedOps = FsOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let opStr = args.value("--op"), let op = FsOp(rawValue: opStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }

        let allowUnsafe = args.has("--allow-unsafe-path")
        let skipCleanup = args.has("--no-cleanup")
        let directPath = args.value("--path")
        let pathClass = args.value("--path-class")

	        if (directPath == nil) == (pathClass == nil) {
	            return badRequest("provide exactly one of --path or --path-class")
	        }

	        let targetStr = args.value("--target")
	        let defaultTarget: FsTarget = {
	            switch op {
	            case .stat, .listdir, .readlink, .realpath:
	                return .base
	            case .mkdir, .rmdir:
	                return .run_dir
	            case .open_read, .open_write, .create, .truncate, .rename, .unlink:
	                return .specimen_file
	            }
	        }()

	        let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? defaultTarget

	        let (resolvedTarget, resolveErr) = resolveFsTarget(
	            directPath: directPath,
	            pathClass: pathClass,
	            target: target,
	            requestedName: args.value("--name")
	        )
	        if let resolveErr { return resolveErr }
	        guard let resolvedTarget else {
	            return badRequest("internal: failed to resolve target path")
	        }

	        var details = baseDetails([
	            "probe_family": "fs_op",
	            "op": op.rawValue,
	            "path_mode": directPath != nil ? "direct_path" : "path_class",
	            "path_class": pathClass ?? "",
	            "target": target.rawValue,
	            "file_path": resolvedTarget.path,
	            "base_dir": resolvedTarget.baseDir ?? "",
	            "harness_dir": resolvedTarget.harnessDir ?? "",
            "run_dir": resolvedTarget.runDir ?? "",
        ])
        details["cleanup_mode"] = skipCleanup ? "disabled" : "default"

        let destructiveOps: Set<FsOp> = [.open_write, .create, .truncate, .rename, .unlink, .mkdir, .rmdir]
        if directPath != nil, destructiveOps.contains(op), !allowUnsafe, !isSafeWritePath(resolvedTarget.path) {
            return RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "",
                normalized_outcome: "bad_request",
                errno: nil,
                error: "refusing potentially destructive op=\(op.rawValue) on non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)",
                details: details,
                layer_attribution: nil
            )
        }

	        let started = Date()
	        var cleanupErrors: [String] = []

	        func finish(rc: Int, outcome: String, errno: Int?, error: String?) -> RunProbeResponse {
	            let elapsedMs = Int((Date().timeIntervalSince(started) * 1000.0).rounded())
	            details["duration_ms"] = "\(elapsedMs)"
	            if !cleanupErrors.isEmpty {
	                details["cleanup_error"] = cleanupErrors.joined(separator: "; ")
	            }
	            return RunProbeResponse(
	                rc: rc,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: errno,
	                error: error,
	                details: details,
	                layer_attribution: nil
	            )
	        }

        func bestEffortCleanup(_ roots: [String]) {
            if skipCleanup {
                details["cleanup_skipped"] = "true"
                return
            }
            for p in roots {
                do {
                    try FileManager.default.removeItem(atPath: p)
	                } catch {
	                    if let e = extractErrno(error), e == ENOENT { continue }
	                    cleanupErrors.append("\(p): \(error)")
	                }
	            }
	        }

	        func createParentDirsIfNeeded(for path: String) throws {
	            let url = URL(fileURLWithPath: path)
	            let parent = url.deletingLastPathComponent()
	            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
	        }

	        func writeSmallFile(path: String, bytes: Data) throws {
	            try createParentDirsIfNeeded(for: path)
	            try bytes.write(to: URL(fileURLWithPath: path), options: [.atomic])
	        }

	        let targetPath = resolvedTarget.path

	        do {
	            switch op {
	            case .stat:
	                var st = stat()
	                if lstat(targetPath, &st) != 0 {
	                    let e = errno
	                    let outcome = (e == ENOENT) ? "not_found" : ((e == EPERM || e == EACCES) ? "permission_error" : "stat_failed")
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                details["mode_octal"] = String(format: "0o%03o", st.st_mode & 0o777)
	                details["size_bytes"] = "\(st.st_size)"
	                return finish(rc: 0, outcome: "ok", errno: nil, error: nil)

	            case .realpath:
	                if let rp = realpathString(targetPath) {
	                    details["realpath"] = rp
	                    return finish(rc: 0, outcome: "ok", errno: nil, error: nil)
	                }
	                let e = errno
	                let outcome = (e == ENOENT) ? "not_found" : ((e == EPERM || e == EACCES) ? "permission_error" : "realpath_failed")
	                return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))

	            case .readlink:
	                var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
	                let n = targetPath.withCString { ptr in
	                    readlink(ptr, &buf, buf.count - 1)
	                }
	                if n < 0 {
	                    let e = errno
	                    let outcome = (e == ENOENT) ? "not_found" : ((e == EPERM || e == EACCES) ? "permission_error" : "readlink_failed")
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                buf[Int(n)] = 0
	                details["link_target"] = String(cString: buf)
	                return finish(rc: 0, outcome: "ok", errno: nil, error: nil)

	            case .listdir:
	                do {
	                    let entries = try FileManager.default.contentsOfDirectory(atPath: targetPath)
	                    details["entries_count"] = "\(entries.count)"
	                    let max = max(0, args.intValue("--max-entries") ?? 25)
	                    if max > 0 {
	                        details["entries"] = Array(entries.prefix(max)).joined(separator: "\n")
	                    }
	                    return finish(rc: 0, outcome: "ok", errno: nil, error: nil)
	                } catch {
	                    let e = extractErrno(error)
	                    let outcome: String
	                    if let e, e == ENOENT { outcome = "not_found" }
	                    else if isPermissionError(error) { outcome = "permission_error" }
	                    else { outcome = "listdir_failed" }
	                    return finish(rc: 1, outcome: outcome, errno: e, error: "\(error)")
	                }

	            case .mkdir:
	                try FileManager.default.createDirectory(atPath: targetPath, withIntermediateDirectories: true, attributes: nil)
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .rmdir:
	                try FileManager.default.removeItem(atPath: targetPath)
	                return finish(rc: 0, outcome: "ok", errno: nil, error: nil)

	            case .create:
	                try writeSmallFile(path: targetPath, bytes: Data("policy-witness fs_op create\n".utf8))
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .open_read:
	                if resolvedTarget.runDir != nil && !FileManager.default.fileExists(atPath: targetPath) {
	                    try writeSmallFile(path: targetPath, bytes: Data("x".utf8))
	                }
                let fd = targetPath.withCString { ptr in
                    pw_open(ptr, O_RDONLY, 0)
                }
	                if fd < 0 {
	                    let e = errno
	                    let outcome = (e == ENOENT) ? "not_found" : ((e == EPERM || e == EACCES) ? "permission_error" : "open_failed")
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                defer { close(fd) }
	                var b: UInt8 = 0
	                let r = read(fd, &b, 1)
	                if r < 0 {
	                    let e = errno
	                    let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "read_failed"
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                details["bytes_read"] = "\(r)"
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .open_write:
	                if resolvedTarget.runDir != nil {
	                    try createParentDirsIfNeeded(for: targetPath)
	                }
                let fd = targetPath.withCString { ptr in
                    pw_open(ptr, O_WRONLY | O_CREAT, Int32(S_IRUSR | S_IWUSR))
                }
	                if fd < 0 {
	                    let e = errno
	                    let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "open_failed"
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                defer { close(fd) }
	                let payload = Data("x".utf8)
	                let w = payload.withUnsafeBytes { ptr in
	                    write(fd, ptr.baseAddress, ptr.count)
	                }
	                if w < 0 {
	                    let e = errno
	                    let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "write_failed"
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                details["bytes_written"] = "\(w)"
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .truncate:
	                if resolvedTarget.runDir != nil && !FileManager.default.fileExists(atPath: targetPath) {
	                    try writeSmallFile(path: targetPath, bytes: Data("hello".utf8))
	                }
	                let truncRc = targetPath.withCString { ptr in
	                    truncate(ptr, 0)
	                }
	                if truncRc != 0 {
	                    let e = errno
	                    let outcome = (e == ENOENT) ? "not_found" : ((e == EPERM || e == EACCES) ? "permission_error" : "truncate_failed")
	                    return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	                }
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .rename:
	                let toPath: String
	                if directPath != nil {
                    guard let to = args.value("--to") ?? args.value("--to-path") else {
                        return badRequest("rename requires --to <path> (or --to-path)")
                    }
                    toPath = to
                    if !allowUnsafe, (!isSafeWritePath(targetPath) || !isSafeWritePath(toPath)) {
                        return badRequest("refusing rename outside harness paths (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)")
                    }
                } else {
	                    let runDir = resolvedTarget.runDir ?? URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
	                    let toName = args.value("--to-name") ?? "renamed-\(UUID().uuidString)"
	                    guard isSinglePathComponent(toName) else {
	                        return badRequest("invalid --to-name (must be a single path component)")
	                    }
	                    toPath = URL(fileURLWithPath: runDir).appendingPathComponent(toName).path
	                }
	                details["to_path"] = toPath

	                if resolvedTarget.runDir != nil && !FileManager.default.fileExists(atPath: targetPath) {
	                    try writeSmallFile(path: targetPath, bytes: Data("hello".utf8))
	                }

	                do {
	                    try FileManager.default.moveItem(atPath: targetPath, toPath: toPath)
	                } catch {
	                    let e = extractErrno(error)
	                    let outcome: String
	                    if let e, e == ENOENT { outcome = "not_found" }
	                    else if isPermissionError(error) { outcome = "permission_error" }
	                    else { outcome = "rename_failed" }
	                    return finish(rc: 1, outcome: outcome, errno: e, error: "\(error)")
	                }

	                bestEffortCleanup([toPath] + resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .unlink:
	                if resolvedTarget.runDir != nil && !FileManager.default.fileExists(atPath: targetPath) {
	                    try writeSmallFile(path: targetPath, bytes: Data("hello".utf8))
	                }
	                do {
	                    try FileManager.default.removeItem(atPath: targetPath)
	                } catch {
	                    let e = extractErrno(error)
	                    let outcome: String
	                    if let e, e == ENOENT { outcome = "not_found" }
	                    else if isPermissionError(error) { outcome = "permission_error" }
	                    else { outcome = "unlink_failed" }
	                    return finish(rc: 1, outcome: outcome, errno: e, error: "\(error)")
	                }
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))
	            }
	        } catch {
	            let e = extractErrno(error)
	            let outcome = isPermissionError(error) ? "permission_error" : "op_failed"
	            bestEffortCleanup(resolvedTarget.cleanupRoots)
	            return finish(rc: 1, outcome: outcome, errno: e, error: "\(error)")
	        }
	    }

	    private static func resolveFsTarget(directPath: String?, pathClass: String?, target: FsTarget, requestedName: String?) -> (FsResolvedTarget?, RunProbeResponse?) {
	        if let directPath {
	            guard directPath.hasPrefix("/") else {
	                return (nil, badRequest("--path must be absolute"))
	            }
	            return (FsResolvedTarget(path: directPath, baseDir: nil, harnessDir: nil, runDir: nil, cleanupRoots: []), nil)
	        }

	        guard let pathClass else {
	            return (nil, badRequest("internal: missing --path-class"))
	        }

	        let name = (requestedName?.isEmpty == false) ? requestedName! : "specimen-\(UUID().uuidString).txt"
	        if target == .specimen_file || target == .path {
	            guard isSinglePathComponent(name) else {
	                return (nil, badRequest("invalid --name (must be a single path component)"))
	            }
	        }

	        func normalizeDirPath(_ path: String) -> String {
	            var out = path
	            while out.hasSuffix("/") && out.count > 1 {
	                out.removeLast()
	            }
	            return out
	        }

	        func getenvString(_ key: String) -> String? {
	            key.withCString { keyPtr in
	                guard let raw = getenv(keyPtr) else { return nil }
	                return String(cString: raw)
	            }
	        }

	        if pathClass == "tmp" || pathClass == "home" {
	            let baseDirRaw: String
	            if pathClass == "tmp" {
	                baseDirRaw = getenvString("TMPDIR") ?? "/tmp"
	            } else {
	                baseDirRaw = getenvString("HOME") ?? ""
	            }
	            let baseDir = normalizeDirPath(baseDirRaw)
	            if baseDir.isEmpty || !baseDir.hasPrefix("/") {
	                return (nil, badRequest("invalid --path-class: \(pathClass) (failed to resolve base directory)"))
	            }

	            let harnessRoot = baseDir + "/policy-witness-harness"
	            let runDir = harnessRoot + "/fs-op/" + UUID().uuidString

	            let targetPath: String
	            switch target {
	            case .path:
	                targetPath = runDir + "/" + name
	            case .base:
	                targetPath = baseDir
	            case .harness_dir:
	                targetPath = harnessRoot
	            case .run_dir:
	                targetPath = runDir
	            case .specimen_file:
	                targetPath = runDir + "/" + name
	            }

	            return (
	                FsResolvedTarget(
	                    path: targetPath,
	                    baseDir: baseDir,
	                    harnessDir: harnessRoot,
	                    runDir: runDir,
	                    cleanupRoots: [runDir]
	                ),
	                nil
	            )
	        }

	        guard let baseURL = resolveStandardDirectory(pathClass) else {
	            return (nil, badRequest("invalid --path-class: \(pathClass) (expected: home|tmp|downloads|desktop|documents|app_support|caches)"))
	        }

	        let harnessRoot = baseURL.appendingPathComponent("policy-witness-harness", isDirectory: true)
	        let runDir = harnessRoot
	            .appendingPathComponent("fs-op", isDirectory: true)
	            .appendingPathComponent(UUID().uuidString, isDirectory: true)

	        let targetPath: String
	        switch target {
	        case .path:
	            targetPath = runDir.appendingPathComponent(name, isDirectory: false).path
	        case .base:
	            targetPath = baseURL.path
	        case .harness_dir:
	            targetPath = harnessRoot.path
	        case .run_dir:
	            targetPath = runDir.path
	        case .specimen_file:
	            targetPath = runDir.appendingPathComponent(name, isDirectory: false).path
	        }

	        return (
	            FsResolvedTarget(
	                path: targetPath,
	                baseDir: baseURL.path,
	                harnessDir: harnessRoot.path,
	                runDir: runDir.path,
	                cleanupRoots: [runDir.path]
	            ),
	            nil
	        )
	    }

	    private static func resolveStandardDirectory(_ cls: String) -> URL? {
	        switch cls {
	        case "home":
	            return FileManager.default.homeDirectoryForCurrentUser
	        case "tmp":
	            return FileManager.default.temporaryDirectory
	        case "downloads":
	            return FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
	        case "desktop":
	            return FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
	        case "documents":
	            return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
	        case "app_support":
	            return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
	        case "caches":
	            return FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
	        default:
	            return nil
	        }
	    }

			    private static func isSafeWritePath(_ path: String) -> Bool {
			        let candidates: [String?] = [
			            FileManager.default.temporaryDirectory.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
			            "/tmp/policy-witness-harness",
			            "/private/tmp/policy-witness-harness",
			            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
			            FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first?.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
			            FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first?.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
			            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
		            FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
	            FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.appendingPathComponent("policy-witness-harness", isDirectory: true).path,
	        ]

	        for root in candidates.compactMap({ $0 }) {
	            if path == root || path.hasPrefix(root + "/") {
	                return true
	            }
	        }
	        return false
	    }

	    private static func realpathString(_ path: String) -> String? {
	        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
	        return path.withCString { cstr in
	            guard realpath(cstr, &buf) != nil else {
	                return nil
	            }
	            return String(cString: buf)
	        }
	    }

	    // MARK: - net_op (parameterized network operations)

	    private enum NetOp: String, CaseIterable {
	        case tcp_connect
	        case udp_send
	        case getaddrinfo
	    }

	    private static func probeNetOp(argv: [String]) -> RunProbeResponse {
	        pw_probe_net_op_marker()
	        let args = Argv(argv)
	        let expectedOps = NetOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let opStr = args.value("--op"), let op = NetOp(rawValue: opStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }

	        let host = args.value("--host")
	        let portStr = args.value("--port")

	        var details = baseDetails([
	            "probe_family": "net_op",
	            "op": op.rawValue,
	            "host": host ?? "",
	            "port": portStr ?? "",
	        ])

	        switch op {
	        case .getaddrinfo:
	            guard let host, !host.isEmpty else {
	                return badRequest("missing required --host")
	            }

	            var hints = addrinfo(
	                ai_flags: args.has("--numeric") ? AI_NUMERICHOST : 0,
	                ai_family: AF_UNSPEC,
	                ai_socktype: 0,
	                ai_protocol: 0,
	                ai_addrlen: 0,
	                ai_canonname: nil,
	                ai_addr: nil,
	                ai_next: nil
	            )
	            var res: UnsafeMutablePointer<addrinfo>?
            let rc = pw_getaddrinfo(host, nil, &hints, &res)
	            if rc != 0 {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "getaddrinfo_failed",
	                    errno: nil,
	                    error: String(cString: gai_strerror(rc)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            defer { freeaddrinfo(res) }

	            var count = 0
	            var families: [String] = []
	            var cur = res
	            while cur != nil, count < 32 {
	                count += 1
	                let fam = cur!.pointee.ai_family
	                if fam == AF_INET { families.append("inet") }
	                else if fam == AF_INET6 { families.append("inet6") }
	                else { families.append("\(fam)") }
	                cur = cur!.pointee.ai_next
	            }

	            details["addr_count"] = "\(count)"
	            details["families"] = families.joined(separator: ",")
	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "ok",
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

	        case .tcp_connect, .udp_send:
	            guard let host, !host.isEmpty else {
	                return badRequest("missing required --host")
	            }
	            guard let portStr, let port = Int(portStr), (1...65535).contains(port) else {
	                return badRequest("missing/invalid --port (expected 1..65535)")
	            }

	            let socktype = (op == .tcp_connect) ? SOCK_STREAM : SOCK_DGRAM
	            var hints = addrinfo(
	                ai_flags: args.has("--numeric") ? AI_NUMERICHOST : 0,
	                ai_family: AF_UNSPEC,
	                ai_socktype: socktype,
	                ai_protocol: 0,
	                ai_addrlen: 0,
	                ai_canonname: nil,
	                ai_addr: nil,
	                ai_next: nil
	            )
	            var res: UnsafeMutablePointer<addrinfo>?
            let gai = pw_getaddrinfo(host, String(port), &hints, &res)
	            if gai != 0 {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "getaddrinfo_failed",
	                    errno: nil,
	                    error: String(cString: gai_strerror(gai)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            defer { freeaddrinfo(res) }

	            var attempts = 0
	            var lastErrno: Int32 = 0
	            var cur = res
	            while cur != nil {
	                attempts += 1
	                let ai = cur!.pointee
	                let fd = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol)
	                if fd < 0 {
	                    lastErrno = errno
	                    cur = ai.ai_next
	                    continue
	                }
	                defer { close(fd) }

	                if op == .tcp_connect {
                    if pw_connect(fd, ai.ai_addr, ai.ai_addrlen) == 0 {
	                        details["attempts"] = "\(attempts)"
	                        details["connect"] = "ok"
	                        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: "ok", errno: nil, error: nil, details: details, layer_attribution: nil)
	                    }
	                    lastErrno = errno
	                } else {
	                    var b: UInt8 = 0x58
                    let sent = withUnsafePointer(to: &b) { ptr in
                        pw_sendto(fd, ptr, 1, 0, ai.ai_addr, ai.ai_addrlen)
                    }
	                    if sent == 1 {
	                        details["attempts"] = "\(attempts)"
	                        details["bytes_sent"] = "1"
	                        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: "ok", errno: nil, error: nil, details: details, layer_attribution: nil)
	                    }
	                    lastErrno = errno
	                }

	                cur = ai.ai_next
	            }

	            details["attempts"] = "\(attempts)"
	            let outcome: String
	            switch lastErrno {
	            case EPERM, EACCES:
	                outcome = "permission_error"
	            case ECONNREFUSED:
	                outcome = "connection_refused"
	            case ETIMEDOUT:
	                outcome = "timed_out"
	            case EHOSTUNREACH, ENETUNREACH:
	                outcome = "unreachable"
	            default:
	                outcome = (op == .tcp_connect) ? "connect_failed" : "send_failed"
	            }

	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: Int(lastErrno),
	                error: String(cString: strerror(lastErrno)),
	                details: details,
	                layer_attribution: nil
	            )
	        }
	    }

	    // MARK: - dlopen_external (library validation / injection surface)

	    private static func probeDlopenExternal(argv: [String]) -> RunProbeResponse {
	        pw_probe_dlopen_external_marker()
	        let args = Argv(argv)
	        let path = args.value("--path") ?? ProcessInfo.processInfo.environment["PW_DLOPEN_PATH"]
	        guard let path, path.hasPrefix("/") else {
	            return badRequest("missing/invalid --path (expected absolute path or PW_DLOPEN_PATH)")
	        }

	        var details = baseDetails([
	            "probe_family": "dlopen_external",
	            "dlopen_path": path,
	            "dlopen_mode": "RTLD_NOW",
	            "has_disable_library_validation": entitlementBool("com.apple.security.cs.disable-library-validation") ? "true" : "false",
	            "has_allow_dyld_env": entitlementBool("com.apple.security.cs.allow-dyld-environment-variables") ? "true" : "false",
	        ])

	        if !FileManager.default.fileExists(atPath: path) {
	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "not_found",
	                errno: nil,
	                error: "file not found",
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        dlerror()
	        let handle = path.withCString { ptr in
	            pw_dlopen(ptr, Int32(RTLD_NOW))
	        }
	        if let handle {
	            dlclose(handle)
	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "ok",
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        let errPtr = dlerror()
	        let errStr = errPtr.map { String(cString: $0) } ?? "dlopen failed (no error string)"
	        details["dlopen_error"] = errStr
	        return RunProbeResponse(
	            rc: 1,
	            stdout: "",
	            stderr: "",
	            normalized_outcome: "dlopen_failed",
	            errno: nil,
	            error: errStr,
	            details: details,
	            layer_attribution: nil
	        )
	    }

	    // MARK: - jit_map_jit (MAP_JIT probe)

	    private static func probeJitMapJit(argv: [String]) -> RunProbeResponse {
	        pw_probe_jit_map_jit_marker()
	        let args = Argv(argv)
	        let size = args.intValue("--size") ?? 16384
	        guard size > 0 else {
	            return badRequest("invalid --size (expected > 0)")
	        }

	        var details = baseDetails([
	            "probe_family": "jit_map_jit",
	            "size": "\(size)",
	            "has_allow_jit": entitlementBool("com.apple.security.cs.allow-jit") ? "true" : "false",
	        ])

	        let flags = MAP_PRIVATE | MAP_ANON | MAP_JIT
	        let prot = PROT_READ | PROT_WRITE
	        guard let ptr = pw_mmap(nil, size, prot, flags, -1, 0), ptr != MAP_FAILED else {
	            let e = errno
	            let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "mmap_failed"
	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: Int(e),
	                error: String(cString: strerror(e)),
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        let addr = UInt64(UInt(bitPattern: ptr))
	        details["mmap_addr"] = String(format: "0x%llx", addr)

	        pthread_jit_write_protect_np(0)
	        pthread_jit_write_protect_np(1)
	        details["jit_write_protect_off_rc"] = "called"
	        details["jit_write_protect_on_rc"] = "called"

	        var outcome = "ok"
	        let unmapRc = pw_munmap(ptr, size)
	        if unmapRc != 0 {
	            outcome = "ok_unmap_failed"
	            details["munmap_error"] = String(cString: strerror(errno))
	        }

	        return RunProbeResponse(
	            rc: 0,
	            stdout: "",
	            stderr: "",
	            normalized_outcome: outcome,
	            errno: nil,
	            error: nil,
	            details: details,
	            layer_attribution: nil
	        )
	    }

	    // MARK: - jit_rwx_legacy (RWX mmap probe)

	    private static func probeJitRwxLegacy(argv: [String]) -> RunProbeResponse {
	        pw_probe_jit_rwx_legacy_marker()
	        let args = Argv(argv)
	        let size = args.intValue("--size") ?? 16384
	        guard size > 0 else {
	            return badRequest("invalid --size (expected > 0)")
	        }

	        var details = baseDetails([
	            "probe_family": "jit_rwx_legacy",
	            "size": "\(size)",
	            "has_allow_unsigned_exec_mem": entitlementBool("com.apple.security.cs.allow-unsigned-executable-memory") ? "true" : "false",
	        ])

	        let flags = MAP_PRIVATE | MAP_ANON
	        let prot = PROT_READ | PROT_WRITE | PROT_EXEC
	        guard let ptr = pw_mmap(nil, size, prot, flags, -1, 0), ptr != MAP_FAILED else {
	            let e = errno
	            let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "mmap_failed"
	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: Int(e),
	                error: String(cString: strerror(e)),
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        let addr = UInt64(UInt(bitPattern: ptr))
	        details["mmap_addr"] = String(format: "0x%llx", addr)

	        var outcome = "ok"
	        let unmapRc = pw_munmap(ptr, size)
	        if unmapRc != 0 {
	            outcome = "ok_unmap_failed"
	            details["munmap_error"] = String(cString: strerror(errno))
	        }

	        return RunProbeResponse(
	            rc: 0,
	            stdout: "",
	            stderr: "",
	            normalized_outcome: outcome,
	            errno: nil,
	            error: nil,
	            details: details,
	            layer_attribution: nil
	        )
	    }

	    // MARK: - bookmark_op (security-scoped bookmark-driven fs ops)

	    private static func probeBookmarkOp(argv: [String]) -> RunProbeResponse {
	        let args = Argv(argv)
	        let b64: String?
	        if let v = args.value("--bookmark-b64") {
	            b64 = v
	        } else if let p = args.value("--bookmark-path") {
	            b64 = (try? String(contentsOfFile: p, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
	        } else {
	            b64 = nil
	        }

	        guard let b64, let bookmarkData = Data(base64Encoded: b64) else {
	            return badRequest("missing/invalid --bookmark-b64 (or --bookmark-path)")
	        }

	        let fsOpStr = args.value("--op") ?? "stat"
	        let expectedOps = FsOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let fsOp = FsOp(rawValue: fsOpStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }

	        var isStale = false
	        let resolvedURL: URL
        do {
            resolvedURL = try URL(
                resolvingBookmarkData: bookmarkData,
                options: [.withSecurityScope, .withoutUI],
                relativeTo: nil,
                bookmarkDataIsStale: &isStale
            )
        } catch {
            let hint = bookmarkEntitlementHint(error)
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "bookmark_resolve_failed",
                errno: extractErrno(error),
                error: "\(error)",
                details: baseDetails([
                    "probe_family": "bookmark_op",
                    "op": fsOp.rawValue,
                    "bookmark_is_stale": isStale ? "true" : "false",
                ]),
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) }
            )
        }

	        let startAccessing = resolvedURL.startAccessingSecurityScopedResource()
	        defer { resolvedURL.stopAccessingSecurityScopedResource() }

	        var targetURL = resolvedURL
	        if let rel = args.value("--relative"), !rel.isEmpty {
	            guard let appended = safeAppendRelativePath(base: resolvedURL, relative: rel) else {
	                return badRequest("invalid --relative (must be a safe relative path with no traversal)")
	            }
	            targetURL = appended
	        }

	        let syntheticArgv = synthesizeFsOpArgv(original: argv, fsOp: fsOp, targetPath: targetURL.path)
	        let resp = probeFsOp(argv: syntheticArgv)

	        var merged = resp.details ?? [:]
	        merged["probe_family"] = "bookmark_op"
	        merged["bookmark_is_stale"] = isStale ? "true" : "false"
	        merged["bookmark_start_accessing"] = startAccessing ? "true" : "false"
	        merged["bookmark_resolved_path"] = resolvedURL.path
	        merged["bookmark_target_path"] = targetURL.path
	        merged["file_path"] = targetURL.path

	        return RunProbeResponse(
	            rc: resp.rc,
	            stdout: resp.stdout,
	            stderr: resp.stderr,
	            normalized_outcome: resp.normalized_outcome,
	            errno: resp.errno,
	            error: resp.error,
	            details: merged,
	            layer_attribution: resp.layer_attribution
	        )
	    }

    private static func safeAppendRelativePath(base: URL, relative: String) -> URL? {
        guard isSafeRelativePath(relative) else {
            return nil
        }
        let comps = relative.split(separator: "/").map(String.init)
        var out = base
        for c in comps {
            out.appendPathComponent(c)
        }
        return out
    }

    private static func isSafeRelativePath(_ relative: String) -> Bool {
        if relative.hasPrefix("/") { return false }
        let comps = relative.split(separator: "/").map(String.init)
        if comps.isEmpty { return false }
        for c in comps {
            if c.isEmpty || c == "." || c == ".." { return false }
            if c.contains("\\") { return false }
        }
        return true
    }

    private static func synthesizeFsOpArgv(original: [String], fsOp: FsOp, targetPath: String) -> [String] {
        var out: [String] = []
        var i = 0
        while i < original.count {
	            let a = original[i]
	            if a == "--bookmark-b64" || a == "--bookmark-path" || a == "--relative" {
	                i += 2
	                continue
	            }
	            out.append(a)
	            i += 1
	        }

	        // Remove any previous --path and replace with our resolved target.
	        if let idx = out.firstIndex(of: "--path") {
	            if idx + 1 < out.count {
	                out.removeSubrange(idx ..< min(idx + 2, out.count))
	            } else {
	                out.remove(at: idx)
	            }
	        }

	        // Force direct-path mode for fs_op.
	        if let idx = out.firstIndex(of: "--path-class") {
	            if idx + 1 < out.count {
	                out.removeSubrange(idx ..< min(idx + 2, out.count))
	            } else {
	                out.remove(at: idx)
	            }
	        }
	        if let idx = out.firstIndex(of: "--target") {
	            if idx + 1 < out.count {
	                out.removeSubrange(idx ..< min(idx + 2, out.count))
	            } else {
	                out.remove(at: idx)
	            }
	        }

        if out.contains("--op") == false {
            out.append(contentsOf: ["--op", fsOp.rawValue])
        }
        out.append(contentsOf: ["--path", targetPath])
        return out
    }

    private static func bookmarkEntitlementHint(_ error: Error) -> String? {
        let ns = error as NSError
        var parts: [String] = []
        if let debug = ns.userInfo[NSDebugDescriptionErrorKey] as? String {
            parts.append(debug)
        }
        parts.append(ns.localizedDescription)
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
            if let debug = underlying.userInfo[NSDebugDescriptionErrorKey] as? String {
                parts.append(debug)
            }
            parts.append(underlying.localizedDescription)
        }
        let haystack = parts.joined(separator: " ").lowercased()
        if haystack.contains("scopedbookmarksagent") || haystack.contains("scoped bookmarks agent") || haystack.contains("com.apple.scopedbookmarksagent.xpc") {
            return "entitlement_missing_bookmarks_app_scope"
        }
        return nil
    }

    private static func probeBookmarkMake(argv: [String]) -> RunProbeResponse {
        let args = Argv(argv)
        guard let path = args.value("--path"), path.hasPrefix("/") else {
            return badRequest("bookmark_make requires --path <absolute-path>")
        }

	        let url = URL(fileURLWithPath: path)
	        let requireExists = !args.has("--allow-missing")
	        if requireExists, !FileManager.default.fileExists(atPath: path) {
	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "not_found",
	                errno: Int(ENOENT),
	                error: "file not found",
	                details: baseDetails([
	                    "probe_family": "bookmark_make",
	                    "file_path": path,
	                ]),
	                layer_attribution: nil
	            )
	        }

	        let useSecurityScope = !args.has("--no-security-scope")
	        var options: URL.BookmarkCreationOptions = []
	        if useSecurityScope {
	            options.insert(.withSecurityScope)
	        }
	        if args.has("--read-only") {
	            options.insert(.securityScopeAllowOnlyReadAccess)
	        }

	        do {
	            let data = try url.bookmarkData(options: options, includingResourceValuesForKeys: nil, relativeTo: nil)
	            let b64 = data.base64EncodedString()
	            return RunProbeResponse(
	                rc: 0,
	                stdout: b64,
	                stderr: "",
	                normalized_outcome: "ok",
	                errno: nil,
	                error: nil,
	                details: baseDetails([
	                    "probe_family": "bookmark_make",
	                    "file_path": path,
	                    "bookmark_len": "\(data.count)",
	                    "security_scope": useSecurityScope ? "true" : "false",
	                    "read_only": args.has("--read-only") ? "true" : "false",
	                ]),
	                layer_attribution: nil
	            )
        } catch {
            let e = extractErrno(error)
            let outcome = isPermissionError(error) ? "permission_error" : "bookmark_make_failed"
            let hint = useSecurityScope ? bookmarkEntitlementHint(error) : nil
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: outcome,
                errno: e,
                error: "\(error)",
                details: baseDetails([
                    "probe_family": "bookmark_make",
                    "file_path": path,
                    "security_scope": useSecurityScope ? "true" : "false",
                    "read_only": args.has("--read-only") ? "true" : "false",
                ]),
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) }
            )
        }
    }

    // MARK: - bookmark_roundtrip (make + resolve + fs_op)

    private static func probeBookmarkRoundtrip(argv: [String]) -> RunProbeResponse {
        let args = Argv(argv)
        guard let path = args.value("--path"), path.hasPrefix("/") else {
            return badRequest("bookmark_roundtrip requires --path <absolute-path>")
        }

        let fsOpStr = args.value("--op") ?? "stat"
        let expectedOps = FsOp.allCases.map(\.rawValue).joined(separator: "|")
        guard let fsOp = FsOp(rawValue: fsOpStr) else {
            return badRequest("missing/invalid --op (expected: \(expectedOps))")
        }

        if let rel = args.value("--relative"), !rel.isEmpty, !isSafeRelativePath(rel) {
            return badRequest("invalid --relative (must be a safe relative path with no traversal)")
        }

        let url = URL(fileURLWithPath: path)
        let requireExists = !args.has("--allow-missing")
        if requireExists, !FileManager.default.fileExists(atPath: path) {
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "not_found",
                errno: Int(ENOENT),
                error: "file not found",
                details: baseDetails([
                    "probe_family": "bookmark_roundtrip",
                    "file_path": path,
                ]),
                layer_attribution: nil
            )
        }

        let useSecurityScope = !args.has("--no-security-scope")
        var options: URL.BookmarkCreationOptions = []
        if useSecurityScope {
            options.insert(.withSecurityScope)
        }
        if args.has("--read-only") {
            options.insert(.securityScopeAllowOnlyReadAccess)
        }

        let bookmarkData: Data
        do {
            bookmarkData = try url.bookmarkData(options: options, includingResourceValuesForKeys: nil, relativeTo: nil)
        } catch {
            let e = extractErrno(error)
            let outcome = isPermissionError(error) ? "permission_error" : "bookmark_make_failed"
            let hint = useSecurityScope ? bookmarkEntitlementHint(error) : nil
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: outcome,
                errno: e,
                error: "\(error)",
                details: baseDetails([
                    "probe_family": "bookmark_roundtrip",
                    "file_path": path,
                    "security_scope": useSecurityScope ? "true" : "false",
                    "read_only": args.has("--read-only") ? "true" : "false",
                ]),
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) }
            )
        }

        let b64 = bookmarkData.base64EncodedString()
        var isStale = false
        let resolvedURL: URL
        do {
            resolvedURL = try URL(
                resolvingBookmarkData: bookmarkData,
                options: [.withSecurityScope, .withoutUI],
                relativeTo: nil,
                bookmarkDataIsStale: &isStale
            )
        } catch {
            let hint = bookmarkEntitlementHint(error)
            return RunProbeResponse(
                rc: 1,
                stdout: b64,
                stderr: "",
                normalized_outcome: "bookmark_resolve_failed",
                errno: extractErrno(error),
                error: "\(error)",
                details: baseDetails([
                    "probe_family": "bookmark_roundtrip",
                    "file_path": path,
                    "bookmark_is_stale": isStale ? "true" : "false",
                    "bookmark_len": "\(bookmarkData.count)",
                    "security_scope": useSecurityScope ? "true" : "false",
                    "read_only": args.has("--read-only") ? "true" : "false",
                ]),
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) }
            )
        }

        let startAccessing = resolvedURL.startAccessingSecurityScopedResource()
        defer { resolvedURL.stopAccessingSecurityScopedResource() }

        var targetURL = resolvedURL
        if let rel = args.value("--relative"), !rel.isEmpty {
            guard let appended = safeAppendRelativePath(base: resolvedURL, relative: rel) else {
                return badRequest("invalid --relative (must be a safe relative path with no traversal)")
            }
            targetURL = appended
        }

        let syntheticArgv = synthesizeFsOpArgv(original: argv, fsOp: fsOp, targetPath: targetURL.path)
        let resp = probeFsOp(argv: syntheticArgv)

        var merged = resp.details ?? [:]
        merged["probe_family"] = "bookmark_roundtrip"
        merged["bookmark_is_stale"] = isStale ? "true" : "false"
        merged["bookmark_start_accessing"] = startAccessing ? "true" : "false"
        merged["bookmark_resolved_path"] = resolvedURL.path
        merged["bookmark_target_path"] = targetURL.path
        merged["bookmark_len"] = "\(bookmarkData.count)"
        merged["security_scope"] = useSecurityScope ? "true" : "false"
        merged["read_only"] = args.has("--read-only") ? "true" : "false"
        merged["file_path"] = targetURL.path

        return RunProbeResponse(
            rc: resp.rc,
            stdout: b64,
            stderr: resp.stderr,
            normalized_outcome: resp.normalized_outcome,
            errno: resp.errno,
            error: resp.error,
            details: merged,
            layer_attribution: resp.layer_attribution
        )
    }

	    // MARK: - fs_coordinated_op (NSFileCoordinator mediated fs ops)

	    private enum FsCoordinatedOp: String, CaseIterable {
	        case read
	        case write
	    }

	    private static func probeFsCoordinatedOp(argv: [String]) -> RunProbeResponse {
	        let args = Argv(argv)
	        let expectedOps = FsCoordinatedOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let opStr = args.value("--op"), let op = FsCoordinatedOp(rawValue: opStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }

	        let allowUnsafe = args.has("--allow-unsafe-path")
	        let directPath = args.value("--path")
	        let pathClass = args.value("--path-class")
	        if (directPath == nil) == (pathClass == nil) {
	            return badRequest("provide exactly one of --path or --path-class")
	        }

	        let targetStr = args.value("--target")
	        let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? .specimen_file

	        let (resolvedTarget, resolveErr) = resolveFsTarget(
	            directPath: directPath,
	            pathClass: pathClass,
	            target: target,
	            requestedName: args.value("--name")
	        )
	        if let resolveErr { return resolveErr }
	        guard let resolvedTarget else {
	            return badRequest("internal: failed to resolve target path")
	        }

        let targetPath = resolvedTarget.path
        if op == .write, directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
            return badRequest("refusing potentially destructive coordinated write on non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)")
        }

	        var details = baseDetails([
	            "probe_family": "fs_coordinated_op",
	            "op": op.rawValue,
	            "path_mode": directPath != nil ? "direct_path" : "path_class",
	            "path_class": pathClass ?? "",
	            "target": target.rawValue,
	            "file_path": targetPath,
	            "base_dir": resolvedTarget.baseDir ?? "",
	            "harness_dir": resolvedTarget.harnessDir ?? "",
	            "run_dir": resolvedTarget.runDir ?? "",
	        ])

	        var cleanupErrors: [String] = []
	        func bestEffortCleanup(_ roots: [String]) {
	            for p in roots {
	                do {
	                    try FileManager.default.removeItem(atPath: p)
	                } catch {
	                    if let e = extractErrno(error), e == ENOENT { continue }
	                    cleanupErrors.append("\(p): \(error)")
	                }
	            }
	        }

	        if resolvedTarget.runDir != nil, op == .read, !FileManager.default.fileExists(atPath: targetPath) {
	            // Ensure a file exists so the coordinated read exercises I/O rather than ENOENT.
	            do {
	                let url = URL(fileURLWithPath: targetPath)
	                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: nil)
	                try Data("x".utf8).write(to: url, options: [.atomic])
	            } catch {
	                let e = extractErrno(error)
	                let outcome = isPermissionError(error) ? "permission_error" : "setup_failed"
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                details["cleanup_error"] = cleanupErrors.joined(separator: "; ")
	                return RunProbeResponse(rc: 1, stdout: "", stderr: "", normalized_outcome: outcome, errno: e, error: "\(error)", details: details, layer_attribution: nil)
	            }
	        }

	        let coordinator = NSFileCoordinator(filePresenter: nil)
	        let url = URL(fileURLWithPath: targetPath)

	        var coordError: NSError?
	        var opError: Error?
	        var bytesRead: Int?
	        var bytesWritten: Int?

	        switch op {
	        case .read:
	            coordinator.coordinate(readingItemAt: url, options: [], error: &coordError) { newURL in
	                do {
	                    let fh = try FileHandle(forReadingFrom: newURL)
	                    defer { try? fh.close() }
	                    let data = try fh.read(upToCount: 1) ?? Data()
	                    bytesRead = data.count
	                } catch {
	                    opError = error
	                }
	            }
	        case .write:
	            coordinator.coordinate(writingItemAt: url, options: [.forReplacing], error: &coordError) { newURL in
	                do {
	                    try FileManager.default.createDirectory(at: newURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: nil)
	                    let data = Data("x".utf8)
	                    try data.write(to: newURL, options: [.atomic])
	                    bytesWritten = data.count
	                } catch {
	                    opError = error
	                }
	            }
	        }

	        if let coordError {
	            let e = extractErrno(coordError)
	            let outcome: String
	            if let e, e == ENOENT { outcome = "not_found" }
	            else if isPermissionError(coordError) { outcome = "permission_error" }
	            else { outcome = "coordination_failed" }
	            bestEffortCleanup(resolvedTarget.cleanupRoots)
	            if !cleanupErrors.isEmpty { details["cleanup_error"] = cleanupErrors.joined(separator: "; ") }
	            return RunProbeResponse(rc: 1, stdout: "", stderr: "", normalized_outcome: outcome, errno: e, error: "\(coordError)", details: details, layer_attribution: nil)
	        }
	        if let opError {
	            let e = extractErrno(opError)
	            let outcome: String
	            if let e, e == ENOENT { outcome = "not_found" }
	            else if isPermissionError(opError) { outcome = "permission_error" }
	            else { outcome = "op_failed" }
	            bestEffortCleanup(resolvedTarget.cleanupRoots)
	            if !cleanupErrors.isEmpty { details["cleanup_error"] = cleanupErrors.joined(separator: "; ") }
	            return RunProbeResponse(rc: 1, stdout: "", stderr: "", normalized_outcome: outcome, errno: e, error: "\(opError)", details: details, layer_attribution: nil)
	        }

	        if let bytesRead { details["bytes_read"] = "\(bytesRead)" }
	        if let bytesWritten { details["bytes_written"] = "\(bytesWritten)" }
	        bestEffortCleanup(resolvedTarget.cleanupRoots)
	        if !cleanupErrors.isEmpty { details["cleanup_error"] = cleanupErrors.joined(separator: "; ") }
	        let outcome = cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed"
	        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: outcome, errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "), details: details, layer_attribution: nil)
	    }

	    // MARK: - capabilities_snapshot (observer)

	    private static func probeCapabilitiesSnapshot() -> RunProbeResponse {
	        let bundleId = Bundle.main.bundleIdentifier ?? ""
	        let prefsPath = FileManager.default.homeDirectoryForCurrentUser
	            .appendingPathComponent("Library/Preferences", isDirectory: true)
	            .appendingPathComponent("\(bundleId).plist", isDirectory: false)
	            .path

	        let details = baseDetails([
	            "probe_family": "capabilities_snapshot",
	            "has_app_sandbox": entitlementBool("com.apple.security.app-sandbox") ? "true" : "false",
	            "has_get_task_allow": entitlementBool("com.apple.security.get-task-allow") ? "true" : "false",
	            "has_disable_library_validation": entitlementBool("com.apple.security.cs.disable-library-validation") ? "true" : "false",
	            "has_allow_dyld_env": entitlementBool("com.apple.security.cs.allow-dyld-environment-variables") ? "true" : "false",
	            "has_allow_jit": entitlementBool("com.apple.security.cs.allow-jit") ? "true" : "false",
	            "has_allow_unsigned_exec_mem": entitlementBool("com.apple.security.cs.allow-unsigned-executable-memory") ? "true" : "false",
	            "has_network_client": entitlementBool("com.apple.security.network.client") ? "true" : "false",
	            "has_downloads_rw": entitlementBool("com.apple.security.files.downloads.read-write") ? "true" : "false",
	            "has_bookmarks_app_scope": entitlementBool("com.apple.security.files.bookmarks.app-scope") ? "true" : "false",
	            "has_user_selected_read_only": entitlementBool("com.apple.security.files.user-selected.read-only") ? "true" : "false",
	            "has_user_selected_read_write": entitlementBool("com.apple.security.files.user-selected.read-write") ? "true" : "false",
	            "has_user_selected_executable": entitlementBool("com.apple.security.files.user-selected.executable") ? "true" : "false",
	            "downloads_dir": FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first?.path ?? "",
	            "desktop_dir": FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first?.path ?? "",
	            "documents_dir": FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? "",
	            "app_support_dir": FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?.path ?? "",
	            "caches_dir": FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.path ?? "",
	            "prefs_path_guess": prefsPath,
	            "file_path": prefsPath,
	        ])

	        let looksContainerized = (details["home_dir"] ?? "").contains("/Library/Containers/")
	        let worldShapeChange = looksContainerized ? "home_containerized" : nil

	        return RunProbeResponse(
	            rc: 0,
	            stdout: "",
	            stderr: "",
	            normalized_outcome: "ok",
	            errno: nil,
	            error: nil,
	            details: details,
	            layer_attribution: LayerAttribution(world_shape_change: worldShapeChange)
	        )
	    }

	    // MARK: - sandbox_check (libsystem_sandbox callsite)

	    private typealias SandboxCheckNoArgFn = @convention(c) (pid_t, UnsafePointer<CChar>, Int32) -> Int32
	    private typealias SandboxCheckPathFn = @convention(c) (pid_t, UnsafePointer<CChar>, Int32, UnsafePointer<CChar>) -> Int32

	    private static func resolveSandboxCheckSymbol() -> UnsafeMutableRawPointer? {
	        // dlfcn's RTLD_DEFAULT is (void*)-2 on Darwin; use it directly.
	        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
	        return "sandbox_check".withCString { sym in
	            dlsym(rtldDefault, sym)
	        }
	    }

	    private static func probeSandboxCheck(argv: [String]) -> RunProbeResponse {
	        pw_probe_sandbox_check_marker()
	        let args = Argv(argv)

	        guard let operation = args.value("--operation"), !operation.isEmpty else {
	            return badRequest("missing --operation <sandbox-op>")
	        }

	        let path = args.value("--path")
	        let repeatCount = max(1, min(200, args.intValue("--repeat") ?? 1))

	        guard let symbol = resolveSandboxCheckSymbol() else {
	            return RunProbeResponse(
	                rc: 1,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "symbol_missing",
	                errno: nil,
	                error: "sandbox_check symbol not found via dlsym(RTLD_DEFAULT, \"sandbox_check\")",
	                details: baseDetails([
	                    "probe_family": "sandbox_check",
	                    "sandbox_check_operation": operation,
	                    "sandbox_check_path": path ?? "",
	                ]),
	                layer_attribution: nil
	            )
	        }

	        var details = baseDetails([
	            "probe_family": "sandbox_check",
	            "sandbox_check_operation": operation,
	            "sandbox_check_path": path ?? "",
	            "sandbox_check_repeat": "\(repeatCount)",
	        ])

	        var lastRc: Int32 = -1
	        var samples: [String] = []

	        for i in 0..<repeatCount {
	            let rc: Int32 = operation.withCString { opPtr in
	                if let path, !path.isEmpty {
	                    // Best-effort: assume the traditional "path" filter type is 1.
	                    let fn = unsafeBitCast(symbol, to: SandboxCheckPathFn.self)
	                    return path.withCString { pathPtr in
	                        fn(getpid(), opPtr, 1, pathPtr)
	                    }
	                }
	                let fn = unsafeBitCast(symbol, to: SandboxCheckNoArgFn.self)
	                return fn(getpid(), opPtr, 0)
	            }
	            lastRc = rc
	            if samples.count < 25 {
	                samples.append("\(i):\(rc)")
	            }
	        }

	        details["sandbox_check_rc"] = "\(lastRc)"
	        details["sandbox_check_rc_samples"] = samples.joined(separator: " ")
	        details["sandbox_check_filter"] = (path?.isEmpty == false) ? "path(guessed_type=1)" : "none(type=0)"

	        let outcome: String
	        if lastRc == 0 {
	            outcome = "allow"
	        } else if lastRc == 1 {
	            outcome = "deny"
	        } else {
	            outcome = "rc_nonstandard"
	        }

	        return RunProbeResponse(
	            rc: 0,
	            stdout: "",
	            stderr: "",
	            normalized_outcome: outcome,
	            errno: nil,
	            error: nil,
	            details: details,
	            layer_attribution: nil
	        )
	    }

	    // MARK: - sandbox_extension (issue/consume/release)

		    private enum SandboxExtensionOp: String, CaseIterable {
		        case issue_file
		        case issue_file_to_pid
		        case issue_extension
		        case issue_fs_extension
		        case issue_fs_rw_extension
		        case consume
		        case release
		        case release_file
		        case update_file
		        case update_file_rename_delta
		        case update_file_by_fileid
		        case update_file_by_fileid_sweep
		        case update_file_by_fileid_delta
		    }

		    private typealias SandboxExtensionIssueFileFn = @convention(c) (UnsafePointer<CChar>, UnsafePointer<CChar>, Int32) -> UnsafeMutablePointer<CChar>?
		    private typealias SandboxExtensionIssueFileToPidFn = @convention(c) (UnsafePointer<CChar>, UnsafePointer<CChar>, Int32, pid_t) -> UnsafeMutablePointer<CChar>?
		    private typealias SandboxIssueExtensionFn = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32
		    private typealias SandboxIssueFsExtensionFn = @convention(c) (UnsafePointer<CChar>, UInt64, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32
		    private typealias SandboxIssueFsRwExtensionFn = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32
		    private typealias SandboxExtensionConsumeHandleFn = @convention(c) (UnsafePointer<CChar>) -> Int64
		    private typealias SandboxExtensionReleaseHandleFn = @convention(c) (Int64) -> Int32
		    private typealias SandboxExtensionConsumeFn = @convention(c) (UnsafePointer<CChar>) -> Int32
		    private typealias SandboxExtensionReleaseFn = @convention(c) (UnsafePointer<CChar>) -> Int32
		    private typealias SandboxExtensionConsumeFlagsFn = @convention(c) (UnsafePointer<CChar>, Int32) -> Int32
		    private typealias SandboxExtensionReleaseFlagsFn = @convention(c) (UnsafePointer<CChar>, Int32) -> Int32
		    private typealias SandboxExtensionUpdateFileFn = @convention(c) (UnsafePointer<CChar>, UInt32) -> Int32
		    private typealias SandboxExtensionUpdateFileByFileidFn = @convention(c) (UnsafePointer<CChar>, UInt64, UInt32) -> Int32
		    private typealias SandboxExtensionUpdateFileByFileidAltFn = @convention(c) (UInt64, UnsafePointer<CChar>, UInt32) -> Int32
		    private typealias SandboxExtensionUpdateFileByFileidPtrFn = @convention(c) (UnsafePointer<UInt64>, UnsafePointer<CChar>?, UInt32) -> Int32
	    private typealias SandboxExtensionUpdateFileByFileidPtrAltFn = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<UInt64>, UInt32) -> Int32
	    private typealias SandboxExtensionUpdateFileByFileidPtrValueFn = @convention(c) (UnsafePointer<UInt64>, UInt64, UInt32) -> Int32
	    private typealias SandboxConsumeExtensionFn = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Int32
	    private typealias SandboxConsumeFsExtensionFn = @convention(c) (UnsafePointer<CChar>?, UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> Int32
	    private typealias SandboxReleaseFsExtensionFn = @convention(c) (UnsafePointer<CChar>?, UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> Int32
	    private typealias SandboxExtensionFreeFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

	    private static func resolveSandboxExtensionSymbol(_ name: String) -> UnsafeMutableRawPointer? {
	        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
	        return name.withCString { sym in
	            dlsym(rtldDefault, sym)
	        }
	    }

	    private static func resolveSandboxExtensionSymbolInfo(_ name: String) -> (Bool, String?, String?) {
	        guard let sym = resolveSandboxExtensionSymbol(name) else {
	            return (false, nil, nil)
	        }
	        let addr = String(format: "0x%llx", UInt64(UInt(bitPattern: sym)))
	        var info = Dl_info()
	        if dladdr(UnsafeRawPointer(sym), &info) != 0, let fname = info.dli_fname {
	            return (true, String(cString: fname), addr)
	        }
	        return (true, nil, addr)
	    }

	    private static func appendSandboxExtensionSymbolIntrospection(_ details: inout [String: String]) {
	        let symbols = [
	            "sandbox_extension_issue_file",
	            "sandbox_extension_issue_file_to_self",
	            "sandbox_extension_issue_file_to_process",
	            "sandbox_extension_issue_file_to_process_by_pid",
	            "sandbox_issue_extension",
	            "sandbox_issue_fs_extension",
	            "sandbox_issue_fs_rw_extension",
	            "sandbox_extension_consume",
	            "sandbox_extension_release",
	            "sandbox_extension_release_file",
	            "sandbox_extension_update_file",
	            "sandbox_extension_update_file_by_fileid",
	            "sandbox_extension_free",
	            "sandbox_consume_extension",
	            "sandbox_consume_fs_extension",
	            "sandbox_release_fs_extension",
	        ]

	        for name in symbols {
	            let (present, image, addr) = resolveSandboxExtensionSymbolInfo(name)
	            details["symbol_\(name)"] = present ? "present" : "missing"
	            if let image {
	                details["symbol_\(name)_image"] = image
	            }
	            if let addr {
	                details["symbol_\(name)_addr"] = addr
	            }
	        }
	    }

	    private static func probeSandboxExtension(argv: [String]) -> RunProbeResponse {
	        pw_probe_sandbox_extension_marker()
	        let args = Argv(argv)
	        let entrySpan = PWSignpostSpan(
	            category: PWSignposts.categoryXpcService,
	            name: "sandbox_ext_entry",
	            label: "enter"
	        )
	        defer { entrySpan.end() }
	        let expectedOps = "issue_file|issue_file_to_pid|issue_extension|issue_fs_extension|issue_fs_rw_extension|consume|release|release_file|update_file|update_file_rename_delta|update_file_by_fileid|update_file_by_fileid_sweep|update_file_by_fileid_delta"
	        let expectedOpsSpan = PWSignpostSpan(
	            category: PWSignposts.categoryXpcService,
	            name: "sandbox_ext_expected_ops",
	            label: "ok"
	        )
	        expectedOpsSpan.end()
	        guard let opStr = args.value("--op"), let op = SandboxExtensionOp(rawValue: opStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }
	        let parsedOpSpan = PWSignpostSpan(
	            category: PWSignposts.categoryXpcService,
	            name: "sandbox_ext_parsed_op",
	            label: "op=\(op.rawValue)"
	        )
	        parsedOpSpan.end()

	        let preDetailsSpan = PWSignpostSpan(
	            category: PWSignposts.categoryXpcService,
	            name: "sandbox_ext_pre_details",
	            label: "start"
	        )
	        preDetailsSpan.end()
	        var details = baseDetails([
	            "probe_family": "sandbox_extension",
	            "op": op.rawValue,
	        ])
	        let postDetailsSpan = PWSignpostSpan(
	            category: PWSignposts.categoryXpcService,
	            name: "sandbox_ext_post_details",
	            label: "ok"
	        )
	        postDetailsSpan.end()
	        if args.has("--introspect") {
	            appendSandboxExtensionSymbolIntrospection(&details)
	        }

	        switch op {
	        case .issue_file, .issue_file_to_pid:
	            guard let extClass = args.value("--class"), !extClass.isEmpty else {
	                return badRequest("missing --class <extension-class>")
	            }

	            let allowUnsafe = args.has("--allow-unsafe-path")
	            let directPath = args.value("--path")
	            let pathClass = args.value("--path-class")
	            if (directPath == nil) == (pathClass == nil) {
	                return badRequest("provide exactly one of --path or --path-class")
	            }

            if args.has("--flags"), args.intValue("--flags") == nil {
                return badRequest("invalid --flags (expected integer)")
            }
            let flags = Int32(args.intValue("--flags") ?? 0)

            let targetPid: pid_t?
            if op == .issue_file_to_pid {
                guard let pidStr = args.value("--pid"), !pidStr.isEmpty else {
                    return badRequest("missing --pid <int|self> (required for issue_file_to_pid)")
                }
                if pidStr == "self" || pidStr == "current" {
                    targetPid = getpid()
                } else if let pidVal = Int32(pidStr) {
                    targetPid = pidVal
                } else {
                    return badRequest("invalid --pid (expected integer or 'self')")
                }
            } else if args.has("--pid") {
                return badRequest("--pid is only supported with --op issue_file_to_pid")
            } else {
                targetPid = nil
            }

            let targetStr = args.value("--target")
            let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? .specimen_file
	            let create = args.has("--create")
	            if create && target == .base {
	                return badRequest("--create is not supported with --target base")
	            }

	            let resolveSpan = PWSignpostSpan(
	                category: PWSignposts.categoryXpcService,
	                name: "sandbox_ext_resolve_target",
	                label: "op=\(op.rawValue)"
	            )
	            let (resolvedTarget, resolveErr) = resolveFsTarget(
	                directPath: directPath,
	                pathClass: pathClass,
	                target: target,
	                requestedName: args.value("--name")
	            )
	            resolveSpan.end()
	            if let resolveErr { return resolveErr }
	            guard let resolvedTarget else {
	                return badRequest("internal: failed to resolve target path")
	            }

	            let targetPath = resolvedTarget.path
            details["extension_class"] = extClass
            details["issue_variant"] = (op == .issue_file_to_pid) ? "issue_file_to_pid" : "issue_file"
            if let targetPid {
                details["target_pid"] = "\(targetPid)"
            }
            details["path_mode"] = (directPath != nil) ? "direct_path" : "path_class"
            details["path_class"] = pathClass ?? ""
            details["target"] = target.rawValue
            details["file_path"] = targetPath
            details["base_dir"] = resolvedTarget.baseDir ?? ""
	            details["harness_dir"] = resolvedTarget.harnessDir ?? ""
	            details["run_dir"] = resolvedTarget.runDir ?? ""
            details["flags"] = "\(flags)"
            details["allow_unsafe_path"] = allowUnsafe ? "true" : "false"
            details["create"] = create ? "true" : "false"

            if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
                return RunProbeResponse(
                    rc: 2,
                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "bad_request",
	                    errno: nil,
	                    error: "refusing to issue extension for non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)",
	                    details: details,
                    layer_attribution: nil
                )
            }

	            if create {
	                let createSpan = PWSignpostSpan(
	                    category: PWSignposts.categoryXpcService,
	                    name: "sandbox_ext_create",
	                    label: "target=\(target.rawValue)"
	                )
	                defer { createSpan.end() }
	                let targetIsDir = (target == .harness_dir || target == .run_dir)
	                var isDir: ObjCBool = false
	                let exists = FileManager.default.fileExists(atPath: targetPath, isDirectory: &isDir)

                if exists {
                    if targetIsDir && !isDir.boolValue {
                        return RunProbeResponse(
                            rc: 2,
                            stdout: "",
                            stderr: "target path exists but is not a directory (use --target specimen_file or remove --create)",
                            normalized_outcome: "bad_request",
                            errno: nil,
                            error: nil,
                            details: details,
                            layer_attribution: nil
                        )
                    }
                    if !targetIsDir && isDir.boolValue {
                        return RunProbeResponse(
                            rc: 2,
                            stdout: "",
                            stderr: "target path exists but is a directory (use --target run_dir/harness_dir or remove --create)",
                            normalized_outcome: "bad_request",
                            errno: nil,
                            error: nil,
                            details: details,
                            layer_attribution: nil
                        )
                    }
                    details["target_kind"] = isDir.boolValue ? "directory" : "file"
                    details["target_created"] = "false"
                } else {
                    do {
                        if targetIsDir {
                            try FileManager.default.createDirectory(atPath: targetPath, withIntermediateDirectories: true, attributes: nil)
                            details["target_created"] = "true"
                            details["target_kind"] = "directory"
                        } else {
                            let url = URL(fileURLWithPath: targetPath)
                            let parent = url.deletingLastPathComponent()
                            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
                            let payload = Data("policy-witness sandbox_extension\n".utf8)
                            try payload.write(to: url, options: [.atomic])
                            details["target_created"] = "true"
                            details["target_kind"] = "file"
                        }
                    } catch {
                        let e = extractErrno(error)
                        let outcome = isPermissionError(error) ? "permission_error" : "create_failed"
                        return RunProbeResponse(
                            rc: 1,
                            stdout: "",
                            stderr: "",
                            normalized_outcome: outcome,
                            errno: e,
                            error: "\(error)",
                            details: details,
                            layer_attribution: nil
                        )
                    }
                }
            }

	            let issueSymbol = (op == .issue_file_to_pid) ? "sandbox_extension_issue_file_to_process_by_pid" : "sandbox_extension_issue_file"
	            details["issue_symbol"] = issueSymbol
	            let dlsymSpan = PWSignpostSpan(
	                category: PWSignposts.categoryXpcService,
	                name: "sandbox_ext_dlsym_issue",
	                label: "symbol=\(issueSymbol)"
	            )
	            defer { dlsymSpan.end() }
	            guard let issueSym = resolveSandboxExtensionSymbol(issueSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(issueSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(issueSymbol)\")",
	                    details: details,
                    layer_attribution: nil
                )
	            }

	            errno = 0
	            let callSpan = PWSignpostSpan(
	                category: PWSignposts.categoryXpcService,
	                name: "sandbox_ext_call_issue",
	                label: "op=\(op.rawValue)"
	            )
	            let tokenPtr = extClass.withCString { classPtr in
	                targetPath.withCString { pathPtr in
	                    if let targetPid {
	                        let issueFn = unsafeBitCast(issueSym, to: SandboxExtensionIssueFileToPidFn.self)
                        return issueFn(classPtr, pathPtr, flags, targetPid)
                    }
	                    let issueFn = unsafeBitCast(issueSym, to: SandboxExtensionIssueFileFn.self)
	                    return issueFn(classPtr, pathPtr, flags)
	                }
	            }
	            callSpan.end()

	            guard let tokenPtr else {
	                let e = errno
		                let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "issue_failed"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: Int(e),
	                    error: String(cString: strerror(e)),
	                    details: details,
	                    layer_attribution: nil
	                )
            }

	            let tokenSpan = PWSignpostSpan(
	                category: PWSignposts.categoryXpcService,
	                name: "sandbox_ext_token_decode",
	                label: "token=cstr"
	            )
	            let token = String(cString: tokenPtr)
	            tokenSpan.end()
	            details["token_len"] = "\(token.utf8.count)"
	            details["token"] = token
            details["token_format"] = "full"
            if let idx = token.firstIndex(of: ";") {
                details["token_prefix"] = String(token[..<idx])
            }
            let tokenFields = token.split(separator: ";", omittingEmptySubsequences: false)
            details["token_fields_count"] = "\(tokenFields.count)"
            if tokenFields.count > 8 { details["token_field_8"] = String(tokenFields[8]) }
            if tokenFields.count > 9 { details["token_field_9"] = String(tokenFields[9]) }
            if tokenFields.count > 10 { details["token_field_10"] = String(tokenFields[10]) }

	            let freeSpan = PWSignpostSpan(
	                category: PWSignposts.categoryXpcService,
	                name: "sandbox_ext_free_token",
	                label: "token_ptr"
	            )
	            if let freeSym = resolveSandboxExtensionSymbol("sandbox_extension_free") {
	                let freeFn = unsafeBitCast(freeSym, to: SandboxExtensionFreeFn.self)
	                freeFn(tokenPtr)
		            } else {
		                free(UnsafeMutableRawPointer(tokenPtr))
		            }
	            freeSpan.end()

		            return RunProbeResponse(
		                rc: 0,
		                stdout: token,
	                stderr: "",
	                normalized_outcome: "ok",
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

        case .issue_extension, .issue_fs_extension, .issue_fs_rw_extension:
            if args.has("--class") {
                return badRequest("--class is only supported with --op issue_file or issue_file_to_pid")
            }
            if args.has("--pid") {
                return badRequest("--pid is only supported with --op issue_file_to_pid")
            }

            let allowUnsafe = args.has("--allow-unsafe-path")
            let directPath = args.value("--path")
            let pathClass = args.value("--path-class")
            if (directPath == nil) == (pathClass == nil) {
                return badRequest("provide exactly one of --path or --path-class")
            }

            var issueFlags: UInt64 = 0
            if op == .issue_fs_extension {
                if args.has("--flags"), args.intValue("--flags") == nil {
                    return badRequest("invalid --flags (expected integer)")
                }
                issueFlags = UInt64(args.intValue("--flags") ?? 0)
            } else if args.has("--flags") {
                return badRequest("--flags is only supported with --op issue_fs_extension")
            }

            let targetStr = args.value("--target")
            let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? .specimen_file
            let create = args.has("--create")
            if create && target == .base {
                return badRequest("--create is not supported with --target base")
            }

            let (resolvedTarget, resolveErr) = resolveFsTarget(
                directPath: directPath,
                pathClass: pathClass,
                target: target,
                requestedName: args.value("--name")
            )
            if let resolveErr { return resolveErr }
            guard let resolvedTarget else {
                return badRequest("internal: failed to resolve target path")
            }

            let targetPath = resolvedTarget.path
            details["issue_variant"] = op.rawValue
            details["path_mode"] = (directPath != nil) ? "direct_path" : "path_class"
            details["path_class"] = pathClass ?? ""
            details["target"] = target.rawValue
            details["file_path"] = targetPath
            details["base_dir"] = resolvedTarget.baseDir ?? ""
            details["harness_dir"] = resolvedTarget.harnessDir ?? ""
            details["run_dir"] = resolvedTarget.runDir ?? ""
            details["allow_unsafe_path"] = allowUnsafe ? "true" : "false"
            details["create"] = create ? "true" : "false"
            if op == .issue_fs_extension {
                details["flags"] = "\(issueFlags)"
            }

            if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
                return RunProbeResponse(
                    rc: 2,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "bad_request",
                    errno: nil,
                    error: "refusing to issue extension for non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)",
                    details: details,
                    layer_attribution: nil
                )
            }

            if create {
                let targetIsDir = (target == .harness_dir || target == .run_dir)
                var isDir: ObjCBool = false
                let exists = FileManager.default.fileExists(atPath: targetPath, isDirectory: &isDir)

                if exists {
                    if targetIsDir && !isDir.boolValue {
                        return RunProbeResponse(
                            rc: 2,
                            stdout: "",
                            stderr: "target path exists but is not a directory (use --target specimen_file or remove --create)",
                            normalized_outcome: "bad_request",
                            errno: nil,
                            error: nil,
                            details: details,
                            layer_attribution: nil
                        )
                    }
                    if !targetIsDir && isDir.boolValue {
                        return RunProbeResponse(
                            rc: 2,
                            stdout: "",
                            stderr: "target path exists but is a directory (use --target run_dir/harness_dir or remove --create)",
                            normalized_outcome: "bad_request",
                            errno: nil,
                            error: nil,
                            details: details,
                            layer_attribution: nil
                        )
                    }
                    details["target_kind"] = isDir.boolValue ? "directory" : "file"
                    details["target_created"] = "false"
                } else {
                    do {
                        if targetIsDir {
                            try FileManager.default.createDirectory(atPath: targetPath, withIntermediateDirectories: true, attributes: nil)
                            details["target_created"] = "true"
                            details["target_kind"] = "directory"
                        } else {
                            let url = URL(fileURLWithPath: targetPath)
                            let parent = url.deletingLastPathComponent()
                            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
                            let payload = Data("policy-witness sandbox_extension\n".utf8)
                            try payload.write(to: url, options: [.atomic])
                            details["target_created"] = "true"
                            details["target_kind"] = "file"
                        }
                    } catch {
                        let e = extractErrno(error)
                        let outcome = isPermissionError(error) ? "permission_error" : "create_failed"
                        return RunProbeResponse(
                            rc: 1,
                            stdout: "",
                            stderr: "",
                            normalized_outcome: outcome,
                            errno: e,
                            error: "\(error)",
                            details: details,
                            layer_attribution: nil
                        )
                    }
                }
            }

            let issueSymbol: String
            switch op {
            case .issue_extension:
                issueSymbol = "sandbox_issue_extension"
            case .issue_fs_extension:
                issueSymbol = "sandbox_issue_fs_extension"
            case .issue_fs_rw_extension:
                issueSymbol = "sandbox_issue_fs_rw_extension"
            default:
                issueSymbol = "sandbox_issue_extension"
            }
            details["issue_symbol"] = issueSymbol
            guard let issueSym = resolveSandboxExtensionSymbol(issueSymbol) else {
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "symbol_missing",
                    errno: nil,
                    error: "\(issueSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(issueSymbol)\")",
                    details: details,
                    layer_attribution: nil
                )
            }

            var tokenPtr: UnsafeMutablePointer<CChar>? = nil
            errno = 0
            let rc: Int32 = targetPath.withCString { pathPtr in
                return withUnsafeMutablePointer(to: &tokenPtr) { tokenOutPtr in
                    switch op {
                    case .issue_extension:
                        let fn = unsafeBitCast(issueSym, to: SandboxIssueExtensionFn.self)
                        return fn(pathPtr, tokenOutPtr)
                    case .issue_fs_extension:
                        let fn = unsafeBitCast(issueSym, to: SandboxIssueFsExtensionFn.self)
                        return fn(pathPtr, issueFlags, tokenOutPtr)
                    case .issue_fs_rw_extension:
                        let fn = unsafeBitCast(issueSym, to: SandboxIssueFsRwExtensionFn.self)
                        return fn(pathPtr, tokenOutPtr)
                    default:
                        return -1
                    }
                }
            }
            let callErrno = errno
            details["call_rc"] = "\(rc)"

            guard let tokenPtr else {
                var e = callErrno
                if e == 0 && rc > 0 {
                    e = rc
                }
                let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "issue_failed"
                let errorMsg = (e > 0) ? String(cString: strerror(e)) : "sandbox issue wrapper returned \(rc)"
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: outcome,
                    errno: e > 0 ? Int(e) : nil,
                    error: errorMsg,
                    details: details,
                    layer_attribution: nil
                )
            }

            let token = String(cString: tokenPtr)
            details["token_len"] = "\(token.utf8.count)"
            details["token"] = token
            details["token_format"] = "full"
            if let idx = token.firstIndex(of: ";") {
                details["token_prefix"] = String(token[..<idx])
            }

            if let freeSym = resolveSandboxExtensionSymbol("sandbox_extension_free") {
                let freeFn = unsafeBitCast(freeSym, to: SandboxExtensionFreeFn.self)
                freeFn(tokenPtr)
            } else {
                free(UnsafeMutableRawPointer(tokenPtr))
            }

            return RunProbeResponse(
                rc: 0,
                stdout: token,
                stderr: "",
                normalized_outcome: "ok",
                errno: nil,
                error: nil,
                details: details,
                layer_attribution: nil
            )

        case .release_file:
            guard let rawToken = args.value("--token"), !rawToken.isEmpty else {
                return badRequest("missing --token <token>")
            }
            let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
            let tokenFormat = args.value("--token-format") ?? "full"
            var tokenUsed = token
            if tokenFormat == "prefix" {
                if let idx = token.firstIndex(of: ";") {
                    tokenUsed = String(token[..<idx])
                }
            } else if tokenFormat != "full" {
                return badRequest("invalid --token-format (expected: full|prefix)")
            }

            details["token_len"] = "\(token.utf8.count)"
            details["token_used_len"] = "\(tokenUsed.utf8.count)"
            details["token_format"] = tokenFormat
            if let idx = token.firstIndex(of: ";") {
                details["token_prefix"] = String(token[..<idx])
            }
            if args.has("--path") || args.has("--path-class") || args.has("--target") || args.has("--name") {
                return badRequest("--op release_file only accepts a token; path args are not used by this symbol")
            }
            if args.has("--flags") {
                return badRequest("--op release_file does not accept --flags")
            }

            let symbolName = "sandbox_extension_release_file"
            details["call_symbol"] = symbolName
            guard let sym = resolveSandboxExtensionSymbol(symbolName) else {
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "symbol_missing",
                    errno: nil,
                    error: "\(symbolName) symbol not found via dlsym(RTLD_DEFAULT, \"\(symbolName)\")",
                    details: details,
                    layer_attribution: nil
                )
            }

            errno = 0
            let rc: Int32 = tokenUsed.withCString { tokenPtr in
                let fn = unsafeBitCast(sym, to: SandboxExtensionReleaseFn.self)
                return fn(tokenPtr)
            }
            let callErrno = errno
            details["call_variant_selected"] = "one_arg"
            details["call_rc"] = "\(rc)"

            if rc != 0 {
                var e = callErrno
                if e == 0 && rc > 0 {
                    e = rc
                }
                let outcome: String
                if e == EINVAL {
                    outcome = "invalid_token"
                    details["token_state"] = "invalid"
                } else if e == EPERM || e == EACCES {
                    outcome = "permission_error"
                } else {
                    outcome = "release_file_failed"
                }
                let errorMsg = (e > 0) ? String(cString: strerror(e)) : "sandbox_extension_release_file returned \(rc)"
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: outcome,
                    errno: e > 0 ? Int(e) : nil,
                    error: errorMsg,
                    details: details,
                    layer_attribution: nil
                )
            }

            details["token_state"] = "released"
            return RunProbeResponse(
                rc: 0,
                stdout: "",
                stderr: "",
                normalized_outcome: "release_ok",
                errno: nil,
                error: nil,
                details: details,
                layer_attribution: nil
            )

	        case .update_file:
	            let allowUnsafe = args.has("--allow-unsafe-path")
	            let directPath = args.value("--path")
	            let pathClass = args.value("--path-class")
	            if (directPath == nil) == (pathClass == nil) {
                return badRequest("provide exactly one of --path or --path-class")
            }
            if args.has("--create") {
                return badRequest("--create is not supported with --op update_file")
            }
            if args.has("--token") || args.has("--token-format") {
                return badRequest("--op update_file expects a path; do not pass --token/--token-format")
            }

            if args.has("--flags"), args.intValue("--flags") == nil {
                return badRequest("invalid --flags (expected integer)")
            }
            let flags = UInt32(args.intValue("--flags") ?? 0)

            let targetStr = args.value("--target")
            let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? .specimen_file

            let (resolvedTarget, resolveErr) = resolveFsTarget(
                directPath: directPath,
                pathClass: pathClass,
                target: target,
                requestedName: args.value("--name")
            )
            if let resolveErr { return resolveErr }
            guard let resolvedTarget else {
                return badRequest("internal: failed to resolve target path")
            }

            let targetPath = resolvedTarget.path
            details["path_mode"] = (directPath != nil) ? "direct_path" : "path_class"
            details["path_class"] = pathClass ?? ""
            details["target"] = target.rawValue
            details["file_path"] = targetPath
            details["base_dir"] = resolvedTarget.baseDir ?? ""
            details["harness_dir"] = resolvedTarget.harnessDir ?? ""
            details["run_dir"] = resolvedTarget.runDir ?? ""
            details["flags"] = "\(flags)"
            details["allow_unsafe_path"] = allowUnsafe ? "true" : "false"

            if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
                return RunProbeResponse(
                    rc: 2,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "bad_request",
                    errno: nil,
                    error: "refusing update_file for non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)",
                    details: details,
                    layer_attribution: nil
                )
            }

            let symbolName = "sandbox_extension_update_file"
            details["call_symbol"] = symbolName
            guard let sym = resolveSandboxExtensionSymbol(symbolName) else {
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "symbol_missing",
                    errno: nil,
                    error: "\(symbolName) symbol not found via dlsym(RTLD_DEFAULT, \"\(symbolName)\")",
                    details: details,
                    layer_attribution: nil
                )
            }

            errno = 0
            let rc: Int32 = targetPath.withCString { pathPtr in
                let fn = unsafeBitCast(sym, to: SandboxExtensionUpdateFileFn.self)
                return fn(pathPtr, flags)
            }
            let callErrno = errno
            details["call_rc"] = "\(rc)"

            if rc != 0 {
                var e = callErrno
                if e == 0 && rc > 0 {
                    e = rc
                }
                let outcome: String
                if e == EINVAL {
                    outcome = "invalid_token"
                    details["token_state"] = "invalid"
                } else if e == EPERM || e == EACCES {
                    outcome = "permission_error"
                } else {
                    outcome = "update_failed"
                }
                let errorMsg = (e > 0) ? String(cString: strerror(e)) : "\(symbolName) returned \(rc)"
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: outcome,
                    errno: e > 0 ? Int(e) : nil,
                    error: errorMsg,
                    details: details,
                    layer_attribution: nil
                )
            }

            return RunProbeResponse(
                rc: 0,
                stdout: "",
                stderr: "",
                normalized_outcome: "update_ok",
                errno: nil,
                error: nil,
                details: details,
	                layer_attribution: nil
	            )

		        case .update_file_rename_delta:
		            // update_file_rename_delta is a rename-retarget semantics harness.
		            //
		            // Lessons (these are enforced/recorded here, not inferred elsewhere):
		            // - open_read (open+read(1)) fails with EPERM before consumption for a denied Desktop read.
		            // - issue + consume flips open_read to success in the same process context.
		            // - The grant is path-scoped: an inode-preserving rename does not transfer access to the new path (open_read yields EPERM).
		            // - sandbox_extension_update_file(path) retargets access across renames in the same durable session.
		            // - sandbox_extension_update_file_by_fileid can return rc==0 without restoring access, so return codes are not evidence.
		            // - Correctness is “access delta observed”: we record post-call access checks and *_changed_access signals.
		            // - Premises are uncheatable: inode-preserving + same device + destination non-existent, with early normalized_outcome exits.
		            // - Full stat snapshots and wait/poll observations are persisted so external choreography is reproducible.
		            guard let extClass = args.value("--class"), !extClass.isEmpty else {
		                return badRequest("missing --class <extension-class>")
		            }

	            let allowUnsafe = args.has("--allow-unsafe-path")
	            guard let oldPath = args.value("--path"), !oldPath.isEmpty else {
	                return badRequest("missing --path <abs>")
	            }
	            guard let newPath = args.value("--new-path"), !newPath.isEmpty else {
	                return badRequest("missing --new-path <abs>")
	            }
	            if oldPath == newPath {
	                return badRequest("--path and --new-path must differ")
	            }
	            if !oldPath.hasPrefix("/") || !newPath.hasPrefix("/") {
	                return badRequest("--path/--new-path must be absolute paths")
	            }

	            if args.has("--flags"), args.intValue("--flags") == nil {
	                return badRequest("invalid --flags (expected integer)")
	            }
	            let issueFlags = Int32(args.intValue("--flags") ?? 0)
	            let updateFlags = UInt32(truncatingIfNeeded: issueFlags)

	            var selector: UInt64 = 2
	            if let selectorStr = args.value("--selector"), !selectorStr.isEmpty {
	                if let parsed = UInt64(selectorStr) {
	                    selector = parsed
	                } else {
	                    return badRequest("invalid --selector (expected u64)")
	                }
	            }

	            let waitForExternalRename = args.has("--wait-for-external-rename")
	            let noCleanup = args.has("--no-cleanup")

	            details["extension_class"] = extClass
	            details["old_path"] = oldPath
	            details["new_path"] = newPath
	            details["flags"] = "\(issueFlags)"
	            details["selector"] = "\(selector)"
	            details["selector_hex"] = String(format: "0x%llx", selector)
	            details["allow_unsafe_path"] = allowUnsafe ? "true" : "false"
	            details["wait_for_external_rename"] = waitForExternalRename ? "true" : "false"
	            details["no_cleanup"] = noCleanup ? "true" : "false"

		            if !allowUnsafe, (!isSafeWritePath(oldPath) || !isSafeWritePath(newPath)) {
		                return RunProbeResponse(
		                    rc: 2,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "bad_request",
	                    errno: nil,
	                    error: "refusing update_file_rename_delta for non-harness paths (use paths under */policy-witness-harness/* or pass --allow-unsafe-path)",
	                    details: details,
	                    layer_attribution: nil
		                )
		            }

		            func appendStatSnapshot(prefix: String, st: stat) {
		                let devU64 = UInt64(truncatingIfNeeded: st.st_dev)
		                let rdevU64 = UInt64(truncatingIfNeeded: st.st_rdev)
		                details["\(prefix)_dev"] = "\(st.st_dev)"
		                details["\(prefix)_dev_hex"] = String(format: "0x%llx", devU64)
		                details["\(prefix)_ino"] = "\(st.st_ino)"
		                details["\(prefix)_ino_hex"] = String(format: "0x%llx", st.st_ino)
		                details["\(prefix)_mode"] = "\(st.st_mode)"
		                details["\(prefix)_mode_octal"] = String(format: "0o%o", st.st_mode)
		                details["\(prefix)_nlink"] = "\(st.st_nlink)"
		                details["\(prefix)_uid"] = "\(st.st_uid)"
		                details["\(prefix)_gid"] = "\(st.st_gid)"
		                details["\(prefix)_rdev"] = "\(st.st_rdev)"
		                details["\(prefix)_rdev_hex"] = String(format: "0x%llx", rdevU64)
		                details["\(prefix)_size"] = "\(st.st_size)"
		                details["\(prefix)_blocks"] = "\(st.st_blocks)"
		                details["\(prefix)_blksize"] = "\(st.st_blksize)"
		                details["\(prefix)_flags"] = "\(st.st_flags)"
		                details["\(prefix)_gen"] = "\(st.st_gen)"
		                details["\(prefix)_atime_sec"] = "\(st.st_atimespec.tv_sec)"
		                details["\(prefix)_atime_nsec"] = "\(st.st_atimespec.tv_nsec)"
		                details["\(prefix)_mtime_sec"] = "\(st.st_mtimespec.tv_sec)"
		                details["\(prefix)_mtime_nsec"] = "\(st.st_mtimespec.tv_nsec)"
		                details["\(prefix)_ctime_sec"] = "\(st.st_ctimespec.tv_sec)"
		                details["\(prefix)_ctime_nsec"] = "\(st.st_ctimespec.tv_nsec)"
		                details["\(prefix)_birthtime_sec"] = "\(st.st_birthtimespec.tv_sec)"
		                details["\(prefix)_birthtime_nsec"] = "\(st.st_birthtimespec.tv_nsec)"
		            }

		            func statForPath(_ path: String) -> (stat?, Int32?) {
		                var st = stat()
		                if stat(path, &st) != 0 {
	                    return (nil, errno)
	                }
	                return (st, nil)
	            }

	            func openReadOutcome(path: String) -> (String, Int32?, String) {
	                let (fd, e): (Int32, Int32?) = path.withCString { pathPtr in
	                    errno = 0
	                    let fd = open(pathPtr, O_RDONLY)
	                    if fd >= 0 { return (fd, nil) }
	                    return (-1, errno)
	                }
	                guard fd >= 0 else {
	                    let err = e ?? 0
	                    if err == ENOENT {
	                        return ("not_found", err, String(cString: strerror(err)))
	                    }
	                    if err == EPERM || err == EACCES {
	                        return ("deny", err, String(cString: strerror(err)))
	                    }
	                    return ("error_\(err)", err, (err != 0) ? String(cString: strerror(err)) : "open() failed")
	                }
	                var b: UInt8 = 0
	                errno = 0
	                let n = Darwin.read(fd, &b, 1)
	                let readErrno = (n < 0) ? errno : 0
	                close(fd)
	                if n < 0 {
	                    let err = readErrno
	                    if err == EPERM || err == EACCES {
	                        return ("deny", err, String(cString: strerror(err)))
	                    }
	                    return ("error_\(err)", err, String(cString: strerror(err)))
	                }
	                return ("allow", nil, "")
	            }

	            func recordOpen(phase: String, label: String, path: String) -> String {
	                let (outcome, errOpt, errStr) = openReadOutcome(path: path)
	                details["access_\(phase)_\(label)_open_outcome"] = outcome
	                if let errOpt {
	                    details["access_\(phase)_\(label)_open_errno"] = "\(errOpt)"
	                    details["access_\(phase)_\(label)_open_error"] = errStr
	                } else {
	                    details["access_\(phase)_\(label)_open_errno"] = ""
	                    details["access_\(phase)_\(label)_open_error"] = ""
	                }
	                return outcome
	            }

		            // Preflight: stat old path and record pre-consume access for both names.
		            let (stOldOpt, stOldErrnoOpt) = statForPath(oldPath)
		            guard let stOld = stOldOpt else {
	                let e = stOldErrnoOpt ?? errno
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "stat_failed",
	                    errno: Int(e),
	                    error: String(cString: strerror(e)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
		            details["stat_old_dev"] = "\(stOld.st_dev)"
		            details["stat_old_dev_hex"] = String(format: "0x%llx", stOld.st_dev)
		            details["stat_old_ino"] = "\(stOld.st_ino)"
		            details["stat_old_ino_hex"] = String(format: "0x%llx", stOld.st_ino)
		            appendStatSnapshot(prefix: "stat_old_pre", st: stOld)

		            let (stNewPreOpt, stNewPreErrnoOpt) = statForPath(newPath)
		            if let stNewPreOpt {
		                details["stat_new_pre_exists"] = "true"
		                details["stat_new_pre_dev"] = "\(stNewPreOpt.st_dev)"
		                details["stat_new_pre_dev_hex"] = String(format: "0x%llx", stNewPreOpt.st_dev)
		                details["stat_new_pre_ino"] = "\(stNewPreOpt.st_ino)"
		                details["stat_new_pre_ino_hex"] = String(format: "0x%llx", stNewPreOpt.st_ino)
		                details["dest_preexisted"] = "true"
		                appendStatSnapshot(prefix: "stat_new_pre", st: stNewPreOpt)
		            } else {
		                details["stat_new_pre_exists"] = "false"
		                details["dest_preexisted"] = "false"
		                if let e = stNewPreErrnoOpt {
		                    details["stat_new_pre_errno"] = "\(e)"
		                    details["stat_new_pre_error"] = String(cString: strerror(e))
		                }
		            }

		            let preOld = recordOpen(phase: "pre_consume", label: "old", path: oldPath)
		            let preNew = recordOpen(phase: "pre_consume", label: "new", path: newPath)

		            if stNewPreOpt != nil {
		                return RunProbeResponse(
		                    rc: 0,
		                    stdout: "",
		                    stderr: "",
		                    normalized_outcome: "dest_preexisted",
		                    errno: nil,
		                    error: nil,
		                    details: details,
		                    layer_attribution: nil
		                )
		            }

		            func cleanupReleaseHandleIfNeeded(_ consumeHandle: Int64) {
		                if noCleanup { return }
		                let releaseSymbol = "sandbox_extension_release"
		                details["cleanup_release_symbol"] = releaseSymbol
		                if let releaseSym = resolveSandboxExtensionSymbol(releaseSymbol) {
		                    errno = 0
		                    let rcRelease: Int32 = {
		                        let fn = unsafeBitCast(releaseSym, to: SandboxExtensionReleaseHandleFn.self)
		                        return fn(consumeHandle)
		                    }()
		                    details["cleanup_release_rc"] = "\(rcRelease)"
		                    details["cleanup_release_errno"] = "\(errno)"
		                    if errno != 0 {
		                        details["cleanup_release_error"] = String(cString: strerror(errno))
		                    } else {
		                        details["cleanup_release_error"] = ""
		                    }
		                } else {
		                    details["cleanup_release_symbol_missing"] = "true"
		                }
		            }

		            // Issue an extension token for the old path.
		            let issueSymbol = "sandbox_extension_issue_file"
		            details["issue_symbol"] = issueSymbol
	            guard let issueSym = resolveSandboxExtensionSymbol(issueSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(issueSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(issueSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            errno = 0
	            let tokenPtr = extClass.withCString { classPtr in
	                oldPath.withCString { pathPtr in
	                    let fn = unsafeBitCast(issueSym, to: SandboxExtensionIssueFileFn.self)
	                    return fn(classPtr, pathPtr, issueFlags)
	                }
	            }
	            let issueErrno = errno
	            guard let tokenPtr else {
	                let outcome = (issueErrno == EPERM || issueErrno == EACCES) ? "permission_error" : "issue_failed"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: Int(issueErrno),
	                    error: String(cString: strerror(issueErrno)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            let token = String(cString: tokenPtr)
	            details["token_len"] = "\(token.utf8.count)"
	            if let idx = token.firstIndex(of: ";") {
	                details["token_prefix"] = String(token[..<idx])
	            }
	            details["token_fields_count"] = "\(token.split(separator: ";", omittingEmptySubsequences: false).count)"

	            if let freeSym = resolveSandboxExtensionSymbol("sandbox_extension_free") {
	                let freeFn = unsafeBitCast(freeSym, to: SandboxExtensionFreeFn.self)
	                freeFn(tokenPtr)
	            } else {
	                free(UnsafeMutableRawPointer(tokenPtr))
	            }

		            // Consume the token to obtain a handle.
		            let consumeSymbol = "sandbox_extension_consume"
	            details["consume_symbol"] = consumeSymbol
	            guard let consumeSym = resolveSandboxExtensionSymbol(consumeSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(consumeSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(consumeSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            errno = 0
	            let consumeHandle: Int64 = token.withCString { tokenCStr in
	                let fn = unsafeBitCast(consumeSym, to: SandboxExtensionConsumeHandleFn.self)
	                return fn(tokenCStr)
	            }
	            let consumeErrno = errno
	            details["consume_handle"] = "\(consumeHandle)"
	            details["consume_handle_hex"] = String(format: "0x%016llx", consumeHandle)
		            if consumeHandle <= 0 {
	                let outcome: String
	                if consumeErrno == EEXIST {
	                    outcome = "already_consumed"
	                } else if consumeErrno == EINVAL {
	                    outcome = "invalid_token"
	                } else if consumeErrno == EPERM || consumeErrno == EACCES {
	                    outcome = "permission_error"
	                } else {
	                    outcome = "consume_failed"
	                }
	                let errorMsg = consumeErrno != 0 ? String(cString: strerror(consumeErrno)) : "consume returned handle=\(consumeHandle)"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: consumeErrno != 0 ? Int(consumeErrno) : nil,
	                    error: errorMsg,
	                    details: details,
	                    layer_attribution: nil
		                )
		            }

	            let consumeLow32 = UInt32(truncatingIfNeeded: consumeHandle)
	            let consumeHigh32 = UInt32(truncatingIfNeeded: consumeHandle >> 32)
	            details["consume_handle_low32"] = "\(consumeLow32)"
	            details["consume_handle_low32_hex"] = String(format: "0x%08x", consumeLow32)
	            details["consume_handle_high32"] = "\(consumeHigh32)"
	            details["consume_handle_high32_hex"] = String(format: "0x%08x", consumeHigh32)

	            let postConsumeOld = recordOpen(phase: "post_consume", label: "old", path: oldPath)
	            let postConsumeNew = recordOpen(phase: "post_consume", label: "new", path: newPath)

	            // Rename step: either wait for a host-side rename or attempt in-service rename.
	            var stAfterRename: stat? = nil
		            if waitForExternalRename {
	                if args.has("--wait-timeout-ms"), args.intValue("--wait-timeout-ms") == nil {
	                    return badRequest("invalid --wait-timeout-ms (expected integer)")
	                }
	                if args.has("--wait-interval-ms"), args.intValue("--wait-interval-ms") == nil {
	                    return badRequest("invalid --wait-interval-ms (expected integer)")
	                }
	                let waitTimeoutMs = max(1, min(300_000, args.intValue("--wait-timeout-ms") ?? 30_000))
	                let waitIntervalMs = max(1, min(1_000, args.intValue("--wait-interval-ms") ?? 50))
	                details["wait_timeout_ms"] = "\(waitTimeoutMs)"
	                details["wait_interval_ms"] = "\(waitIntervalMs)"

		                let waitStartNs = DispatchTime.now().uptimeNanoseconds
		                details["wait_started_at_ns"] = "\(waitStartNs)"

		                var lastOldErrno: Int32? = nil
		                var lastNewErrno: Int32? = nil
		                var pollCount = 0
		                var sawOldDisappear = false
		                var sawNewAppear = false
		                var oldDisappearAtNs: UInt64? = nil
		                var newAppearAtNs: UInt64? = nil
		                while true {
		                    pollCount += 1
		                    let nowNs = DispatchTime.now().uptimeNanoseconds
		                    let (stOldNow, oldErrnoOpt) = statForPath(oldPath)
		                    let (stNewNow, newErrnoOpt) = statForPath(newPath)
		                    lastOldErrno = oldErrnoOpt
		                    lastNewErrno = newErrnoOpt

		                    let oldMissing = (stOldNow == nil && oldErrnoOpt == ENOENT)
		                    let newExists = (stNewNow != nil)

		                    if oldMissing && !sawOldDisappear {
		                        sawOldDisappear = true
		                        oldDisappearAtNs = nowNs
		                        details["wait_saw_old_disappear"] = "true"
		                        details["wait_old_disappeared_at_ns"] = "\(nowNs)"
		                    }
		                    if newExists && !sawNewAppear {
		                        sawNewAppear = true
		                        newAppearAtNs = nowNs
		                        details["wait_saw_new_appear"] = "true"
		                        details["wait_new_appeared_at_ns"] = "\(nowNs)"
		                        if let stNewNow {
		                            details["wait_new_first_dev"] = "\(stNewNow.st_dev)"
		                            details["wait_new_first_dev_hex"] = String(format: "0x%llx", stNewNow.st_dev)
		                            details["wait_new_first_ino"] = "\(stNewNow.st_ino)"
		                            details["wait_new_first_ino_hex"] = String(format: "0x%llx", stNewNow.st_ino)
		                        }
		                    }
		                    if let stNewNow {
		                        details["wait_new_last_dev"] = "\(stNewNow.st_dev)"
		                        details["wait_new_last_dev_hex"] = String(format: "0x%llx", stNewNow.st_dev)
		                        details["wait_new_last_ino"] = "\(stNewNow.st_ino)"
		                        details["wait_new_last_ino_hex"] = String(format: "0x%llx", stNewNow.st_ino)
		                    }

		                    if oldMissing, let stNewNow {
		                        stAfterRename = stNewNow
		                        break
		                    }

		                    let elapsedMs = Int((DispatchTime.now().uptimeNanoseconds - waitStartNs) / 1_000_000)
		                    if elapsedMs >= waitTimeoutMs {
		                        details["wait_timed_out"] = "true"
		                        details["wait_elapsed_ms"] = "\(elapsedMs)"
		                        details["wait_poll_count"] = "\(pollCount)"
		                        details["wait_saw_old_disappear"] = sawOldDisappear ? "true" : "false"
		                        details["wait_saw_new_appear"] = sawNewAppear ? "true" : "false"
		                        if let oldDisappearAtNs {
		                            details["wait_old_disappeared_at_ns"] = "\(oldDisappearAtNs)"
		                        }
		                        if let newAppearAtNs {
		                            details["wait_new_appeared_at_ns"] = "\(newAppearAtNs)"
		                        }
		                        if let lastOldErrno {
		                            details["wait_last_old_errno"] = "\(lastOldErrno)"
		                            details["wait_last_old_error"] = String(cString: strerror(lastOldErrno))
		                        }
			                        if let lastNewErrno {
			                            details["wait_last_new_errno"] = "\(lastNewErrno)"
			                            details["wait_last_new_error"] = String(cString: strerror(lastNewErrno))
			                        }
			                        let outcome: String
			                        if (sawOldDisappear && !sawNewAppear) || (!sawOldDisappear && sawNewAppear) {
			                            outcome = "rename_ambiguous"
			                        } else {
			                            outcome = "rename_timeout"
			                        }
			                        return RunProbeResponse(
			                            rc: 1,
			                            stdout: "",
			                            stderr: "",
			                            normalized_outcome: outcome,
			                            errno: nil,
			                            error: "timed out waiting for host-side rename: \(oldPath) -> \(newPath)",
			                            details: details,
			                            layer_attribution: nil
			                        )
			                    }
		                    usleep(useconds_t(waitIntervalMs * 1000))
		                }
		                let waitEndNs = DispatchTime.now().uptimeNanoseconds
		                details["wait_ended_at_ns"] = "\(waitEndNs)"
		                details["wait_duration_ms"] = "\(Int((waitEndNs - waitStartNs) / 1_000_000))"
		                details["wait_poll_count"] = "\(pollCount)"
		                details["wait_saw_old_disappear"] = sawOldDisappear ? "true" : "false"
		                details["wait_saw_new_appear"] = sawNewAppear ? "true" : "false"
		                if let oldDisappearAtNs {
		                    details["wait_old_disappeared_at_ns"] = "\(oldDisappearAtNs)"
		                }
		                if let newAppearAtNs {
		                    details["wait_new_appeared_at_ns"] = "\(newAppearAtNs)"
		                }
		            } else {
	                errno = 0
	                if Darwin.rename(oldPath, newPath) != 0 {
	                    let e = errno
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: (e == EPERM || e == EACCES) ? "permission_error" : "rename_failed",
	                        errno: Int(e),
	                        error: String(cString: strerror(e)),
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	                let (stNewOpt, stNewErrnoOpt) = statForPath(newPath)
	                guard let stNew = stNewOpt else {
	                    let e = stNewErrnoOpt ?? errno
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "stat_failed",
	                        errno: Int(e),
	                        error: String(cString: strerror(e)),
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	                stAfterRename = stNew
	            }

	            guard let stNew = stAfterRename else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "internal_error",
	                    errno: nil,
	                    error: "internal: missing stat_after_rename",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

		            details["stat_new_dev"] = "\(stNew.st_dev)"
		            details["stat_new_dev_hex"] = String(format: "0x%llx", stNew.st_dev)
		            details["stat_new_ino"] = "\(stNew.st_ino)"
		            details["stat_new_ino_hex"] = String(format: "0x%llx", stNew.st_ino)
		            appendStatSnapshot(prefix: "stat_new_post", st: stNew)

	            let sameDev = (stNew.st_dev == stOld.st_dev)
	            let sameIno = (stNew.st_ino == stOld.st_ino)
		            details["rename_same_dev"] = sameDev ? "true" : "false"
		            details["rename_same_inode"] = sameIno ? "true" : "false"
		            let renameWasInodePreserving = sameDev && sameIno
		            details["rename_was_inode_preserving"] = renameWasInodePreserving ? "true" : "false"

		            let afterRenameOld = recordOpen(phase: "after_rename", label: "old", path: oldPath)
		            let afterRenameNew = recordOpen(phase: "after_rename", label: "new", path: newPath)

		            var newOutcomes: [String] = [preNew, postConsumeNew, afterRenameNew]
		            let oldOutcomes: [String] = [preOld, postConsumeOld, afterRenameOld]
		            details["delta_old_open_transition"] = oldOutcomes.joined(separator: "->")
		            details["delta_new_open_transition"] = newOutcomes.joined(separator: "->")

		            if !renameWasInodePreserving {
		                cleanupReleaseHandleIfNeeded(consumeHandle)
		                let outcome: String
		                if !sameDev {
		                    outcome = "rename_cross_device"
		                } else {
		                    outcome = "rename_inode_changed"
		                }
		                return RunProbeResponse(
		                    rc: 0,
		                    stdout: "",
		                    stderr: "",
		                    normalized_outcome: outcome,
		                    errno: nil,
		                    error: nil,
		                    details: details,
		                    layer_attribution: nil
		                )
		            }

			            // Candidate sweep note:
			            // - Per-candidate post-call access checks exist to avoid “errno hunting”.
			            // - rc==0 is not evidence; *_changed_access is the signal.
			            // - The witness records action + outcome per phase: open_read, consume, update (rc/errno), then post-call open_read.
			            //
			            // Attempt update_file_by_fileid candidates while the new path is denied.
			            let updateByFileidSymbol = "sandbox_extension_update_file_by_fileid"
		            details["update_by_fileid_symbol"] = updateByFileidSymbol
		            guard let updateByFileidSym = resolveSandboxExtensionSymbol(updateByFileidSymbol) else {
		                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(updateByFileidSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(updateByFileidSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

		            let candidates: [(String, UInt64)] = [
		                ("st_ino", UInt64(truncatingIfNeeded: stNew.st_ino)),
		                ("st_dev", UInt64(truncatingIfNeeded: stNew.st_dev)),
		                ("consume_handle_low32", UInt64(consumeLow32)),
		                ("consume_handle_high32", UInt64(consumeHigh32)),
		                ("consume_handle_xor32", UInt64(consumeLow32 ^ consumeHigh32)),
			            ]
			            details["update_by_fileid_candidate_count"] = "\(candidates.count)"

			            var lastNewOutcomeForDelta = afterRenameNew
			            for (idx, candidate) in candidates.enumerated() {
			                let (name, value) = candidate
			                details["update_by_fileid_\(name)_attempt_index"] = "\(idx)"
			                details["update_by_fileid_candidate_\(idx)_name"] = name
		                details["update_by_fileid_\(name)_payload_u64"] = "\(value)"
		                details["update_by_fileid_\(name)_payload_hex"] = String(format: "0x%llx", value)
		                let low32 = UInt32(truncatingIfNeeded: value)
		                details["update_by_fileid_\(name)_payload_low32"] = "\(low32)"
		                details["update_by_fileid_\(name)_payload_low32_hex"] = String(format: "0x%08x", low32)

	                var payloadCopy = value
	                errno = 0
	                let rc: Int32 = withUnsafePointer(to: &payloadCopy) { payloadPtr in
	                    let fn = unsafeBitCast(updateByFileidSym, to: SandboxExtensionUpdateFileByFileidPtrValueFn.self)
	                    return fn(payloadPtr, selector, 0)
	                }
	                let err = errno
	                let normErr: Int32 = (err != 0) ? err : ((rc > 0) ? rc : 0)
	                details["update_by_fileid_\(name)_rc"] = "\(rc)"
	                details["update_by_fileid_\(name)_errno"] = "\(err)"
	                details["update_by_fileid_\(name)_norm_errno"] = "\(normErr)"
		                details["update_by_fileid_\(name)_error"] = (normErr != 0) ? String(cString: strerror(normErr)) : ""

		                let phase = "after_update_by_fileid_\(name)"
		                let newOutcome = recordOpen(phase: phase, label: "new", path: newPath)
		                details["update_by_fileid_\(name)_changed_access"] = (newOutcome != lastNewOutcomeForDelta) ? "true" : "false"
		                lastNewOutcomeForDelta = newOutcome
		                newOutcomes.append(newOutcome)
		            }

		            // Call update_file(newPath) and re-check access.
	            let updateFileSymbol = "sandbox_extension_update_file"
	            details["update_file_symbol"] = updateFileSymbol
	            guard let updateFileSym = resolveSandboxExtensionSymbol(updateFileSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(updateFileSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(updateFileSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            errno = 0
	            let updateFileRc: Int32 = newPath.withCString { pathPtr in
	                let fn = unsafeBitCast(updateFileSym, to: SandboxExtensionUpdateFileFn.self)
	                return fn(pathPtr, updateFlags)
	            }
	            let updateFileErrno = errno
	            let updateFileNormErr: Int32 = (updateFileErrno != 0) ? updateFileErrno : ((updateFileRc > 0) ? updateFileRc : 0)
	            details["update_file_rc"] = "\(updateFileRc)"
	            details["update_file_errno"] = "\(updateFileErrno)"
	            details["update_file_norm_errno"] = "\(updateFileNormErr)"
	            details["update_file_error"] = (updateFileNormErr != 0) ? String(cString: strerror(updateFileNormErr)) : ""

		            let afterUpdateFileNew = recordOpen(phase: "after_update_file", label: "new", path: newPath)
		            newOutcomes.append(afterUpdateFileNew)

		            details["delta_old_open_transition"] = oldOutcomes.joined(separator: "->")
		            details["delta_new_open_transition"] = newOutcomes.joined(separator: "->")

		            cleanupReleaseHandleIfNeeded(consumeHandle)

	            let outcome: String
	            if preOld == "deny", postConsumeOld == "allow", afterRenameNew == "deny", afterUpdateFileNew == "allow" {
	                outcome = "expected"
	            } else if preOld != "deny" {
	                outcome = "pre_not_denied"
	            } else if postConsumeOld != "allow" {
	                outcome = "consume_no_effect"
	            } else if afterRenameNew != "deny" {
	                outcome = "post_rename_not_denied"
	            } else if afterUpdateFileNew != "allow" {
	                outcome = "update_file_no_effect"
	            } else {
	                outcome = "ok"
	            }

	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

	        case .update_file_by_fileid:
	            guard let rawToken = args.value("--token"), !rawToken.isEmpty else {
	                return badRequest("missing --token <token>")
	            }
            let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
            let tokenFormat = args.value("--token-format") ?? "full"
            var tokenUsed = token
            if tokenFormat == "prefix" {
                if let idx = token.firstIndex(of: ";") {
                    tokenUsed = String(token[..<idx])
                }
            } else if tokenFormat != "full" {
                return badRequest("invalid --token-format (expected: full|prefix)")
            }

            if args.has("--flags"), args.intValue("--flags") == nil {
                return badRequest("invalid --flags (expected integer)")
            }
            let flags = UInt32(args.intValue("--flags") ?? 0)

            var selectorValue: UInt64? = nil
            if let selectorStr = args.value("--selector"), !selectorStr.isEmpty {
                if let parsed = UInt64(selectorStr) {
                    selectorValue = parsed
                    details["selector"] = "\(parsed)"
                    details["selector_hex"] = String(format: "0x%llx", parsed)
                } else {
                    return badRequest("invalid --selector (expected u64)")
                }
            }

            var fileId: UInt64? = nil
            if let fileIdStr = args.value("--file-id"), !fileIdStr.isEmpty {
                if let parsed = UInt64(fileIdStr) {
                    fileId = parsed
                    details["file_id_source"] = "arg"
                } else {
                    return badRequest("invalid --file-id (expected u64)")
                }
            } else if let path = args.value("--path"), !path.isEmpty {
                var st = stat()
                if stat(path, &st) != 0 {
                    let e = errno
                    return RunProbeResponse(
                        rc: 1,
                        stdout: "",
                        stderr: "",
                        normalized_outcome: "stat_failed",
                        errno: Int(e),
                        error: String(cString: strerror(e)),
                        details: details,
                        layer_attribution: nil
                    )
                }
                fileId = UInt64(st.st_ino)
                details["file_id_source"] = "stat"
                details["file_id_stat_dev"] = "\(st.st_dev)"
                details["file_id_stat_dev_hex"] = String(format: "0x%llx", st.st_dev)
                details["file_id_stat_ino"] = "\(st.st_ino)"
                details["file_id_stat_ino_hex"] = String(format: "0x%llx", st.st_ino)
                details["file_path"] = path
            } else {
                return badRequest("missing --file-id <u64> or --path <abs> (required for update_file_by_fileid)")
            }

            if args.has("--path-class") || args.has("--target") || args.has("--name") {
                return badRequest("update_file_by_fileid does not accept --path-class/--target/--name")
            }

            details["token_len"] = "\(token.utf8.count)"
            details["token_used_len"] = "\(tokenUsed.utf8.count)"
            details["token_format"] = tokenFormat
            details["flags"] = "\(flags)"
            if let idx = token.firstIndex(of: ";") {
                details["token_prefix"] = String(token[..<idx])
            }

            let callVariant = args.value("--call-variant") ?? "auto"
            let allowedVariants: Set<String> = ["token_fileid", "fileid_token", "fileid_ptr_token", "token_ptr_fileid", "fileid_ptr_selector", "payload_ptr_selector", "auto"]
            if !allowedVariants.contains(callVariant) {
                let allowed = allowedVariants.sorted().joined(separator: "|")
                return badRequest("invalid --call-variant (expected: \(allowed))")
            }
            details["call_variant"] = callVariant
            if (callVariant == "fileid_ptr_selector" || callVariant == "payload_ptr_selector") && selectorValue == nil {
                return badRequest("missing --selector <u64> (required for --call-variant \(callVariant))")
            }

            let symbolName = "sandbox_extension_update_file_by_fileid"
            details["call_symbol"] = symbolName
            guard let sym = resolveSandboxExtensionSymbol(symbolName) else {
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "symbol_missing",
                    errno: nil,
                    error: "\(symbolName) symbol not found via dlsym(RTLD_DEFAULT, \"\(symbolName)\")",
                    details: details,
                    layer_attribution: nil
                )
            }

            if let fileId {
                details["file_id"] = "\(fileId)"
                details["file_id_hex"] = String(format: "0x%llx", fileId)
                let low32 = UInt32(truncatingIfNeeded: fileId)
                details["file_id_low32"] = "\(low32)"
                details["file_id_low32_hex"] = String(format: "0x%08x", low32)
            }

            func callUpdateByFileid(_ variant: String) -> (Int32, Int32) {
                errno = 0
                let idValue = fileId ?? 0
                var idValueCopy = idValue
                let rc: Int32 = withUnsafePointer(to: &idValueCopy) { idPtr in
                    tokenUsed.withCString { tokenPtr in
                        switch variant {
                        case "payload_ptr_selector", "fileid_ptr_selector":
                            guard let selectorValue else {
                                return -1
                            }
                            let fn = unsafeBitCast(sym, to: SandboxExtensionUpdateFileByFileidPtrValueFn.self)
                            return fn(idPtr, selectorValue, 0)
                        case "fileid_ptr_token":
                            let fn = unsafeBitCast(sym, to: SandboxExtensionUpdateFileByFileidPtrFn.self)
                            return fn(idPtr, tokenPtr, flags)
                        case "token_ptr_fileid":
                            let fn = unsafeBitCast(sym, to: SandboxExtensionUpdateFileByFileidPtrAltFn.self)
                            return fn(tokenPtr, idPtr, flags)
                        case "fileid_token":
                            let fn = unsafeBitCast(sym, to: SandboxExtensionUpdateFileByFileidAltFn.self)
                            return fn(idValue, tokenPtr, flags)
                        default:
                            let fn = unsafeBitCast(sym, to: SandboxExtensionUpdateFileByFileidFn.self)
                            return fn(tokenPtr, idValue, flags)
                        }
                    }
                }
                return (rc, errno)
            }

            var rc: Int32 = -1
            var callErrno: Int32 = 0
            var selectedVariant: String? = nil
            if callVariant == "auto" {
                var variants: [String] = []
                if selectorValue != nil {
                    variants.append("payload_ptr_selector")
                }
                variants.append(contentsOf: ["fileid_ptr_token", "token_fileid", "fileid_token", "token_ptr_fileid"])
                for variant in variants {
                    let (rcCandidate, errnoCandidate) = callUpdateByFileid(variant)
                    details["variant_\(variant)_rc"] = "\(rcCandidate)"
                    details["variant_\(variant)_errno"] = "\(errnoCandidate)"
                    rc = rcCandidate
                    callErrno = errnoCandidate
                    if rcCandidate == 0 {
                        selectedVariant = variant
                        break
                    }
                }
            } else {
                let (rcCandidate, errnoCandidate) = callUpdateByFileid(callVariant)
                rc = rcCandidate
                callErrno = errnoCandidate
                selectedVariant = callVariant
            }

            details["call_variant_selected"] = selectedVariant ?? "none"
            if selectedVariant == "payload_ptr_selector" || selectedVariant == "fileid_ptr_selector" {
                details["call_flags_forced_zero"] = "true"
            }
            details["call_rc"] = "\(rc)"

            if rc != 0 {
                var e = callErrno
                if e == 0 && rc > 0 {
                    e = rc
                }
                let outcome: String
                if e == EINVAL {
                    outcome = "invalid_token"
                    details["token_state"] = "invalid"
                } else if e == EPERM || e == EACCES {
                    outcome = "permission_error"
                } else {
                    outcome = "update_failed"
                }
                let errorMsg = (e > 0) ? String(cString: strerror(e)) : "\(symbolName) returned \(rc)"
                return RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: outcome,
                    errno: e > 0 ? Int(e) : nil,
                    error: errorMsg,
                    details: details,
                    layer_attribution: nil
                )
            }

	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "update_ok",
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

	        case .update_file_by_fileid_sweep:
	            guard let extClass = args.value("--class"), !extClass.isEmpty else {
	                return badRequest("missing --class <extension-class>")
	            }

	            let allowUnsafe = args.has("--allow-unsafe-path")
	            let directPath = args.value("--path")
	            let pathClass = args.value("--path-class")
	            if (directPath == nil) == (pathClass == nil) {
	                return badRequest("provide exactly one of --path or --path-class")
	            }

	            let targetStr = args.value("--target")
	            let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? .specimen_file
	            if target == .harness_dir || target == .run_dir || target == .base {
	                return badRequest("update_file_by_fileid_sweep requires a file target (use --target specimen_file)")
	            }
	            let create = args.has("--create")

	            if args.has("--flags"), args.intValue("--flags") == nil {
	                return badRequest("invalid --flags (expected integer)")
	            }
	            let issueFlags = Int32(args.intValue("--flags") ?? 0)

	            let selectorsRaw = args.value("--selectors") ?? "0,1,2"
	            let includeTokenFields = args.has("--include-token-fields")
	            let noCleanup = args.has("--no-cleanup")

	            details["extension_class"] = extClass
	            details["issue_flags"] = "\(issueFlags)"
	            details["allow_unsafe_path"] = allowUnsafe ? "true" : "false"
	            details["create"] = create ? "true" : "false"
	            details["selectors"] = selectorsRaw
	            details["include_token_fields"] = includeTokenFields ? "true" : "false"
	            details["no_cleanup"] = noCleanup ? "true" : "false"

	            func parseU64List(_ raw: String) -> [UInt64]? {
	                let parts = raw.split { $0 == "," || $0 == " " || $0 == "\t" || $0 == "\n" || $0 == ";" }
	                var out: [UInt64] = []
	                out.reserveCapacity(parts.count)
	                for p in parts {
	                    guard let v = UInt64(p) else { return nil }
	                    if !out.contains(v) {
	                        out.append(v)
	                    }
	                }
	                return out.isEmpty ? nil : out
	            }

	            guard let selectors = parseU64List(selectorsRaw) else {
	                return badRequest("invalid --selectors (expected comma-separated u64 list)")
	            }

	            let (resolvedTarget, resolveErr) = resolveFsTarget(
	                directPath: directPath,
	                pathClass: pathClass,
	                target: target,
	                requestedName: args.value("--name")
	            )
	            if let resolveErr { return resolveErr }
	            guard let resolvedTarget else {
	                return badRequest("internal: failed to resolve target path")
	            }

	            let targetPath = resolvedTarget.path
	            details["path_mode"] = (directPath != nil) ? "direct_path" : "path_class"
	            details["path_class"] = pathClass ?? ""
	            details["target"] = target.rawValue
	            details["file_path"] = targetPath
	            details["base_dir"] = resolvedTarget.baseDir ?? ""
	            details["harness_dir"] = resolvedTarget.harnessDir ?? ""
	            details["run_dir"] = resolvedTarget.runDir ?? ""

	            if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
	                return RunProbeResponse(
	                    rc: 2,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "bad_request",
	                    errno: nil,
	                    error: "refusing to run update_file_by_fileid_sweep for non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            func statForPath(_ path: String) -> (stat?, Int32?) {
	                var st = stat()
	                if stat(path, &st) != 0 {
	                    return (nil, errno)
	                }
	                return (st, nil)
	            }

	            var isDir: ObjCBool = false
	            let exists = FileManager.default.fileExists(atPath: targetPath, isDirectory: &isDir)
	            if exists && isDir.boolValue {
	                return badRequest("target path is a directory; update_file_by_fileid_sweep requires a file target")
	            }
	            if !exists {
	                if !create {
	                    return badRequest("target file does not exist (pass --create to create it under the harness)")
	                }
	                do {
	                    let url = URL(fileURLWithPath: targetPath)
	                    let parent = url.deletingLastPathComponent()
	                    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
	                    let payload = Data("policy-witness sandbox_extension sweep\n".utf8)
	                    try payload.write(to: url, options: [.atomic])
	                    details["target_created"] = "true"
	                } catch {
	                    let e = extractErrno(error)
	                    let outcome = isPermissionError(error) ? "permission_error" : "create_failed"
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: outcome,
	                        errno: e,
	                        error: "\(error)",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	            } else {
	                details["target_created"] = "false"
	            }

	            let (stOpt, stErrOpt) = statForPath(targetPath)
	            guard let st = stOpt else {
	                let e = stErrOpt ?? errno
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "stat_failed",
	                    errno: Int(e),
	                    error: String(cString: strerror(e)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            details["stat_dev"] = "\(st.st_dev)"
	            details["stat_dev_hex"] = String(format: "0x%llx", st.st_dev)
	            details["stat_ino"] = "\(st.st_ino)"
	            details["stat_ino_hex"] = String(format: "0x%llx", st.st_ino)

	            // Issue an extension token for the current path.
	            let issueSymbol = "sandbox_extension_issue_file"
	            details["issue_symbol"] = issueSymbol
	            guard let issueSym = resolveSandboxExtensionSymbol(issueSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(issueSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(issueSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            errno = 0
	            let tokenPtr = extClass.withCString { classPtr in
	                targetPath.withCString { pathPtr in
	                    let issueFn = unsafeBitCast(issueSym, to: SandboxExtensionIssueFileFn.self)
	                    return issueFn(classPtr, pathPtr, issueFlags)
	                }
	            }
	            let issueErrno = errno
	            guard let tokenPtr else {
	                let outcome = (issueErrno == EPERM || issueErrno == EACCES) ? "permission_error" : "issue_failed"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: Int(issueErrno),
	                    error: String(cString: strerror(issueErrno)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            let token = String(cString: tokenPtr)
	            details["token_len"] = "\(token.utf8.count)"
	            if let idx = token.firstIndex(of: ";") {
	                details["token_prefix"] = String(token[..<idx])
	            }
	            let tokenFields = token.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
	            details["token_fields_count"] = "\(tokenFields.count)"

	            if let freeSym = resolveSandboxExtensionSymbol("sandbox_extension_free") {
	                let freeFn = unsafeBitCast(freeSym, to: SandboxExtensionFreeFn.self)
	                freeFn(tokenPtr)
	            } else {
	                free(UnsafeMutableRawPointer(tokenPtr))
	            }

	            // Consume the token to obtain a handle.
	            let consumeSymbol = "sandbox_extension_consume"
	            details["consume_symbol"] = consumeSymbol
	            guard let consumeSym = resolveSandboxExtensionSymbol(consumeSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(consumeSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(consumeSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            errno = 0
	            let consumeHandle: Int64 = token.withCString { tokenCStr in
	                let fn = unsafeBitCast(consumeSym, to: SandboxExtensionConsumeHandleFn.self)
	                return fn(tokenCStr)
	            }
	            let consumeErrno = errno
	            details["consume_handle"] = "\(consumeHandle)"
	            details["consume_handle_hex"] = String(format: "0x%016llx", UInt64(bitPattern: consumeHandle))
	            let consumeLow32 = UInt32(truncatingIfNeeded: consumeHandle)
	            let consumeHigh32 = UInt32(truncatingIfNeeded: UInt64(bitPattern: consumeHandle) >> 32)
	            details["consume_handle_low32"] = "\(consumeLow32)"
	            details["consume_handle_low32_hex"] = String(format: "0x%08x", consumeLow32)
	            details["consume_handle_high32"] = "\(consumeHigh32)"
	            details["consume_handle_high32_hex"] = String(format: "0x%08x", consumeHigh32)
	            if consumeHandle <= 0 {
	                let outcome: String
	                if consumeErrno == EEXIST {
	                    outcome = "already_consumed"
	                } else if consumeErrno == EINVAL {
	                    outcome = "invalid_token"
	                } else if consumeErrno == EPERM || consumeErrno == EACCES {
	                    outcome = "permission_error"
	                } else {
	                    outcome = "consume_failed"
	                }
	                let errorMsg = consumeErrno != 0 ? String(cString: strerror(consumeErrno)) : "consume returned handle=\(consumeHandle)"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: consumeErrno != 0 ? Int(consumeErrno) : nil,
	                    error: errorMsg,
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            // Candidate payloads: handle-derived + stat; optionally token numeric fields.
	            var candidates: [(String, UInt64)] = [
	                ("consume_handle_low32", UInt64(consumeLow32)),
	                ("consume_handle_high32", UInt64(consumeHigh32)),
	                ("consume_handle_xor32", UInt64(consumeLow32 ^ consumeHigh32)),
	                ("st_dev", UInt64(truncatingIfNeeded: st.st_dev)),
	                ("st_ino", UInt64(truncatingIfNeeded: st.st_ino)),
	            ]

	            if includeTokenFields {
	                func parseU64Maybe(_ s: String) -> UInt64? {
	                    if s.hasPrefix("0x") || s.hasPrefix("0X") {
	                        return UInt64(s.dropFirst(2), radix: 16)
	                    }
	                    return UInt64(s)
	                }
	                let maxFields = min(16, tokenFields.count)
	                details["token_fields_included_max"] = "\(maxFields)"
	                for i in 0..<maxFields {
	                    let fieldStr = tokenFields[i]
	                    if let v = parseU64Maybe(fieldStr) {
	                        candidates.append(("token_field_\(i)", v))
	                    }
	                }
	            }

	            details["sweep_candidate_count"] = "\(candidates.count)"
	            for (i, (name, value)) in candidates.enumerated() {
	                details["sweep_candidate_\(i)_name"] = name
	                details["sweep_candidate_\(i)_value"] = "\(value)"
	                details["sweep_candidate_\(i)_value_hex"] = String(format: "0x%llx", value)
	                let low32 = UInt32(truncatingIfNeeded: value)
	                details["sweep_candidate_\(i)_low32"] = "\(low32)"
	                details["sweep_candidate_\(i)_low32_hex"] = String(format: "0x%08x", low32)
	            }

	            let updateSymbol = "sandbox_extension_update_file_by_fileid"
	            details["update_symbol"] = updateSymbol
	            guard let updateSym = resolveSandboxExtensionSymbol(updateSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(updateSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(updateSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            var anyOk = false
	            var anyNonEinval = false
	            for (i, (_, value)) in candidates.enumerated() {
	                for sel in selectors {
	                    var payloadCopy = value
	                    errno = 0
	                    let rcCandidate: Int32 = withUnsafePointer(to: &payloadCopy) { payloadPtr in
	                        let fn = unsafeBitCast(updateSym, to: SandboxExtensionUpdateFileByFileidPtrValueFn.self)
	                        return fn(payloadPtr, sel, 0)
	                    }
	                    let err = errno
	                    let normErr: Int32 = (err != 0) ? err : ((rcCandidate > 0) ? rcCandidate : 0)
	                    details["sweep_candidate_\(i)_sel_\(sel)_rc"] = "\(rcCandidate)"
	                    details["sweep_candidate_\(i)_sel_\(sel)_errno"] = "\(err)"
	                    details["sweep_candidate_\(i)_sel_\(sel)_norm_errno"] = "\(normErr)"
	                    if normErr != 0 {
	                        details["sweep_candidate_\(i)_sel_\(sel)_error"] = String(cString: strerror(normErr))
	                    } else {
	                        details["sweep_candidate_\(i)_sel_\(sel)_error"] = ""
	                    }

	                    let cls: String
	                    if rcCandidate == 0 {
	                        cls = "ok"
	                        anyOk = true
	                    } else if normErr == EINVAL {
	                        cls = "einval"
	                    } else if normErr == EFAULT {
	                        cls = "efault"
	                    } else if normErr != 0 {
	                        cls = "errno_\(normErr)"
	                        anyNonEinval = true
	                    } else {
	                        cls = "rc_\(rcCandidate)"
	                    }
	                    details["sweep_candidate_\(i)_sel_\(sel)_class"] = cls
	                }
	            }

	            // Best-effort cleanup: release the consumed handle.
	            if !noCleanup {
	                let releaseSymbol = "sandbox_extension_release"
	                details["cleanup_release_symbol"] = releaseSymbol
	                if let releaseSym = resolveSandboxExtensionSymbol(releaseSymbol) {
	                    errno = 0
	                    let rcRelease: Int32 = {
	                        let fn = unsafeBitCast(releaseSym, to: SandboxExtensionReleaseHandleFn.self)
	                        return fn(consumeHandle)
	                    }()
	                    details["cleanup_release_rc"] = "\(rcRelease)"
	                    details["cleanup_release_errno"] = "\(errno)"
	                    if errno != 0 {
	                        details["cleanup_release_error"] = String(cString: strerror(errno))
	                    } else {
	                        details["cleanup_release_error"] = ""
	                    }
	                } else {
	                    details["cleanup_release_symbol_missing"] = "true"
	                }
	            }

	            let outcome: String
	            if anyOk {
	                outcome = "found_ok"
	            } else if anyNonEinval {
	                outcome = "found_non_einval"
	            } else {
	                outcome = "all_einval"
	            }
	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

	        case .update_file_by_fileid_delta:
	            guard let extClass = args.value("--class"), !extClass.isEmpty else {
	                return badRequest("missing --class <extension-class>")
	            }

	            let allowUnsafe = args.has("--allow-unsafe-path")
	            let directPath = args.value("--path")
	            let pathClass = args.value("--path-class")
	            if (directPath == nil) == (pathClass == nil) {
	                return badRequest("provide exactly one of --path or --path-class")
	            }

	            let targetStr = args.value("--target")
	            let target: FsTarget = targetStr.flatMap { FsTarget(rawValue: $0) } ?? .specimen_file
	            if target == .harness_dir || target == .run_dir || target == .base {
	                return badRequest("update_file_by_fileid_delta requires a file target (use --target specimen_file)")
	            }
	            let create = args.has("--create")

	            if args.has("--flags"), args.intValue("--flags") == nil {
	                return badRequest("invalid --flags (expected integer)")
	            }
	            let issueFlags = Int32(args.intValue("--flags") ?? 0)

	            var selectorValue: UInt64 = 2
	            if let selectorStr = args.value("--selector"), !selectorStr.isEmpty {
	                guard let parsed = UInt64(selectorStr) else {
	                    return badRequest("invalid --selector (expected u64)")
	                }
	                selectorValue = parsed
	            }
	            details["selector"] = "\(selectorValue)"
	            details["selector_hex"] = String(format: "0x%llx", selectorValue)

	            let payloadSource = args.value("--payload-source") ?? "st_dev"
	            let payloadArg = args.value("--payload")
	            let sandboxOp = args.value("--sandbox-op") ?? "file-read-data"
	            let skipUpdate = args.has("--skip-update")
	            let noCleanup = args.has("--no-cleanup")
	            let waitForExternalReplace = args.has("--wait-for-external-replace")
	            let waitTimeoutMs = max(0, min(600_000, args.intValue("--wait-timeout-ms") ?? 30_000))
	            let waitIntervalMs = max(1, min(10_000, args.intValue("--wait-interval-ms") ?? 50))

	            details["extension_class"] = extClass
	            details["issue_flags"] = "\(issueFlags)"
	            details["payload_source"] = payloadSource
	            details["payload_arg"] = payloadArg ?? ""
	            details["sandbox_op"] = sandboxOp
	            details["skip_update"] = skipUpdate ? "true" : "false"
	            details["no_cleanup"] = noCleanup ? "true" : "false"
	            details["wait_for_external_replace"] = waitForExternalReplace ? "true" : "false"
	            details["wait_timeout_ms"] = "\(waitTimeoutMs)"
	            details["wait_interval_ms"] = "\(waitIntervalMs)"

	            let (resolvedTarget, resolveErr) = resolveFsTarget(
	                directPath: directPath,
	                pathClass: pathClass,
	                target: target,
	                requestedName: args.value("--name")
	            )
	            if let resolveErr { return resolveErr }
	            guard let resolvedTarget else {
	                return badRequest("internal: failed to resolve target path")
	            }

	            let targetPath = resolvedTarget.path
	            details["path_mode"] = (directPath != nil) ? "direct_path" : "path_class"
	            details["path_class"] = pathClass ?? ""
	            details["target"] = target.rawValue
	            details["file_path"] = targetPath
	            details["base_dir"] = resolvedTarget.baseDir ?? ""
	            details["harness_dir"] = resolvedTarget.harnessDir ?? ""
	            details["run_dir"] = resolvedTarget.runDir ?? ""
	            details["allow_unsafe_path"] = allowUnsafe ? "true" : "false"
	            details["create"] = create ? "true" : "false"

	            if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
	                return RunProbeResponse(
	                    rc: 2,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "bad_request",
	                    errno: nil,
	                    error: "refusing to run update_file_by_fileid_delta for non-harness path (use --path-class <...> or a path under */policy-witness-harness/*; use --allow-unsafe-path to override)",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            func statForPath(_ path: String) -> (stat?, Int32?) {
	                var st = stat()
	                if stat(path, &st) != 0 {
	                    return (nil, errno)
	                }
	                return (st, nil)
	            }

	            var isDir: ObjCBool = false
	            let exists = FileManager.default.fileExists(atPath: targetPath, isDirectory: &isDir)
	            if exists && isDir.boolValue {
	                return badRequest("target path is a directory; update_file_by_fileid_delta requires a file target")
	            }
	            if !exists {
	                if !create {
	                    return badRequest("target file does not exist (pass --create to create it under the harness)")
	                }
	                do {
	                    let url = URL(fileURLWithPath: targetPath)
	                    let parent = url.deletingLastPathComponent()
	                    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
	                    let payload = Data("policy-witness sandbox_extension delta\n".utf8)
	                    try payload.write(to: url, options: [.atomic])
	                    details["target_created"] = "true"
	                } catch {
	                    let e = extractErrno(error)
	                    let outcome = isPermissionError(error) ? "permission_error" : "create_failed"
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: outcome,
	                        errno: e,
	                        error: "\(error)",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	            } else {
	                details["target_created"] = "false"
	            }

	            let (stBeforeOpt, stBeforeErrnoOpt) = statForPath(targetPath)
	            guard let stBefore = stBeforeOpt else {
	                let e = stBeforeErrnoOpt ?? errno
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "stat_failed",
	                    errno: Int(e),
	                    error: String(cString: strerror(e)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            details["stat_before_dev"] = "\(stBefore.st_dev)"
	            details["stat_before_dev_hex"] = String(format: "0x%llx", stBefore.st_dev)
	            details["stat_before_ino"] = "\(stBefore.st_ino)"
	            details["stat_before_ino_hex"] = String(format: "0x%llx", stBefore.st_ino)

	            func sandboxCheckRc(operation: String, path: String) -> Int32? {
	                guard let sym = resolveSandboxCheckSymbol() else { return nil }
	                return operation.withCString { opPtr in
	                    path.withCString { pathPtr in
	                        let fn = unsafeBitCast(sym, to: SandboxCheckPathFn.self)
	                        return fn(getpid(), opPtr, 1, pathPtr)
	                    }
	                }
	            }

	            func openReadRc(path: String) -> (Int32, Int32?) {
	                let (fd, e): (Int32, Int32?) = path.withCString { pathPtr in
	                    errno = 0
	                    let fd = open(pathPtr, O_RDONLY)
	                    if fd >= 0 {
	                        return (fd, nil)
	                    }
	                    return (-1, errno)
	                }
	                guard fd >= 0 else {
	                    return (1, e)
	                }
	                var b: UInt8 = 0
	                errno = 0
	                let n = Darwin.read(fd, &b, 1)
	                let readErrno = (n < 0) ? errno : 0
	                close(fd)
	                if n < 0 {
	                    return (1, readErrno)
	                }
	                return (0, nil)
	            }

	            func recordAccess(phase: String) -> (Bool, Bool) {
	                let (openRc, openErrno) = openReadRc(path: targetPath)
	                details["access_\(phase)_open_rc"] = "\(openRc)"
	                if let openErrno {
	                    details["access_\(phase)_open_errno"] = "\(openErrno)"
	                    details["access_\(phase)_open_error"] = String(cString: strerror(openErrno))
	                } else {
	                    details["access_\(phase)_open_errno"] = ""
	                    details["access_\(phase)_open_error"] = ""
	                }

	                let sbRc = sandboxCheckRc(operation: sandboxOp, path: targetPath)
	                if let sbRc {
	                    details["access_\(phase)_sandbox_check_rc"] = "\(sbRc)"
	                    details["access_\(phase)_sandbox_check_outcome"] = (sbRc == 0) ? "allow" : (sbRc == 1) ? "deny" : "rc_nonstandard"
	                } else {
	                    details["access_\(phase)_sandbox_check_rc"] = "missing"
	                    details["access_\(phase)_sandbox_check_outcome"] = "missing"
	                }

	                let openOk = (openRc == 0)
	                let sbOk = (sbRc == 0)
	                return (openOk, sbOk)
	            }

	            let (openPreConsumeOk, sbPreConsumeOk) = recordAccess(phase: "pre_consume")

	            // Issue an extension token for the current path.
	            let issueSymbol = "sandbox_extension_issue_file"
	            details["issue_symbol"] = issueSymbol
	            guard let issueSym = resolveSandboxExtensionSymbol(issueSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(issueSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(issueSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            errno = 0
	            let tokenPtr = extClass.withCString { classPtr in
	                targetPath.withCString { pathPtr in
	                    let issueFn = unsafeBitCast(issueSym, to: SandboxExtensionIssueFileFn.self)
	                    return issueFn(classPtr, pathPtr, issueFlags)
	                }
	            }
	            let issueErrno = errno
	            guard let tokenPtr else {
	                let outcome = (issueErrno == EPERM || issueErrno == EACCES) ? "permission_error" : "issue_failed"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: Int(issueErrno),
	                    error: String(cString: strerror(issueErrno)),
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            let token = String(cString: tokenPtr)
	            details["token_len"] = "\(token.utf8.count)"
	            if let idx = token.firstIndex(of: ";") {
	                details["token_prefix"] = String(token[..<idx])
	            }
	            details["token_fields_count"] = "\(token.split(separator: ";", omittingEmptySubsequences: false).count)"

	            if let freeSym = resolveSandboxExtensionSymbol("sandbox_extension_free") {
	                let freeFn = unsafeBitCast(freeSym, to: SandboxExtensionFreeFn.self)
	                freeFn(tokenPtr)
	            } else {
	                free(UnsafeMutableRawPointer(tokenPtr))
	            }

	            // Consume the token to obtain a handle.
	            let consumeSymbol = "sandbox_extension_consume"
	            details["consume_symbol"] = consumeSymbol
	            guard let consumeSym = resolveSandboxExtensionSymbol(consumeSymbol) else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "symbol_missing",
	                    errno: nil,
	                    error: "\(consumeSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(consumeSymbol)\")",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            errno = 0
	            let consumeHandle: Int64 = token.withCString { tokenCStr in
	                let fn = unsafeBitCast(consumeSym, to: SandboxExtensionConsumeHandleFn.self)
	                return fn(tokenCStr)
	            }
	            let consumeErrno = errno
	            details["consume_handle"] = "\(consumeHandle)"
	            details["consume_handle_hex"] = String(format: "0x%016llx", UInt64(bitPattern: consumeHandle))
	            let consumeLow32 = UInt32(truncatingIfNeeded: consumeHandle)
	            let consumeHigh32 = UInt32(truncatingIfNeeded: UInt64(bitPattern: consumeHandle) >> 32)
	            details["consume_handle_low32"] = "\(consumeLow32)"
	            details["consume_handle_low32_hex"] = String(format: "0x%08x", consumeLow32)
	            details["consume_handle_high32"] = "\(consumeHigh32)"
	            details["consume_handle_high32_hex"] = String(format: "0x%08x", consumeHigh32)
	            if consumeHandle <= 0 {
	                let outcome: String
	                if consumeErrno == EEXIST {
	                    outcome = "already_consumed"
	                } else if consumeErrno == EINVAL {
	                    outcome = "invalid_token"
	                } else if consumeErrno == EPERM || consumeErrno == EACCES {
	                    outcome = "permission_error"
	                } else {
	                    outcome = "consume_failed"
	                }
	                let errorMsg = consumeErrno != 0 ? String(cString: strerror(consumeErrno)) : "consume returned handle=\(consumeHandle)"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: consumeErrno != 0 ? Int(consumeErrno) : nil,
	                    error: errorMsg,
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            let (openBeforeOk, sbBeforeOk) = recordAccess(phase: "before_replace")

	            var stAfterReplaceOpt: stat? = nil
	            if waitForExternalReplace {
	                let waitStartNs = DispatchTime.now().uptimeNanoseconds
	                details["wait_started_at_ns"] = "\(waitStartNs)"
	                let deadlineNs = waitStartNs + UInt64(waitTimeoutMs) * 1_000_000
	                var lastStatErrno: Int32? = nil
	                var lastIno: UInt64? = nil
	                while true {
	                    let (stCandidateOpt, stCandidateErrnoOpt) = statForPath(targetPath)
	                    if let stCandidate = stCandidateOpt {
	                        let ino = UInt64(stCandidate.st_ino)
	                        lastIno = ino
	                        if ino != UInt64(stBefore.st_ino) {
	                            stAfterReplaceOpt = stCandidate
	                            break
	                        }
	                    } else {
	                        lastStatErrno = stCandidateErrnoOpt
	                    }
	                    let now = DispatchTime.now().uptimeNanoseconds
	                    if now >= deadlineNs {
	                        details["wait_last_ino"] = lastIno.map { "\($0)" } ?? ""
	                        if let lastStatErrno {
	                            details["wait_last_stat_errno"] = "\(lastStatErrno)"
	                            details["wait_last_stat_error"] = String(cString: strerror(lastStatErrno))
	                        }
	                        return RunProbeResponse(
	                            rc: 1,
	                            stdout: "",
	                            stderr: "",
	                            normalized_outcome: "wait_timeout",
	                            errno: nil,
	                            error: "timed out waiting for external inode change at: \(targetPath)",
	                            details: details,
	                            layer_attribution: nil
	                        )
	                    }
	                    usleep(useconds_t(waitIntervalMs * 1000))
	                }
	                let waitEndNs = DispatchTime.now().uptimeNanoseconds
	                details["wait_ended_at_ns"] = "\(waitEndNs)"
	                details["wait_duration_ms"] = "\(Int((waitEndNs - waitStartNs) / 1_000_000))"
	            } else {
	                // Identity perturbation: atomic replace via rename(2) in the same directory.
	                let tmpPath = targetPath + ".tmp." + UUID().uuidString
	                do {
	                    let tmpURL = URL(fileURLWithPath: tmpPath)
	                    let payload = Data("policy-witness sandbox_extension delta replace\n".utf8)
	                    try payload.write(to: tmpURL, options: [.atomic])
	                } catch {
	                    let e = extractErrno(error)
	                    let outcome = isPermissionError(error) ? "permission_error" : "replace_prepare_failed"
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: outcome,
	                        errno: e,
	                        error: "failed to write temp file for replace: \(error)",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }

	                errno = 0
	                if Darwin.rename(tmpPath, targetPath) != 0 {
	                    let e = errno
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "replace_failed",
	                        errno: Int(e),
	                        error: String(cString: strerror(e)),
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }

	                let (stAfterReplaceCandidateOpt, stAfterReplaceErrnoOpt) = statForPath(targetPath)
	                guard let stCandidate = stAfterReplaceCandidateOpt else {
	                    let e = stAfterReplaceErrnoOpt ?? errno
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "stat_failed",
	                        errno: Int(e),
	                        error: String(cString: strerror(e)),
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	                stAfterReplaceOpt = stCandidate
	            }
	            guard let stAfterReplace = stAfterReplaceOpt else {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "internal_error",
	                    errno: nil,
	                    error: "internal: missing stat_after_replace",
	                    details: details,
	                    layer_attribution: nil
	                )
	            }
	            details["stat_after_replace_dev"] = "\(stAfterReplace.st_dev)"
	            details["stat_after_replace_dev_hex"] = String(format: "0x%llx", stAfterReplace.st_dev)
	            details["stat_after_replace_ino"] = "\(stAfterReplace.st_ino)"
	            details["stat_after_replace_ino_hex"] = String(format: "0x%llx", stAfterReplace.st_ino)
	            let inoChanged = (stBefore.st_ino != stAfterReplace.st_ino)
	            details["replace_inode_changed"] = inoChanged ? "true" : "false"

	            let (openAfterReplaceOk, sbAfterReplaceOk) = recordAccess(phase: "after_replace_before_update")

	            if !skipUpdate {
	                let payloadValue: UInt64
	                if let payloadArg, !payloadArg.isEmpty {
	                    guard let parsed = UInt64(payloadArg) else {
	                        return badRequest("invalid --payload (expected u64)")
	                    }
	                    payloadValue = parsed
	                    details["payload_value_source"] = "arg"
	                } else {
	                    switch payloadSource {
	                    case "st_dev":
	                        payloadValue = UInt64(truncatingIfNeeded: stBefore.st_dev)
	                    case "st_ino":
	                        payloadValue = UInt64(truncatingIfNeeded: stBefore.st_ino)
	                    case "handle_low32":
	                        payloadValue = UInt64(consumeLow32)
	                    case "handle_high32":
	                        payloadValue = UInt64(consumeHigh32)
	                    case "handle_xor32":
	                        payloadValue = UInt64(consumeLow32 ^ consumeHigh32)
	                    default:
	                        return badRequest("invalid --payload-source (expected: st_dev|st_ino|handle_low32|handle_high32|handle_xor32)")
	                    }
	                    details["payload_value_source"] = payloadSource
	                }

	                details["payload_value"] = "\(payloadValue)"
	                details["payload_value_hex"] = String(format: "0x%llx", payloadValue)
	                let payloadLow32 = UInt32(truncatingIfNeeded: payloadValue)
	                details["payload_value_low32"] = "\(payloadLow32)"
	                details["payload_value_low32_hex"] = String(format: "0x%08x", payloadLow32)

	                let updateSymbol = "sandbox_extension_update_file_by_fileid"
	                details["update_symbol"] = updateSymbol
	                guard let updateSym = resolveSandboxExtensionSymbol(updateSymbol) else {
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "symbol_missing",
	                        errno: nil,
	                        error: "\(updateSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(updateSymbol)\")",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }

	                var payloadCopy = payloadValue
	                errno = 0
	                let rcCandidate: Int32 = withUnsafePointer(to: &payloadCopy) { payloadPtr in
	                    let fn = unsafeBitCast(updateSym, to: SandboxExtensionUpdateFileByFileidPtrValueFn.self)
	                    return fn(payloadPtr, selectorValue, 0)
	                }
	                details["update_call_variant"] = "payload_ptr_selector"
	                details["update_call_rc"] = "\(rcCandidate)"
	                details["update_call_errno"] = "\(errno)"
	                if errno != 0 {
	                    details["update_call_error"] = String(cString: strerror(errno))
	                } else {
	                    details["update_call_error"] = ""
	                }
	            }

	            let (openAfterUpdateOk, sbAfterUpdateOk) = recordAccess(phase: "after_update")

	            // Best-effort cleanup: release the consumed handle.
	            if !noCleanup {
	                let releaseSymbol = "sandbox_extension_release"
	                details["cleanup_release_symbol"] = releaseSymbol
	                if let releaseSym = resolveSandboxExtensionSymbol(releaseSymbol) {
	                    errno = 0
	                    let rcRelease: Int32 = {
	                        let fn = unsafeBitCast(releaseSym, to: SandboxExtensionReleaseHandleFn.self)
	                        return fn(consumeHandle)
	                    }()
	                    details["cleanup_release_rc"] = "\(rcRelease)"
	                    details["cleanup_release_errno"] = "\(errno)"
	                    if errno != 0 {
	                        details["cleanup_release_error"] = String(cString: strerror(errno))
	                    } else {
	                        details["cleanup_release_error"] = ""
	                    }
	                } else {
	                    details["cleanup_release_symbol_missing"] = "true"
	                }
	            }

	            let openTransition = "\(openPreConsumeOk ? "allow" : "deny")->\(openBeforeOk ? "allow" : "deny")->\(openAfterReplaceOk ? "allow" : "deny")->\(openAfterUpdateOk ? "allow" : "deny")"
	            let sbTransition = "\(sbPreConsumeOk ? "allow" : "deny")->\(sbBeforeOk ? "allow" : "deny")->\(sbAfterReplaceOk ? "allow" : "deny")->\(sbAfterUpdateOk ? "allow" : "deny")"
	            details["delta_open_transition"] = openTransition
	            details["delta_sandbox_check_transition"] = sbTransition

	            let outcome: String
	            if !inoChanged {
	                outcome = "replace_no_inode_change"
	            } else if !openBeforeOk {
	                outcome = "baseline_open_denied"
	            } else if openAfterReplaceOk {
	                outcome = "no_break"
	            } else if skipUpdate {
	                outcome = "broken_no_update"
	            } else if openAfterUpdateOk {
	                outcome = "restored"
	            } else {
	                outcome = "not_restored"
	            }

	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

	        case .consume:
	            guard let rawToken = args.value("--token"), !rawToken.isEmpty else {
	                return badRequest("missing --token <token>")
	            }
	            if args.has("--handle") {
	                return badRequest("--handle is not supported with --op consume")
	            }
	            let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
	            let tokenFormat = args.value("--token-format") ?? "full"
	            var tokenUsed = token
	            if tokenFormat == "prefix" {
	                if let idx = token.firstIndex(of: ";") {
	                    tokenUsed = String(token[..<idx])
	                }
	            } else if tokenFormat != "full" {
	                return badRequest("invalid --token-format (expected: full|prefix)")
	            }

	            if args.has("--flags"), args.intValue("--flags") == nil {
	                return badRequest("invalid --flags (expected integer)")
	            }
	            let callFlags = Int32(args.intValue("--flags") ?? 0)

	            let callVariant = args.value("--call-variant") ?? "auto"
	            let allowedVariants: Set<String> = ["handle_one_arg", "one_arg", "two_arg", "token_second", "token_and_ptr", "auto"]
	            if !allowedVariants.contains(callVariant) {
	                let allowed = allowedVariants.sorted().joined(separator: "|")
	                return badRequest("invalid --call-variant (expected: \(allowed))")
	            }

	            details["token_len"] = "\(token.utf8.count)"
	            details["token_used_len"] = "\(tokenUsed.utf8.count)"
	            details["token_format"] = tokenFormat
	            details["call_variant"] = callVariant
	            details["call_flags"] = "\(callFlags)"
	            if let idx = token.firstIndex(of: ";") {
	                details["token_prefix"] = String(token[..<idx])
	            }

	            let defaultSymbol = "sandbox_extension_consume"
	            let callSymbolArg = args.value("--call-symbol")
	            let callSymbolProvided = callSymbolArg != nil
	            let callSymbol = callSymbolArg ?? defaultSymbol
	            if callSymbol.isEmpty {
	                return badRequest("invalid --call-symbol (empty)")
	            }
	            details["call_symbol"] = callSymbol
	            if callSymbolProvided {
	                details["call_symbol_requested"] = callSymbol
	            }

	            var selectedHandle: Int64? = nil
	            var selectedSymbol: String? = nil
	            var selectedVariant: String? = nil
	            var rc: Int32 = -1
	            var callErrno: Int32 = 0
	            var attemptIndex = 0

	            func recordAttempt(symbolName: String, variant: String, rcCandidate: Int32, errnoCandidate: Int32, handleCandidate: Int64?) {
	                details["attempt_\(attemptIndex)_symbol"] = symbolName
	                details["attempt_\(attemptIndex)_variant"] = variant
	                details["attempt_\(attemptIndex)_rc"] = "\(rcCandidate)"
	                details["attempt_\(attemptIndex)_errno"] = "\(errnoCandidate)"
	                if let handleCandidate {
	                    details["attempt_\(attemptIndex)_handle"] = "\(handleCandidate)"
	                    details["attempt_\(attemptIndex)_handle_hex"] = String(format: "0x%016llx", UInt64(bitPattern: handleCandidate))
	                    let low32 = UInt32(truncatingIfNeeded: handleCandidate)
	                    let high32 = UInt32(truncatingIfNeeded: UInt64(bitPattern: handleCandidate) >> 32)
	                    details["attempt_\(attemptIndex)_handle_low32"] = "\(low32)"
	                    details["attempt_\(attemptIndex)_handle_low32_hex"] = String(format: "0x%08x", low32)
	                    details["attempt_\(attemptIndex)_handle_high32"] = "\(high32)"
	                    details["attempt_\(attemptIndex)_handle_high32_hex"] = String(format: "0x%08x", high32)
	                }
	                attemptIndex += 1
	            }

	            func shouldStopAuto(success: Bool, errnoCandidate: Int32, handleCandidate: Int64?) -> Bool {
	                if success {
	                    return true
	                }
	                if errnoCandidate == EEXIST {
	                    return true
	                }
	                if let handleCandidate, handleCandidate > 0 {
	                    return true
	                }
	                return false
	            }

	            func callConsumeWithVariant(_ sym: UnsafeMutableRawPointer, _ variant: String) -> (Bool, Int32, Int32, Int64?) {
	                switch variant {
	                case "handle_one_arg":
	                    errno = 0
	                    let handle: Int64 = tokenUsed.withCString { tokenPtr in
	                        let fn = unsafeBitCast(sym, to: SandboxExtensionConsumeHandleFn.self)
	                        return fn(tokenPtr)
	                    }
	                    let e = errno
	                    let ok = handle > 0
	                    return (ok, ok ? 0 : 1, e, handle)
	                case "one_arg":
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsed.withCString { tokenPtr in
	                        let fn = unsafeBitCast(sym, to: SandboxExtensionConsumeFn.self)
	                        return fn(tokenPtr)
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno, nil)
	                case "two_arg":
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsed.withCString { tokenPtr in
	                        let fn = unsafeBitCast(sym, to: SandboxExtensionConsumeFlagsFn.self)
	                        return fn(tokenPtr, callFlags)
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno, nil)
	                case "token_second":
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsed.withCString { tokenPtr in
	                        return "".withCString { emptyPtr in
	                            let fn = unsafeBitCast(sym, to: SandboxConsumeExtensionFn.self)
	                            return fn(emptyPtr, tokenPtr)
	                        }
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno, nil)
	                case "token_and_ptr":
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsed.withCString { tokenPtr in
	                        var tokenPtrVar: UnsafePointer<CChar>? = tokenPtr
	                        return withUnsafeMutablePointer(to: &tokenPtrVar) { tokenPtrPtr in
	                            let fn = unsafeBitCast(sym, to: SandboxConsumeFsExtensionFn.self)
	                            return fn(tokenPtr, tokenPtrPtr)
	                        }
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno, nil)
	                default:
	                    return (false, -1, 0, nil)
	                }
	            }

	            if callVariant == "auto" {
	                let attemptPlan: [(String, [String])]
	                if callSymbolProvided {
	                    let variants: [String]
	                    switch callSymbol {
	                    case "sandbox_extension_consume":
	                        variants = ["handle_one_arg", "one_arg", "two_arg"]
	                    case "sandbox_consume_extension":
	                        variants = ["token_second"]
	                    case "sandbox_consume_fs_extension":
	                        variants = ["token_and_ptr"]
	                    default:
	                        variants = ["handle_one_arg", "one_arg", "two_arg"]
	                    }
	                    attemptPlan = [(callSymbol, variants)]
	                } else {
	                    attemptPlan = [
	                        ("sandbox_extension_consume", ["handle_one_arg", "one_arg", "two_arg"]),
	                        ("sandbox_consume_extension", ["token_second"]),
	                        ("sandbox_consume_fs_extension", ["token_and_ptr"]),
	                    ]
	                }

	                var resolvedAny = false
	                outerLoop: for (symbolName, variants) in attemptPlan {
	                    guard let sym = resolveSandboxExtensionSymbol(symbolName) else { continue }
	                    resolvedAny = true
	                    for variant in variants {
	                        let (ok, rcCandidate, errnoCandidate, handleCandidate) = callConsumeWithVariant(sym, variant)
	                        recordAttempt(symbolName: symbolName, variant: variant, rcCandidate: rcCandidate, errnoCandidate: errnoCandidate, handleCandidate: handleCandidate)
	                        rc = rcCandidate
	                        callErrno = errnoCandidate
	                        selectedHandle = handleCandidate
	                        selectedSymbol = symbolName
	                        selectedVariant = variant
	                        if shouldStopAuto(success: ok, errnoCandidate: errnoCandidate, handleCandidate: handleCandidate) {
	                            break outerLoop
	                        }
	                    }
	                }

	                if !resolvedAny {
	                    let attemptedSymbols = attemptPlan.map { $0.0 }.joined(separator: ", ")
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "symbol_missing",
	                        errno: nil,
	                        error: "no sandbox extension symbols available (attempted: \(attemptedSymbols))",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	            } else {
	                guard let sym = resolveSandboxExtensionSymbol(callSymbol) else {
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "symbol_missing",
	                        errno: nil,
	                        error: "\(callSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(callSymbol)\")",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	                let (ok, rcCandidate, errnoCandidate, handleCandidate) = callConsumeWithVariant(sym, callVariant)
	                recordAttempt(symbolName: callSymbol, variant: callVariant, rcCandidate: rcCandidate, errnoCandidate: errnoCandidate, handleCandidate: handleCandidate)
	                rc = rcCandidate
	                callErrno = errnoCandidate
	                selectedHandle = handleCandidate
	                selectedSymbol = callSymbol
	                selectedVariant = callVariant
	                if ok {
	                    // success already captured
	                }
	            }

	            if let selectedSymbol {
	                details["call_symbol"] = selectedSymbol
	                details["call_symbol_selected"] = selectedSymbol
	            } else {
	                details["call_symbol"] = callSymbol
	                details["call_symbol_selected"] = "none"
	            }
	            details["call_variant_selected"] = selectedVariant ?? "none"
	            details["call_rc"] = "\(rc)"
	            if let selectedHandle {
	                details["consume_handle"] = "\(selectedHandle)"
	                details["consume_handle_hex"] = String(format: "0x%016llx", UInt64(bitPattern: selectedHandle))
	                let low32 = UInt32(truncatingIfNeeded: selectedHandle)
	                let high32 = UInt32(truncatingIfNeeded: UInt64(bitPattern: selectedHandle) >> 32)
	                details["consume_handle_low32"] = "\(low32)"
	                details["consume_handle_low32_hex"] = String(format: "0x%08x", low32)
	                details["consume_handle_high32"] = "\(high32)"
	                details["consume_handle_high32_hex"] = String(format: "0x%08x", high32)
	            }

	            let success = (selectedHandle.map { $0 > 0 } ?? (rc == 0))
	            if !success {
	                let e = (callErrno != 0) ? callErrno : ((rc > 0) ? rc : 0)
	                let outcome: String
	                if e == EEXIST {
	                    outcome = "already_consumed"
	                    details["token_state"] = "already_consumed"
	                } else if e == EINVAL {
	                    outcome = "invalid_token"
	                    details["token_state"] = "invalid"
	                } else if e == EPERM || e == EACCES {
	                    outcome = "permission_error"
	                } else {
	                    outcome = "consume_failed"
	                }
	                let errorMsg: String
	                if e > 0 {
	                    errorMsg = String(cString: strerror(e))
	                } else if let selectedHandle {
	                    errorMsg = "consume returned handle=\(selectedHandle) with errno=0"
	                } else {
	                    errorMsg = "sandbox_extension consume call failed"
	                }
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: e > 0 ? Int(e) : nil,
	                    error: errorMsg,
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            details["token_state"] = "consumed"
	            return RunProbeResponse(
	                rc: 0,
	                stdout: selectedHandle.map { "\($0)" } ?? "",
	                stderr: "",
	                normalized_outcome: "consume_ok",
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )

	        case .release:
	            let rawHandle = args.value("--handle")?.trimmingCharacters(in: .whitespacesAndNewlines)
	            let rawToken = args.value("--token")?.trimmingCharacters(in: .whitespacesAndNewlines)
	            if (rawHandle == nil || rawHandle == "") && (rawToken == nil || rawToken == "") {
	                return badRequest("missing --handle <i64> (preferred) or --token <token>")
	            }

	            func parseHandle(_ s: String) -> Int64? {
	                if s.hasPrefix("0x") || s.hasPrefix("0X") {
	                    return Int64(s.dropFirst(2), radix: 16)
	                }
	                return Int64(s)
	            }

	            let handleValue: Int64?
	            if let rawHandle, !rawHandle.isEmpty {
	                guard let parsed = parseHandle(rawHandle) else {
	                    return badRequest("invalid --handle (expected i64 or 0x... hex)")
	                }
	                handleValue = parsed
	                details["release_handle"] = "\(parsed)"
	                details["release_handle_hex"] = String(format: "0x%016llx", UInt64(bitPattern: parsed))
	                let low32 = UInt32(truncatingIfNeeded: parsed)
	                let high32 = UInt32(truncatingIfNeeded: UInt64(bitPattern: parsed) >> 32)
	                details["release_handle_low32"] = "\(low32)"
	                details["release_handle_low32_hex"] = String(format: "0x%08x", low32)
	                details["release_handle_high32"] = "\(high32)"
	                details["release_handle_high32_hex"] = String(format: "0x%08x", high32)
	            } else {
	                handleValue = nil
	            }

	            let tokenUsedValue: String?
	            if let rawToken, !rawToken.isEmpty {
	                let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
	                let tokenFormat = args.value("--token-format") ?? "full"
	                var tokenUsed = token
	                if tokenFormat == "prefix" {
	                    if let idx = token.firstIndex(of: ";") {
	                        tokenUsed = String(token[..<idx])
	                    }
	                } else if tokenFormat != "full" {
	                    return badRequest("invalid --token-format (expected: full|prefix)")
	                }
	                tokenUsedValue = tokenUsed
	                details["token_len"] = "\(token.utf8.count)"
	                details["token_used_len"] = "\(tokenUsed.utf8.count)"
	                details["token_format"] = tokenFormat
	                if let idx = token.firstIndex(of: ";") {
	                    details["token_prefix"] = String(token[..<idx])
	                }
	            } else {
	                tokenUsedValue = nil
	            }

	            if args.has("--flags"), args.intValue("--flags") == nil {
	                return badRequest("invalid --flags (expected integer)")
	            }
	            let callFlags = Int32(args.intValue("--flags") ?? 0)

	            let callVariant = args.value("--call-variant") ?? "auto"
	            let allowedVariants: Set<String> = ["handle_one_arg", "one_arg", "two_arg", "token_and_ptr", "auto"]
	            if !allowedVariants.contains(callVariant) {
	                let allowed = allowedVariants.sorted().joined(separator: "|")
	                return badRequest("invalid --call-variant (expected: \(allowed))")
	            }
	            details["call_variant"] = callVariant
	            details["call_flags"] = "\(callFlags)"

	            let defaultSymbol = "sandbox_extension_release"
	            let callSymbolArg = args.value("--call-symbol")
	            let callSymbolProvided = callSymbolArg != nil
	            let callSymbol = callSymbolArg ?? defaultSymbol
	            if callSymbol.isEmpty {
	                return badRequest("invalid --call-symbol (empty)")
	            }
	            details["call_symbol"] = callSymbol
	            if callSymbolProvided {
	                details["call_symbol_requested"] = callSymbol
	            }

	            var rc: Int32 = -1
	            var callErrno: Int32 = 0
	            var selectedSymbol: String? = nil
	            var selectedVariant: String? = nil
	            var attemptIndex = 0

	            func recordAttempt(symbolName: String, variant: String, rcCandidate: Int32, errnoCandidate: Int32) {
	                details["attempt_\(attemptIndex)_symbol"] = symbolName
	                details["attempt_\(attemptIndex)_variant"] = variant
	                details["attempt_\(attemptIndex)_rc"] = "\(rcCandidate)"
	                details["attempt_\(attemptIndex)_errno"] = "\(errnoCandidate)"
	                attemptIndex += 1
	            }

	            func callReleaseWithVariant(_ sym: UnsafeMutableRawPointer, _ variant: String) -> (Bool, Int32, Int32) {
	                switch variant {
	                case "handle_one_arg":
	                    guard let handleValue else {
	                        return (false, -1, 0)
	                    }
	                    errno = 0
	                    let rcCandidate: Int32 = {
	                        let fn = unsafeBitCast(sym, to: SandboxExtensionReleaseHandleFn.self)
	                        return fn(handleValue)
	                    }()
	                    return (rcCandidate == 0, rcCandidate, errno)
	                case "one_arg":
	                    guard let tokenUsedValue else {
	                        return (false, -1, 0)
	                    }
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsedValue.withCString { tokenPtr in
	                        let fn = unsafeBitCast(sym, to: SandboxExtensionReleaseFn.self)
	                        return fn(tokenPtr)
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno)
	                case "two_arg":
	                    guard let tokenUsedValue else {
	                        return (false, -1, 0)
	                    }
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsedValue.withCString { tokenPtr in
	                        let fn = unsafeBitCast(sym, to: SandboxExtensionReleaseFlagsFn.self)
	                        return fn(tokenPtr, callFlags)
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno)
	                case "token_and_ptr":
	                    guard let tokenUsedValue else {
	                        return (false, -1, 0)
	                    }
	                    errno = 0
	                    let rcCandidate: Int32 = tokenUsedValue.withCString { tokenPtr in
	                        var tokenPtrVar: UnsafePointer<CChar>? = tokenPtr
	                        return withUnsafeMutablePointer(to: &tokenPtrVar) { tokenPtrPtr in
	                            let fn = unsafeBitCast(sym, to: SandboxReleaseFsExtensionFn.self)
	                            return fn(tokenPtr, tokenPtrPtr)
	                        }
	                    }
	                    return (rcCandidate == 0, rcCandidate, errno)
	                default:
	                    return (false, -1, 0)
	                }
	            }

	            if callVariant == "auto" {
	                var attemptPlan: [(String, [String])] = []
	                if callSymbolProvided {
	                    let variants: [String]
	                    switch callSymbol {
	                    case "sandbox_extension_release":
	                        var v: [String] = []
	                        if handleValue != nil { v.append("handle_one_arg") }
	                        if tokenUsedValue != nil { v.append(contentsOf: ["one_arg", "two_arg"]) }
	                        variants = v.isEmpty ? ["handle_one_arg"] : v
	                    case "sandbox_release_fs_extension":
	                        variants = ["one_arg", "token_and_ptr"]
	                    default:
	                        variants = (handleValue != nil) ? ["handle_one_arg"] : ["one_arg", "two_arg"]
	                    }
	                    attemptPlan = [(callSymbol, variants)]
	                } else {
	                    if handleValue != nil {
	                        attemptPlan.append(("sandbox_extension_release", ["handle_one_arg"]))
	                    }
	                    if tokenUsedValue != nil {
	                        attemptPlan.append(("sandbox_extension_release", ["one_arg", "two_arg"]))
	                        attemptPlan.append(("sandbox_release_fs_extension", ["one_arg", "token_and_ptr"]))
	                    }
	                }

	                var resolvedAny = false
	                outerLoop: for (symbolName, variants) in attemptPlan {
	                    guard let sym = resolveSandboxExtensionSymbol(symbolName) else { continue }
	                    resolvedAny = true
	                    for variant in variants {
	                        let (ok, rcCandidate, errnoCandidate) = callReleaseWithVariant(sym, variant)
	                        recordAttempt(symbolName: symbolName, variant: variant, rcCandidate: rcCandidate, errnoCandidate: errnoCandidate)
	                        rc = rcCandidate
	                        callErrno = errnoCandidate
	                        selectedSymbol = symbolName
	                        selectedVariant = variant
	                        if ok {
	                            break outerLoop
	                        }
	                    }
	                }

	                if !resolvedAny {
	                    let attemptedSymbols = attemptPlan.map { $0.0 }.joined(separator: ", ")
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "symbol_missing",
	                        errno: nil,
	                        error: "no sandbox extension symbols available (attempted: \(attemptedSymbols))",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	            } else {
	                guard let sym = resolveSandboxExtensionSymbol(callSymbol) else {
	                    return RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "symbol_missing",
	                        errno: nil,
	                        error: "\(callSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(callSymbol)\")",
	                        details: details,
	                        layer_attribution: nil
	                    )
	                }
	                let (ok, rcCandidate, errnoCandidate) = callReleaseWithVariant(sym, callVariant)
	                recordAttempt(symbolName: callSymbol, variant: callVariant, rcCandidate: rcCandidate, errnoCandidate: errnoCandidate)
	                rc = rcCandidate
	                callErrno = errnoCandidate
	                selectedSymbol = callSymbol
	                selectedVariant = callVariant
	                if ok {
	                    // success already captured
	                }
	            }

	            if let selectedSymbol {
	                details["call_symbol"] = selectedSymbol
	                details["call_symbol_selected"] = selectedSymbol
	            } else {
	                details["call_symbol"] = callSymbol
	                details["call_symbol_selected"] = "none"
	            }
	            details["call_variant_selected"] = selectedVariant ?? "none"
	            details["call_rc"] = "\(rc)"

	            if rc != 0 {
	                var e = callErrno
	                if e == 0 && rc > 0 {
	                    e = rc
	                }
	                let outcome: String
	                if selectedVariant == "handle_one_arg" {
	                    if e == EINVAL {
	                        outcome = "invalid_handle"
	                    } else if e == EPERM || e == EACCES {
	                        outcome = "permission_error"
	                    } else {
	                        outcome = "release_failed"
	                    }
	                } else {
	                    if e == EINVAL {
	                        outcome = "invalid_token"
	                        details["token_state"] = "invalid"
	                    } else if e == EPERM || e == EACCES {
	                        outcome = "permission_error"
	                    } else {
	                        outcome = "release_failed"
	                    }
	                }
	                let errorMsg = (e > 0) ? String(cString: strerror(e)) : "sandbox_extension release call returned \(rc)"
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: outcome,
	                    errno: e > 0 ? Int(e) : nil,
	                    error: errorMsg,
	                    details: details,
	                    layer_attribution: nil
	                )
	            }

	            details["token_state"] = "released"
	            return RunProbeResponse(
	                rc: 0,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: "release_ok",
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )
	        }
	    }

	    // MARK: - inherit_child (paired-process harness)

	    private static func probeInheritChild(argv: [String], eventSink: ProbeEventSink?) -> RunProbeResponse {
	        // inherit_child is a reliability/discrimination harness, not just “one more probe”.
	        //
	        // Lessons (these are why the harness looks the way it does):
	        // - A run with no child-emitted events is diagnostic (child died before writing), not a sandbox deny.
	        // - Raw write(2) loops are used (not fragile FileHandle paths) so instrumentation failures don’t masquerade as sandbox outcomes.
	        // - The trace uses the actual socketpair FDs (no hardcoded fd numbers); an ultra-early sentinel proves the child reached user code
	        //   and records event/right FD identities.
	        // - The two-channel design (event bus vs rights bus) exists to keep SCM_RIGHTS capability passing from corrupting structured events.
	        // - Protocol version/namespace/cap-id validation makes mismatches explicit (child_protocol_violation/protocol_error), not UB.
	        // - Parent lifecycle discipline (writer stays open until reader finishes) prevents deadlocks and spurious truncation.
	        // - start-suspended spawn + stop markers make stop-on-entry/deny race-free and testable without a debugger.
	        // - Stable callsite identifiers (and backtraces where available) localize denies to specific code paths.
	        pw_probe_inherit_child_marker()
	        let args = Argv(argv)
        let scenario = args.value("--scenario") ?? "dynamic_extension"
        let allowUnsafe = args.has("--allow-unsafe-path")
        let stopOnEntry = args.has("--stop-on-entry")
        let stopOnDeny = args.has("--stop-on-deny")
        let stopAutoResume = args.has("--stop-auto-resume")
	        let bookmarkMove = args.has("--bookmark-move")
        let bookmarkInvalid = args.has("--bookmark-invalid")
        let protocolBadCapId = args.has("--protocol-bad-cap-id")
        let runId = UUID().uuidString
        let inheritSpan = PWSignpostSpan(
            category: PWSignposts.categoryXpcService,
            name: "inherit_child",
            label: "scenario=\(scenario) run_id=\(runId)"
        )
        defer { inheritSpan.end() }

        let parentPid = Int(getpid())
        let profileName = Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String
        let serviceBundleId = Bundle.main.bundleIdentifier ?? ""
        let processName = ProcessInfo.processInfo.processName
        let eventLock = NSLock()
        var events: [InheritChildEvent] = []

        func snapshotEvents() -> [InheritChildEvent] {
            eventLock.lock()
            let out = events
            eventLock.unlock()
            return out
        }

        func attachWitness(
            _ response: RunProbeResponse,
            childPid: Int = -1,
            childExitStatus: Int = -1,
            childPath: String = "",
            childEventFd: Int = -1,
            childRightsFd: Int = -1,
            childBundleId: String = "",
            childTeamId: String = "",
            childEntitlements: [String: EntitlementValue] = [:],
            inheritContractOk: Bool = false,
            capabilityResults: [InheritChildCapabilityResult] = [],
            protocolError: InheritChildProtocolError? = nil,
            outcomeSummary: String? = nil
        ) -> RunProbeResponse {
            var out = response
            if out.witness == nil {
                out.witness = InheritChildWitness(
                    protocol_version: InheritChildProtocol.version,
                    capability_namespace: InheritChildProtocol.capabilityNamespace,
                    run_id: runId,
                    scenario: scenario,
                    profile: profileName,
                    parent_pid: parentPid,
                    child_pid: childPid,
                    child_exit_status: childExitStatus,
                    child_event_fd: childEventFd,
                    child_rights_fd: childRightsFd,
                    child_path: childPath,
                    service_bundle_id: serviceBundleId,
                    process_name: processName,
                    child_bundle_id: childBundleId,
                    child_team_id: childTeamId,
                    child_entitlements: childEntitlements,
                    inherit_contract_ok: inheritContractOk,
                    capability_results: capabilityResults,
                    stop_on_entry: stopOnEntry,
                    stop_on_deny: stopOnDeny,
                    events: snapshotEvents(),
                    system_sandbox_reports: nil,
                    sandbox_log_capture_status: "not_requested",
                    sandbox_log_capture: [:],
                    protocol_error: protocolError,
                    outcome_summary: outcomeSummary
                )
            }
            return out
        }

        func inheritChildBadRequest(_ message: String, extra: [String: String] = [:]) -> RunProbeResponse {
            var details = baseDetails([
                "probe_family": "inherit_child",
                "scenario": scenario,
                "run_id": runId
            ])
            for (key, value) in extra {
                details[key] = value
            }
            let witness = InheritChildWitness(
                protocol_version: InheritChildProtocol.version,
                capability_namespace: InheritChildProtocol.capabilityNamespace,
                run_id: runId,
                scenario: scenario,
                profile: profileName,
                parent_pid: parentPid,
                child_pid: -1,
                child_exit_status: -1,
                child_event_fd: -1,
                child_rights_fd: -1,
                child_path: args.value("--path") ?? "",
                service_bundle_id: serviceBundleId,
                process_name: processName,
                child_bundle_id: "",
                child_team_id: "",
                child_entitlements: [:],
                inherit_contract_ok: false,
                capability_results: [],
                stop_on_entry: stopOnEntry,
                stop_on_deny: stopOnDeny,
                events: [],
                system_sandbox_reports: nil,
                sandbox_log_capture_status: "not_requested",
                sandbox_log_capture: [:],
                protocol_error: nil,
                outcome_summary: "bad_request"
            )
            return RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "",
                normalized_outcome: "bad_request",
                errno: nil,
                error: message,
                details: details,
                witness: witness,
                layer_attribution: nil
            )
        }

        guard let scenarioPlan = inheritChildScenarioCatalog[scenario] else {
            let supported = inheritChildScenarioList.joined(separator: ",")
            return inheritChildBadRequest(
                "unsupported --scenario",
                extra: ["supported_scenarios": supported]
            )
        }

        let capabilityPlan = scenarioPlan.capabilities
        let usesSandboxExtension = scenarioPlan.usesSandboxExtension
        if bookmarkMove, scenario != "bookmark_ferry" {
            return inheritChildBadRequest("--bookmark-move is only valid with --scenario bookmark_ferry")
        }
        if bookmarkInvalid, scenario != "bookmark_ferry" {
            return inheritChildBadRequest("--bookmark-invalid is only valid with --scenario bookmark_ferry")
        }
        if bookmarkInvalid, bookmarkMove {
            return inheritChildBadRequest("--bookmark-invalid cannot be combined with --bookmark-move")
        }

        let needsPath = capabilityPlan.contains { plan in
            switch plan.type {
            case .socketFd:
                return false
            default:
                return true
            }
        }
        let directPath = args.value("--path")
        let pathClass = args.value("--path-class")
        if needsPath, (directPath == nil) == (pathClass == nil) {
            return inheritChildBadRequest("provide exactly one of --path or --path-class")
        }

        func nowUnixMs() -> UInt64 {
            UInt64(Date().timeIntervalSince1970 * 1000.0)
        }

        func monotonicNs() -> UInt64 {
            var ts = timespec()
            clock_gettime(CLOCK_MONOTONIC, &ts)
            return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
        }

        func captureBacktrace(limit: Int = 16) -> ([String]?, String?) {
            let frames = Thread.callStackReturnAddresses
            if frames.isEmpty {
                return (nil, "empty_backtrace")
            }
            let out = frames.prefix(limit).map {
                String(format: "0x%llx", $0.uint64Value)
            }
            return (out, nil)
        }

        func denyBacktrace(_ errno: Int?) -> ([String]?, String?) {
            guard let errno, errno == EPERM || errno == EACCES else {
                return (nil, nil)
            }
            return captureBacktrace()
        }

        func recordEvent(
            actor: String,
            phase: String,
            pid: Int? = nil,
            callsiteId: String? = nil,
            op: String? = nil,
            backtrace: [String]? = nil,
            backtraceError: String? = nil,
            lineage: InheritChildLineage? = nil,
            details: [String: String]? = nil,
            errno: Int? = nil,
            rc: Int? = nil
        ) {
            let event = InheritChildEvent(
                actor: actor,
                phase: phase,
                run_id: runId,
                pid: pid,
                time_unix_ms: nowUnixMs(),
                monotonic_ns: monotonicNs(),
                callsite_id: callsiteId,
                op: op,
                backtrace: backtrace,
                backtrace_error: backtraceError,
                lineage: lineage,
                details: details,
                errno: errno,
                rc: rc
            )
            eventLock.lock()
            events.append(event)
            eventLock.unlock()
        }

        func recordOpEvent(
            actor: String,
            phase: String,
            pid: Int? = nil,
            capId: String,
            capType: String,
            op: String,
            callsiteId: String,
            rc: Int,
            errno: Int?,
            details: [String: String] = [:]
        ) {
            var merged = details
            merged["cap_id"] = capId
            merged["cap_type"] = capType
            let isDeny = errno.map { $0 == EPERM || $0 == EACCES } ?? false
            let (backtrace, backtraceError) = denyBacktrace(errno)
            recordEvent(
                actor: actor,
                phase: phase,
                pid: pid,
                callsiteId: isDeny ? callsiteId : nil,
                op: isDeny ? op : nil,
                backtrace: backtrace,
                backtraceError: backtraceError,
                details: merged,
                errno: errno,
                rc: rc
            )
        }

        func signalName(_ sig: Int32) -> String {
            if let cStr = strsignal(sig) {
                return String(cString: cStr)
            }
            return "signal_\(sig)"
        }

        func wStatus(_ status: Int32) -> Int32 {
            status & 0o177
        }

        func wStopSig(_ status: Int32) -> Int32 {
            (status >> 8) & 0xff
        }

        func wExitStatus(_ status: Int32) -> Int32 {
            (status >> 8) & 0xff
        }

        func wIfStopped(_ status: Int32) -> Bool {
            wStatus(status) == 0o177 && wStopSig(status) != 0x13
        }

        func wIfExited(_ status: Int32) -> Bool {
            wStatus(status) == 0
        }

        func wIfSignaled(_ status: Int32) -> Bool {
            wStatus(status) != 0o177 && wStatus(status) != 0
        }

        func wTermSig(_ status: Int32) -> Int32 {
            wStatus(status)
        }

        func resolveAppBundleURL() -> URL? {
            var url = Bundle.main.bundleURL
            for _ in 0..<3 {
                url.deleteLastPathComponent()
            }
            guard url.pathExtension == "app" else {
                return nil
            }
            return url
        }

        func entitlementValue(from value: Any) -> EntitlementValue? {
            switch value {
            case let bool as Bool:
                return .bool(bool)
            case let string as String:
                return .string(string)
            case let number as NSNumber:
                if CFGetTypeID(number) == CFBooleanGetTypeID() {
                    return .bool(number.boolValue)
                }
                let doubleValue = number.doubleValue
                if doubleValue.rounded(.towardZero) == doubleValue {
                    let intValue = number.intValue
                    if Double(intValue) == doubleValue {
                        return .int(intValue)
                    }
                }
                return .double(doubleValue)
            case let array as [Any]:
                return .array(array.map { entitlementValue(from: $0) ?? .string(String(describing: $0)) })
            case let dict as [String: Any]:
                var mapped: [String: EntitlementValue] = [:]
                for (key, value) in dict {
                    mapped[key] = entitlementValue(from: value) ?? .string(String(describing: value))
                }
                return .dict(mapped)
            case is NSNull:
                return .null
            default:
                return .string(String(describing: value))
            }
        }

        func entitlementMap(from dict: [String: Any]) -> [String: EntitlementValue] {
            var mapped: [String: EntitlementValue] = [:]
            for (key, value) in dict {
                mapped[key] = entitlementValue(from: value) ?? .string(String(describing: value))
            }
            return mapped
        }

        func boolFromEntitlement(_ value: Any?) -> Bool? {
            if let bool = value as? Bool {
                return bool
            }
            if let number = value as? NSNumber {
                return number.boolValue
            }
            return nil
        }

        func readSigningInfo(path: String) -> (identifier: String?, teamId: String?, entitlements: [String: EntitlementValue], rawEntitlements: [String: Any]?) {
            var staticCode: SecStaticCode?
            let url = URL(fileURLWithPath: path) as CFURL
            guard SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode) == errSecSuccess,
                  let staticCode else {
                return (nil, nil, [:], nil)
            }

            var info: CFDictionary?
            let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
            guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
                  let infoDict = info as? [String: Any] else {
                return (nil, nil, [:], nil)
            }

            let identifier = infoDict[kSecCodeInfoIdentifier as String] as? String
            let teamId = infoDict[kSecCodeInfoTeamIdentifier as String] as? String
            let rawEntitlements = infoDict[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
            let entitlements = rawEntitlements.map(entitlementMap) ?? [:]
            return (identifier, teamId, entitlements, rawEntitlements)
        }

        func inheritContractOk(entitlements: [String: Any]?) -> Bool {
            guard let entitlements else { return false }
            let sandboxKeys = entitlements.keys.filter { $0.hasPrefix("com.apple.security.") }
            let expected: Set<String> = [
                "com.apple.security.app-sandbox",
                "com.apple.security.inherit"
            ]
            guard Set(sandboxKeys) == expected else { return false }
            guard boolFromEntitlement(entitlements["com.apple.security.app-sandbox"]) == true else { return false }
            guard boolFromEntitlement(entitlements["com.apple.security.inherit"]) == true else { return false }
            return true
        }

        struct CapabilityPayload {
            var cap_id: Int32
            var meta0: Int32
            var meta1: Int32
            var meta2: Int32
        }

        func cmsgAlign(_ length: Int) -> Int {
            let align = MemoryLayout<UInt32>.size
            return (length + align - 1) & ~(align - 1)
        }

        func cmsgSpace(_ length: Int) -> Int {
            cmsgAlign(MemoryLayout<cmsghdr>.size) + cmsgAlign(length)
        }

        func cmsgLen(_ length: Int) -> Int {
            cmsgAlign(MemoryLayout<cmsghdr>.size) + length
        }

        func sendCapability(socketFd: Int32, fdToSend: Int32, capId: Int32, meta: [Int32]) -> (Int, Int32?) {
            var payload = CapabilityPayload(
                cap_id: capId,
                meta0: meta.count > 0 ? meta[0] : 0,
                meta1: meta.count > 1 ? meta[1] : 0,
                meta2: meta.count > 2 ? meta[2] : 0
            )
            let controlLen = cmsgSpace(MemoryLayout<Int32>.size)
            var control = [UInt8](repeating: 0, count: controlLen)
            var msg = msghdr()
            let rc = withUnsafeMutableBytes(of: &payload) { payloadBuffer -> ssize_t in
                var iov = iovec(
                    iov_base: payloadBuffer.baseAddress,
                    iov_len: payloadBuffer.count
                )
                return control.withUnsafeMutableBytes { controlBuffer -> ssize_t in
                    return withUnsafeMutablePointer(to: &iov) { iovPtr -> ssize_t in
                        msg = msghdr(
                            msg_name: nil,
                            msg_namelen: 0,
                            msg_iov: iovPtr,
                            msg_iovlen: 1,
                            msg_control: controlBuffer.baseAddress,
                            msg_controllen: socklen_t(controlBuffer.count),
                            msg_flags: 0
                        )
                        if let base = controlBuffer.baseAddress {
                            let cmsg = base.assumingMemoryBound(to: cmsghdr.self)
                            cmsg.pointee.cmsg_len = socklen_t(cmsgLen(MemoryLayout<Int32>.size))
                            cmsg.pointee.cmsg_level = SOL_SOCKET
                            cmsg.pointee.cmsg_type = SCM_RIGHTS
                            let dataPtr = UnsafeMutableRawPointer(cmsg).advanced(by: MemoryLayout<cmsghdr>.size)
                            dataPtr.assumingMemoryBound(to: Int32.self).pointee = fdToSend
                        }
                        return sendmsg(socketFd, &msg, 0)
                    }
                }
            }
            if rc < 0 {
                return (1, errno)
            }
            return (0, nil)
        }

        func writeAll(_ fd: Int32, _ data: Data) -> (Bool, Int32?) {
            var lastErrno: Int32? = nil
            let ok = data.withUnsafeBytes { rawBuffer -> Bool in
                guard let base = rawBuffer.baseAddress else { return true }
                var remaining = rawBuffer.count
                var offset = 0
                while remaining > 0 {
                    let written = write(fd, base.advanced(by: offset), remaining)
                    if written <= 0 {
                        lastErrno = errno
                        return false
                    }
                    remaining -= written
                    offset += written
                }
                return true
            }
            return (ok, lastErrno)
        }

        func sendEventPayload(eventFd: Int32, capId: String, capType: String, payload: Data) -> (Int, Int32?) {
            let header = "\(InheritChildProtocol.eventPayloadPrefix) " +
            "\(InheritChildProtocol.eventPayloadKeyProtocolVersion)=\(InheritChildProtocol.version) " +
            "\(InheritChildProtocol.eventPayloadKeyCapabilityNamespace)=\(InheritChildProtocol.capabilityNamespace) " +
            "\(InheritChildProtocol.eventPayloadKeyCapId)=\(capId) " +
            "\(InheritChildProtocol.eventPayloadKeyCapType)=\(capType) " +
            "\(InheritChildProtocol.eventPayloadKeyLength)=\(payload.count)\n"
            let (headerOk, headerErr) = writeAll(eventFd, Data(header.utf8))
            if !headerOk {
                return (1, headerErr)
            }
            let (payloadOk, payloadErr) = writeAll(eventFd, payload)
            if !payloadOk {
                return (1, payloadErr)
            }
            return (0, nil)
        }

        func connectUnixSocket(path: String) -> (Int32?, Int32?) {
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            if fd < 0 {
                return (nil, errno)
            }
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
            let pathBytes = Array(path.utf8CString)
            if pathBytes.count > maxLen {
                close(fd)
                return (nil, ENAMETOOLONG)
            }
            withUnsafeMutableBytes(of: &addr.sun_path) { (pathBuffer: UnsafeMutableRawBufferPointer) in
                pathBytes.withUnsafeBytes { src in
                    pathBuffer.copyBytes(from: src)
                }
            }
            let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(fd, $0, addrLen)
                }
            }
            if rc != 0 {
                let e = errno
                close(fd)
                return (nil, e)
            }
            return (fd, nil)
        }

	        func startEchoServer(maxConnections: Int) -> (String?, Int32?, String?) {
	            let socketRoot = FileManager.default.temporaryDirectory
	            let maxLen = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
	            let shortName = "pw-echo-\(getpid()).sock"
	            let fallbackName = "pw.sock"
	            var socketPath = socketRoot.appendingPathComponent(shortName, isDirectory: false).path
            if socketPath.utf8.count > maxLen {
                socketPath = socketRoot.appendingPathComponent(fallbackName, isDirectory: false).path
            }
            if socketPath.utf8.count > maxLen {
                socketPath = "/tmp/\(fallbackName)"
            }
            if socketPath.utf8.count > maxLen {
                return (nil, nil, "socket path too long")
            }

            _ = socketPath.withCString { unlink($0) }
            let listener = socket(AF_UNIX, SOCK_STREAM, 0)
            if listener < 0 {
                return (nil, nil, "socket() failed: \(String(cString: strerror(errno)))")
            }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = Array(socketPath.utf8CString)
            if pathBytes.count > maxLen {
                close(listener)
                return (nil, nil, "socket path too long")
            }
            withUnsafeMutableBytes(of: &addr.sun_path) { (pathBuffer: UnsafeMutableRawBufferPointer) in
                pathBytes.withUnsafeBytes { src in
                    pathBuffer.copyBytes(from: src)
                }
            }

            let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let bindRc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(listener, $0, addrLen)
                }
            }
            if bindRc != 0 {
                let err = String(cString: strerror(errno))
                close(listener)
                return (nil, nil, "bind failed: \(err)")
            }

            if listen(listener, 4) != 0 {
                let err = String(cString: strerror(errno))
                close(listener)
                return (nil, nil, "listen failed: \(err)")
            }

            DispatchQueue.global().async {
                var accepted = 0
                while accepted < maxConnections {
                    let conn = accept(listener, nil, nil)
                    if conn < 0 {
                        continue
                    }
                    accepted += 1
                    DispatchQueue.global().async {
                        var buf = [UInt8](repeating: 0, count: 128)
                        let count = read(conn, &buf, buf.count)
                        if count > 0 {
                            _ = write(conn, buf, count)
                        }
                        close(conn)
                    }
                }
            }

            return (socketPath, listener, nil)
        }

        let rightsCapabilityPlan = capabilityPlan.filter { $0.transport == .rightsBus }
        let eventPayloadPlan = capabilityPlan.filter { $0.transport == .eventBus }
        if protocolBadCapId, rightsCapabilityPlan.isEmpty {
            return inheritChildBadRequest("--protocol-bad-cap-id requires a rights-bus capability scenario")
        }

        var details = baseDetails([
            "probe_family": "inherit_child",
            "scenario": scenario,
            "run_id": runId,
            "stop_on_entry": stopOnEntry ? "true" : "false",
            "stop_on_deny": stopOnDeny ? "true" : "false",
            "stop_auto_resume": stopAutoResume ? "true" : "false",
            "protocol_bad_cap_id": protocolBadCapId ? "true" : "false",
            "bookmark_invalid": bookmarkInvalid ? "true" : "false",
            "capability_count": "\(capabilityPlan.count)",
            "capability_rights_count": "\(rightsCapabilityPlan.count)",
            "capability_event_count": "\(eventPayloadPlan.count)",
        ])
        var parentToken: String? = nil

        recordEvent(actor: "parent", phase: "parent_start", pid: parentPid, details: [
            "scenario": scenario
        ])

        let requestedName = args.value("--name") ?? "pw_child.txt"
        let targetArg = args.value("--target") ?? "specimen_file"
        guard let fsTarget = FsTarget(rawValue: targetArg) else {
            return inheritChildBadRequest("invalid --target (expected: path|base|harness_dir|run_dir|specimen_file)")
        }
        if usesSandboxExtension, fsTarget != .specimen_file && fsTarget != .path {
            return inheritChildBadRequest("dynamic_extension requires --target specimen_file (or omit --target)")
        }

		        var targetPath = ""
		        var targetDir = ""
		        var targetName = ""
			        if needsPath {
			            if usesSandboxExtension {
			                let extClass = "com.apple.app-sandbox.read"
			                let (resolved, error) = resolveFsTarget(
			                    directPath: directPath,
			                    pathClass: pathClass,
			                    target: fsTarget,
			                    requestedName: args.value("--name")
			                )
			                if let error {
			                    return error
			                }
			                guard let resolved else {
			                    return inheritChildBadRequest("internal: failed to resolve target path")
			                }
			                targetPath = resolved.path
			                if let harnessDir = resolved.harnessDir {
			                    details["harness_dir"] = harnessDir
			                }
			                if let runDir = resolved.runDir {
			                    details["run_dir"] = runDir
			                }
			                details["target_path"] = targetPath

			                if args.has("--create") {
			                    if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
			                        return inheritChildBadRequest("refusing to create file outside harness path (use --path-class/--target or --allow-unsafe-path)")
			                    }
			                    do {
			                        let parent = URL(fileURLWithPath: targetPath).deletingLastPathComponent()
			                        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
			                        let data = Data("hello".utf8)
			                        try data.write(to: URL(fileURLWithPath: targetPath), options: [.atomic])
			                    } catch {
			                        return attachWitness(
			                            RunProbeResponse(
			                                rc: 1,
			                                stdout: "",
			                                stderr: "",
			                                normalized_outcome: "create_failed",
			                                errno: extractErrno(error).map { Int($0) },
			                                error: "\(error)",
			                                details: details,
			                                layer_attribution: nil
			                            ),
			                            childPath: targetPath,
			                            outcomeSummary: "create_failed"
			                        )
			                    }
			                }

			                let issueSpan = PWSignpostSpan(
			                    category: PWSignposts.categoryXpcService,
			                    name: "issue_token",
			                    label: "sandbox_extension_issue_file"
			                )
			                defer { issueSpan.end() }

			                let issueSymbol = "sandbox_extension_issue_file"
			                details["issue_symbol"] = issueSymbol
			                guard let issueSym = resolveSandboxExtensionSymbol(issueSymbol) else {
			                    return attachWitness(
			                        RunProbeResponse(
			                            rc: 1,
			                            stdout: "",
			                            stderr: "",
			                            normalized_outcome: "symbol_missing",
			                            errno: nil,
			                            error: "\(issueSymbol) symbol not found via dlsym(RTLD_DEFAULT, \"\(issueSymbol)\")",
			                            details: details,
			                            layer_attribution: nil
			                        ),
			                        childPath: targetPath,
			                        outcomeSummary: "issue_token_failed"
			                    )
			                }

			                errno = 0
			                let tokenPtr = extClass.withCString { classPtr in
			                    targetPath.withCString { pathPtr in
			                        let issueFn = unsafeBitCast(issueSym, to: SandboxExtensionIssueFileFn.self)
			                        return issueFn(classPtr, pathPtr, 0)
			                    }
			                }
			                guard let tokenPtr else {
			                    let e = errno
			                    let outcome = (e == EPERM || e == EACCES) ? "permission_error" : "issue_failed"
			                    return attachWitness(
			                        RunProbeResponse(
			                            rc: 1,
			                            stdout: "",
			                            stderr: "",
			                            normalized_outcome: outcome,
			                            errno: Int(e),
			                            error: String(cString: strerror(e)),
			                            details: details,
			                            layer_attribution: nil
			                        ),
			                        childPath: targetPath,
			                        outcomeSummary: "issue_token_failed"
			                    )
			                }

			                let tokenParent = String(cString: tokenPtr)
			                let tokenLen = tokenParent.utf8.count
			                let tokenPrefix: String = {
			                    if let idx = tokenParent.firstIndex(of: ";") {
			                        return String(tokenParent[..<idx])
			                    }
			                    return ""
			                }()

			                if let freeSym = resolveSandboxExtensionSymbol("sandbox_extension_free") {
			                    let freeFn = unsafeBitCast(freeSym, to: SandboxExtensionFreeFn.self)
			                    freeFn(tokenPtr)
			                } else {
			                    free(UnsafeMutableRawPointer(tokenPtr))
			                }

			                details["extension_class"] = extClass
			                details["parent_token_prefix"] = tokenPrefix
			                details["parent_token_len"] = "\(tokenLen)"
			                parentToken = tokenParent

			                recordEvent(actor: "parent", phase: "parent_token_issued", pid: parentPid, details: [
			                    "token_prefix": tokenPrefix,
			                    "token_len": "\(tokenLen)"
			                ])
			            } else {
			                let (resolved, error) = resolveFsTarget(
			                    directPath: directPath,
			                    pathClass: pathClass,
                    target: fsTarget,
                    requestedName: args.value("--name")
                )
                if let error {
                    return error
                }
                guard let resolved else {
                    return inheritChildBadRequest("internal: failed to resolve target path")
                }
                targetPath = resolved.path
                if let harnessDir = resolved.harnessDir {
                    details["harness_dir"] = harnessDir
                }
                if let runDir = resolved.runDir {
                    details["run_dir"] = runDir
                }
                details["target_path"] = targetPath

                if args.has("--create") {
                    if directPath != nil, !allowUnsafe, !isSafeWritePath(targetPath) {
                        return inheritChildBadRequest("refusing to create file outside harness path (use --path-class/--target or --allow-unsafe-path)")
                    }
                    do {
                        let parent = URL(fileURLWithPath: targetPath).deletingLastPathComponent()
                        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
                        let data = Data("hello".utf8)
                        try data.write(to: URL(fileURLWithPath: targetPath), options: [.atomic])
                    } catch {
                        return attachWitness(
                            RunProbeResponse(
                                rc: 1,
                                stdout: "",
                                stderr: "",
                                normalized_outcome: "create_failed",
                                errno: extractErrno(error).map { Int($0) },
                                error: "\(error)",
                                details: details,
                                layer_attribution: nil
                            ),
                            childPath: targetPath,
                            outcomeSummary: "create_failed"
                        )
                    }
                }
            }
        }

        if !targetPath.isEmpty {
            var isDir = ObjCBool(false)
            _ = FileManager.default.fileExists(atPath: targetPath, isDirectory: &isDir)
            if isDir.boolValue {
                targetDir = targetPath
                targetName = requestedName
                targetPath = URL(fileURLWithPath: targetDir).appendingPathComponent(targetName).path
            } else {
                targetDir = URL(fileURLWithPath: targetPath).deletingLastPathComponent().path
                targetName = URL(fileURLWithPath: targetPath).lastPathComponent
            }
        }

        details["target_dir"] = targetDir
        details["target_name"] = targetName

        var socketPath = ""
        var socketListenerFd: Int32? = nil
        if capabilityPlan.contains(where: { $0.type == .socketFd }) {
            let (path, listener, error) = startEchoServer(maxConnections: 2)
            if let error {
                return attachWitness(
                    RunProbeResponse(
                        rc: 1,
                        stdout: "",
                        stderr: "",
                        normalized_outcome: "socket_setup_failed",
                        errno: nil,
                        error: error,
                        details: details,
                        layer_attribution: nil
                    ),
                    childPath: targetPath,
                    outcomeSummary: "socket_setup_failed"
                )
            }
            socketPath = path ?? ""
            socketListenerFd = listener
            details["socket_path"] = socketPath
        }

        // Prefer the service bundle copy; sandboxed XPC services cannot read the host app bundle.
        let childHelperName = scenario == "inherit_bad_entitlements" ? "pw-inherit-child-bad" : "pw-inherit-child"
        let serviceBundle = Bundle.main.bundleURL
        let serviceChildPath = serviceBundle.appendingPathComponent("Contents/MacOS/\(childHelperName)").path
        var candidatePaths = [serviceChildPath]
        if let appBundle = resolveAppBundleURL() {
            let appChildPath = appBundle.appendingPathComponent("Contents/MacOS/\(childHelperName)").path
            candidatePaths.append(appChildPath)
        }

        var childPath: String?
        for path in candidatePaths {
            if FileManager.default.isExecutableFile(atPath: path) {
                childPath = path
                break
            }
        }

        guard let resolvedChildPath = childPath else {
            let attempted = candidatePaths.joined(separator: ", ")
            return attachWitness(
                RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "child_missing",
                    errno: nil,
                    error: "missing or non-executable child helper (attempted: \(attempted))",
                    details: details,
                    layer_attribution: nil
                ),
                childPath: candidatePaths.first ?? "",
                outcomeSummary: "child_missing"
            )
        }
        details["child_path"] = resolvedChildPath

        let childSigningInfo = readSigningInfo(path: resolvedChildPath)
        let childBundleId = childSigningInfo.identifier
        let childTeamId = childSigningInfo.teamId
        let childEntitlements = childSigningInfo.entitlements
        let inheritContractOk = inheritContractOk(entitlements: childSigningInfo.rawEntitlements)

        struct CapabilityBuilder {
            var capId: String
            var capType: String
            var notes: String
            var parentAcquire: InheritChildCapabilityOpResult? = nil
            var childAcquire: InheritChildCapabilityOpResult? = nil
            var childUse: InheritChildCapabilityOpResult? = nil
            var bookmark: InheritChildBookmarkResult? = nil
        }

        var builders: [String: CapabilityBuilder] = [:]
        for plan in capabilityPlan {
            builders[plan.type.rawValue] = CapabilityBuilder(
                capId: plan.type.rawValue,
                capType: plan.type.rawValue,
                notes: plan.notes
            )
        }

        struct EventCapabilityPayload {
            var plan: InheritChildCapabilityPlan
            var data: Data
        }
        var eventPayloadsToSend: [EventCapabilityPayload] = []
        if !eventPayloadPlan.isEmpty {
            for plan in eventPayloadPlan {
                switch plan.type {
                case .bookmark:
                    guard !targetPath.isEmpty else {
                        return inheritChildBadRequest("missing --path/--path-class for bookmark")
                    }
                    let url = URL(fileURLWithPath: targetPath)
                    let options: URL.BookmarkCreationOptions = [.withSecurityScope, .securityScopeAllowOnlyReadAccess]
                    do {
                        let data: Data
                        if bookmarkInvalid {
                            data = Data("PW_INVALID_BOOKMARK".utf8)
                        } else {
                            data = try url.bookmarkData(options: options, includingResourceValuesForKeys: nil, relativeTo: nil)
                        }
                        eventPayloadsToSend.append(EventCapabilityPayload(plan: plan, data: data))
                        recordOpEvent(
                            actor: "parent",
                            phase: "parent_acquire_attempt",
                            pid: parentPid,
                            capId: plan.type.rawValue,
                            capType: plan.type.rawValue,
                            op: "bookmark_make",
                            callsiteId: "parent.bookmark.make",
                            rc: 0,
                            errno: nil,
                            details: [
                                "path": targetPath,
                                "bookmark_len": "\(data.count)",
                                "bookmark_read_only": "true",
                                "bookmark_invalid": bookmarkInvalid ? "true" : "false"
                            ]
                        )
                        if var builder = builders[plan.type.rawValue] {
                            builder.parentAcquire = InheritChildCapabilityOpResult(rc: 0, errno: nil)
                            builders[plan.type.rawValue] = builder
                        }
                        if bookmarkMove {
                            let movedPath = targetPath + ".moved"
                            do {
                                if FileManager.default.fileExists(atPath: movedPath) {
                                    try FileManager.default.removeItem(atPath: movedPath)
                                }
                                try FileManager.default.moveItem(atPath: targetPath, toPath: movedPath)
                                details["bookmark_moved_path"] = movedPath
                                recordEvent(
                                    actor: "parent",
                                    phase: "parent_bookmark_moved",
                                    pid: parentPid,
                                    details: [
                                        "from": targetPath,
                                        "to": movedPath
                                    ]
                                )
                            } catch {
                                return attachWitness(
                                    RunProbeResponse(
                                        rc: 1,
                                        stdout: "",
                                        stderr: "",
                                        normalized_outcome: "parent_bookmark_move_failed",
                                        errno: extractErrno(error).map { Int($0) },
                                        error: "failed to move bookmark target: \(error)",
                                        details: details,
                                        layer_attribution: nil
                                    ),
                                    childPath: resolvedChildPath,
                                    childBundleId: childBundleId ?? "",
                                    childTeamId: childTeamId ?? "",
                                    childEntitlements: childEntitlements,
                                    inheritContractOk: inheritContractOk,
                                    outcomeSummary: "parent_bookmark_move_failed"
                                )
                            }
                        }
                    } catch {
                        let e = extractErrno(error)
                        recordOpEvent(
                            actor: "parent",
                            phase: "parent_acquire_attempt",
                            pid: parentPid,
                            capId: plan.type.rawValue,
                            capType: plan.type.rawValue,
                            op: "bookmark_make",
                            callsiteId: "parent.bookmark.make",
                            rc: 1,
                            errno: e,
                            details: [
                                "path": targetPath
                            ]
                        )
                        if var builder = builders[plan.type.rawValue] {
                            builder.parentAcquire = InheritChildCapabilityOpResult(rc: 1, errno: e)
                            builders[plan.type.rawValue] = builder
                        }
                        return attachWitness(
                            RunProbeResponse(
                                rc: 1,
                                stdout: "",
                                stderr: "",
                                normalized_outcome: "parent_acquire_failed",
                                errno: e,
                                error: "parent failed to create bookmark payload",
                                details: details,
                                layer_attribution: nil
                            ),
                            childPath: resolvedChildPath,
                            childBundleId: childBundleId ?? "",
                            childTeamId: childTeamId ?? "",
                            childEntitlements: childEntitlements,
                            inheritContractOk: inheritContractOk,
                            outcomeSummary: "parent_acquire_failed"
                        )
                    }
                default:
                    continue
                }
            }
        }

        struct ParentCapability {
            var plan: InheritChildCapabilityPlan
            var fd: Int32
        }
        func acquireParentCapabilities() -> ([ParentCapability]?, RunProbeResponse?) {
            var acquired: [ParentCapability] = []
            for plan in rightsCapabilityPlan {
                switch plan.type {
                case .fileFd:
                    guard !targetPath.isEmpty else {
                        return (nil, inheritChildBadRequest("missing --path/--path-class for file_fd"))
                    }
                    let (fd, err): (Int32, Int32?) = targetPath.withCString { pathPtr in
                        errno = 0
                        let fd = open(pathPtr, O_RDONLY)
                        if fd >= 0 {
                            return (fd, nil)
                        }
                        return (-1, errno)
                    }
                    let rc = fd >= 0 ? 0 : 1
                    recordOpEvent(
                        actor: "parent",
                        phase: "parent_acquire_attempt",
                        pid: parentPid,
                        capId: plan.type.rawValue,
                        capType: plan.type.rawValue,
                        op: "open",
                        callsiteId: "parent.open.path",
                        rc: rc,
                        errno: err.map { Int($0) },
                        details: ["path": targetPath]
                    )
                    if var builder = builders[plan.type.rawValue] {
                        builder.parentAcquire = InheritChildCapabilityOpResult(
                            rc: rc,
                            errno: err.map { Int($0) }
                        )
                        builders[plan.type.rawValue] = builder
                    }
                    if fd < 0 {
                        return (
                            nil,
                            RunProbeResponse(
                                rc: 1,
                                stdout: "",
                                stderr: "",
                                normalized_outcome: "parent_acquire_failed",
                                errno: err.map { Int($0) },
                                error: "parent failed to open file for file_fd",
                                details: details,
                                layer_attribution: nil
                            )
                        )
                    }
                    acquired.append(ParentCapability(plan: plan, fd: fd))

                case .dirFd:
                    guard !targetDir.isEmpty else {
                        return (nil, inheritChildBadRequest("missing directory for dir_fd (use --path/--path-class)"))
                    }
                    let (fd, err): (Int32, Int32?) = targetDir.withCString { pathPtr in
                        errno = 0
                        let fd = open(pathPtr, O_RDONLY | O_DIRECTORY)
                        if fd >= 0 {
                            return (fd, nil)
                        }
                        return (-1, errno)
                    }
                    let rc = fd >= 0 ? 0 : 1
                    recordOpEvent(
                        actor: "parent",
                        phase: "parent_acquire_attempt",
                        pid: parentPid,
                        capId: plan.type.rawValue,
                        capType: plan.type.rawValue,
                        op: "open",
                        callsiteId: "parent.open.dir",
                        rc: rc,
                        errno: err.map { Int($0) },
                        details: ["path": targetDir]
                    )
                    if var builder = builders[plan.type.rawValue] {
                        builder.parentAcquire = InheritChildCapabilityOpResult(
                            rc: rc,
                            errno: err.map { Int($0) }
                        )
                        builders[plan.type.rawValue] = builder
                    }
                    if fd < 0 {
                        return (
                            nil,
                            RunProbeResponse(
                                rc: 1,
                                stdout: "",
                                stderr: "",
                                normalized_outcome: "parent_acquire_failed",
                                errno: err.map { Int($0) },
                                error: "parent failed to open directory for dir_fd",
                                details: details,
                                layer_attribution: nil
                            )
                        )
                    }
                    acquired.append(ParentCapability(plan: plan, fd: fd))

                case .socketFd:
                    guard !socketPath.isEmpty else {
                        return (nil, inheritChildBadRequest("internal: missing socket path for socket_fd"))
                    }
                    let (fd, err) = connectUnixSocket(path: socketPath)
                    let rc = fd == nil ? 1 : 0
                    recordOpEvent(
                        actor: "parent",
                        phase: "parent_acquire_attempt",
                        pid: parentPid,
                        capId: plan.type.rawValue,
                        capType: plan.type.rawValue,
                        op: "connect",
                        callsiteId: "parent.socket.connect",
                        rc: rc,
                        errno: err.map { Int($0) },
                        details: ["path": socketPath]
                    )
                    if var builder = builders[plan.type.rawValue] {
                        builder.parentAcquire = InheritChildCapabilityOpResult(
                            rc: rc,
                            errno: err.map { Int($0) }
                        )
                        builders[plan.type.rawValue] = builder
                    }
                    guard let fd else {
                        return (
                            nil,
                            RunProbeResponse(
                                rc: 1,
                                stdout: "",
                                stderr: "",
                                normalized_outcome: "parent_acquire_failed",
                                errno: err.map { Int($0) },
                                error: "parent failed to connect socket for socket_fd",
                                details: details,
                                layer_attribution: nil
                            )
                        )
                    }
                    acquired.append(ParentCapability(plan: plan, fd: fd))
                case .bookmark:
                    continue
                }
            }
            return (acquired, nil)
        }

        var parentCapabilities: [ParentCapability] = []
        if !usesSandboxExtension {
            let (acquired, response) = acquireParentCapabilities()
            if let response {
                return attachWitness(
                    response,
                    childPath: resolvedChildPath,
                    childBundleId: childBundleId ?? "",
                    childTeamId: childTeamId ?? "",
                    childEntitlements: childEntitlements,
                    inheritContractOk: inheritContractOk,
                    outcomeSummary: response.normalized_outcome
                )
            }
            if let acquired {
                parentCapabilities = acquired
            }
        }

        var eventFds: [Int32] = [0, 0]
        if socketpair(AF_UNIX, SOCK_STREAM, 0, &eventFds) != 0 {
            let e = errno
            return attachWitness(
                RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "socketpair_failed",
                    errno: Int(e),
                    error: String(cString: strerror(e)),
                    details: details,
                    layer_attribution: nil
                ),
                childPath: resolvedChildPath,
                childBundleId: childBundleId ?? "",
                childTeamId: childTeamId ?? "",
                childEntitlements: childEntitlements,
                inheritContractOk: inheritContractOk,
                outcomeSummary: "socketpair_failed"
            )
        }

        var rightsFds: [Int32] = [0, 0]
        if socketpair(AF_UNIX, SOCK_STREAM, 0, &rightsFds) != 0 {
            let e = errno
            close(eventFds[0])
            close(eventFds[1])
            return attachWitness(
                RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "socketpair_failed",
                    errno: Int(e),
                    error: String(cString: strerror(e)),
                    details: details,
                    layer_attribution: nil
                ),
                childPath: resolvedChildPath,
                childBundleId: childBundleId ?? "",
                childTeamId: childTeamId ?? "",
                childEntitlements: childEntitlements,
                inheritContractOk: inheritContractOk,
                outcomeSummary: "socketpair_failed"
            )
        }

        let eventParentFd = eventFds[0]
        let eventChildFd = eventFds[1]
        let rightsParentFd = rightsFds[0]
        let rightsChildFd = rightsFds[1]
        let eventFd = eventChildFd
        let rightsFd = rightsChildFd

        var env = ProcessInfo.processInfo.environment
        env["PW_CORRELATION_ID"] = PWTraceContext.correlationId() ?? ""
        if PWSignposts.isEnabled() {
            env["PW_ENABLE_SIGNPOSTS"] = "1"
        }
        env["PW_RUN_ID"] = runId
        env["PW_SCENARIO"] = scenario
        env["PW_PATH"] = targetPath
        env["PW_TARGET_NAME"] = targetName
        env["PW_SOCKET_PATH"] = socketPath
        env["PW_ACTOR"] = "child"
        env["PW_LINEAGE_DEPTH"] = "1"

        // Two-bus protocol (parent/child contract):
        // - eventFd/rightFd are explicit numbers passed via PW_EVENT_FD/PW_RIGHTS_FD, dup2'd in the child.
        // - Event bus: socketpair. Child->parent sends JSONL events; the first bytes are
        //   "PW_CHILD_SENTINEL ... protocol_version=<v> cap_namespace=<ns>\n".
        //   Parent->child may send "PW_CAP_PAYLOAD proto=<v> cap_ns=<ns> cap_id=<id> cap_type=<type> len=<n>\n"
        //   followed by raw payload bytes.
        // - Rights bus: socketpair for SCM_RIGHTS. Parent->child sends CapabilityPayload bytes with
        //   an SCM_RIGHTS control message; meta0 holds the protocol version.
        env["PW_EVENT_FD"] = "\(eventFd)"
        env["PW_RIGHTS_FD"] = "\(rightsFd)"
        env["PW_PROTOCOL_VERSION"] = "\(InheritChildProtocol.version)"
        env["PW_CAP_NAMESPACE"] = InheritChildProtocol.capabilityNamespace
        env["PW_RIGHTS_CAP_COUNT"] = "\(rightsCapabilityPlan.count)"
        env["PW_EVENT_CAP_COUNT"] = "\(eventPayloadPlan.count)"
        env["PW_CAP_COUNT"] = "\(rightsCapabilityPlan.count)"
        env["PW_RIGHTS_CAP_IDS"] = rightsCapabilityPlan.map { String($0.id) }.joined(separator: ",")
        env["PW_EVENT_CAP_IDS"] = eventPayloadPlan.map { $0.type.rawValue }.joined(separator: ",")
        if usesSandboxExtension {
            env["PW_PRE_ACQUIRE"] = "1"
        }
        if stopOnEntry {
            env["PW_STOP_ON_ENTRY"] = "1"
        }
        if stopOnDeny {
            env["PW_STOP_ON_DENY"] = "1"
        }

        let envStrings = env.map { "\($0)=\($1)" }
        var envp: [UnsafeMutablePointer<CChar>?] = envStrings.map { strdup($0) }
        envp.append(nil)
        defer {
            for ptr in envp {
                if let ptr { free(ptr) }
            }
        }

        var argvC: [UnsafeMutablePointer<CChar>?] = [strdup(resolvedChildPath), nil]
        defer {
            for ptr in argvC {
                if let ptr { free(ptr) }
            }
        }

        var actions: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&actions)
        posix_spawn_file_actions_adddup2(&actions, eventChildFd, eventFd)
        posix_spawn_file_actions_addclose(&actions, eventParentFd)
        posix_spawn_file_actions_addclose(&actions, rightsParentFd)
        if eventChildFd != eventFd {
            posix_spawn_file_actions_addclose(&actions, eventChildFd)
        }

        var attrs: posix_spawnattr_t? = nil
        if stopOnEntry {
            posix_spawnattr_init(&attrs)
            var flags: Int16 = 0
            posix_spawnattr_getflags(&attrs, &flags)
            flags |= Int16(POSIX_SPAWN_START_SUSPENDED)
            posix_spawnattr_setflags(&attrs, flags)
        }

        var childPid: pid_t = 0
        let spawnSpan = PWSignpostSpan(
            category: PWSignposts.categoryXpcService,
            name: "child_spawn",
            label: "helper=\(childHelperName)"
        )
        let spawnRc = posix_spawn(&childPid, resolvedChildPath, &actions, &attrs, &argvC, &envp)
        spawnSpan.end()
        posix_spawn_file_actions_destroy(&actions)
        if attrs != nil {
            posix_spawnattr_destroy(&attrs)
        }

        if spawnRc != 0 {
            close(eventParentFd)
            close(eventChildFd)
            close(rightsParentFd)
            close(rightsChildFd)
            return attachWitness(
                RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "spawn_failed",
                    errno: Int(spawnRc),
                    error: String(cString: strerror(spawnRc)),
                    details: details,
                    layer_attribution: nil
                ),
                childPath: resolvedChildPath,
                childEventFd: Int(eventFd),
                childRightsFd: Int(rightsFd),
                childBundleId: childBundleId ?? "",
                childTeamId: childTeamId ?? "",
                childEntitlements: childEntitlements,
                inheritContractOk: inheritContractOk,
                outcomeSummary: "spawn_failed"
            )
        }

        close(eventChildFd)
        close(rightsChildFd)
        let childPidInt = Int(childPid)
        details["child_pid"] = "\(childPidInt)"
        eventSink?("child_spawned", childPidInt, runId, "child spawned")
        recordEvent(actor: "parent", phase: "child_spawned", pid: parentPid, details: [
            "child_pid": "\(childPidInt)"
        ])

        for payload in eventPayloadsToSend {
            let sendRc = sendEventPayload(
                eventFd: eventParentFd,
                capId: payload.plan.type.rawValue,
                capType: payload.plan.type.rawValue,
                payload: payload.data
            )
            recordEvent(
                actor: "parent",
                phase: "parent_capability_payload_sent",
                pid: parentPid,
                details: [
                    "cap_id": payload.plan.type.rawValue,
                    "cap_type": payload.plan.type.rawValue,
                    "payload_len": "\(payload.data.count)"
                ],
                errno: sendRc.1.map { Int($0) },
                rc: sendRc.0
            )
            if sendRc.0 != 0 {
                close(rightsParentFd)
                close(eventParentFd)
                return attachWitness(
                    RunProbeResponse(
                        rc: 1,
                        stdout: "",
                        stderr: "",
                        normalized_outcome: "child_event_bus_io_error",
                        errno: sendRc.1.map { Int($0) },
                        error: "failed to send event payload for \(payload.plan.type.rawValue)",
                        details: details,
                        layer_attribution: nil
                    ),
                    childPid: childPidInt,
                    childPath: resolvedChildPath,
                    childEventFd: Int(eventFd),
                    childRightsFd: Int(rightsFd),
                    childBundleId: childBundleId ?? "",
                    childTeamId: childTeamId ?? "",
                    childEntitlements: childEntitlements,
                    inheritContractOk: inheritContractOk,
                    outcomeSummary: "child_event_bus_io_error"
                )
            }
        }

        var childEventFdObserved: Int? = nil
        var childRightsFdObserved: Int? = nil
        var childProtocolVersionObserved: Int? = nil
        var childCapabilityNamespaceObserved: String? = nil
        var protocolError: InheritChildProtocolError? = nil

        let preAcquireSemaphore = usesSandboxExtension ? DispatchSemaphore(value: 0) : nil
        let preAcquireLock = NSLock()
        var preAcquireSignaled = false

        let readGroup = DispatchGroup()
        readGroup.enter()
        DispatchQueue.global().async {
            var buffer = Data()
            var temp = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = read(eventParentFd, &temp, temp.count)
                if count <= 0 {
                    break
                }
                buffer.append(contentsOf: temp[0..<count])
                while let range = buffer.range(of: Data([0x0A])) {
                    let line = buffer.subdata(in: 0..<range.lowerBound)
                    buffer.removeSubrange(0...range.lowerBound)
                    guard !line.isEmpty else { continue }
                    let lineStr = String(data: line, encoding: .utf8) ?? ""
                    if lineStr.hasPrefix("\(InheritChildProtocol.sentinelPrefix) ") {
                        for part in lineStr.split(separator: " ") {
                            if part.hasPrefix("event_fd=") {
                                childEventFdObserved = Int(part.dropFirst("event_fd=".count))
                            } else if part.hasPrefix("rights_fd=") {
                                childRightsFdObserved = Int(part.dropFirst("rights_fd=".count))
                            } else if part.hasPrefix("\(InheritChildProtocol.sentinelKeyProtocolVersion)=") {
                                childProtocolVersionObserved = Int(part.dropFirst((InheritChildProtocol.sentinelKeyProtocolVersion + "=").count))
                            } else if part.hasPrefix("\(InheritChildProtocol.sentinelKeyCapabilityNamespace)=") {
                                childCapabilityNamespaceObserved = String(part.dropFirst((InheritChildProtocol.sentinelKeyCapabilityNamespace + "=").count))
                            }
                        }
                        recordEvent(
                            actor: "child",
                            phase: "child_sentinel",
                            pid: childPidInt,
                            details: ["line": lineStr]
                        )
                        if let observed = childProtocolVersionObserved,
                           observed != InheritChildProtocol.version,
                           protocolError == nil {
                            protocolError = InheritChildProtocolError(
                                kind: "protocol_version_mismatch",
                                expected: "\(InheritChildProtocol.version)",
                                observed: "\(observed)"
                            )
                        }
                        if childProtocolVersionObserved == nil, protocolError == nil {
                            protocolError = InheritChildProtocolError(
                                kind: "protocol_version_missing",
                                expected: "\(InheritChildProtocol.version)",
                                observed: ""
                            )
                        }
                        if let observedNs = childCapabilityNamespaceObserved,
                           observedNs != InheritChildProtocol.capabilityNamespace,
                           protocolError == nil {
                            protocolError = InheritChildProtocolError(
                                kind: "capability_namespace_mismatch",
                                expected: InheritChildProtocol.capabilityNamespace,
                                observed: observedNs
                            )
                        }
                        if childCapabilityNamespaceObserved == nil, protocolError == nil {
                            protocolError = InheritChildProtocolError(
                                kind: "capability_namespace_missing",
                                expected: InheritChildProtocol.capabilityNamespace,
                                observed: ""
                            )
                        }
                        continue
                    }
                    if let decoded = try? decodeJSON(InheritChildEvent.self, from: line) {
                        eventLock.lock()
                        events.append(decoded)
                        eventLock.unlock()
                        if let details = decoded.details {
                            if let eventFdStr = details["event_fd"], childEventFdObserved == nil {
                                childEventFdObserved = Int(eventFdStr)
                            }
                            if let rightsFdStr = details["rights_fd"], childRightsFdObserved == nil {
                                childRightsFdObserved = Int(rightsFdStr)
                            }
                        }
                        if decoded.phase == "child_capability_result" {
                            let details = decoded.details ?? [:]
                            let capId = details["cap_id"] ?? ""
                            let acquireRc = Int(details["child_acquire_rc"] ?? "")
                            let acquireErrno = Int(details["child_acquire_errno"] ?? "")
                            let useRc = Int(details["child_use_rc"] ?? "")
                            let useErrno = Int(details["child_use_errno"] ?? "")
                            if var builder = builders[capId] {
                                builder.childAcquire = InheritChildCapabilityOpResult(
                                    rc: acquireRc,
                                    errno: acquireErrno
                                )
                                builder.childUse = InheritChildCapabilityOpResult(
                                    rc: useRc,
                                    errno: useErrno
                                )
                                if capId == "bookmark" {
                                    let resolveRc = Int(details["bookmark_resolve_rc"] ?? "")
                                    let resolveError = details["bookmark_resolve_error"]
                                    let resolveErrorDomain = details["bookmark_resolve_error_domain"]
                                    let resolveErrorCode = Int(details["bookmark_resolve_error_code"] ?? "")
                                    let isStale = details["bookmark_is_stale"].map { $0 == "true" }
                                    let startAccessing = details["bookmark_start_accessing"].map { $0 == "true" }
                                    let accessRc = Int(details["bookmark_access_rc"] ?? "")
                                    let accessErrno = Int(details["bookmark_access_errno"] ?? "")
                                    builder.bookmark = InheritChildBookmarkResult(
                                        resolve_rc: resolveRc,
                                        resolve_error: resolveError,
                                        resolve_error_domain: resolveErrorDomain,
                                        resolve_error_code: resolveErrorCode,
                                        is_stale: isStale,
                                        start_accessing: startAccessing,
                                        access_rc: accessRc,
                                        access_errno: accessErrno
                                    )
                                }
                                builders[capId] = builder
                            }
                        }
                        if decoded.phase == "child_capability_recv_failed" {
                            let details = decoded.details ?? [:]
                            let kind = details["reason"] ?? "protocol_violation"
                            let capId = details["cap_id"]
                            let expected = details["expected"]
                            let observed = details["observed"]
                            let nonProtocolKinds: Set<String> = [
                                "recvmsg_failed",
                                "rights_fd_invalid"
                            ]
                            if protocolError == nil, !nonProtocolKinds.contains(kind) {
                                protocolError = InheritChildProtocolError(
                                    kind: kind,
                                    cap_id: capId,
                                    expected: expected,
                                    observed: observed,
                                    details: details
                                )
                            }
                        }
                        if decoded.phase == "child_protocol_violation", protocolError == nil {
                            let details = decoded.details ?? [:]
                            let expected = details["expected_protocol"] ?? details["expected"]
                            let observed = details["observed_protocol"] ?? details["observed"]
                            protocolError = InheritChildProtocolError(
                                kind: "child_protocol_violation",
                                cap_id: nil,
                                expected: expected,
                                observed: observed,
                                details: details
                            )
                        }
                        if decoded.phase == "child_acquire_attempt",
                           decoded.details?["cap_id"] == "file_fd",
                           let semaphore = preAcquireSemaphore {
                            preAcquireLock.lock()
                            if !preAcquireSignaled {
                                preAcquireSignaled = true
                                semaphore.signal()
                            }
                            preAcquireLock.unlock()
                        }
                        if decoded.phase == "child_ready" {
                            eventSink?("child_ready", childPidInt, runId, "child ready")
                        }
                    } else {
                        recordEvent(
                            actor: "parent",
                            phase: "child_event_decode_failed",
                            pid: parentPid,
                            details: ["line": lineStr]
                        )
                    }
                }
            }
            readGroup.leave()
        }

        if let preAcquireSemaphore {
            let waitResult = preAcquireSemaphore.wait(timeout: .now() + .seconds(2))
            if waitResult == .timedOut {
                recordEvent(
                    actor: "parent",
                    phase: "child_pre_acquire_timeout",
                    pid: parentPid,
                    details: ["cap_id": "file_fd"]
                )
            }
	        }

	        if usesSandboxExtension, let parentToken {
	            let consumeSymbol = "sandbox_extension_consume"
	            let consumeVariant = "handle_one_arg"
	            let tokenUsed = parentToken.trimmingCharacters(in: .whitespacesAndNewlines)

	            let handle: Int64
	            let consumeErrno: Int32
	            if let consumeSym = resolveSandboxExtensionSymbol(consumeSymbol) {
	                errno = 0
	                let fn = unsafeBitCast(consumeSym, to: SandboxExtensionConsumeHandleFn.self)
	                handle = tokenUsed.withCString { tokenPtr in
	                    fn(tokenPtr)
	                }
	                consumeErrno = errno
	            } else {
	                handle = -1
	                consumeErrno = 0
	            }

	            let ok = handle > 0 && consumeErrno == 0
	            recordEvent(
	                actor: "parent",
	                phase: "parent_token_consumed",
	                pid: parentPid,
	                details: [
	                    "call_symbol": consumeSymbol,
	                    "call_variant": consumeVariant,
	                    "handle": "\(handle)"
	                ],
	                errno: consumeErrno == 0 ? nil : Int(consumeErrno),
	                rc: ok ? 0 : 1
	            )
	            if !ok {
	                kill(childPid, SIGKILL)
	                close(rightsParentFd)
	                close(eventParentFd)
	                let errMsg = (consumeErrno != 0) ? String(cString: strerror(consumeErrno)) : "sandbox_extension_consume failed"
	                return attachWitness(
	                    RunProbeResponse(
	                        rc: 1,
	                        stdout: "",
	                        stderr: "",
	                        normalized_outcome: "consume_failed",
	                        errno: consumeErrno != 0 ? Int(consumeErrno) : nil,
	                        error: errMsg,
	                        details: details,
	                        layer_attribution: nil
	                    ),
	                    childPid: childPidInt,
	                    childPath: resolvedChildPath,
	                    childEventFd: Int(eventFd),
	                    childRightsFd: Int(rightsFd),
	                    childBundleId: childBundleId ?? "",
	                    childTeamId: childTeamId ?? "",
	                    childEntitlements: childEntitlements,
	                    inheritContractOk: inheritContractOk,
	                    outcomeSummary: "consume_failed"
	                )
	            }
	        }

	        if usesSandboxExtension {
	            let (acquired, response) = acquireParentCapabilities()
	            if let response {
                kill(childPid, SIGKILL)
                close(rightsParentFd)
                close(eventParentFd)
                return attachWitness(
                    response,
                    childPid: childPidInt,
                    childPath: resolvedChildPath,
                    childEventFd: Int(eventFd),
                    childRightsFd: Int(rightsFd),
                    childBundleId: childBundleId ?? "",
                    childTeamId: childTeamId ?? "",
                    childEntitlements: childEntitlements,
                    inheritContractOk: inheritContractOk,
                    outcomeSummary: response.normalized_outcome
                )
            }
            if let acquired {
                parentCapabilities = acquired
            }
        }

        var badCapSent = false
        for cap in parentCapabilities {
            var capIdToSend = cap.plan.id
            if protocolBadCapId, !badCapSent {
                capIdToSend = 9999
                badCapSent = true
            }
            let sendRc = sendCapability(
                socketFd: rightsParentFd,
                fdToSend: cap.fd,
                capId: capIdToSend,
                meta: [Int32(InheritChildProtocol.version), 0, 0]
            )
            recordEvent(
                actor: "parent",
                phase: "parent_capability_sent",
                pid: parentPid,
                details: [
                    "cap_id": cap.plan.type.rawValue,
                    "cap_type": cap.plan.type.rawValue,
                    "cap_id_sent": "\(capIdToSend)",
                    "cap_id_expected": "\(cap.plan.id)"
                ],
                errno: sendRc.1.map { Int($0) },
                rc: sendRc.0
            )
            close(cap.fd)
            if sendRc.0 != 0 {
                close(rightsParentFd)
                close(eventParentFd)
                return attachWitness(
                    RunProbeResponse(
                        rc: 1,
                        stdout: "",
                        stderr: "",
                        normalized_outcome: "child_rights_bus_io_error",
                        errno: sendRc.1.map { Int($0) },
                        error: "failed to send capability \(cap.plan.type.rawValue) over rights bus",
                        details: details,
                        layer_attribution: nil
                    ),
                    childPid: childPidInt,
                    childPath: resolvedChildPath,
                    childEventFd: Int(eventFd),
                    childRightsFd: Int(rightsFd),
                    childBundleId: childBundleId ?? "",
                    childTeamId: childTeamId ?? "",
                    childEntitlements: childEntitlements,
                    inheritContractOk: inheritContractOk,
                    outcomeSummary: "child_rights_bus_io_error"
                )
            }
        }
        close(rightsParentFd)

        var childExitStatus: Int? = nil
        var status: Int32 = 0
        while true {
            let waitRc = waitpid(childPid, &status, WUNTRACED)
            if waitRc == -1 {
                break
            }
            if wIfStopped(status) {
                let sig = wStopSig(status)
                eventSink?("child_stopped", childPidInt, runId, "signal=\(signalName(sig))")
                recordEvent(
                    actor: "parent",
                    phase: "child_stopped",
                    pid: parentPid,
                    details: ["signal": signalName(sig)]
                )
                if stopAutoResume {
                    let resumeRc = kill(childPid, SIGCONT)
                    if resumeRc == 0 {
                        recordEvent(
                            actor: "parent",
                            phase: "child_resumed",
                            pid: parentPid,
                            details: ["signal": "SIGCONT"]
                        )
                    } else {
                        recordEvent(
                            actor: "parent",
                            phase: "child_resume_failed",
                            pid: parentPid,
                            details: [
                                "signal": "SIGCONT",
                                "errno": "\(errno)"
                            ]
                        )
                    }
                }
                continue
            }
            if wIfExited(status) {
                childExitStatus = Int(wExitStatus(status))
                break
            }
            if wIfSignaled(status) {
                childExitStatus = 128 + Int(wTermSig(status))
                break
            }
        }

        _ = readGroup.wait(timeout: .now() + .seconds(2))
        close(eventParentFd)
        if childEventFdObserved == nil {
            childEventFdObserved = Int(eventFd)
        }
        if childRightsFdObserved == nil {
            childRightsFdObserved = Int(rightsFd)
        }
        if let socketListenerFd {
            close(socketListenerFd)
            _ = socketPath.withCString { unlink($0) }
        }

        if let childExitStatus {
            details["child_exit_status"] = "\(childExitStatus)"
        }

        if let childExitStatus {
            eventSink?("child_exited", childPidInt, runId, "status=\(childExitStatus)")
            recordEvent(
                actor: "parent",
                phase: "child_exited",
                pid: parentPid,
                details: ["status": "\(childExitStatus)"]
            )
        }

        func summarizeResult(_ result: InheritChildCapabilityOpResult?) -> String {
            guard let result else { return "unknown" }
            if result.rc == 0 {
                return "ok"
            }
            if let errno = result.errno, errno == EPERM || errno == EACCES {
                return "deny"
            }
            return "err"
        }

        eventLock.lock()
        let finalEvents = events
        eventLock.unlock()

        var capabilityResults: [InheritChildCapabilityResult] = []
        for plan in capabilityPlan {
            if let builder = builders[plan.type.rawValue] {
                capabilityResults.append(
                    InheritChildCapabilityResult(
                        cap_id: builder.capId,
                        cap_type: builder.capType,
                        parent_acquire: builder.parentAcquire,
                        child_acquire: builder.childAcquire,
                        child_use: builder.childUse,
                        bookmark: builder.bookmark,
                        notes: builder.notes
                    )
                )
            }
        }

        var summary = capabilityResults.map { result in
            let acquire = summarizeResult(result.child_acquire)
            let use = summarizeResult(result.child_use)
            return "\(result.cap_id): acquire=\(acquire) use=\(use)"
        }.joined(separator: " ")

        if capabilityResults.isEmpty {
            if scenario == "inherit_bad_entitlements" {
                let statusStr = childExitStatus.map { "\($0)" } ?? "unknown"
                summary = "expected abort due to inheritance entitlement contamination (status=\(statusStr))"
            } else if scenario == "lineage_basic" {
                summary = "lineage: ok"
            }
        }

        let childProtocolViolationExit = 96
        let childRightsBusExit = 97
        let childEventBusExit = 98
        var normalizedOutcome = "ok"
        if protocolError != nil {
            normalizedOutcome = "child_protocol_violation"
        } else if let childExitStatus {
            if childExitStatus == childProtocolViolationExit {
                normalizedOutcome = "child_protocol_violation"
            } else if childExitStatus == childRightsBusExit {
                normalizedOutcome = "child_rights_bus_io_error"
            } else if childExitStatus == childEventBusExit {
                normalizedOutcome = "child_event_bus_io_error"
            } else if scenario == "inherit_bad_entitlements" {
                normalizedOutcome = childExitStatus >= 128 ? "child_abort_expected" : "child_abort_missing"
            } else if childExitStatus != 0 {
                normalizedOutcome = "child_exit_nonzero"
            }
        } else {
            normalizedOutcome = "child_exit_unknown"
        }

        let witness = InheritChildWitness(
            protocol_version: InheritChildProtocol.version,
            capability_namespace: InheritChildProtocol.capabilityNamespace,
            run_id: runId,
            scenario: scenario,
            profile: profileName,
            parent_pid: parentPid,
            child_pid: childPidInt,
            child_exit_status: childExitStatus ?? -1,
            child_event_fd: childEventFdObserved ?? Int(eventFd),
            child_rights_fd: childRightsFdObserved ?? Int(rightsFd),
            child_path: resolvedChildPath,
            service_bundle_id: serviceBundleId,
            process_name: processName,
            child_bundle_id: childBundleId ?? "",
            child_team_id: childTeamId ?? "",
            child_entitlements: childEntitlements,
            inherit_contract_ok: inheritContractOk,
            capability_results: capabilityResults,
            stop_on_entry: stopOnEntry,
            stop_on_deny: stopOnDeny,
            events: finalEvents,
            system_sandbox_reports: nil,
            sandbox_log_capture_status: "not_requested",
            sandbox_log_capture: [:],
            protocol_error: protocolError,
            outcome_summary: summary
        )

        let ok = normalizedOutcome == "ok" || normalizedOutcome == "child_abort_expected"
        return RunProbeResponse(
            rc: ok ? 0 : 1,
            stdout: "",
            stderr: "",
            normalized_outcome: normalizedOutcome,
            errno: nil,
            error: nil,
            details: details,
            witness: witness,
            layer_attribution: nil
        )
    }

	    // MARK: - userdefaults_op (containerization + API mediation)

	    private static func probeUserDefaultsOp(argv: [String]) -> RunProbeResponse {
	        let args = Argv(argv)
	        let op = args.value("--op") ?? "read"
	        let key = args.value("--key") ?? "entitlement_jail_userdefaults_probe"
	        let value = args.value("--value") ?? "1"
	        let suite = args.value("--suite")

	        let defaults: UserDefaults
	        if let suite, !suite.isEmpty {
	            defaults = UserDefaults(suiteName: suite) ?? .standard
	        } else {
	            defaults = .standard
	        }

	        let domain = (suite?.isEmpty == false ? suite! : (Bundle.main.bundleIdentifier ?? ""))
	        let prefsPath = FileManager.default.homeDirectoryForCurrentUser
	            .appendingPathComponent("Library/Preferences", isDirectory: true)
	            .appendingPathComponent("\(domain).plist", isDirectory: false)
	            .path

	        var details = baseDetails([
	            "probe_family": "userdefaults_op",
	            "op": op,
	            "key": key,
	            "value_len": "\(value.utf8.count)",
	            "suite": suite ?? "",
	            "domain": domain,
	            "file_path": prefsPath,
	        ])

	        func finish(rc: Int, outcome: String) -> RunProbeResponse {
	            RunProbeResponse(
	                rc: rc,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: nil,
	                error: nil,
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        switch op {
	        case "read":
	            let v = defaults.string(forKey: key)
	            details["present"] = (v == nil) ? "false" : "true"
	            return finish(rc: 0, outcome: "ok")
	        case "write":
	            defaults.set(value, forKey: key)
	            details["synchronized"] = defaults.synchronize() ? "true" : "false"
	            return finish(rc: 0, outcome: "ok")
	        case "remove":
	            defaults.removeObject(forKey: key)
	            details["synchronized"] = defaults.synchronize() ? "true" : "false"
	            return finish(rc: 0, outcome: "ok")
	        case "sync":
	            details["synchronized"] = defaults.synchronize() ? "true" : "false"
	            return finish(rc: 0, outcome: "ok")
	        default:
	            return badRequest("invalid --op for userdefaults_op (expected: read|write|remove|sync)")
	        }
	    }

	    // MARK: - fs_xattr (xattr operations; read-only by default)

	    private enum FsXattrOp: String, CaseIterable {
	        case get
	        case list
	        case set
	        case remove
	    }

	    private static func probeFsXattr(argv: [String]) -> RunProbeResponse {
	        let args = Argv(argv)
	        let expectedOps = FsXattrOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let opStr = args.value("--op"), let op = FsXattrOp(rawValue: opStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }
	        guard let path = args.value("--path"), path.hasPrefix("/") else {
	            return badRequest("fs_xattr requires --path <absolute-path>")
	        }

        let allowWrite = args.has("--allow-write") || args.has("--allow-unsafe-path")
        if (op == .set || op == .remove), !allowWrite, !isSafeWritePath(path) {
            return RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "",
                normalized_outcome: "bad_request",
                errno: nil,
                error: "refusing xattr write on non-harness path (use a path under */policy-witness-harness/*; use --allow-write or --allow-unsafe-path to override)",
                details: baseDetails([
                    "probe_family": "fs_xattr",
                    "op": op.rawValue,
                    "file_path": path,
                ]),
	                layer_attribution: nil
	            )
	        }

	        var details = baseDetails([
	            "probe_family": "fs_xattr",
	            "op": op.rawValue,
	            "file_path": path,
	        ])

	        let name = args.value("--name") ?? "com.apple.quarantine"

	        func finish(rc: Int, outcome: String, errno: Int?, error: String?) -> RunProbeResponse {
	            RunProbeResponse(
	                rc: rc,
	                stdout: "",
	                stderr: "",
	                normalized_outcome: outcome,
	                errno: errno,
	                error: error,
	                details: details,
	                layer_attribution: nil
	            )
	        }

	        func withCString2<T>(_ a: String, _ b: String, _ f: (UnsafePointer<CChar>, UnsafePointer<CChar>) -> T) -> T {
	            a.withCString { aPtr in
	                b.withCString { bPtr in
	                    f(aPtr, bPtr)
	                }
	            }
	        }

	        switch op {
	        case .get:
	            let size = withCString2(path, name) { pathPtr, namePtr in
	                getxattr(pathPtr, namePtr, nil, 0, 0, 0)
	            }
	            if size < 0 {
	                let e = errno
	                let outcome: String
	                if e == ENOATTR || e == ENODATA { outcome = "absent" }
	                else if e == ENOENT { outcome = "not_found" }
	                else if e == EPERM || e == EACCES { outcome = "permission_error" }
	                else { outcome = "getxattr_failed" }
	                return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	            }
	            details["xattr_present"] = "true"
	            details["xattr_size"] = "\(size)"
	            return finish(rc: 0, outcome: "ok", errno: nil, error: nil)

	        case .list:
	            let size = path.withCString { pathPtr in
	                listxattr(pathPtr, nil, 0, 0)
	            }
	            if size < 0 {
	                let e = errno
	                let outcome: String
	                if e == ENOENT { outcome = "not_found" }
	                else if e == EPERM || e == EACCES { outcome = "permission_error" }
	                else { outcome = "listxattr_failed" }
	                return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	            }
	            details["xattr_list_size"] = "\(size)"
	            return finish(rc: 0, outcome: "ok", errno: nil, error: nil)

	        case .set:
	            let value = args.value("--value") ?? ""
	            let data = Data(value.utf8)
	            let rc = data.withUnsafeBytes { bytes in
	                withCString2(path, name) { pathPtr, namePtr in
	                    setxattr(pathPtr, namePtr, bytes.baseAddress, bytes.count, 0, 0)
	                }
	            }
	            if rc != 0 {
	                let e = errno
	                let outcome: String
	                if e == ENOENT { outcome = "not_found" }
	                else if e == EPERM || e == EACCES { outcome = "permission_error" }
	                else { outcome = "setxattr_failed" }
	                return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	            }
	            details["xattr_value_len"] = "\(data.count)"
	            return finish(rc: 0, outcome: "ok", errno: nil, error: nil)

	        case .remove:
	            let rc = withCString2(path, name) { pathPtr, namePtr in
	                removexattr(pathPtr, namePtr, 0)
	            }
	            if rc != 0 {
	                let e = errno
	                let outcome: String
	                if e == ENOATTR || e == ENODATA { outcome = "absent" }
	                else if e == ENOENT { outcome = "not_found" }
	                else if e == EPERM || e == EACCES { outcome = "permission_error" }
	                else { outcome = "removexattr_failed" }
	                return finish(rc: 1, outcome: outcome, errno: Int(e), error: String(cString: strerror(e)))
	            }
	            return finish(rc: 0, outcome: "ok", errno: nil, error: nil)
	        }
	    }

    private static func badRequest(_ msg: String) -> RunProbeResponse {
        RunProbeResponse(
            rc: 2,
            stdout: "",
            stderr: msg,
            normalized_outcome: "bad_request",
            errno: nil,
            error: nil,
            details: baseDetails([
                "probe_family": "bad_request",
            ]),
            layer_attribution: nil
        )
    }

	    private static func validateProbeId(_ probeId: String) -> Bool {
	        if probeId.isEmpty { return false }
	        if probeId == "." || probeId == ".." { return false }
	        if probeId.contains("/") || probeId.contains("\\") { return false }
	        return true
	    }

	    private static func isSinglePathComponent(_ s: String) -> Bool {
	        if s.isEmpty || s == "." || s == ".." { return false }
	        return !s.contains("/") && !s.contains("\\")
	    }

	    private static func entitlementBool(_ key: String) -> Bool {
	        guard let task = SecTaskCreateFromSelf(nil) else {
	            return false
	        }
        guard let value = SecTaskCopyValueForEntitlement(task, key as CFString, nil) else {
            return false
        }
        if let b = value as? Bool {
            return b
        }
        if let n = value as? NSNumber {
            return n.boolValue
        }
        return false
    }

    private static func extractErrno(_ error: Error) -> Int? {
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain {
            return ns.code
        }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError, underlying.domain == NSPOSIXErrorDomain {
            return underlying.code
        }
        return nil
    }

    private static func isPermissionError(_ error: Error) -> Bool {
        guard let e = extractErrno(error) else { return false }
        return e == EPERM || e == EACCES
    }
}

private struct Argv {
    private var args: [String]

    init(_ args: [String]) {
        self.args = args
    }

	    func value(_ flag: String) -> String? {
	        guard let idx = args.firstIndex(of: flag) else {
	            return nil
	        }
        let vIdx = idx + 1
	        guard vIdx < args.count else {
	            return nil
	        }
	        return args[vIdx]
	    }

	    func intValue(_ flag: String) -> Int? {
	        guard let s = value(flag) else { return nil }
	        return Int(s)
	    }

	    func has(_ flag: String) -> Bool {
	        args.contains(flag)
	    }
	}

@_silgen_name("open")
private func c_open(_ path: UnsafePointer<CChar>?, _ flags: Int32, _ mode: Int32) -> Int32

@_cdecl("pw_open")
@inline(never)
public func pw_open(_ path: UnsafePointer<CChar>?, _ flags: Int32, _ mode: Int32) -> Int32 {
    c_open(path, flags, mode)
}

@_cdecl("pw_connect")
@inline(never)
public func pw_connect(_ socket: Int32, _ addr: UnsafePointer<sockaddr>?, _ len: socklen_t) -> Int32 {
    Darwin.connect(socket, addr, len)
}

@_cdecl("pw_getaddrinfo")
@inline(never)
public func pw_getaddrinfo(
    _ node: UnsafePointer<CChar>?,
    _ service: UnsafePointer<CChar>?,
    _ hints: UnsafePointer<addrinfo>?,
    _ res: UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>?>?
) -> Int32 {
    getaddrinfo(node, service, hints, res)
}

@_cdecl("pw_sendto")
@inline(never)
public func pw_sendto(
    _ socket: Int32,
    _ buffer: UnsafeRawPointer?,
    _ len: Int,
    _ flags: Int32,
    _ addr: UnsafePointer<sockaddr>?,
    _ addrlen: socklen_t
) -> Int {
    sendto(socket, buffer, len, flags, addr, addrlen)
}

@_cdecl("pw_dlopen")
@inline(never)
public func pw_dlopen(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> UnsafeMutableRawPointer? {
    dlopen(path, mode)
}

@_cdecl("pw_mmap")
@inline(never)
public func pw_mmap(
    _ addr: UnsafeMutableRawPointer?,
    _ len: Int,
    _ prot: Int32,
    _ flags: Int32,
    _ fd: Int32,
    _ offset: Int64
) -> UnsafeMutableRawPointer? {
    mmap(addr, len, prot, flags, fd, offset)
}

@_cdecl("pw_munmap")
@inline(never)
public func pw_munmap(_ addr: UnsafeMutableRawPointer?, _ len: Int) -> Int32 {
    munmap(addr, len)
}
