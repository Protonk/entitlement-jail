import Foundation
import Darwin
import Security

// Stable, C-callable trace markers for external instrumentation tools.
@_cdecl("ej_probe_fs_op")
@inline(never)
@_optimize(none)
public func ej_probe_fs_op_marker() {}

@_cdecl("ej_probe_fs_op_wait")
@inline(never)
@_optimize(none)
public func ej_probe_fs_op_wait_marker() {}

@_cdecl("ej_probe_net_op")
@inline(never)
@_optimize(none)
public func ej_probe_net_op_marker() {}

@_cdecl("ej_probe_dlopen_external")
@inline(never)
@_optimize(none)
public func ej_probe_dlopen_external_marker() {}

@_cdecl("ej_probe_jit_map_jit")
@inline(never)
@_optimize(none)
public func ej_probe_jit_map_jit_marker() {}

@_cdecl("ej_probe_jit_rwx_legacy")
@inline(never)
@_optimize(none)
public func ej_probe_jit_rwx_legacy_marker() {}

public enum InProcessProbeCore {
    public static func run(_ req: RunProbeRequest) -> RunProbeResponse {
        let started = Date()
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
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

        var waitDetails: [String: String] = [:]
        if let waitSpec = req.wait_spec {
            let waitOutcome = performWaitFromSpec(waitSpec)
            waitDetails = waitOutcome.details
            if waitOutcome.result.normalizedOutcome != "ok" {
                let response = RunProbeResponse(
                    rc: waitOutcome.rc,
                    stdout: "",
                    stderr: waitOutcome.stderr,
                    normalized_outcome: waitOutcome.result.normalizedOutcome,
                    errno: waitOutcome.result.errno.map { Int($0) },
                    error: waitOutcome.result.error,
                    details: baseDetails(waitDetails.merging([
                        "probe_family": "wait",
                    ], uniquingKeysWith: { cur, _ in cur })),
                    layer_attribution: nil,
                    sandbox_log_excerpt_ref: nil
                )
                let ended = Date()
                return decorate(response, req: req, started: started, ended: ended)
            }
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
        case "userdefaults_op":
            response = probeUserDefaultsOp(argv: req.argv)
        case "fs_xattr":
            response = probeFsXattr(argv: req.argv)
        case "fs_coordinated_op":
            response = probeFsCoordinatedOp(argv: req.argv)
        default:
            response = unknownProbeResponse(req.probe_id)
        }
        if !waitDetails.isEmpty {
            var details = response.details ?? [:]
            for (k, v) in waitDetails {
                details[k] = v
            }
            response.details = details
        }
        let ended = Date()
        return decorate(response, req: req, started: started, ended: ended)
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
        response.expected_outcome = req.expected_outcome ?? response.expected_outcome
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
            "home_dir": NSHomeDirectory(),
            "tmp_dir": NSTemporaryDirectory(),
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
            summary: "read/write/remove a file under Downloads/entitlement-jail-harness",
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
                "Writes under Downloads/entitlement-jail-harness."
            ]
        ),
        ProbeSpec(
            probe_id: "fs_op",
            summary: "parameterized filesystem operations",
            usage: """
fs_op --op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>
      (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
      [--target <base|harness_dir|run_dir|specimen_file>] [--name <file-name>]
      [--to <path>|--to-path <path>|--to-name <file-name>] [--max-entries <n>] [--allow-unsafe-path]
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
                "--allow-unsafe-path"
            ],
            examples: [
                "fs_op --op stat --path-class downloads",
                "fs_op --op create --path-class tmp --target run_dir"
            ],
            entitlement_hints: ["path-dependent (file access entitlements)"],
            notes: [
                "Destructive direct-path ops are refused unless you use --path-class/--target (or a path under */entitlement-jail-harness/*) or set --allow-unsafe-path."
            ]
        ),
        ProbeSpec(
            probe_id: "fs_op_wait",
            summary: "wait for a trigger, then run fs_op",
            usage: """
fs_op_wait --op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>
          (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
          [--target <base|harness_dir|run_dir|specimen_file>] [--name <file-name>]
          [--to <path>|--to-path <path>|--to-name <file-name>] [--max-entries <n>] [--allow-unsafe-path]
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
                "--wait-timeout-ms <n>",
                "--wait-interval-ms <n>"
            ],
            examples: [
                "fs_op_wait --op open_read --path-class tmp --wait-fifo /tmp/ej-wait.fifo",
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
            usage: "dlopen_external --path <abs> (or set EJ_DLOPEN_PATH)",
            required_args: [
                "--path <abs> (or EJ_DLOPEN_PATH)"
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
                "Uses ScopedBookmarksAgent IPC for security-scoped bookmarks."
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
                "Security-scoped bookmarks use ScopedBookmarksAgent IPC."
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
                "Returns the bookmark token in stdout and the fs_op result in details."
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
                "Coordinated writes to direct paths are refused unless you use --path-class/--target (or a path under */entitlement-jail-harness/*) or set --allow-unsafe-path."
            ]
        )
    ]

    private static let traceSymbols: [TraceSymbolSpec] = [
        TraceSymbolSpec(probe_id: "fs_op", symbols: ["ej_probe_fs_op"]),
        TraceSymbolSpec(probe_id: "fs_op_wait", symbols: ["ej_probe_fs_op_wait"]),
        TraceSymbolSpec(probe_id: "net_op", symbols: ["ej_probe_net_op"]),
        TraceSymbolSpec(probe_id: "dlopen_external", symbols: ["ej_probe_dlopen_external"]),
        TraceSymbolSpec(probe_id: "jit_map_jit", symbols: ["ej_probe_jit_map_jit"]),
        TraceSymbolSpec(probe_id: "jit_rwx_legacy", symbols: ["ej_probe_jit_rwx_legacy"]),
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
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
            layer_attribution: nil,
            sandbox_log_excerpt_ref: nil
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
            layer_attribution: nil,
            sandbox_log_excerpt_ref: nil
        )
    }

    private static func probeWorldShape() -> RunProbeResponse {
        let home = NSHomeDirectory()
        let tmp = NSTemporaryDirectory()
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
            layer_attribution: LayerAttribution(world_shape_change: worldShapeChange),
            sandbox_log_excerpt_ref: nil
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }
        defer { close(fd) }

        var addrCopy = addr
        let connectResult: Int32 = withUnsafePointer(to: &addrCopy) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                ej_connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.stride))
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
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
            layer_attribution: nil,
            sandbox_log_excerpt_ref: nil
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }

        let harnessDir = downloadsDir.appendingPathComponent("entitlement-jail-harness", isDirectory: true)
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }

        do {
            try FileManager.default.createDirectory(at: harnessDir, withIntermediateDirectories: true, attributes: nil)
        } catch {
            let outcome = isPermissionError(error) ? "permission_error" : "mkdir_failed"
            return opError(outcome, error, op: "mkdir")
        }

        let payload = Data("entitlement-jail downloads_rw probe\n".utf8)
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
	            layer_attribution: nil,
	            sandbox_log_excerpt_ref: nil
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

        private struct WaitOutcome {
            var result: WaitResult
            var details: [String: String]
            var rc: Int
            var stderr: String
        }

        private struct WaitConfig {
            var mode: String
            var path: String
            var pathClass: String?
            var name: String?
            var timeoutMs: Int?
            var intervalMs: Int
            var create: Bool
        }

        private struct WaitSpecError: Error {
            var message: String
        }

        private static func performWaitFromSpec(_ spec: WaitSpec) -> WaitOutcome {
            let resolved = resolveWaitSpec(spec)
            switch resolved {
            case .failure(let err):
                return WaitOutcome(
                    result: WaitResult(normalizedOutcome: "bad_request", errno: nil, error: nil),
                    details: ["wait_error": err.message],
                    rc: 2,
                    stderr: err.message
                )
            case .success(let config):
                let (result, details) = performWait(config)
                let rc = (result.normalizedOutcome == "ok") ? 0 : 1
                return WaitOutcome(result: result, details: details, rc: rc, stderr: "")
            }
        }

        private static func resolveWaitSpec(_ spec: WaitSpec) -> Result<WaitConfig, WaitSpecError> {
            guard let mode = spec.mode, !mode.isEmpty else {
                return .failure(WaitSpecError(message: "missing wait_spec.mode (expected fifo|exists)"))
            }
            if mode != "fifo" && mode != "exists" {
                return .failure(WaitSpecError(message: "invalid wait_spec.mode (expected fifo|exists)"))
            }
            if let timeoutMs = spec.timeout_ms, timeoutMs < 0 {
                return .failure(WaitSpecError(message: "wait_spec.timeout_ms must be >= 0"))
            }
            if let intervalMs = spec.interval_ms, intervalMs < 1 {
                return .failure(WaitSpecError(message: "wait_spec.interval_ms must be >= 1"))
            }
            if spec.create == true && mode != "fifo" {
                return .failure(WaitSpecError(message: "wait_spec.create is only valid with mode=fifo"))
            }
            if spec.path != nil && (spec.path_class != nil || spec.name != nil) {
                return .failure(WaitSpecError(message: "wait_spec.path cannot be combined with wait_spec.path_class/name"))
            }

            var resolvedPath = spec.path
            if resolvedPath == nil {
                guard let pathClass = spec.path_class, let name = spec.name else {
                    return .failure(WaitSpecError(message: "wait_spec.path or (wait_spec.path_class + wait_spec.name) is required"))
                }
                guard isSinglePathComponent(name) else {
                    return .failure(WaitSpecError(message: "wait_spec.name must be a single path component"))
                }
                guard let base = resolveStandardDirectory(pathClass) else {
                    return .failure(WaitSpecError(message: "invalid wait_spec.path_class: \(pathClass) (expected: home|tmp|downloads|desktop|documents|app_support|caches)"))
                }
                resolvedPath = base.appendingPathComponent(name, isDirectory: false).path
            }

            guard let resolvedPath, resolvedPath.hasPrefix("/") else {
                return .failure(WaitSpecError(message: "wait path must be absolute"))
            }

            let intervalMs = spec.interval_ms ?? 200
            let create = spec.create ?? false

            return .success(WaitConfig(
                mode: mode,
                path: resolvedPath,
                pathClass: spec.path_class,
                name: spec.name,
                timeoutMs: spec.timeout_ms,
                intervalMs: intervalMs,
                create: create
            ))
        }

        private static func performWait(_ config: WaitConfig) -> (WaitResult, [String: String]) {
            var details: [String: String] = [
                "wait_mode": config.mode,
                "wait_path": config.path,
            ]
            if let pathClass = config.pathClass { details["wait_path_class"] = pathClass }
            if let name = config.name { details["wait_name"] = name }
            if let timeoutMs = config.timeoutMs { details["wait_timeout_ms"] = "\(timeoutMs)" }
            if config.mode == "exists" { details["wait_interval_ms"] = "\(config.intervalMs)" }
            if config.create { details["wait_create"] = "true" }

            let waitStartNs = DispatchTime.now().uptimeNanoseconds
            details["wait_started_at_ns"] = "\(waitStartNs)"

            let result: WaitResult
            if config.mode == "fifo" {
                if config.create, let err = ensureFifo(path: config.path) {
                    let waitEndNs = DispatchTime.now().uptimeNanoseconds
                    details["wait_ended_at_ns"] = "\(waitEndNs)"
                    details["wait_duration_ms"] = "\(Int((waitEndNs - waitStartNs) / 1_000_000))"
                    return (err, details)
                }
                result = waitForFifo(path: config.path, timeoutMs: config.timeoutMs)
            } else {
                result = waitForPathExists(path: config.path, timeoutMs: config.timeoutMs, intervalMs: config.intervalMs)
            }

            let waitEndNs = DispatchTime.now().uptimeNanoseconds
            details["wait_ended_at_ns"] = "\(waitEndNs)"
            details["wait_duration_ms"] = "\(Int((waitEndNs - waitStartNs) / 1_000_000))"
            return (result, details)
        }

        private static func ensureFifo(path: String) -> WaitResult? {
            var st = stat()
            if lstat(path, &st) == 0 {
                if (st.st_mode & S_IFMT) != S_IFIFO {
                    return WaitResult(normalizedOutcome: "wait_failed", errno: nil, error: "wait path exists and is not a fifo")
                }
                return nil
            }
            let e = errno
            if e != ENOENT {
                return WaitResult(normalizedOutcome: "wait_failed", errno: e, error: String(cString: strerror(e)))
            }
            let rc = path.withCString { ptr in
                mkfifo(ptr, 0o600)
            }
            if rc != 0 {
                let e2 = errno
                if e2 == EEXIST {
                    if lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFIFO {
                        return nil
                    }
                    return WaitResult(normalizedOutcome: "wait_failed", errno: nil, error: "wait path exists and is not a fifo")
                }
                return WaitResult(normalizedOutcome: "wait_failed", errno: e2, error: String(cString: strerror(e2)))
            }
            return nil
        }

	    // MARK: - fs_op_wait (delayed fs_op for attach)

	    private static func probeFsOpWait(argv: [String]) -> RunProbeResponse {
	        ej_probe_fs_op_wait_marker()
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
	            pathClass: nil,
	            name: nil,
	            timeoutMs: timeoutMs,
	            intervalMs: intervalMs,
	            create: false
	        )
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
	                ej_open(ptr, O_RDONLY, 0)
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
	                ej_open(ptr, O_WRONLY | O_NONBLOCK, 0)
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
	        ej_probe_fs_op_marker()
	        let args = Argv(argv)
	        let expectedOps = FsOp.allCases.map(\.rawValue).joined(separator: "|")
	        guard let opStr = args.value("--op"), let op = FsOp(rawValue: opStr) else {
	            return badRequest("missing/invalid --op (expected: \(expectedOps))")
	        }

	        let allowUnsafe = args.has("--allow-unsafe-path") || args.has("--unsafe-path")
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

        let destructiveOps: Set<FsOp> = [.open_write, .create, .truncate, .rename, .unlink, .mkdir, .rmdir]
        if directPath != nil, destructiveOps.contains(op), !allowUnsafe, !isSafeWritePath(resolvedTarget.path) {
            return RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "",
                normalized_outcome: "bad_request",
                errno: nil,
                error: "refusing potentially destructive op=\(op.rawValue) on non-harness path (use --path-class <...> or a path under */entitlement-jail-harness/*; use --allow-unsafe-path to override)",
                details: details,
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
	            )
	        }

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
	                try writeSmallFile(path: targetPath, bytes: Data("entitlement-jail fs_op create\n".utf8))
	                bestEffortCleanup(resolvedTarget.cleanupRoots)
	                return finish(rc: 0, outcome: cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed", errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "))

	            case .open_read:
	                if resolvedTarget.runDir != nil && !FileManager.default.fileExists(atPath: targetPath) {
	                    try writeSmallFile(path: targetPath, bytes: Data("x".utf8))
	                }
                let fd = targetPath.withCString { ptr in
                    ej_open(ptr, O_RDONLY, 0)
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
                    ej_open(ptr, O_WRONLY | O_CREAT, Int32(S_IRUSR | S_IWUSR))
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
                        return badRequest("refusing rename outside harness paths (use --path-class <...> or a path under */entitlement-jail-harness/*; use --allow-unsafe-path to override)")
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
	        guard let baseURL = resolveStandardDirectory(pathClass) else {
	            return (nil, badRequest("invalid --path-class: \(pathClass) (expected: home|tmp|downloads|desktop|documents|app_support|caches)"))
	        }

	        let harnessRoot = baseURL.appendingPathComponent("entitlement-jail-harness", isDirectory: true)
	        let runDir = harnessRoot.appendingPathComponent("fs-op", isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)

	        let name = (requestedName?.isEmpty == false) ? requestedName! : "specimen-\(UUID().uuidString).txt"
	        if target == .specimen_file || target == .path {
	            guard isSinglePathComponent(name) else {
	                return (nil, badRequest("invalid --name (must be a single path component)"))
	            }
	        }

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
	            return URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
	        case "tmp":
	            return URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
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
	            URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
	            URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true).appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
	            FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first?.appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
	            FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first?.appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
	            FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
	            FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?.appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
	            FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?.appendingPathComponent("entitlement-jail-harness", isDirectory: true).path,
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
	        ej_probe_net_op_marker()
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
            let rc = ej_getaddrinfo(host, nil, &hints, &res)
	            if rc != 0 {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "getaddrinfo_failed",
	                    errno: nil,
	                    error: String(cString: gai_strerror(rc)),
	                    details: details,
	                    layer_attribution: nil,
	                    sandbox_log_excerpt_ref: nil
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
            let gai = ej_getaddrinfo(host, String(port), &hints, &res)
	            if gai != 0 {
	                return RunProbeResponse(
	                    rc: 1,
	                    stdout: "",
	                    stderr: "",
	                    normalized_outcome: "getaddrinfo_failed",
	                    errno: nil,
	                    error: String(cString: gai_strerror(gai)),
	                    details: details,
	                    layer_attribution: nil,
	                    sandbox_log_excerpt_ref: nil
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
                    if ej_connect(fd, ai.ai_addr, ai.ai_addrlen) == 0 {
	                        details["attempts"] = "\(attempts)"
	                        details["connect"] = "ok"
	                        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: "ok", errno: nil, error: nil, details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
	                    }
	                    lastErrno = errno
	                } else {
	                    var b: UInt8 = 0x58
                    let sent = withUnsafePointer(to: &b) { ptr in
                        ej_sendto(fd, ptr, 1, 0, ai.ai_addr, ai.ai_addrlen)
                    }
	                    if sent == 1 {
	                        details["attempts"] = "\(attempts)"
	                        details["bytes_sent"] = "1"
	                        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: "ok", errno: nil, error: nil, details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
	            )
	        }
	    }

	    // MARK: - dlopen_external (library validation / injection surface)

	    private static func probeDlopenExternal(argv: [String]) -> RunProbeResponse {
	        ej_probe_dlopen_external_marker()
	        let args = Argv(argv)
	        let path = args.value("--path") ?? ProcessInfo.processInfo.environment["EJ_DLOPEN_PATH"]
	        guard let path, path.hasPrefix("/") else {
	            return badRequest("missing/invalid --path (expected absolute path or EJ_DLOPEN_PATH)")
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
	            )
	        }

	        dlerror()
	        let handle = path.withCString { ptr in
	            ej_dlopen(ptr, Int32(RTLD_NOW))
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
	            layer_attribution: nil,
	            sandbox_log_excerpt_ref: nil
	        )
	    }

	    // MARK: - jit_map_jit (MAP_JIT probe)

	    private static func probeJitMapJit(argv: [String]) -> RunProbeResponse {
	        ej_probe_jit_map_jit_marker()
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
	        guard let ptr = ej_mmap(nil, size, prot, flags, -1, 0), ptr != MAP_FAILED else {
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
	            )
	        }

	        let addr = UInt64(UInt(bitPattern: ptr))
	        details["mmap_addr"] = String(format: "0x%llx", addr)

	        pthread_jit_write_protect_np(0)
	        pthread_jit_write_protect_np(1)
	        details["jit_write_protect_off_rc"] = "called"
	        details["jit_write_protect_on_rc"] = "called"

	        var outcome = "ok"
	        let unmapRc = ej_munmap(ptr, size)
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
	            layer_attribution: nil,
	            sandbox_log_excerpt_ref: nil
	        )
	    }

	    // MARK: - jit_rwx_legacy (RWX mmap probe)

	    private static func probeJitRwxLegacy(argv: [String]) -> RunProbeResponse {
	        ej_probe_jit_rwx_legacy_marker()
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
	        guard let ptr = ej_mmap(nil, size, prot, flags, -1, 0), ptr != MAP_FAILED else {
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
	            )
	        }

	        let addr = UInt64(UInt(bitPattern: ptr))
	        details["mmap_addr"] = String(format: "0x%llx", addr)

	        var outcome = "ok"
	        let unmapRc = ej_munmap(ptr, size)
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
	            layer_attribution: nil,
	            sandbox_log_excerpt_ref: nil
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
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) },
                sandbox_log_excerpt_ref: nil
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
	            layer_attribution: resp.layer_attribution,
	            sandbox_log_excerpt_ref: resp.sandbox_log_excerpt_ref
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) },
                sandbox_log_excerpt_ref: nil
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
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
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
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) },
                sandbox_log_excerpt_ref: nil
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
                layer_attribution: hint.map { LayerAttribution(service_refusal: $0) },
                sandbox_log_excerpt_ref: nil
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
            layer_attribution: resp.layer_attribution,
            sandbox_log_excerpt_ref: resp.sandbox_log_excerpt_ref
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

	        let allowUnsafe = args.has("--allow-unsafe-path") || args.has("--unsafe-path")
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
            return badRequest("refusing potentially destructive coordinated write on non-harness path (use --path-class <...> or a path under */entitlement-jail-harness/*; use --allow-unsafe-path to override)")
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
	                return RunProbeResponse(rc: 1, stdout: "", stderr: "", normalized_outcome: outcome, errno: e, error: "\(error)", details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
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
	            return RunProbeResponse(rc: 1, stdout: "", stderr: "", normalized_outcome: outcome, errno: e, error: "\(coordError)", details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
	        }
	        if let opError {
	            let e = extractErrno(opError)
	            let outcome: String
	            if let e, e == ENOENT { outcome = "not_found" }
	            else if isPermissionError(opError) { outcome = "permission_error" }
	            else { outcome = "op_failed" }
	            bestEffortCleanup(resolvedTarget.cleanupRoots)
	            if !cleanupErrors.isEmpty { details["cleanup_error"] = cleanupErrors.joined(separator: "; ") }
	            return RunProbeResponse(rc: 1, stdout: "", stderr: "", normalized_outcome: outcome, errno: e, error: "\(opError)", details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
	        }

	        if let bytesRead { details["bytes_read"] = "\(bytesRead)" }
	        if let bytesWritten { details["bytes_written"] = "\(bytesWritten)" }
	        bestEffortCleanup(resolvedTarget.cleanupRoots)
	        if !cleanupErrors.isEmpty { details["cleanup_error"] = cleanupErrors.joined(separator: "; ") }
	        let outcome = cleanupErrors.isEmpty ? "ok" : "ok_cleanup_failed"
	        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: outcome, errno: nil, error: cleanupErrors.isEmpty ? nil : cleanupErrors.joined(separator: "; "), details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
	    }

	    // MARK: - capabilities_snapshot (observer)

	    private static func probeCapabilitiesSnapshot() -> RunProbeResponse {
	        let bundleId = Bundle.main.bundleIdentifier ?? ""
	        let prefsPath = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
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
	            layer_attribution: LayerAttribution(world_shape_change: worldShapeChange),
	            sandbox_log_excerpt_ref: nil
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
	        let prefsPath = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
                error: "refusing xattr write on non-harness path (use a path under */entitlement-jail-harness/*; use --allow-write or --allow-unsafe-path to override)",
                details: baseDetails([
                    "probe_family": "fs_xattr",
                    "op": op.rawValue,
                    "file_path": path,
                ]),
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
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
            layer_attribution: nil,
            sandbox_log_excerpt_ref: nil
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

@_cdecl("ej_open")
@inline(never)
public func ej_open(_ path: UnsafePointer<CChar>?, _ flags: Int32, _ mode: Int32) -> Int32 {
    c_open(path, flags, mode)
}

@_cdecl("ej_connect")
@inline(never)
public func ej_connect(_ socket: Int32, _ addr: UnsafePointer<sockaddr>?, _ len: socklen_t) -> Int32 {
    Darwin.connect(socket, addr, len)
}

@_cdecl("ej_getaddrinfo")
@inline(never)
public func ej_getaddrinfo(
    _ node: UnsafePointer<CChar>?,
    _ service: UnsafePointer<CChar>?,
    _ hints: UnsafePointer<addrinfo>?,
    _ res: UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>?>?
) -> Int32 {
    getaddrinfo(node, service, hints, res)
}

@_cdecl("ej_sendto")
@inline(never)
public func ej_sendto(
    _ socket: Int32,
    _ buffer: UnsafeRawPointer?,
    _ len: Int,
    _ flags: Int32,
    _ addr: UnsafePointer<sockaddr>?,
    _ addrlen: socklen_t
) -> Int {
    sendto(socket, buffer, len, flags, addr, addrlen)
}

@_cdecl("ej_dlopen")
@inline(never)
public func ej_dlopen(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> UnsafeMutableRawPointer? {
    dlopen(path, mode)
}

@_cdecl("ej_mmap")
@inline(never)
public func ej_mmap(
    _ addr: UnsafeMutableRawPointer?,
    _ len: Int,
    _ prot: Int32,
    _ flags: Int32,
    _ fd: Int32,
    _ offset: Int64
) -> UnsafeMutableRawPointer? {
    mmap(addr, len, prot, flags, fd, offset)
}

@_cdecl("ej_munmap")
@inline(never)
public func ej_munmap(_ addr: UnsafeMutableRawPointer?, _ len: Int) -> Int32 {
    munmap(addr, len)
}
