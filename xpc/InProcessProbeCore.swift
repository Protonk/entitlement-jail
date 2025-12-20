import Foundation
import Darwin
import Security

public enum InProcessProbeCore {
    public static func run(_ req: RunProbeRequest) -> RunProbeResponse {
        guard validateProbeId(req.probe_id) else {
            return RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "invalid probe_id: \(req.probe_id)",
                normalized_outcome: "bad_request",
                errno: nil,
                error: nil,
                details: nil,
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }

	        switch req.probe_id {
	        case "world_shape":
	            return probeWorldShape()
	        case "network_tcp_connect":
	            return probeNetworkTCPConnect(argv: req.argv)
	        case "downloads_rw":
	            return probeDownloadsReadWrite(argv: req.argv)
	        case "fs_op":
	            return probeFsOp(argv: req.argv)
	        case "net_op":
	            return probeNetOp(argv: req.argv)
	        case "bookmark_op":
	            return probeBookmarkOp(argv: req.argv)
	        case "bookmark_make":
	            return probeBookmarkMake(argv: req.argv)
	        case "capabilities_snapshot":
	            return probeCapabilitiesSnapshot()
	        case "userdefaults_op":
	            return probeUserDefaultsOp(argv: req.argv)
	        case "fs_xattr":
	            return probeFsXattr(argv: req.argv)
	        case "fs_coordinated_op":
	            return probeFsCoordinatedOp(argv: req.argv)
	        default:
	            return RunProbeResponse(
	                rc: 2,
	                stdout: "",
                stderr: "unknown probe_id: \(req.probe_id)",
                normalized_outcome: "unknown_probe",
                errno: nil,
                error: nil,
                details: nil,
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
	        }
	    }

	    // MARK: - Common metadata

	    private static func baseDetails(_ extra: [String: String] = [:]) -> [String: String] {
	        var out: [String: String] = [
	            "bundle_id": Bundle.main.bundleIdentifier ?? "",
	            "process_name": ProcessInfo.processInfo.processName,
	            "pid": "\(getpid())",
	            "home_dir": NSHomeDirectory(),
	            "tmp_dir": NSTemporaryDirectory(),
	            "cwd": FileManager.default.currentDirectoryPath,
	        ]
	        for (k, v) in extra {
	            out[k] = v
	        }
	        return out
	    }

	    private static func probeWorldShape() -> RunProbeResponse {
	        let home = NSHomeDirectory()
	        let tmp = NSTemporaryDirectory()
	        let cwd = FileManager.default.currentDirectoryPath

        let looksContainerized = home.contains("/Library/Containers/")
        let worldShapeChange = looksContainerized ? "home_containerized" : nil

        let details: [String: String] = [
            "bundle_id": Bundle.main.bundleIdentifier ?? "",
            "process_name": ProcessInfo.processInfo.processName,
            "pid": "\(getpid())",
            "home_dir": home,
            "tmp_dir": tmp,
            "cwd": cwd,
            "has_app_sandbox": entitlementBool("com.apple.security.app-sandbox") ? "true" : "false",
            "has_network_client": entitlementBool("com.apple.security.network.client") ? "true" : "false",
            "has_downloads_rw": entitlementBool("com.apple.security.files.downloads.read-write") ? "true" : "false",
            "has_user_selected_executable": entitlementBool("com.apple.security.files.user-selected.executable") ? "true" : "false",
        ]

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

        let baseDetails: [String: String] = [
            "bundle_id": Bundle.main.bundleIdentifier ?? "",
            "process_name": ProcessInfo.processInfo.processName,
            "pid": "\(getpid())",
            "host": host,
            "port": "\(port)",
        ]

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
                details: baseDetails,
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }
        defer { close(fd) }

        var addrCopy = addr
        let connectResult: Int32 = withUnsafePointer(to: &addrCopy) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_in>.stride))
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
                details: baseDetails.merging(["connect": "ok"], uniquingKeysWith: { cur, _ in cur }),
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
            details: baseDetails.merging(["connect": "failed"], uniquingKeysWith: { cur, _ in cur }),
            layer_attribution: nil,
            sandbox_log_excerpt_ref: nil
        )
    }

    private static func probeDownloadsReadWrite(argv: [String]) -> RunProbeResponse {
        let args = Argv(argv)
        let requestedName = args.value("--name")

        let baseDetails: [String: String] = [
            "bundle_id": Bundle.main.bundleIdentifier ?? "",
            "process_name": ProcessInfo.processInfo.processName,
            "pid": "\(getpid())",
        ]

        guard let downloadsDir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first else {
            return RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "downloads_dir_unavailable",
                errno: nil,
                error: "failed to resolve downloads directory",
                details: baseDetails,
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }

        let harnessDir = downloadsDir.appendingPathComponent("entitlement-jail-harness", isDirectory: true)
        let fileName = requestedName?.isEmpty == false ? requestedName! : "probe-\(UUID().uuidString).txt"
        let fileURL = harnessDir.appendingPathComponent(fileName, isDirectory: false)

        func opError(_ outcome: String, _ error: Error, op: String) -> RunProbeResponse {
            let e = extractErrno(error)
            let details: [String: String] = baseDetails.merging([
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

        let details: [String: String] = baseDetails.merging([
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

	    private static func probeFsOp(argv: [String]) -> RunProbeResponse {
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
	                error: "refusing potentially destructive op=\(op.rawValue) on non-harness path (use --allow-unsafe-path to override)",
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
	                    open(ptr, O_RDONLY)
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
	                    open(ptr, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR)
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
	                        return badRequest("refusing rename outside harness paths (use --allow-unsafe-path to override)")
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
	            let rc = getaddrinfo(host, nil, &hints, &res)
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
	            let gai = getaddrinfo(host, String(port), &hints, &res)
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
	                    if Darwin.connect(fd, ai.ai_addr, ai.ai_addrlen) == 0 {
	                        details["attempts"] = "\(attempts)"
	                        details["connect"] = "ok"
	                        return RunProbeResponse(rc: 0, stdout: "", stderr: "", normalized_outcome: "ok", errno: nil, error: nil, details: details, layer_attribution: nil, sandbox_log_excerpt_ref: nil)
	                    }
	                    lastErrno = errno
	                } else {
	                    var b: UInt8 = 0x58
	                    let sent = withUnsafePointer(to: &b) { ptr in
	                        sendto(fd, ptr, 1, 0, ai.ai_addr, ai.ai_addrlen)
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
	                layer_attribution: nil,
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
	        if relative.hasPrefix("/") { return nil }
	        let comps = relative.split(separator: "/").map(String.init)
	        if comps.isEmpty { return nil }
	        for c in comps {
	            if c.isEmpty || c == "." || c == ".." { return nil }
	            if c.contains("\\") { return nil }
	        }
	        var out = base
	        for c in comps {
	            out.appendPathComponent(c)
	        }
	        return out
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
	                layer_attribution: nil,
	                sandbox_log_excerpt_ref: nil
	            )
	        }
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
	            return badRequest("refusing potentially destructive coordinated write on non-harness path (use --allow-unsafe-path to override)")
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
	                error: "refusing xattr write on non-harness path (use --allow-write or --allow-unsafe-path to override)",
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
            details: nil,
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
