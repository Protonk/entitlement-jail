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
}
