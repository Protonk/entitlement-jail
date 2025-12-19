import Foundation

final class ProbeService: NSObject, ProbeServiceProtocol {
    func runProbe(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let response: RunProbeResponse
        do {
            let decoded = try decodeJSON(RunProbeRequest.self, from: request)
            response = runProbe(decoded)
        } catch {
            response = RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "bad request: \(error)",
                normalized_outcome: "bad_request",
                sandbox_log_excerpt_ref: nil
            )
        }

        do {
            reply(try encodeJSON(response))
        } catch {
            let fallback = #"{"rc":2,"stdout":"","stderr":"failed to encode response"}"#
            reply(Data(fallback.utf8))
        }
    }

    private func runProbe(_ req: RunProbeRequest) -> RunProbeResponse {
        let probeId = req.probe_id
        guard validateProbeId(probeId) else {
            return RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "invalid probe_id: \(probeId)",
                normalized_outcome: "bad_request",
                sandbox_log_excerpt_ref: nil
            )
        }

        guard let probeURL = resolveProbeExecutable(probeId) else {
            return RunProbeResponse(
                rc: 127,
                stdout: "",
                stderr: "probe not found: \(probeId)",
                normalized_outcome: "not_found",
                sandbox_log_excerpt_ref: nil
            )
        }

        let process = Process()
        process.executableURL = probeURL
        process.arguments = req.argv

        if let envOverrides = req.env_overrides {
            var env = ProcessInfo.processInfo.environment
            for (k, v) in envOverrides {
                env[k] = v
            }
            process.environment = env
        }

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
        } catch {
            return RunProbeResponse(
                rc: 127,
                stdout: "",
                stderr: "failed to spawn probe: \(error)",
                normalized_outcome: "spawn_error",
                sandbox_log_excerpt_ref: nil
            )
        }

        process.waitUntilExit()

        let stdoutData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = errPipe.fileHandleForReading.readDataToEndOfFile()

        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""
        let rc = Int(process.terminationStatus)
        let outcome = (rc == 0) ? "ok" : "nonzero_exit"

        return RunProbeResponse(
            rc: rc,
            stdout: stdout,
            stderr: stderr,
            normalized_outcome: outcome,
            sandbox_log_excerpt_ref: nil
        )
    }

    private func validateProbeId(_ probeId: String) -> Bool {
        if probeId.isEmpty {
            return false
        }
        if probeId == "." || probeId == ".." {
            return false
        }
        return !probeId.contains("/") && !probeId.contains("\\")
    }

    private func resolveProbeExecutable(_ probeId: String) -> URL? {
        let serviceBundleURL = Bundle.main.bundleURL
        let hostContentsURL = serviceBundleURL
            .deletingLastPathComponent() // XPCServices
            .deletingLastPathComponent() // Contents

        let candidates: [URL] = [
            hostContentsURL.appendingPathComponent("Helpers/Probes/\(probeId)"),
            hostContentsURL.appendingPathComponent("Helpers/\(probeId)"),
        ]
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) })
    }
}

final class ServiceDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: ProbeServiceProtocol.self)
        newConnection.exportedObject = ProbeService()
        newConnection.resume()
        return true
    }
}

let listener = NSXPCListener.service()
let delegate = ServiceDelegate()
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
