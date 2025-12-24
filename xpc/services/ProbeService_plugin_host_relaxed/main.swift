import Foundation

final class ProbeService: NSObject, ProbeServiceProtocol {
    func runProbe(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let response: RunProbeResponse
        do {
            let decoded = try decodeJSON(RunProbeRequest.self, from: request)
            response = InProcessProbeCore.run(decoded)
        } catch {
            response = RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "bad request: \(error)",
                normalized_outcome: "bad_request",
                errno: nil,
                error: "\(error)",
                details: nil,
                layer_attribution: nil,
                sandbox_log_excerpt_ref: nil
            )
        }

        do {
            reply(try encodeJSON(response))
        } catch {
            let fallback = #"{"schema_version":1,"rc":2,"stdout":"","stderr":"failed to encode response","normalized_outcome":"encode_failed"}"#
            reply(Data(fallback.utf8))
        }
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
