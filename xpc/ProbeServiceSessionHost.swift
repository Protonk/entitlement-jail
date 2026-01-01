import Foundation
import Darwin

private struct WaitConfig {
    var mode: String
    var path: String
    var timeoutMs: Int?
    var intervalMs: Int
}

private struct WaitTriggerResult {
    var ok: Bool
    var normalizedOutcome: String
    var error: String?
    var triggerBytes: Int?
}

private struct WaitSpecError: Error, CustomStringConvertible {
    var message: String

    var description: String {
        message
    }
}

private func nowUnixMs() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1000.0)
}

private func bundleString(_ key: String) -> String? {
    Bundle.main.object(forInfoDictionaryKey: key) as? String
}

private func autoWaitFifoPath() -> String {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(
        "policy-witness-session",
        isDirectory: true
    )
    let name = "wait.\(UUID().uuidString).fifo"
    return dir.appendingPathComponent(name, isDirectory: false).path
}

private func ensureFifo(path: String) -> WaitTriggerResult? {
    let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
    do {
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: nil)
    } catch {
        return WaitTriggerResult(
            ok: false,
            normalizedOutcome: "wait_failed",
            error: "failed to create fifo parent directory: \(error)",
            triggerBytes: nil
        )
    }

    var st = stat()
    if lstat(path, &st) == 0 {
        if (st.st_mode & S_IFMT) != S_IFIFO {
            return WaitTriggerResult(
                ok: false,
                normalizedOutcome: "wait_failed",
                error: "wait path exists and is not a fifo",
                triggerBytes: nil
            )
        }
        return nil
    }

    let e = errno
    if e != ENOENT {
        return WaitTriggerResult(
            ok: false,
            normalizedOutcome: "wait_failed",
            error: String(cString: strerror(e)),
            triggerBytes: nil
        )
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
            return WaitTriggerResult(
                ok: false,
                normalizedOutcome: "wait_failed",
                error: "wait path exists and is not a fifo",
                triggerBytes: nil
            )
        }
        return WaitTriggerResult(
            ok: false,
            normalizedOutcome: "wait_failed",
            error: String(cString: strerror(e2)),
            triggerBytes: nil
        )
    }

    return nil
}

private func waitForFifoTrigger(path: String, timeoutMs: Int?) -> WaitTriggerResult {
    let lock = NSLock()
    var openedFd: Int32 = -1
    var openErrno: Int32?
    let sema = DispatchSemaphore(value: 0)

    DispatchQueue.global(qos: .userInitiated).async {
        let fd = path.withCString { ptr in
            open(ptr, O_RDONLY, 0)
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
            open(ptr, O_WRONLY | O_NONBLOCK, 0)
        }
        if unblockFd >= 0 {
            close(unblockFd)
        }
        _ = sema.wait(timeout: .now() + .milliseconds(50))
        return WaitTriggerResult(ok: false, normalizedOutcome: "timeout", error: "wait timeout", triggerBytes: nil)
    }

    lock.lock()
    let err = openErrno
    let fd = openedFd
    lock.unlock()

    if let err {
        return WaitTriggerResult(
            ok: false,
            normalizedOutcome: "wait_failed",
            error: String(cString: strerror(err)),
            triggerBytes: nil
        )
    }
    if fd < 0 {
        return WaitTriggerResult(ok: false, normalizedOutcome: "wait_failed", error: "wait failed", triggerBytes: nil)
    }

    let maxWaitMs = min(200, timeoutMs ?? 200)
    let currentFlags = fcntl(fd, F_GETFL)
    var bytesRead = 0
    if currentFlags >= 0, fcntl(fd, F_SETFL, currentFlags | O_NONBLOCK) >= 0 {
        var b: UInt8 = 0
        var attempts = 0
        while attempts < maxWaitMs {
            let n = Darwin.read(fd, &b, 1)
            if n > 0 {
                bytesRead += Int(n)
                break
            }
            if n == 0 {
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
    return WaitTriggerResult(ok: true, normalizedOutcome: "ok", error: nil, triggerBytes: bytesRead)
}

private func waitForPathExistsTrigger(path: String, timeoutMs: Int?, intervalMs: Int) -> WaitTriggerResult {
    if FileManager.default.fileExists(atPath: path) {
        return WaitTriggerResult(ok: true, normalizedOutcome: "ok", error: nil, triggerBytes: nil)
    }
    if let timeoutMs, timeoutMs <= 0 {
        return WaitTriggerResult(ok: false, normalizedOutcome: "timeout", error: "wait timeout", triggerBytes: nil)
    }

    let start = DispatchTime.now().uptimeNanoseconds
    while true {
        if let timeoutMs {
            let now = DispatchTime.now().uptimeNanoseconds
            let elapsedMs = (now - start) / 1_000_000
            if elapsedMs >= UInt64(timeoutMs) {
                return WaitTriggerResult(ok: false, normalizedOutcome: "timeout", error: "wait timeout", triggerBytes: nil)
            }
            let remainingMs = Int(UInt64(timeoutMs) - elapsedMs)
            let sleepMs = max(1, min(intervalMs, remainingMs))
            usleep(useconds_t(sleepMs * 1000))
        } else {
            usleep(useconds_t(intervalMs * 1000))
        }

        if FileManager.default.fileExists(atPath: path) {
            return WaitTriggerResult(ok: true, normalizedOutcome: "ok", error: nil, triggerBytes: nil)
        }
    }
}

private func resolveWaitConfig(_ spec: WaitSpec) -> Result<WaitConfig, WaitSpecError> {
    if let timeoutMs = spec.timeout_ms, timeoutMs < 0 {
        return .failure(WaitSpecError(message: "wait_spec.timeout_ms must be >= 0"))
    }
    if let intervalMs = spec.interval_ms, intervalMs < 1 {
        return .failure(WaitSpecError(message: "wait_spec.interval_ms must be >= 1"))
    }

    let intervalMs = spec.interval_ms ?? 50
    let raw = spec.spec
    if raw.isEmpty {
        return .failure(WaitSpecError(message: "wait_spec.spec is empty (expected fifo:auto|fifo:/abs|exists:/abs)"))
    }

    if raw == "fifo:auto" {
        return .success(
            WaitConfig(mode: "fifo", path: autoWaitFifoPath(), timeoutMs: spec.timeout_ms, intervalMs: intervalMs)
        )
    }
    if raw.hasPrefix("fifo:") {
        let path = String(raw.dropFirst("fifo:".count))
        guard path.hasPrefix("/") else {
            return .failure(WaitSpecError(message: "invalid wait_spec.spec (fifo paths must be absolute)"))
        }
        return .success(WaitConfig(mode: "fifo", path: path, timeoutMs: spec.timeout_ms, intervalMs: intervalMs))
    }
    if raw.hasPrefix("exists:") {
        let path = String(raw.dropFirst("exists:".count))
        guard path.hasPrefix("/") else {
            return .failure(WaitSpecError(message: "invalid wait_spec.spec (exists paths must be absolute)"))
        }
        return .success(WaitConfig(mode: "exists", path: path, timeoutMs: spec.timeout_ms, intervalMs: intervalMs))
    }

    return .failure(WaitSpecError(message: "invalid wait_spec.spec (expected fifo:auto|fifo:/abs|exists:/abs)"))
}

final class ProbeServiceSessionHost: NSObject, ProbeServiceProtocol {
    // Durable sessions are required to test extension liveness across multiple operations; otherwise the probe degenerates to
    // fresh-start semantics (new process, new state, no continuity).
    //
    // This is why the system supports multi-phase transcripts: “before/after” checks (open/consume/update, etc.) are meaningful
    // only when they occur in the same process context.
    private struct SessionState {
        var token: String
        var planId: String?
        var correlationId: String?
        var waitConfig: WaitConfig?
        var triggered: Bool
        var enableSignposts: Bool
    }

    private let lock = NSLock()
    private var eventSink: SessionEventSinkProtocol?
    private var session: SessionState?

    init(connection: NSXPCConnection) {
        super.init()
        self.eventSink = connection.remoteObjectProxyWithErrorHandler { error in
            fputs("event sink error: \(error)\n", stderr)
        } as? SessionEventSinkProtocol
    }

    private func emitSessionEvent(
        event: String,
        planId: String?,
        correlationId: String?,
        sessionToken: String?,
        waitConfig: WaitConfig?,
        childPid: Int? = nil,
        runId: String? = nil,
        triggerBytes: Int? = nil,
        probeId: String? = nil,
        probeArgv: [String]? = nil,
        message: String? = nil
    ) {
        guard let eventSink else { return }

        let pid = Int(getpid())
        let bundleId = Bundle.main.bundleIdentifier ?? ""
        let serviceName = ProcessInfo.processInfo.processName

        let data = XpcSessionEventData(
            event: event,
            plan_id: planId,
            correlation_id: correlationId,
            session_token: sessionToken,
            pid: pid,
            child_pid: childPid,
            run_id: runId,
            service_bundle_id: bundleId,
            service_name: serviceName,
            wait_mode: waitConfig?.mode,
            wait_path: waitConfig?.path,
            trigger_bytes: triggerBytes,
            probe_id: probeId,
            probe_argv: probeArgv,
            message: message
        )
        let result = JsonResult(ok: true, rc: 0, exit_code: 0, normalized_outcome: "ok")
        let envelope = JsonEnvelope(
            kind: "xpc_session_event",
            generated_at_unix_ms: nowUnixMs(),
            result: result,
            data: data
        )
        if let encoded = try? encodeJSON(envelope) {
            eventSink.emitEvent(encoded)
        }
    }

    private func emitSessionError(
        event: String,
        planId: String?,
        correlationId: String?,
        sessionToken: String?,
        waitConfig: WaitConfig?,
        error: String
    ) {
        guard let eventSink else { return }

        let pid = Int(getpid())
        let bundleId = Bundle.main.bundleIdentifier ?? ""
        let serviceName = ProcessInfo.processInfo.processName

        let data = XpcSessionErrorData(
            event: event,
            plan_id: planId,
            correlation_id: correlationId,
            session_token: sessionToken,
            pid: pid,
            service_bundle_id: bundleId,
            service_name: serviceName,
            wait_mode: waitConfig?.mode,
            wait_path: waitConfig?.path,
            error: error
        )
        let result = JsonResult(ok: false, rc: 1, exit_code: 1, normalized_outcome: "error", error: error)
        let envelope = JsonEnvelope(
            kind: "xpc_session_error",
            generated_at_unix_ms: nowUnixMs(),
            result: result,
            data: data
        )
        if let encoded = try? encodeJSON(envelope) {
            eventSink.emitEvent(encoded)
        }
    }

    private func startWait(
        sessionToken: String,
        planId: String?,
        correlationId: String?,
        config: WaitConfig,
        enableSignposts: Bool
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            PWSignposts.withEnabled(enableSignposts) {
                let waitSpan = PWSignpostSpan(
                    category: PWSignposts.categoryXpcService,
                    name: "wait",
                    label: "session_wait mode=\(config.mode)",
                    correlationId: correlationId
                )
                defer { waitSpan.end() }

                let result: WaitTriggerResult
                if config.mode == "fifo" {
                    result = waitForFifoTrigger(path: config.path, timeoutMs: config.timeoutMs)
                } else {
                    result = waitForPathExistsTrigger(
                        path: config.path,
                        timeoutMs: config.timeoutMs,
                        intervalMs: config.intervalMs
                    )
                }

                self.lock.lock()
                if var s = self.session, s.token == sessionToken, result.ok {
                    s.triggered = true
                    self.session = s
                }
                let stillOpen = self.session?.token == sessionToken
                self.lock.unlock()

                guard stillOpen else {
                    self.emitSessionEvent(
                        event: "trigger_ignored",
                        planId: planId,
                        correlationId: correlationId,
                        sessionToken: sessionToken,
                        waitConfig: config,
                        triggerBytes: result.triggerBytes,
                        message: "trigger arrived after session closed"
                    )
                    return
                }

                if result.ok {
                    self.emitSessionEvent(
                        event: "trigger_received",
                        planId: planId,
                        correlationId: correlationId,
                        sessionToken: sessionToken,
                        waitConfig: config,
                        triggerBytes: result.triggerBytes
                    )
                } else {
                    self.emitSessionError(
                        event: "wait_failed",
                        planId: planId,
                        correlationId: correlationId,
                        sessionToken: sessionToken,
                        waitConfig: config,
                        error: result.error ?? "wait failed"
                    )
                }
            }
        }
    }

    func openSession(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let decoded: SessionOpenRequest
        do {
            decoded = try decodeJSON(SessionOpenRequest.self, from: request)
        } catch {
            let response = SessionOpenResponse(rc: 2, error: "bad request: \(error)")
            reply((try? encodeJSON(response)) ?? Data())
            return
        }

        let correlationId = decoded.correlation_id ?? UUID().uuidString
        let enableSignposts = decoded.enable_signposts == true

        PWSignposts.withEnabled(enableSignposts) {
            PWTraceContext.set(
                correlationId: correlationId,
                planId: decoded.plan_id,
                rowId: nil,
                probeId: "open_session"
            )
            defer { PWTraceContext.clear() }
            let span = PWSignpostSpan(
                category: PWSignposts.categoryXpcService,
                name: "xpc_request",
                label: "open_session",
                correlationId: correlationId
            )
            defer { span.end() }

            lock.lock()
            let alreadyOpen = (session != nil)
            lock.unlock()
            if alreadyOpen {
                let response = SessionOpenResponse(rc: 1, error: "session already open")
                reply((try? encodeJSON(response)) ?? Data())
                return
            }

            let token = UUID().uuidString
            let pid = Int(getpid())
            let bundleId = Bundle.main.bundleIdentifier ?? ""
            let serviceName = ProcessInfo.processInfo.processName
            let serviceVersion = bundleString("CFBundleShortVersionString")
            let serviceBuild = bundleString("CFBundleVersion")

            var resolvedWait: WaitConfig?
	        if let spec = decoded.wait_spec {
	            switch resolveWaitConfig(spec) {
	            case .failure(let err):
	                let response = SessionOpenResponse(rc: 2, error: err.message)
	                reply((try? encodeJSON(response)) ?? Data())
	                return
	            case .success(let cfg):
                if cfg.mode == "fifo" {
                    if let err = ensureFifo(path: cfg.path) {
                        let response = SessionOpenResponse(rc: 1, error: err.error ?? "failed to create fifo")
                        reply((try? encodeJSON(response)) ?? Data())
                        return
                    }
                }
                resolvedWait = cfg
            }
        }

            lock.lock()
            session = SessionState(
                token: token,
                planId: decoded.plan_id,
                correlationId: correlationId,
                waitConfig: resolvedWait,
                triggered: resolvedWait == nil,
                enableSignposts: enableSignposts
            )
            lock.unlock()

            emitSessionEvent(
                event: "session_ready",
                planId: decoded.plan_id,
                correlationId: correlationId,
                sessionToken: token,
                waitConfig: resolvedWait,
                message: "session opened"
            )

            if let resolvedWait {
                emitSessionEvent(
                    event: "wait_ready",
                    planId: decoded.plan_id,
                    correlationId: correlationId,
                    sessionToken: token,
                    waitConfig: resolvedWait,
                    message: "wait configured"
                )
                startWait(
                    sessionToken: token,
                    planId: decoded.plan_id,
                    correlationId: correlationId,
                    config: resolvedWait,
                    enableSignposts: enableSignposts
                )
            }

            let response = SessionOpenResponse(
                rc: 0,
                session_token: token,
                pid: pid,
                service_bundle_id: bundleId,
                service_name: serviceName,
                service_version: serviceVersion,
                service_build: serviceBuild,
                wait_mode: resolvedWait?.mode,
                wait_path: resolvedWait?.path
            )
            reply((try? encodeJSON(response)) ?? Data())
        }
    }

    func keepaliveSession(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let decoded: SessionKeepaliveRequest
        do {
            decoded = try decodeJSON(SessionKeepaliveRequest.self, from: request)
        } catch {
            let response = SessionControlResponse(rc: 2, error: "bad request: \(error)")
            reply((try? encodeJSON(response)) ?? Data())
            return
        }

        lock.lock()
        let current = session
        lock.unlock()
        guard let current, current.token == decoded.session_token else {
            let response = SessionControlResponse(rc: 1, error: "session not found")
            reply((try? encodeJSON(response)) ?? Data())
            return
        }

        PWSignposts.withEnabled(current.enableSignposts) {
            let keepaliveSpan = PWSignpostSpan(
                category: PWSignposts.categoryXpcService,
                name: "xpc_request",
                label: "keepalive",
                correlationId: current.correlationId
            )
            defer { keepaliveSpan.end() }

            emitSessionEvent(
                event: "keepalive_ok",
                planId: current.planId,
                correlationId: current.correlationId,
                sessionToken: current.token,
                waitConfig: current.waitConfig
            )

            let response = SessionControlResponse(rc: 0)
            reply((try? encodeJSON(response)) ?? Data())
        }
    }

    func runProbeInSession(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let decoded: SessionRunProbeRequest
        do {
            decoded = try decodeJSON(SessionRunProbeRequest.self, from: request)
        } catch {
            let response = RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "bad request: \(error)",
                normalized_outcome: "bad_request",
                errno: nil,
                error: "\(error)",
                details: nil,
                layer_attribution: LayerAttribution(service_refusal: "bad request")
            )
            reply((try? encodeJSON(response)) ?? Data())
            return
        }

        lock.lock()
        let current = session
        lock.unlock()
        guard let current, current.token == decoded.session_token else {
            let response = RunProbeResponse(
                rc: 1,
                stdout: "",
                stderr: "",
                normalized_outcome: "session_not_found",
                errno: nil,
                error: "session not found",
                details: nil,
                layer_attribution: LayerAttribution(service_refusal: "session not found")
            )
            reply((try? encodeJSON(response)) ?? Data())
            return
        }

        PWSignposts.withEnabled(current.enableSignposts) {
            if current.waitConfig != nil && !current.triggered {
                let response = RunProbeResponse(
                    rc: 1,
                    stdout: "",
                    stderr: "",
                    normalized_outcome: "session_not_triggered",
                    errno: nil,
                    error: "session wait not triggered",
                    details: nil,
                    layer_attribution: LayerAttribution(service_refusal: "session wait not triggered")
                )
                reply((try? encodeJSON(response)) ?? Data())
                return
            }

            emitSessionEvent(
                event: "probe_starting",
                planId: current.planId,
                correlationId: current.correlationId,
                sessionToken: current.token,
                waitConfig: current.waitConfig,
                probeId: decoded.probe_request.probe_id,
                probeArgv: decoded.probe_request.argv
            )

            var probeReq = decoded.probe_request
            if probeReq.plan_id == nil {
                probeReq.plan_id = current.planId
            }
            if probeReq.correlation_id == nil {
                probeReq.correlation_id = current.correlationId
            }
            if probeReq.enable_signposts == nil, current.enableSignposts {
                probeReq.enable_signposts = true
            }

            let runProbeSpan = PWSignpostSpan(
                category: PWSignposts.categoryXpcService,
                name: "xpc_request",
                label: "run_probe_in_session probe_id=\(probeReq.probe_id)",
                correlationId: probeReq.correlation_id
            )
            defer { runProbeSpan.end() }

            let probeEventSink: InProcessProbeCore.ProbeEventSink = { event, childPid, runId, message in
                self.emitSessionEvent(
                    event: event,
                    planId: current.planId,
                    correlationId: current.correlationId,
                    sessionToken: current.token,
                    waitConfig: current.waitConfig,
                    childPid: childPid,
                    runId: runId,
                    message: message
                )
            }
            var response = InProcessProbeCore.run(probeReq, eventSink: probeEventSink)
            var details = response.details ?? [:]
            details["session_token"] = current.token
            response.details = details

            emitSessionEvent(
                event: "probe_done",
                planId: current.planId,
                correlationId: current.correlationId,
                sessionToken: current.token,
                waitConfig: current.waitConfig,
                probeId: decoded.probe_request.probe_id,
                probeArgv: decoded.probe_request.argv,
                message: "normalized_outcome=\(response.normalized_outcome) rc=\(response.rc)"
            )

            reply((try? encodeJSON(response)) ?? Data())
        }
    }

    func closeSession(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let decoded: SessionCloseRequest
        do {
            decoded = try decodeJSON(SessionCloseRequest.self, from: request)
        } catch {
            let response = SessionControlResponse(rc: 2, error: "bad request: \(error)")
            reply((try? encodeJSON(response)) ?? Data())
            return
        }

        lock.lock()
        let current = session
        if let current, current.token == decoded.session_token {
            session = nil
        }
        lock.unlock()

        if let current, current.token == decoded.session_token {
            PWSignposts.withEnabled(current.enableSignposts) {
                let closeSpan = PWSignpostSpan(
                    category: PWSignposts.categoryXpcService,
                    name: "xpc_request",
                    label: "close_session",
                    correlationId: current.correlationId
                )
                defer { closeSpan.end() }

                emitSessionEvent(
                    event: "session_closed",
                    planId: current.planId,
                    correlationId: current.correlationId,
                    sessionToken: current.token,
                    waitConfig: current.waitConfig,
                    message: "session closed"
                )
                let response = SessionControlResponse(rc: 0)
                reply((try? encodeJSON(response)) ?? Data())
                return
            }
        }

        let response = SessionControlResponse(rc: 1, error: "session not found")
        reply((try? encodeJSON(response)) ?? Data())
    }
}

final class ProbeServiceSessionDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: ProbeServiceProtocol.self)
        newConnection.remoteObjectInterface = NSXPCInterface(with: SessionEventSinkProtocol.self)
        newConnection.exportedObject = ProbeServiceSessionHost(connection: newConnection)
        newConnection.resume()
        return true
    }
}
