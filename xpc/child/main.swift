import Foundation
import Darwin

private var eventActorLabel = "child"
private var eventLineage: InheritChildLineage? = nil
private var eventBusFailed = false

private let childProtocolViolationExit: Int32 = 96
private let childRightsBusExit: Int32 = 97
private let childEventBusExit: Int32 = 98

@_cdecl("pw_inherit_child_stop_entry")
@inline(never)
@_optimize(none)
public func pw_inherit_child_stop_entry_marker() {}

@_cdecl("pw_inherit_child_stop_on_deny")
@inline(never)
@_optimize(none)
public func pw_inherit_child_stop_on_deny_marker() {}

private func nowUnixMs() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1000.0)
}

private func monotonicNs() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return UInt64(ts.tv_sec) * 1_000_000_000 + UInt64(ts.tv_nsec)
}

private func writeSentinel(_ fd: Int32, _ message: String) -> (Bool, Int32?) {
    guard let data = message.data(using: .utf8) else {
        return (false, EINVAL)
    }
    return writeAll(fd, data)
}

private func writeAll(_ fd: Int32, _ data: Data) -> (Bool, Int32?) {
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

private func captureBacktrace(limit: Int = 16) -> ([String]?, String?) {
    let frames = Thread.callStackReturnAddresses
    if frames.isEmpty {
        return (nil, "empty_backtrace")
    }
    let out = frames.prefix(limit).map {
        String(format: "0x%llx", $0.uint64Value)
    }
    return (out, nil)
}

private func denyBacktrace(_ errno: Int32?) -> ([String]?, String?) {
    guard let errno, (errno == EPERM || errno == EACCES) else {
        return (nil, nil)
    }
    return captureBacktrace()
}

private func emitEvent(
    _ traceFd: Int32,
    runId: String,
    phase: String,
    callsiteId: String? = nil,
    op: String? = nil,
    backtrace: [String]? = nil,
    backtraceError: String? = nil,
    details: [String: String]? = nil,
    errno: Int32? = nil,
    rc: Int? = nil,
    actor: String? = nil,
    lineage: InheritChildLineage? = nil
) {
    let event = InheritChildEvent(
        actor: actor ?? eventActorLabel,
        phase: phase,
        run_id: runId,
        pid: Int(getpid()),
        time_unix_ms: nowUnixMs(),
        monotonic_ns: monotonicNs(),
        callsite_id: callsiteId,
        op: op,
        backtrace: backtrace,
        backtrace_error: backtraceError,
        lineage: lineage ?? eventLineage,
        details: details,
        errno: errno.map { Int($0) },
        rc: rc
    )
    guard let data = try? encodeJSON(event) else {
        return
    }
    if traceFd < 0 {
        return
    }
    let (ok, err) = writeAll(traceFd, data)
    if !ok {
        failEventBus(err, context: "write_event")
    }
    let (nlOk, nlErr) = writeAll(traceFd, Data("\n".utf8))
    if !nlOk {
        failEventBus(nlErr, context: "write_event_newline")
    }
}

private func emitOpEvent(
    _ traceFd: Int32,
    runId: String,
    phase: String,
    capId: String,
    capType: String,
    op: String,
    callsiteId: String,
    rc: Int,
    errno: Int32?,
    extra: [String: String] = [:],
    stopOnDeny: Bool
) {
    var details = extra
    details["cap_id"] = capId
    details["cap_type"] = capType
    let isDeny = errno == EPERM || errno == EACCES
    let (backtrace, backtraceError) = denyBacktrace(errno)
    emitEvent(
        traceFd,
        runId: runId,
        phase: phase,
        callsiteId: isDeny ? callsiteId : nil,
        op: isDeny ? op : nil,
        backtrace: backtrace,
        backtraceError: backtraceError,
        details: details,
        errno: errno,
        rc: rc
    )
    if stopOnDeny, isDeny {
        emitEvent(
            traceFd,
            runId: runId,
            phase: "child_stop_on_deny",
            callsiteId: callsiteId,
            op: op,
            backtrace: backtrace,
            backtraceError: backtraceError,
            details: details,
            errno: errno,
            rc: rc
        )
        pw_inherit_child_stop_on_deny_marker()
        raise(SIGSTOP)
    }
}

private struct CapabilityPayload {
    var cap_id: Int32
    var meta0: Int32
    var meta1: Int32
    var meta2: Int32
}

private struct ReceivedCapability {
    var cap_id: Int32
    var fd: Int32
    var meta: [Int32]
}

private func cmsgAlign(_ length: Int) -> Int {
    let align = MemoryLayout<UInt32>.size
    return (length + align - 1) & ~(align - 1)
}

private func cmsgSpace(_ length: Int) -> Int {
    cmsgAlign(MemoryLayout<cmsghdr>.size) + cmsgAlign(length)
}

private func recvCapability(_ socketFd: Int32) -> ReceivedCapability? {
    var payload = CapabilityPayload(cap_id: 0, meta0: 0, meta1: 0, meta2: 0)
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
                return recvmsg(socketFd, &msg, 0)
            }
        }
    }
    if rc <= 0 {
        return nil
    }
    var receivedFd: Int32 = -1
    if msg.msg_controllen >= socklen_t(MemoryLayout<cmsghdr>.size) {
        control.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            let cmsg = base.assumingMemoryBound(to: cmsghdr.self)
            if cmsg.pointee.cmsg_level == SOL_SOCKET, cmsg.pointee.cmsg_type == SCM_RIGHTS {
                let dataPtr = UnsafeRawPointer(cmsg).advanced(by: MemoryLayout<cmsghdr>.size)
                receivedFd = dataPtr.assumingMemoryBound(to: Int32.self).pointee
            }
        }
    }
    return ReceivedCapability(
        cap_id: payload.cap_id,
        fd: receivedFd,
        meta: [payload.meta0, payload.meta1, payload.meta2]
    )
}

struct EventPayload {
    var cap_id: String
    var cap_type: String
    var data: Data
}

private struct EventPayloadError {
    var reason: String
    var expected: String?
    var observed: String?
    var details: [String: String]
}

private func readExact(_ fd: Int32, length: Int) -> (Data?, Int32?) {
    var buffer = Data(count: length)
    let rc = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
        guard let base = rawBuffer.baseAddress else { return -1 }
        var remaining = length
        var offset = 0
        while remaining > 0 {
            let readCount = read(fd, base.advanced(by: offset), remaining)
            if readCount <= 0 {
                return -1
            }
            remaining -= readCount
            offset += readCount
        }
        return length
    }
    if rc < 0 {
        return (nil, errno)
    }
    return (buffer, nil)
}

private func readLine(_ fd: Int32, maxLen: Int = 8192) -> (String?, Int32?) {
    var bytes: [UInt8] = []
    bytes.reserveCapacity(128)
    var byte: UInt8 = 0
    while bytes.count < maxLen {
        let rc = read(fd, &byte, 1)
        if rc <= 0 {
            return (nil, errno)
        }
        if byte == 0x0A {
            break
        }
        bytes.append(byte)
    }
    let line = String(bytes: bytes, encoding: .utf8)
    return (line, nil)
}

private func recvEventPayload(_ fd: Int32) -> (EventPayload?, EventPayloadError?, Int32?) {
    let (line, lineErrno) = readLine(fd)
    guard let line else {
        return (nil, EventPayloadError(reason: "io_error", expected: nil, observed: nil, details: [:]), lineErrno)
    }
    let expectedPrefix = "\(InheritChildProtocol.eventPayloadPrefix) "
    guard line.hasPrefix(expectedPrefix) else {
        return (
            nil,
            EventPayloadError(
                reason: "event_payload_prefix_mismatch",
                expected: expectedPrefix.trimmingCharacters(in: .whitespaces),
                observed: line,
                details: ["line": line]
            ),
            nil
        )
    }
    var capId = ""
    var capType = ""
    var length = -1
    var protoStr = ""
    var capNamespace = ""
    for part in line.split(separator: " ") {
        if part.hasPrefix("\(InheritChildProtocol.eventPayloadKeyCapId)=") {
            capId = String(part.dropFirst((InheritChildProtocol.eventPayloadKeyCapId + "=").count))
        } else if part.hasPrefix("\(InheritChildProtocol.eventPayloadKeyCapType)=") {
            capType = String(part.dropFirst((InheritChildProtocol.eventPayloadKeyCapType + "=").count))
        } else if part.hasPrefix("\(InheritChildProtocol.eventPayloadKeyLength)=") {
            length = Int(part.dropFirst((InheritChildProtocol.eventPayloadKeyLength + "=").count)) ?? -1
        } else if part.hasPrefix("\(InheritChildProtocol.eventPayloadKeyProtocolVersion)=") {
            protoStr = String(part.dropFirst((InheritChildProtocol.eventPayloadKeyProtocolVersion + "=").count))
        } else if part.hasPrefix("\(InheritChildProtocol.eventPayloadKeyCapabilityNamespace)=") {
            capNamespace = String(part.dropFirst((InheritChildProtocol.eventPayloadKeyCapabilityNamespace + "=").count))
        }
    }
    if capId.isEmpty || capType.isEmpty || length < 0 {
        return (
            nil,
            EventPayloadError(
                reason: "event_payload_invalid",
                expected: "cap_id/cap_type/len",
                observed: line,
                details: ["line": line]
            ),
            nil
        )
    }
    let observedProto = Int(protoStr) ?? -1
    if observedProto != InheritChildProtocol.version || capNamespace != InheritChildProtocol.capabilityNamespace {
        return (
            nil,
            EventPayloadError(
                reason: "event_payload_protocol_mismatch",
                expected: "\(InheritChildProtocol.version)|\(InheritChildProtocol.capabilityNamespace)",
                observed: "\(protoStr)|\(capNamespace)",
                details: [
                    "expected_protocol": "\(InheritChildProtocol.version)",
                    "observed_protocol": protoStr,
                    "expected_cap_namespace": InheritChildProtocol.capabilityNamespace,
                    "observed_cap_namespace": capNamespace,
                    "cap_id": capId,
                    "cap_type": capType
                ]
            ),
            nil
        )
    }
    let (payload, payloadErrno) = readExact(fd, length: length)
    guard let payload else {
        return (nil, EventPayloadError(reason: "io_error", expected: nil, observed: nil, details: [:]), payloadErrno)
    }
    return (EventPayload(cap_id: capId, cap_type: capType, data: payload), nil, nil)
}

private func connectUnixSocket(path: String) -> (Int32?, Int32?) {
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

private func readFromFd(_ fd: Int32) -> (Int, Int32?) {
    var buf = [UInt8](repeating: 0, count: 64)
    let rc = read(fd, &buf, buf.count)
    if rc >= 0 {
        return (0, nil)
    }
    return (1, errno)
}

private func echoOnSocket(_ fd: Int32) -> (Int, Int32?) {
    let payload = Array("ping".utf8)
    let writeRc = payload.withUnsafeBytes { rawBuffer in
        write(fd, rawBuffer.baseAddress, rawBuffer.count)
    }
    if writeRc <= 0 {
        return (1, errno)
    }
    var buf = [UInt8](repeating: 0, count: 16)
    let readRc = read(fd, &buf, buf.count)
    if readRc <= 0 {
        return (1, errno)
    }
    return (0, nil)
}

private func spawnGrandchild(
    executable: String,
    eventFd: Int32,
    rightsFd: Int32,
    runId: String,
    scenario: String,
    path: String,
    targetName: String,
    socketPath: String,
    depth: Int
) -> pid_t? {
    var env = ProcessInfo.processInfo.environment
    env["PW_RUN_ID"] = runId
    env["PW_SCENARIO"] = scenario
    env["PW_PATH"] = path
    env["PW_TARGET_NAME"] = targetName
    env["PW_SOCKET_PATH"] = socketPath
    env["PW_EVENT_FD"] = "\(eventFd)"
    env["PW_RIGHTS_FD"] = "-1"
    env["PW_RIGHTS_CAP_COUNT"] = "0"
    env["PW_EVENT_CAP_COUNT"] = "0"
    env["PW_CAP_COUNT"] = "0"
    env["PW_RIGHTS_CAP_IDS"] = ""
    env["PW_EVENT_CAP_IDS"] = ""
    env["PW_PROTOCOL_VERSION"] = "\(InheritChildProtocol.version)"
    env["PW_CAP_NAMESPACE"] = InheritChildProtocol.capabilityNamespace
    env["PW_ACTOR"] = "grandchild"
    env["PW_LINEAGE_DEPTH"] = "\(depth)"

    let envStrings = env.map { "\($0)=\($1)" }
    var envp: [UnsafeMutablePointer<CChar>?] = envStrings.map { strdup($0) }
    envp.append(nil)
    defer {
        for ptr in envp {
            if let ptr { free(ptr) }
        }
    }

    var argvC: [UnsafeMutablePointer<CChar>?] = [strdup(executable), nil]
    defer {
        for ptr in argvC {
            if let ptr { free(ptr) }
        }
    }

    var actions: posix_spawn_file_actions_t? = nil
    posix_spawn_file_actions_init(&actions)
    posix_spawn_file_actions_adddup2(&actions, eventFd, eventFd)
    if rightsFd >= 0 {
        posix_spawn_file_actions_addclose(&actions, rightsFd)
    }

    var grandchildPid: pid_t = 0
    let rc = posix_spawn(&grandchildPid, executable, &actions, nil, &argvC, &envp)
    posix_spawn_file_actions_destroy(&actions)
    if rc != 0 {
        return nil
    }
    return grandchildPid
}

let env = ProcessInfo.processInfo.environment
let runId = env["PW_RUN_ID"] ?? UUID().uuidString
let scenario = env["PW_SCENARIO"] ?? ""
let path = env["PW_PATH"] ?? ""
let targetName = env["PW_TARGET_NAME"] ?? ""
let socketPath = env["PW_SOCKET_PATH"] ?? ""
let stopOnEntry = env["PW_STOP_ON_ENTRY"] == "1"
let stopOnDeny = env["PW_STOP_ON_DENY"] == "1"

// Two-bus protocol (child view):
// - Raw write(2) loops are used (not fragile FileHandle paths) so instrumentation failures don’t masquerade as sandbox outcomes.
// - eventFd/rightsFd are the actual socketpair FDs from the parent (no hardcoded fd numbers); the sentinel records their identities.
// - eventFd/rightFd are explicit numbers passed via PW_EVENT_FD/PW_RIGHTS_FD, dup2'd by the parent.
// - Event bus: child writes JSONL events; the first bytes are
//   "PW_CHILD_SENTINEL ... protocol_version=<v> cap_namespace=<ns>\n".
//   Parent may send "PW_CAP_PAYLOAD proto=<v> cap_ns=<ns> cap_id=<id> cap_type=<type> len=<n>\n"
//   followed by <n> raw bytes.
// - Rights bus: parent sends CapabilityPayload bytes with SCM_RIGHTS control; meta0 holds protocol_version.
let eventFd = Int32(env["PW_EVENT_FD"].flatMap { Int($0) } ?? -1)
let rightsFd = Int32(env["PW_RIGHTS_FD"].flatMap { Int($0) } ?? -1)
let rightsCapCount = Int(env["PW_RIGHTS_CAP_COUNT"] ?? env["PW_CAP_COUNT"] ?? "") ?? 0
let eventCapCount = Int(env["PW_EVENT_CAP_COUNT"] ?? "") ?? 0
let preAcquire = env["PW_PRE_ACQUIRE"] == "1"
let lineageDepth = Int(env["PW_LINEAGE_DEPTH"] ?? "") ?? 1
let actorLabel = env["PW_ACTOR"] ?? (lineageDepth >= 2 ? "grandchild" : "child")
eventActorLabel = actorLabel
eventLineage = InheritChildLineage(depth: lineageDepth, pid: Int(getpid()), ppid: Int(getppid()))

func parseCapIdList(_ raw: String?) -> [Int32] {
    guard let raw, !raw.isEmpty else { return [] }
    return raw.split(separator: ",").compactMap { Int32($0) }
}

func parseCapNameList(_ raw: String?) -> [String] {
    guard let raw, !raw.isEmpty else { return [] }
    return raw.split(separator: ",").map { String($0) }
}

let expectedRightsCapIds = parseCapIdList(env["PW_RIGHTS_CAP_IDS"])
let expectedEventCapIds = parseCapNameList(env["PW_EVENT_CAP_IDS"])

let sentinel = "\(InheritChildProtocol.sentinelPrefix) pid=\(getpid()) run_id=\(runId) scenario=\(scenario) path=\(path) event_fd=\(eventFd) rights_fd=\(rightsFd) \(InheritChildProtocol.sentinelKeyProtocolVersion)=\(InheritChildProtocol.version) \(InheritChildProtocol.sentinelKeyCapabilityNamespace)=\(InheritChildProtocol.capabilityNamespace)\n"
_ = writeSentinel(STDERR_FILENO, sentinel)
if eventFd < 0 {
    fputs("inherit_child: missing PW_EVENT_FD (no event bus)\n", stderr)
    exit(childEventBusExit)
}
if rightsCapCount > 0, rightsFd < 0 {
    fputs("inherit_child: missing PW_RIGHTS_FD (no rights bus)\n", stderr)
    exit(childRightsBusExit)
}
if eventFd >= 0 {
    let (ok, err) = writeSentinel(eventFd, sentinel)
    if !ok {
        failEventBus(err, context: "write_sentinel")
    }
}

let envProtocolStr = env["PW_PROTOCOL_VERSION"] ?? ""
let envProtocol = Int(envProtocolStr) ?? -1
let envCapNamespace = env["PW_CAP_NAMESPACE"] ?? ""
if envProtocol != InheritChildProtocol.version || envCapNamespace != InheritChildProtocol.capabilityNamespace {
    emitEvent(eventFd, runId: runId, phase: "child_protocol_violation", details: [
        "expected_protocol": "\(InheritChildProtocol.version)",
        "observed_protocol": envProtocolStr,
        "expected_cap_namespace": InheritChildProtocol.capabilityNamespace,
        "observed_cap_namespace": envCapNamespace,
        "event_fd": "\(eventFd)",
        "rights_fd": "\(rightsFd)"
    ])
    exit(childProtocolViolationExit)
}

emitEvent(eventFd, runId: runId, phase: "child_start", details: [
    "scenario": scenario,
    "path": path,
    "event_fd": "\(eventFd)",
    "rights_fd": "\(rightsFd)",
    "protocol_version": "\(InheritChildProtocol.version)",
    "cap_namespace": InheritChildProtocol.capabilityNamespace,
    "target_name": targetName,
    "socket_path": socketPath
])

if stopOnEntry {
    emitEvent(eventFd, runId: runId, phase: "child_stop_on_entry")
    pw_inherit_child_stop_entry_marker()
    raise(SIGSTOP)
}

emitEvent(eventFd, runId: runId, phase: "child_ready")
let capFileFd = InheritChildCapabilityId.fileFd.rawValue
let capDirFd = InheritChildCapabilityId.dirFd.rawValue
let capSocketFd = InheritChildCapabilityId.socketFd.rawValue
var preAcquireResults: [Int32: (rc: Int, errno: Int32?)] = [:]
var eventPayloads: [String: EventPayload] = [:]

if preAcquire, scenario == "dynamic_extension", !path.isEmpty {
    let capIdStr = "file_fd"
    let (acquireRc, acquireErrno): (Int, Int32?) = path.withCString { pathPtr in
        errno = 0
        let fd = open(pathPtr, O_RDONLY)
        if fd >= 0 {
            close(fd)
            return (0, nil)
        }
        return (1, errno)
    }
    preAcquireResults[capFileFd] = (acquireRc, acquireErrno)
    emitOpEvent(
        eventFd,
        runId: runId,
        phase: "child_acquire_attempt",
        capId: capIdStr,
        capType: capIdStr,
        op: "open",
        callsiteId: "child.open.path",
        rc: acquireRc,
        errno: acquireErrno,
        extra: ["path": path, "pre_acquire": "true"],
        stopOnDeny: stopOnDeny
    )
}

func failEventBus(_ err: Int32?, context: String) -> Never {
    if eventBusFailed {
        exit(childEventBusExit)
    }
    eventBusFailed = true
    let msg = "PW_CHILD_EVENT_BUS_ERROR context=\(context) errno=\(err.map { "\($0)" } ?? "")\n"
    _ = writeSentinel(STDERR_FILENO, msg)
    exit(childEventBusExit)
}

func failCapabilityRecv(
    _ reason: String,
    capId: Int32? = nil,
    expected: String? = nil,
    observed: String? = nil,
    details extra: [String: String] = [:]
) -> Never {
    var details: [String: String] = [
        "reason": reason,
        "event_fd": "\(eventFd)",
        "rights_fd": "\(rightsFd)"
    ]
    if let capId {
        details["cap_id"] = "\(capId)"
    }
    if let expected {
        details["expected"] = expected
    }
    if let observed {
        details["observed"] = observed
    }
    for (key, value) in extra {
        details[key] = value
    }
    emitEvent(eventFd, runId: runId, phase: "child_capability_recv_failed", details: details)
    switch reason {
    case "recvmsg_failed", "rights_fd_invalid":
        exit(childRightsBusExit)
    case "missing_fd", "unexpected_cap_id", "event_payload_invalid", "event_payload_missing",
         "event_payload_prefix_mismatch", "event_payload_protocol_mismatch",
         "rights_cap_ids_missing", "event_cap_ids_missing",
         "rights_cap_count_mismatch", "event_cap_count_mismatch",
         "rights_payload_protocol_mismatch":
        exit(childProtocolViolationExit)
    default:
        exit(childProtocolViolationExit)
    }
}

if scenario == "lineage_basic", actorLabel == "child" {
    let selfPath = CommandLine.arguments.first ?? ""
    if selfPath.isEmpty {
        emitEvent(eventFd, runId: runId, phase: "grandchild_spawn_failed", details: [
            "error": "missing argv[0]"
        ])
    } else if let grandchildPid = spawnGrandchild(
        executable: selfPath,
        eventFd: eventFd,
        rightsFd: rightsFd,
        runId: runId,
        scenario: scenario,
        path: path,
        targetName: targetName,
        socketPath: socketPath,
        depth: lineageDepth + 1
    ) {
        emitEvent(eventFd, runId: runId, phase: "grandchild_spawned", details: [
            "grandchild_pid": "\(grandchildPid)"
        ])
        var status: Int32 = 0
        _ = waitpid(grandchildPid, &status, 0)
        let exitStatus: Int32 = (status & 0x7f) == 0 ? ((status >> 8) & 0xff) : (128 + (status & 0x7f))
        emitEvent(eventFd, runId: runId, phase: "grandchild_exited", details: [
            "status": "\(exitStatus)"
        ])
    } else {
        emitEvent(eventFd, runId: runId, phase: "grandchild_spawn_failed", details: [
            "error": "posix_spawn_failed"
        ])
    }
}

if eventCapCount > 0 {
    if eventFd < 0 {
        failEventBus(nil, context: "event_fd_invalid")
    }
    if expectedEventCapIds.isEmpty {
        failCapabilityRecv("event_cap_ids_missing", expected: "list", observed: "")
    }
    if expectedEventCapIds.count != eventCapCount {
        failCapabilityRecv(
            "event_cap_count_mismatch",
            expected: "\(expectedEventCapIds.count)",
            observed: "\(eventCapCount)"
        )
    }
    for idx in 0..<eventCapCount {
        let (payload, payloadErr, err) = recvEventPayload(eventFd)
        if let payload {
            let expectedCapId = expectedEventCapIds[idx]
            if payload.cap_id != expectedCapId {
                failCapabilityRecv(
                    "unexpected_cap_id",
                    expected: expectedCapId,
                    observed: payload.cap_id,
                    details: ["cap_id": payload.cap_id, "cap_type": payload.cap_type]
                )
            }
            eventPayloads[payload.cap_id] = payload
            continue
        }
        if let payloadErr {
            if payloadErr.reason == "io_error" {
                failEventBus(err, context: "event_payload_read")
            } else {
                failCapabilityRecv(
                    payloadErr.reason,
                    expected: payloadErr.expected,
                    observed: payloadErr.observed,
                    details: payloadErr.details
                )
            }
        } else {
            failCapabilityRecv("event_payload_invalid")
        }
    }
} else if !expectedEventCapIds.isEmpty {
    failCapabilityRecv(
        "event_cap_count_mismatch",
        expected: "\(expectedEventCapIds.count)",
        observed: "\(eventCapCount)"
    )
}

if rightsCapCount > 0, rightsFd < 0 {
    failCapabilityRecv("rights_fd_invalid")
}
if rightsCapCount > 0 {
    if expectedRightsCapIds.isEmpty {
        failCapabilityRecv("rights_cap_ids_missing", expected: "list", observed: "")
    }
    if expectedRightsCapIds.count != rightsCapCount {
        failCapabilityRecv(
            "rights_cap_count_mismatch",
            expected: "\(expectedRightsCapIds.count)",
            observed: "\(rightsCapCount)"
        )
    }
}

for idx in 0..<rightsCapCount {
    guard let received = recvCapability(rightsFd) else {
        failCapabilityRecv("recvmsg_failed")
    }
    let capId = received.cap_id
    let fd = received.fd
    let capType: String
    if received.meta.first != Int32(InheritChildProtocol.version) {
        failCapabilityRecv(
            "rights_payload_protocol_mismatch",
            capId: capId,
            expected: "\(InheritChildProtocol.version)",
            observed: "\(received.meta.first ?? 0)",
            details: ["cap_id": "\(capId)"]
        )
    }
    if idx < expectedRightsCapIds.count {
        let expectedCapId = expectedRightsCapIds[idx]
        if capId != expectedCapId {
            failCapabilityRecv(
                "unexpected_cap_id",
                capId: capId,
                expected: "\(expectedCapId)",
                observed: "\(capId)",
                details: ["cap_id": "\(capId)"]
            )
        }
    }
    switch capId {
    case capFileFd:
        capType = "file_fd"
        let capIdStr = "file_fd"
        let acquireResult: (rc: Int, errno: Int32?)
        if let pre = preAcquireResults[capFileFd] {
            acquireResult = pre
        } else {
            let (acquireRc, acquireErrno): (Int, Int32?) = path.withCString { pathPtr in
                errno = 0
                let fd = open(pathPtr, O_RDONLY)
                if fd >= 0 {
                    close(fd)
                    return (0, nil)
                }
                return (1, errno)
            }
            acquireResult = (acquireRc, acquireErrno)
            emitOpEvent(
                eventFd,
                runId: runId,
                phase: "child_acquire_attempt",
                capId: capIdStr,
                capType: capType,
                op: "open",
                callsiteId: "child.open.path",
                rc: acquireRc,
                errno: acquireErrno,
                extra: ["path": path],
                stopOnDeny: stopOnDeny
            )
        }

        if fd < 0 {
            failCapabilityRecv("missing_fd", capId: capId)
        }
        let (useRc, useErrno) = readFromFd(fd)
        emitOpEvent(
            eventFd,
            runId: runId,
            phase: "child_use_attempt",
            capId: capIdStr,
            capType: capType,
            op: "read",
            callsiteId: "child.use.fd.read",
            rc: useRc,
            errno: useErrno,
            extra: ["path": path],
            stopOnDeny: stopOnDeny
        )
        close(fd)

        emitEvent(eventFd, runId: runId, phase: "child_capability_result", details: [
            "cap_id": capIdStr,
            "cap_type": capType,
            "child_acquire_rc": "\(acquireResult.rc)",
            "child_acquire_errno": acquireResult.errno.map { "\($0)" } ?? "",
            "child_use_rc": "\(useRc)",
            "child_use_errno": useErrno.map { "\($0)" } ?? ""
        ])

    case capDirFd:
        capType = "dir_fd"
        let capIdStr = "dir_fd"
        let dirPath = URL(fileURLWithPath: path).deletingLastPathComponent().path
        let (acquireRc, acquireErrno): (Int, Int32?) = dirPath.withCString { pathPtr in
            errno = 0
            let fd = open(pathPtr, O_RDONLY | O_DIRECTORY)
            if fd >= 0 {
                close(fd)
                return (0, nil)
            }
            return (1, errno)
        }
        emitOpEvent(
            eventFd,
            runId: runId,
            phase: "child_acquire_attempt",
            capId: capIdStr,
            capType: capType,
            op: "open",
            callsiteId: "child.open.dir",
            rc: acquireRc,
            errno: acquireErrno,
            extra: ["path": dirPath],
            stopOnDeny: stopOnDeny
        )

        if fd < 0 {
            failCapabilityRecv("missing_fd", capId: capId)
        }
        let (useRc, useErrno): (Int, Int32?) = targetName.withCString { namePtr in
            errno = 0
            let openFd = openat(fd, namePtr, O_RDONLY)
            if openFd >= 0 {
                close(openFd)
                return (0, nil)
            }
            return (1, errno)
        }
        emitOpEvent(
            eventFd,
            runId: runId,
            phase: "child_use_attempt",
            capId: capIdStr,
            capType: capType,
            op: "openat",
            callsiteId: "child.openat.file",
            rc: useRc,
            errno: useErrno,
            extra: ["dir": dirPath, "name": targetName],
            stopOnDeny: stopOnDeny
        )
        close(fd)

        emitEvent(eventFd, runId: runId, phase: "child_capability_result", details: [
            "cap_id": capIdStr,
            "cap_type": capType,
            "child_acquire_rc": "\(acquireRc)",
            "child_acquire_errno": acquireErrno.map { "\($0)" } ?? "",
            "child_use_rc": "\(useRc)",
            "child_use_errno": useErrno.map { "\($0)" } ?? ""
        ])

    case capSocketFd:
        capType = "socket_fd"
        let capIdStr = "socket_fd"
        let (connFd, connErrno) = connectUnixSocket(path: socketPath)
        let acquireRc = connFd == nil ? 1 : 0
        emitOpEvent(
            eventFd,
            runId: runId,
            phase: "child_acquire_attempt",
            capId: capIdStr,
            capType: capType,
            op: "connect",
            callsiteId: "child.socket.connect",
            rc: acquireRc,
            errno: connErrno,
            extra: ["path": socketPath],
            stopOnDeny: stopOnDeny
        )
        if let connFd {
            close(connFd)
        }

        if fd < 0 {
            failCapabilityRecv("missing_fd", capId: capId)
        }
        let (useRc, useErrno) = echoOnSocket(fd)
        emitOpEvent(
            eventFd,
            runId: runId,
            phase: "child_use_attempt",
            capId: capIdStr,
            capType: capType,
            op: "sendrecv",
            callsiteId: "child.socket.use",
            rc: useRc,
            errno: useErrno,
            extra: ["path": socketPath],
            stopOnDeny: stopOnDeny
        )
        close(fd)

        emitEvent(eventFd, runId: runId, phase: "child_capability_result", details: [
            "cap_id": capIdStr,
            "cap_type": capType,
            "child_acquire_rc": "\(acquireRc)",
            "child_acquire_errno": connErrno.map { "\($0)" } ?? "",
            "child_use_rc": "\(useRc)",
            "child_use_errno": useErrno.map { "\($0)" } ?? ""
        ])

    default:
        failCapabilityRecv("unexpected_cap_id", capId: capId)
    }
}

if scenario == "bookmark_ferry" {
    guard let payload = eventPayloads["bookmark"] else {
        failCapabilityRecv("event_payload_missing")
    }
    let capIdStr = "bookmark"
    let capType = "bookmark"
    let (acquireRc, acquireErrno): (Int, Int32?) = path.withCString { pathPtr in
        errno = 0
        let fd = open(pathPtr, O_RDONLY)
        if fd >= 0 {
            close(fd)
            return (0, nil)
        }
        return (1, errno)
    }
    emitOpEvent(
        eventFd,
        runId: runId,
        phase: "child_acquire_attempt",
        capId: capIdStr,
        capType: capType,
        op: "open",
        callsiteId: "child.bookmark.open",
        rc: acquireRc,
        errno: acquireErrno,
        extra: ["path": path],
        stopOnDeny: stopOnDeny
    )

    var resolveRc = 1
    var resolveError = ""
    var resolveErrorDomain = ""
    var resolveErrorCode: Int? = nil
    var isStale = false
    var startAccessing = false
    var accessRc = 1
    var accessErrno: Int32? = nil
    var resolvedPath = ""
    do {
        let resolvedURL = try URL(
            resolvingBookmarkData: payload.data,
            options: [.withSecurityScope, .withoutUI],
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        )
        resolveRc = 0
        resolvedPath = resolvedURL.path
        startAccessing = resolvedURL.startAccessingSecurityScopedResource()
        defer { resolvedURL.stopAccessingSecurityScopedResource() }

        let (useRc, useErrno): (Int, Int32?) = resolvedPath.withCString { pathPtr in
            errno = 0
            let fd = open(pathPtr, O_RDONLY)
            if fd >= 0 {
                close(fd)
                return (0, nil)
            }
            return (1, errno)
        }
        accessRc = useRc
        accessErrno = useErrno
    } catch let error as NSError {
        resolveError = error.localizedDescription
        resolveErrorDomain = error.domain
        resolveErrorCode = error.code
    } catch {
        resolveError = "\(error)"
    }

    emitOpEvent(
        eventFd,
        runId: runId,
        phase: "child_use_attempt",
        capId: capIdStr,
        capType: capType,
        op: "bookmark_access",
        callsiteId: "child.bookmark.use",
        rc: accessRc,
        errno: accessErrno,
        extra: [
            "resolved_path": resolvedPath,
            "bookmark_is_stale": isStale ? "true" : "false",
            "bookmark_start_accessing": startAccessing ? "true" : "false",
            "bookmark_resolve_rc": "\(resolveRc)"
        ],
        stopOnDeny: stopOnDeny
    )

    emitEvent(eventFd, runId: runId, phase: "child_capability_result", details: [
        "cap_id": capIdStr,
        "cap_type": capType,
        "child_acquire_rc": "\(acquireRc)",
        "child_acquire_errno": acquireErrno.map { "\($0)" } ?? "",
        "child_use_rc": "\(accessRc)",
        "child_use_errno": accessErrno.map { "\($0)" } ?? "",
        "bookmark_resolve_rc": "\(resolveRc)",
        "bookmark_resolve_error": resolveError,
        "bookmark_resolve_error_domain": resolveErrorDomain,
        "bookmark_resolve_error_code": resolveErrorCode.map { "\($0)" } ?? "",
        "bookmark_is_stale": isStale ? "true" : "false",
        "bookmark_start_accessing": startAccessing ? "true" : "false",
        "bookmark_access_rc": "\(accessRc)",
        "bookmark_access_errno": accessErrno.map { "\($0)" } ?? ""
    ])
}

emitEvent(eventFd, runId: runId, phase: "child_done")
exit(0)
