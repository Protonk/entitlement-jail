import Foundation

@objc public protocol ProbeServiceProtocol {
    func openSession(_ request: Data, withReply reply: @escaping (Data) -> Void)
    func keepaliveSession(_ request: Data, withReply reply: @escaping (Data) -> Void)
    func runProbeInSession(_ request: Data, withReply reply: @escaping (Data) -> Void)
    func closeSession(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

// Bidirectional XPC: the service can emit lifecycle events to the client (JSON-over-Data).
@objc public protocol SessionEventSinkProtocol {
    func emitEvent(_ event: Data)
}

@objc public protocol QuarantineLabProtocol {
    func writeArtifact(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

public struct WaitSpec: Codable {
    public var spec: String
    public var timeout_ms: Int?
    public var interval_ms: Int?

    public init(
        spec: String,
        timeout_ms: Int? = nil,
        interval_ms: Int? = nil
    ) {
        self.spec = spec
        self.timeout_ms = timeout_ms
        self.interval_ms = interval_ms
    }
}

public struct SessionOpenRequest: Codable {
    public var plan_id: String?
    public var correlation_id: String?
    public var wait_spec: WaitSpec?

    public init(
        plan_id: String? = nil,
        correlation_id: String? = nil,
        wait_spec: WaitSpec? = nil
    ) {
        self.plan_id = plan_id
        self.correlation_id = correlation_id
        self.wait_spec = wait_spec
    }
}

public struct SessionOpenResponse: Codable {
    public var schema_version: Int
    public var rc: Int
    public var error: String?
    public var session_token: String?
    public var pid: Int?
    public var service_bundle_id: String?
    public var service_name: String?
    public var service_version: String?
    public var service_build: String?
    public var wait_mode: String?
    public var wait_path: String?

    public init(
        schema_version: Int = 1,
        rc: Int,
        error: String? = nil,
        session_token: String? = nil,
        pid: Int? = nil,
        service_bundle_id: String? = nil,
        service_name: String? = nil,
        service_version: String? = nil,
        service_build: String? = nil,
        wait_mode: String? = nil,
        wait_path: String? = nil
    ) {
        self.schema_version = schema_version
        self.rc = rc
        self.error = error
        self.session_token = session_token
        self.pid = pid
        self.service_bundle_id = service_bundle_id
        self.service_name = service_name
        self.service_version = service_version
        self.service_build = service_build
        self.wait_mode = wait_mode
        self.wait_path = wait_path
    }
}

public struct SessionKeepaliveRequest: Codable {
    public var session_token: String

    public init(session_token: String) {
        self.session_token = session_token
    }
}

public struct SessionCloseRequest: Codable {
    public var session_token: String

    public init(session_token: String) {
        self.session_token = session_token
    }
}

public struct SessionRunProbeRequest: Codable {
    public var session_token: String
    public var probe_request: RunProbeRequest

    public init(session_token: String, probe_request: RunProbeRequest) {
        self.session_token = session_token
        self.probe_request = probe_request
    }
}

public struct SessionControlResponse: Codable {
    public var schema_version: Int
    public var rc: Int
    public var error: String?

    public init(schema_version: Int = 1, rc: Int, error: String? = nil) {
        self.schema_version = schema_version
        self.rc = rc
        self.error = error
    }
}

public struct XpcSessionEventData: Codable {
    public var event: String
    public var plan_id: String?
    public var correlation_id: String?
    public var session_token: String?
    public var pid: Int?
    public var child_pid: Int?
    public var run_id: String?
    public var service_bundle_id: String?
    public var service_name: String?
    public var wait_mode: String?
    public var wait_path: String?
    public var trigger_bytes: Int?
    public var probe_id: String?
    public var probe_argv: [String]?
    public var message: String?

    public init(
        event: String,
        plan_id: String? = nil,
        correlation_id: String? = nil,
        session_token: String? = nil,
        pid: Int? = nil,
        child_pid: Int? = nil,
        run_id: String? = nil,
        service_bundle_id: String? = nil,
        service_name: String? = nil,
        wait_mode: String? = nil,
        wait_path: String? = nil,
        trigger_bytes: Int? = nil,
        probe_id: String? = nil,
        probe_argv: [String]? = nil,
        message: String? = nil
    ) {
        self.event = event
        self.plan_id = plan_id
        self.correlation_id = correlation_id
        self.session_token = session_token
        self.pid = pid
        self.child_pid = child_pid
        self.run_id = run_id
        self.service_bundle_id = service_bundle_id
        self.service_name = service_name
        self.wait_mode = wait_mode
        self.wait_path = wait_path
        self.trigger_bytes = trigger_bytes
        self.probe_id = probe_id
        self.probe_argv = probe_argv
        self.message = message
    }
}

public struct XpcSessionErrorData: Codable {
    public var event: String
    public var plan_id: String?
    public var correlation_id: String?
    public var session_token: String?
    public var pid: Int?
    public var service_bundle_id: String?
    public var service_name: String?
    public var wait_mode: String?
    public var wait_path: String?
    public var error: String

    public init(
        event: String,
        plan_id: String? = nil,
        correlation_id: String? = nil,
        session_token: String? = nil,
        pid: Int? = nil,
        service_bundle_id: String? = nil,
        service_name: String? = nil,
        wait_mode: String? = nil,
        wait_path: String? = nil,
        error: String
    ) {
        self.event = event
        self.plan_id = plan_id
        self.correlation_id = correlation_id
        self.session_token = session_token
        self.pid = pid
        self.service_bundle_id = service_bundle_id
        self.service_name = service_name
        self.wait_mode = wait_mode
        self.wait_path = wait_path
        self.error = error
    }
}

public struct RunProbeRequest: Codable {
    public var plan_id: String?
    public var row_id: String?
    public var correlation_id: String?
    public var probe_id: String
    public var argv: [String]

    public init(
        plan_id: String? = nil,
        row_id: String? = nil,
        correlation_id: String? = nil,
        probe_id: String,
        argv: [String]
    ) {
        self.plan_id = plan_id
        self.row_id = row_id
        self.correlation_id = correlation_id
        self.probe_id = probe_id
        self.argv = argv
    }
}

// RunProbeResponse is a witness record for one probe invocation.
//
// - Action + outcome are first-class per phase (rc/errno and post-action observations), not just a final return code.
// - Success is an observable policy transition (access delta), not “rc==0” (see sandbox_extension update_file_rename_delta).
// - normalized_outcome distinguishes premise failures, sandbox denies, harness failures, and expected abort canaries.
public struct RunProbeResponse: Codable {
    public var schema_version: Int
    public var plan_id: String?
    public var row_id: String?
    public var correlation_id: String?
    public var probe_id: String?
    public var argv: [String]?
    public var service_bundle_id: String?
    public var service_name: String?
    public var service_version: String?
    public var service_build: String?
    public var started_at_iso8601: String?
    public var ended_at_iso8601: String?
    public var thread_id: String?
    public var rc: Int
    public var stdout: String
    public var stderr: String
    public var normalized_outcome: String
    public var errno: Int?
    public var error: String?
    public var details: [String: String]?
    public var witness: InheritChildWitness?
    public var layer_attribution: LayerAttribution?

    public init(
        schema_version: Int = 1,
        plan_id: String? = nil,
        row_id: String? = nil,
        correlation_id: String? = nil,
        probe_id: String? = nil,
        argv: [String]? = nil,
        service_bundle_id: String? = nil,
        service_name: String? = nil,
        service_version: String? = nil,
        service_build: String? = nil,
        started_at_iso8601: String? = nil,
        ended_at_iso8601: String? = nil,
        thread_id: String? = nil,
        rc: Int,
        stdout: String,
        stderr: String,
        normalized_outcome: String,
        errno: Int? = nil,
        error: String? = nil,
        details: [String: String]? = nil,
        witness: InheritChildWitness? = nil,
        layer_attribution: LayerAttribution? = nil
    ) {
        self.schema_version = schema_version
        self.plan_id = plan_id
        self.row_id = row_id
        self.correlation_id = correlation_id
        self.probe_id = probe_id
        self.argv = argv
        self.service_bundle_id = service_bundle_id
        self.service_name = service_name
        self.service_version = service_version
        self.service_build = service_build
        self.started_at_iso8601 = started_at_iso8601
        self.ended_at_iso8601 = ended_at_iso8601
        self.thread_id = thread_id
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        self.normalized_outcome = normalized_outcome
        self.errno = errno
        self.error = error
        self.details = details
        self.witness = witness
        self.layer_attribution = layer_attribution
    }
}

public enum InheritChildProtocol {
    public static let version = 1
    public static let capabilityNamespace = "inherit_child.cap.v1"
    public static let sentinelPrefix = "PW_CHILD_SENTINEL"
    public static let eventPayloadPrefix = "PW_CAP_PAYLOAD"
    public static let sentinelKeyProtocolVersion = "protocol_version"
    public static let sentinelKeyCapabilityNamespace = "cap_namespace"
    public static let eventPayloadKeyProtocolVersion = "proto"
    public static let eventPayloadKeyCapabilityNamespace = "cap_ns"
    public static let eventPayloadKeyCapId = "cap_id"
    public static let eventPayloadKeyCapType = "cap_type"
    public static let eventPayloadKeyLength = "len"
    // Event bus framing: JSONL events from child plus a sentinel line:
    // "PW_CHILD_SENTINEL ... protocol_version=<v> cap_namespace=<ns>\n".
    // Parent->child payloads over the event bus are a header line:
    // "PW_CAP_PAYLOAD proto=<v> cap_ns=<ns> cap_id=<id> cap_type=<type> len=<n>\n"
    // followed by <n> raw bytes.
    // Rights bus header (SCM_RIGHTS payload) is four int32s: cap_id, meta0, meta1, meta2.
    // meta0 is the protocol version; meta1/meta2 are reserved (0).
}

public enum InheritChildCapabilityId: Int32, Codable {
    case fileFd = 1
    case dirFd = 2
    case socketFd = 3
    case bookmark = 4
}

public struct InheritChildEvent: Codable {
    public var actor: String
    public var phase: String
    public var run_id: String
    public var pid: Int?
    public var time_unix_ms: UInt64
    public var monotonic_ns: UInt64?
    public var callsite_id: String?
    public var op: String?
    public var backtrace: [String]?
    public var backtrace_error: String?
    public var lineage: InheritChildLineage?
    public var details: [String: String]?
    public var errno: Int?
    public var rc: Int?

    public init(
        actor: String,
        phase: String,
        run_id: String,
        pid: Int? = nil,
        time_unix_ms: UInt64,
        monotonic_ns: UInt64? = nil,
        callsite_id: String? = nil,
        op: String? = nil,
        backtrace: [String]? = nil,
        backtrace_error: String? = nil,
        lineage: InheritChildLineage? = nil,
        details: [String: String]? = nil,
        errno: Int? = nil,
        rc: Int? = nil
    ) {
        self.actor = actor
        self.phase = phase
        self.run_id = run_id
        self.pid = pid
        self.time_unix_ms = time_unix_ms
        self.monotonic_ns = monotonic_ns
        self.callsite_id = callsite_id
        self.op = op
        self.backtrace = backtrace
        self.backtrace_error = backtrace_error
        self.lineage = lineage
        self.details = details
        self.errno = errno
        self.rc = rc
    }
}

public struct InheritChildProtocolError: Codable {
    public var kind: String
    public var cap_id: String?
    public var expected: String?
    public var observed: String?
    public var details: [String: String]?

    public init(
        kind: String,
        cap_id: String? = nil,
        expected: String? = nil,
        observed: String? = nil,
        details: [String: String]? = nil
    ) {
        self.kind = kind
        self.cap_id = cap_id
        self.expected = expected
        self.observed = observed
        self.details = details
    }
}

public struct InheritChildLineage: Codable {
    public var depth: Int
    public var pid: Int
    public var ppid: Int

    public init(depth: Int, pid: Int, ppid: Int) {
        self.depth = depth
        self.pid = pid
        self.ppid = ppid
    }
}

public struct InheritChildCapabilityOpResult: Codable {
    public var rc: Int?
    public var errno: Int?

    public init(rc: Int? = nil, errno: Int? = nil) {
        self.rc = rc
        self.errno = errno
    }
}

public struct InheritChildBookmarkResult: Codable {
    public var resolve_rc: Int?
    public var resolve_error: String?
    public var resolve_error_domain: String?
    public var resolve_error_code: Int?
    public var is_stale: Bool?
    public var start_accessing: Bool?
    public var access_rc: Int?
    public var access_errno: Int?

    public init(
        resolve_rc: Int? = nil,
        resolve_error: String? = nil,
        resolve_error_domain: String? = nil,
        resolve_error_code: Int? = nil,
        is_stale: Bool? = nil,
        start_accessing: Bool? = nil,
        access_rc: Int? = nil,
        access_errno: Int? = nil
    ) {
        self.resolve_rc = resolve_rc
        self.resolve_error = resolve_error
        self.resolve_error_domain = resolve_error_domain
        self.resolve_error_code = resolve_error_code
        self.is_stale = is_stale
        self.start_accessing = start_accessing
        self.access_rc = access_rc
        self.access_errno = access_errno
    }
}

public struct InheritChildCapabilityResult: Codable {
    public var cap_id: String
    public var cap_type: String
    public var parent_acquire: InheritChildCapabilityOpResult?
    public var child_acquire: InheritChildCapabilityOpResult?
    public var child_use: InheritChildCapabilityOpResult?
    public var bookmark: InheritChildBookmarkResult?
    public var notes: String?

    public init(
        cap_id: String,
        cap_type: String,
        parent_acquire: InheritChildCapabilityOpResult? = nil,
        child_acquire: InheritChildCapabilityOpResult? = nil,
        child_use: InheritChildCapabilityOpResult? = nil,
        bookmark: InheritChildBookmarkResult? = nil,
        notes: String? = nil
    ) {
        self.cap_id = cap_id
        self.cap_type = cap_type
        self.parent_acquire = parent_acquire
        self.child_acquire = child_acquire
        self.child_use = child_use
        self.bookmark = bookmark
        self.notes = notes
    }
}

public enum EntitlementValue: Codable, Equatable {
    case bool(Bool)
    case string(String)
    case int(Int)
    case double(Double)
    case array([EntitlementValue])
    case dict([String: EntitlementValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
            return
        }
        if let value = try? container.decode(Bool.self) {
            self = .bool(value)
            return
        }
        if let value = try? container.decode(Int.self) {
            self = .int(value)
            return
        }
        if let value = try? container.decode(Double.self) {
            self = .double(value)
            return
        }
        if let value = try? container.decode(String.self) {
            self = .string(value)
            return
        }
        if let value = try? container.decode([EntitlementValue].self) {
            self = .array(value)
            return
        }
        if let value = try? container.decode([String: EntitlementValue].self) {
            self = .dict(value)
            return
        }
        throw DecodingError.dataCorruptedError(in: container, debugDescription: "unsupported entitlement value")
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .bool(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .int(let value):
            try container.encode(value)
        case .double(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .dict(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

// InheritChildWitness is present even when the child never emits structured events.
//
// - Guardrail identity fields (bundle id, team id, entitlements, inherit_contract_ok) stay populated so early aborts remain diagnosable.
// - sandbox_log_capture_status records tri-state semantics: not_requested / requested_unavailable / captured (absence of logs is interpretable).
// - protocol_error is structured so protocol mismatches become explicit child_protocol_violation/protocol_error outcomes, not undefined behavior.
public struct InheritChildWitness: Codable {
    public var schema_version: Int
    public var protocol_version: Int
    public var capability_namespace: String
    public var run_id: String
    public var scenario: String
    public var profile: String?
    public var parent_pid: Int
    public var child_pid: Int
    public var child_exit_status: Int
    public var child_event_fd: Int
    public var child_rights_fd: Int
    public var child_path: String
    public var service_bundle_id: String
    public var process_name: String
    public var child_bundle_id: String
    public var child_team_id: String
    public var child_entitlements: [String: EntitlementValue]
    public var inherit_contract_ok: Bool
    public var capability_results: [InheritChildCapabilityResult]
    public var stop_on_entry: Bool?
    public var stop_on_deny: Bool?
    public var events: [InheritChildEvent]
    public var system_sandbox_reports: [String]?
    public var sandbox_log_capture_status: String
    public var sandbox_log_capture: [String: String]
    public var protocol_error: InheritChildProtocolError?
    public var outcome_summary: String?

    public init(
        schema_version: Int = 1,
        protocol_version: Int = InheritChildProtocol.version,
        capability_namespace: String = InheritChildProtocol.capabilityNamespace,
        run_id: String,
        scenario: String,
        profile: String? = nil,
        parent_pid: Int,
        child_pid: Int = -1,
        child_exit_status: Int = -1,
        child_event_fd: Int = -1,
        child_rights_fd: Int = -1,
        child_path: String = "",
        service_bundle_id: String = "",
        process_name: String = "",
        child_bundle_id: String = "",
        child_team_id: String = "",
        child_entitlements: [String: EntitlementValue] = [:],
        inherit_contract_ok: Bool = false,
        capability_results: [InheritChildCapabilityResult] = [],
        stop_on_entry: Bool? = nil,
        stop_on_deny: Bool? = nil,
        events: [InheritChildEvent],
        system_sandbox_reports: [String]? = nil,
        sandbox_log_capture_status: String = "not_requested",
        sandbox_log_capture: [String: String] = [:],
        protocol_error: InheritChildProtocolError? = nil,
        outcome_summary: String? = nil
    ) {
        self.schema_version = schema_version
        self.protocol_version = protocol_version
        self.capability_namespace = capability_namespace
        self.run_id = run_id
        self.scenario = scenario
        self.profile = profile
        self.parent_pid = parent_pid
        self.child_pid = child_pid
        self.child_exit_status = child_exit_status
        self.child_event_fd = child_event_fd
        self.child_rights_fd = child_rights_fd
        self.child_path = child_path
        self.service_bundle_id = service_bundle_id
        self.process_name = process_name
        self.child_bundle_id = child_bundle_id
        self.child_team_id = child_team_id
        self.child_entitlements = child_entitlements
        self.inherit_contract_ok = inherit_contract_ok
        self.capability_results = capability_results
        self.stop_on_entry = stop_on_entry
        self.stop_on_deny = stop_on_deny
        self.events = events
        self.system_sandbox_reports = system_sandbox_reports
        self.sandbox_log_capture_status = sandbox_log_capture_status
        self.sandbox_log_capture = sandbox_log_capture
        self.protocol_error = protocol_error
        self.outcome_summary = outcome_summary
    }
}

public struct LayerAttribution: Codable {
    public var seatbelt_deny_op: String?
    public var service_refusal: String?
    public var quarantine_delta: String?
    public var gatekeeper_signal: String?
    public var world_shape_change: String?
    public var other: String?

    public init(
        seatbelt_deny_op: String? = nil,
        service_refusal: String? = nil,
        quarantine_delta: String? = nil,
        gatekeeper_signal: String? = nil,
        world_shape_change: String? = nil,
        other: String? = nil
    ) {
        self.seatbelt_deny_op = seatbelt_deny_op
        self.service_refusal = service_refusal
        self.quarantine_delta = quarantine_delta
        self.gatekeeper_signal = gatekeeper_signal
        self.world_shape_change = world_shape_change
        self.other = other
    }
}

public struct QuarantineXattrParsed: Codable {
    public var raw: String
    public var fields: [String]
    public var flags_raw: String?
    public var flags_hex: String?
    public var flags_int: Int?
    public var timestamp_raw: String?
    public var timestamp_unix: Int?
    public var timestamp_iso8601: String?
    public var agent: String?
    public var uuid: String?

    public init(
        raw: String,
        fields: [String],
        flags_raw: String?,
        flags_hex: String?,
        flags_int: Int?,
        timestamp_raw: String?,
        timestamp_unix: Int?,
        timestamp_iso8601: String?,
        agent: String?,
        uuid: String?
    ) {
        self.raw = raw
        self.fields = fields
        self.flags_raw = flags_raw
        self.flags_hex = flags_hex
        self.flags_int = flags_int
        self.timestamp_raw = timestamp_raw
        self.timestamp_unix = timestamp_unix
        self.timestamp_iso8601 = timestamp_iso8601
        self.agent = agent
        self.uuid = uuid
    }
}

public struct QuarantineWriteRequest: Codable {
    public var test_case_id: String?
    public var selection_mechanism: String?
    public var path_class: String?
    public var operation: String?
    public var payload_class: String
    public var existing_path: String?
    public var file_name: String?
    public var make_executable: Bool?

    public init(
        test_case_id: String? = nil,
        selection_mechanism: String? = nil,
        path_class: String? = nil,
        operation: String? = nil,
        payload_class: String,
        existing_path: String? = nil,
        file_name: String? = nil,
        make_executable: Bool? = nil
    ) {
        self.test_case_id = test_case_id
        self.selection_mechanism = selection_mechanism
        self.path_class = path_class
        self.operation = operation
        self.payload_class = payload_class
        self.existing_path = existing_path
        self.file_name = file_name
        self.make_executable = make_executable
    }
}

public struct QuarantineWriteResponse: Codable {
    public var schema_version: Int
    public var rc: Int
    public var normalized_outcome: String
    public var error: String?
    public var test_case_id: String?
    public var selection_mechanism: String?
    public var path_class: String?
    public var operation: String?
    public var payload_class: String?
    public var existing_path: String?
    public var existing_quarantine_present: Bool?
    public var existing_quarantine_raw: String?
    public var existing_quarantine_parsed: QuarantineXattrParsed?
    public var target_path: String?
    public var target_existed_before: Bool?
    public var target_existed_after: Bool?
    public var written_path: String?
    public var mode_octal: String?
    public var is_executable: Bool?
    public var quarantine_xattr_present: Bool?
    public var quarantine_xattr_raw: String?
    public var quarantine_xattr_parsed: QuarantineXattrParsed?
    public var quarantine_before_present: Bool?
    public var quarantine_before_raw: String?
    public var quarantine_before_parsed: QuarantineXattrParsed?
    public var quarantine_after_present: Bool?
    public var quarantine_after_raw: String?
    public var quarantine_after_parsed: QuarantineXattrParsed?
    public var has_app_sandbox: Bool?
    public var has_user_selected_executable: Bool?
    public var service_bundle_id: String?
    public var layer_attribution: LayerAttribution?

    public init(
        schema_version: Int = 1,
        rc: Int,
        normalized_outcome: String,
        error: String? = nil,
        test_case_id: String? = nil,
        selection_mechanism: String? = nil,
        path_class: String? = nil,
        operation: String? = nil,
        payload_class: String? = nil,
        existing_path: String? = nil,
        existing_quarantine_present: Bool? = nil,
        existing_quarantine_raw: String? = nil,
        existing_quarantine_parsed: QuarantineXattrParsed? = nil,
        target_path: String? = nil,
        target_existed_before: Bool? = nil,
        target_existed_after: Bool? = nil,
        written_path: String? = nil,
        mode_octal: String? = nil,
        is_executable: Bool? = nil,
        quarantine_xattr_present: Bool? = nil,
        quarantine_xattr_raw: String? = nil,
        quarantine_xattr_parsed: QuarantineXattrParsed? = nil,
        quarantine_before_present: Bool? = nil,
        quarantine_before_raw: String? = nil,
        quarantine_before_parsed: QuarantineXattrParsed? = nil,
        quarantine_after_present: Bool? = nil,
        quarantine_after_raw: String? = nil,
        quarantine_after_parsed: QuarantineXattrParsed? = nil,
        has_app_sandbox: Bool? = nil,
        has_user_selected_executable: Bool? = nil,
        service_bundle_id: String? = nil,
        layer_attribution: LayerAttribution? = nil
    ) {
        self.schema_version = schema_version
        self.rc = rc
        self.normalized_outcome = normalized_outcome
        self.error = error
        self.test_case_id = test_case_id
        self.selection_mechanism = selection_mechanism
        self.path_class = path_class
        self.operation = operation
        self.payload_class = payload_class
        self.existing_path = existing_path
        self.existing_quarantine_present = existing_quarantine_present
        self.existing_quarantine_raw = existing_quarantine_raw
        self.existing_quarantine_parsed = existing_quarantine_parsed
        self.target_path = target_path
        self.target_existed_before = target_existed_before
        self.target_existed_after = target_existed_after
        self.written_path = written_path
        self.mode_octal = mode_octal
        self.is_executable = is_executable
        self.quarantine_xattr_present = quarantine_xattr_present
        self.quarantine_xattr_raw = quarantine_xattr_raw
        self.quarantine_xattr_parsed = quarantine_xattr_parsed
        self.quarantine_before_present = quarantine_before_present
        self.quarantine_before_raw = quarantine_before_raw
        self.quarantine_before_parsed = quarantine_before_parsed
        self.quarantine_after_present = quarantine_after_present
        self.quarantine_after_raw = quarantine_after_raw
        self.quarantine_after_parsed = quarantine_after_parsed
        self.has_app_sandbox = has_app_sandbox
        self.has_user_selected_executable = has_user_selected_executable
        self.service_bundle_id = service_bundle_id
        self.layer_attribution = layer_attribution
    }
}

public struct JsonResult: Codable {
    public var ok: Bool
    public var rc: Int?
    public var exit_code: Int?
    public var normalized_outcome: String?
    public var errno: Int?
    public var error: String?
    public var stderr: String?
    public var stdout: String?

    public init(
        ok: Bool,
        rc: Int? = nil,
        exit_code: Int? = nil,
        normalized_outcome: String? = nil,
        errno: Int? = nil,
        error: String? = nil,
        stderr: String? = nil,
        stdout: String? = nil
    ) {
        self.ok = ok
        self.rc = rc
        self.exit_code = exit_code
        self.normalized_outcome = normalized_outcome
        self.errno = errno
        self.error = error
        self.stderr = stderr
        self.stdout = stdout
    }
}

public struct JsonEnvelope<T: Encodable>: Encodable {
    public var schema_version: Int
    public var kind: String
    public var generated_at_unix_ms: UInt64
    public var result: JsonResult
    public var data: T

    public init(
        schema_version: Int = 1,
        kind: String,
        generated_at_unix_ms: UInt64,
        result: JsonResult,
        data: T
    ) {
        self.schema_version = schema_version
        self.kind = kind
        self.generated_at_unix_ms = generated_at_unix_ms
        self.result = result
        self.data = data
    }
}

public func encodeJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
}

public func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    let decoder = JSONDecoder()
    return try decoder.decode(type, from: data)
}
