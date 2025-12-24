import Foundation

@objc public protocol ProbeServiceProtocol {
    func runProbe(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

@objc public protocol QuarantineLabProtocol {
    func writeArtifact(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

public struct WaitSpec: Codable {
    public var mode: String?
    public var path: String?
    public var path_class: String?
    public var name: String?
    public var timeout_ms: Int?
    public var interval_ms: Int?
    public var create: Bool?

    public init(
        mode: String? = nil,
        path: String? = nil,
        path_class: String? = nil,
        name: String? = nil,
        timeout_ms: Int? = nil,
        interval_ms: Int? = nil,
        create: Bool? = nil
    ) {
        self.mode = mode
        self.path = path
        self.path_class = path_class
        self.name = name
        self.timeout_ms = timeout_ms
        self.interval_ms = interval_ms
        self.create = create
    }
}

public struct RunProbeRequest: Codable {
    public var plan_id: String?
    public var row_id: String?
    public var correlation_id: String?
    public var probe_id: String
    public var argv: [String]
    public var expected_outcome: String?
    public var env_overrides: [String: String]?
    public var wait_spec: WaitSpec?

    public init(
        plan_id: String?,
        row_id: String? = nil,
        correlation_id: String? = nil,
        probe_id: String,
        argv: [String],
        expected_outcome: String? = nil,
        env_overrides: [String: String]?,
        wait_spec: WaitSpec? = nil
    ) {
        self.plan_id = plan_id
        self.row_id = row_id
        self.correlation_id = correlation_id
        self.probe_id = probe_id
        self.argv = argv
        self.expected_outcome = expected_outcome
        self.env_overrides = env_overrides
        self.wait_spec = wait_spec
    }
}

public struct RunProbeResponse: Codable {
    public var schema_version: Int
    public var plan_id: String?
    public var row_id: String?
    public var correlation_id: String?
    public var probe_id: String?
    public var argv: [String]?
    public var expected_outcome: String?
    public var service_bundle_id: String?
    public var service_name: String?
    public var service_version: String?
    public var service_build: String?
    public var started_at_iso8601: String?
    public var ended_at_iso8601: String?
    public var thread_id: String?
    public var os_status: Int?
    public var rc: Int
    public var stdout: String
    public var stderr: String
    public var normalized_outcome: String
    public var errno: Int?
    public var error: String?
    public var details: [String: String]?
    public var log_capture_status: String?
    public var log_capture_path: String?
    public var log_capture_error: String?
    public var deny_evidence: String?
    public var layer_attribution: LayerAttribution?
    public var sandbox_log_excerpt_ref: String?

    public init(
        schema_version: Int = 1,
        plan_id: String? = nil,
        row_id: String? = nil,
        correlation_id: String? = nil,
        probe_id: String? = nil,
        argv: [String]? = nil,
        expected_outcome: String? = nil,
        service_bundle_id: String? = nil,
        service_name: String? = nil,
        service_version: String? = nil,
        service_build: String? = nil,
        started_at_iso8601: String? = nil,
        ended_at_iso8601: String? = nil,
        thread_id: String? = nil,
        os_status: Int? = nil,
        rc: Int,
        stdout: String,
        stderr: String,
        normalized_outcome: String,
        errno: Int? = nil,
        error: String? = nil,
        details: [String: String]? = nil,
        log_capture_status: String? = nil,
        log_capture_path: String? = nil,
        log_capture_error: String? = nil,
        deny_evidence: String? = nil,
        layer_attribution: LayerAttribution? = nil,
        sandbox_log_excerpt_ref: String?
    ) {
        self.schema_version = schema_version
        self.plan_id = plan_id
        self.row_id = row_id
        self.correlation_id = correlation_id
        self.probe_id = probe_id
        self.argv = argv
        self.expected_outcome = expected_outcome
        self.service_bundle_id = service_bundle_id
        self.service_name = service_name
        self.service_version = service_version
        self.service_build = service_build
        self.started_at_iso8601 = started_at_iso8601
        self.ended_at_iso8601 = ended_at_iso8601
        self.thread_id = thread_id
        self.os_status = os_status
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        self.normalized_outcome = normalized_outcome
        self.errno = errno
        self.error = error
        self.details = details
        self.log_capture_status = log_capture_status
        self.log_capture_path = log_capture_path
        self.log_capture_error = log_capture_error
        self.deny_evidence = deny_evidence
        self.layer_attribution = layer_attribution
        self.sandbox_log_excerpt_ref = sandbox_log_excerpt_ref
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
