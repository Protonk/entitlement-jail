import Foundation

@objc public protocol ProbeServiceProtocol {
    func runProbe(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

@objc public protocol QuarantineLabProtocol {
    func writeArtifact(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

public struct RunProbeRequest: Codable {
    public var plan_id: String?
    public var probe_id: String
    public var argv: [String]
    public var env_overrides: [String: String]?

    public init(plan_id: String?, probe_id: String, argv: [String], env_overrides: [String: String]?) {
        self.plan_id = plan_id
        self.probe_id = probe_id
        self.argv = argv
        self.env_overrides = env_overrides
    }
}

public struct RunProbeResponse: Codable {
    public var rc: Int
    public var stdout: String
    public var stderr: String
    public var normalized_outcome: String
    public var errno: Int?
    public var error: String?
    public var details: [String: String]?
    public var layer_attribution: LayerAttribution?
    public var sandbox_log_excerpt_ref: String?

    public init(
        rc: Int,
        stdout: String,
        stderr: String,
        normalized_outcome: String,
        errno: Int? = nil,
        error: String? = nil,
        details: [String: String]? = nil,
        layer_attribution: LayerAttribution? = nil,
        sandbox_log_excerpt_ref: String?
    ) {
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        self.normalized_outcome = normalized_outcome
        self.errno = errno
        self.error = error
        self.details = details
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

public func encodeJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
}

public func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    let decoder = JSONDecoder()
    return try decoder.decode(type, from: data)
}
