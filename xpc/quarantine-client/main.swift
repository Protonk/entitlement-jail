import Foundation
import Darwin

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "xpc-quarantine-client"
    fputs(
        """
        usage:
          \(exe) <xpc-service-bundle-id> <payload-class> [options...]

        payload-class:
          shell_script | command_file | text | webarchive_like

        options:
          --operation <create_new|open_only|open_existing_save>
          --existing-path <path>        (required for open_existing_save; optional for open_only)
          --dir <tmp|app_support>
          --name <file-name>
          --selection <string>          (annotation only; does not grant access)
          --test-case-id <id>
          --exec | --no-exec
        """,
        stderr
    )
}

if ProcessInfo.processInfo.environment["PW_XPC_CLIENT_DEBUG"] == "1" {
    let exePath = CommandLine.arguments.first ?? "<unknown>"
    let bundlePath = Bundle.main.bundleURL.path
    let bundleId = Bundle.main.bundleIdentifier ?? "<nil>"
    fputs("debug: exe=\(exePath)\n", stderr)
    fputs("debug: Bundle.main.bundlePath=\(bundlePath)\n", stderr)
    fputs("debug: Bundle.main.bundleIdentifier=\(bundleId)\n", stderr)
}

private struct QuarantineData: Encodable {
    var test_case_id: String?
    var selection_mechanism: String?
    var path_class: String?
    var operation: String?
    var payload_class: String?
    var existing_path: String?
    var existing_quarantine_present: Bool?
    var existing_quarantine_raw: String?
    var existing_quarantine_parsed: QuarantineXattrParsed?
    var target_path: String?
    var target_existed_before: Bool?
    var target_existed_after: Bool?
    var written_path: String?
    var mode_octal: String?
    var is_executable: Bool?
    var quarantine_xattr_present: Bool?
    var quarantine_xattr_raw: String?
    var quarantine_xattr_parsed: QuarantineXattrParsed?
    var quarantine_before_present: Bool?
    var quarantine_before_raw: String?
    var quarantine_before_parsed: QuarantineXattrParsed?
    var quarantine_after_present: Bool?
    var quarantine_after_raw: String?
    var quarantine_after_parsed: QuarantineXattrParsed?
    var has_app_sandbox: Bool?
    var has_user_selected_executable: Bool?
    var service_bundle_id: String?
    var layer_attribution: LayerAttribution?
}

private struct DecodeFailureData: Encodable {
    var raw_response: String?
    var decode_error: String
}

let args = CommandLine.arguments
guard args.count >= 3 else {
    printUsage()
    exit(2)
}

let serviceName = args[1]
let payloadClass = args[2]

var pathClass: String? = "tmp"
var operation: String? = "create_new"
var existingPath: String?
var fileName: String?
var selectionMechanism: String?
var testCaseId: String?
var makeExecutable: Bool?

var i = 3
while i < args.count {
    switch args[i] {
    case "-h", "--help":
        printUsage()
        exit(0)
    case "--dir":
        guard i + 1 < args.count else {
            fputs("missing value for --dir\n", stderr)
            exit(2)
        }
        pathClass = args[i + 1]
        i += 2
    case "--operation":
        guard i + 1 < args.count else {
            fputs("missing value for --operation\n", stderr)
            exit(2)
        }
        operation = args[i + 1]
        i += 2
    case "--existing-path":
        guard i + 1 < args.count else {
            fputs("missing value for --existing-path\n", stderr)
            exit(2)
        }
        existingPath = args[i + 1]
        i += 2
    case "--name":
        guard i + 1 < args.count else {
            fputs("missing value for --name\n", stderr)
            exit(2)
        }
        fileName = args[i + 1]
        i += 2
    case "--selection":
        guard i + 1 < args.count else {
            fputs("missing value for --selection\n", stderr)
            exit(2)
        }
        selectionMechanism = args[i + 1]
        i += 2
    case "--test-case-id":
        guard i + 1 < args.count else {
            fputs("missing value for --test-case-id\n", stderr)
            exit(2)
        }
        testCaseId = args[i + 1]
        i += 2
    case "--exec":
        makeExecutable = true
        i += 1
    case "--no-exec":
        makeExecutable = false
        i += 1
    default:
        fputs("unknown option: \(args[i])\n", stderr)
        printUsage()
        exit(2)
    }
}

let request = QuarantineWriteRequest(
    test_case_id: testCaseId,
    selection_mechanism: selectionMechanism,
    path_class: pathClass,
    operation: operation,
    payload_class: payloadClass,
    existing_path: existingPath,
    file_name: fileName,
    make_executable: makeExecutable
)

let requestData: Data
do {
    requestData = try encodeJSON(request)
} catch {
    fputs("failed to encode request JSON: \(error)\n", stderr)
    exit(2)
}

let connection = NSXPCConnection(serviceName: serviceName)
connection.remoteObjectInterface = NSXPCInterface(with: QuarantineLabProtocol.self)
connection.resume()

let semaphore = DispatchSemaphore(value: 0)
var exitCode: Int32 = 1

guard
    let proxy = connection.remoteObjectProxyWithErrorHandler({ err in
        fputs("xpc connection error: \(err)\n", stderr)
        semaphore.signal()
    }) as? QuarantineLabProtocol
else {
    fputs("failed to create xpc proxy\n", stderr)
    exit(1)
}

proxy.writeArtifact(requestData) { responseData in
    do {
        let response = try decodeJSON(QuarantineWriteResponse.self, from: responseData)
        exitCode = Int32(clamping: response.rc)

        let data = QuarantineData(
            test_case_id: response.test_case_id,
            selection_mechanism: response.selection_mechanism,
            path_class: response.path_class,
            operation: response.operation,
            payload_class: response.payload_class,
            existing_path: response.existing_path,
            existing_quarantine_present: response.existing_quarantine_present,
            existing_quarantine_raw: response.existing_quarantine_raw,
            existing_quarantine_parsed: response.existing_quarantine_parsed,
            target_path: response.target_path,
            target_existed_before: response.target_existed_before,
            target_existed_after: response.target_existed_after,
            written_path: response.written_path,
            mode_octal: response.mode_octal,
            is_executable: response.is_executable,
            quarantine_xattr_present: response.quarantine_xattr_present,
            quarantine_xattr_raw: response.quarantine_xattr_raw,
            quarantine_xattr_parsed: response.quarantine_xattr_parsed,
            quarantine_before_present: response.quarantine_before_present,
            quarantine_before_raw: response.quarantine_before_raw,
            quarantine_before_parsed: response.quarantine_before_parsed,
            quarantine_after_present: response.quarantine_after_present,
            quarantine_after_raw: response.quarantine_after_raw,
            quarantine_after_parsed: response.quarantine_after_parsed,
            has_app_sandbox: response.has_app_sandbox,
            has_user_selected_executable: response.has_user_selected_executable,
            service_bundle_id: response.service_bundle_id,
            layer_attribution: response.layer_attribution
        )

        let result = JsonResult(
            ok: response.rc == 0,
            rc: response.rc,
            exit_code: nil,
            normalized_outcome: response.normalized_outcome,
            errno: nil,
            error: response.error,
            stderr: nil,
            stdout: nil
        )

        let envelope = JsonEnvelope(
            kind: "quarantine_response",
            generated_at_unix_ms: UInt64(Date().timeIntervalSince1970 * 1000.0),
            result: result,
            data: data
        )

        do {
            let data = try encodeJSON(envelope)
            if let json = String(data: data, encoding: .utf8) {
                print(json)
            } else {
                fputs("failed to encode response JSON\n", stderr)
            }
        } catch {
            fputs("failed to encode response JSON: \(error)\n", stderr)
        }
    } catch {
        let raw = String(data: responseData, encoding: .utf8)
        let data = DecodeFailureData(raw_response: raw, decode_error: "\(error)")
        let result = JsonResult(
            ok: false,
            rc: nil,
            exit_code: 1,
            normalized_outcome: nil,
            errno: nil,
            error: "decode_failed",
            stderr: nil,
            stdout: nil
        )
        let envelope = JsonEnvelope(
            kind: "quarantine_response",
            generated_at_unix_ms: UInt64(Date().timeIntervalSince1970 * 1000.0),
            result: result,
            data: data
        )
        if let encoded = try? encodeJSON(envelope),
           let json = String(data: encoded, encoding: .utf8) {
            print(json)
        } else {
            fputs("failed to encode response JSON: \(error)\n", stderr)
        }
        exitCode = 1
    }
    semaphore.signal()
}

_ = semaphore.wait(timeout: .distantFuture)
connection.invalidate()
exit(exitCode)
