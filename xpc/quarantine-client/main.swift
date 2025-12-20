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

if ProcessInfo.processInfo.environment["EJ_XPC_CLIENT_DEBUG"] == "1" {
    let exePath = CommandLine.arguments.first ?? "<unknown>"
    let bundlePath = Bundle.main.bundleURL.path
    let bundleId = Bundle.main.bundleIdentifier ?? "<nil>"
    fputs("debug: exe=\(exePath)\n", stderr)
    fputs("debug: Bundle.main.bundlePath=\(bundlePath)\n", stderr)
    fputs("debug: Bundle.main.bundleIdentifier=\(bundleId)\n", stderr)
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
    if let json = String(data: responseData, encoding: .utf8) {
        print(json)
    } else {
        fputs("service returned non-utf8 response\n", stderr)
    }

    do {
        let response = try decodeJSON(QuarantineWriteResponse.self, from: responseData)
        exitCode = Int32(clamping: response.rc)
    } catch {
        fputs("failed to decode response JSON: \(error)\n", stderr)
        exitCode = 1
    }
    semaphore.signal()
}

_ = semaphore.wait(timeout: .distantFuture)
connection.invalidate()
exit(exitCode)
