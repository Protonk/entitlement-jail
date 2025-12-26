import Foundation
import Security
import Darwin

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "witness-substrate"
    fputs(
        """
        usage:
          \(exe) probe <probe-id> [probe-args...]
          \(exe) quarantine-lab <payload-class> [options...]

        probe-id:
          probe_catalog
          world_shape
          network_tcp_connect   --host <ipv4> --port <1..65535>
          downloads_rw          [--name <file-name>]
          fs_op                 --op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>
                               (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
                               [--target <base|harness_dir|run_dir|specimen_file>] [--name <file-name>] [--to <path>] [--to-name <file-name>]
                               [--max-entries <n>] [--allow-unsafe-path]
          fs_op_wait            --op <stat|open_read|open_write|create|truncate|rename|unlink|mkdir|rmdir|listdir|readlink|realpath>
                               (--path <abs> | --path-class <home|tmp|downloads|desktop|documents|app_support|caches>)
                               [--target <base|harness_dir|run_dir|specimen_file>] [--name <file-name>] [--to <path>] [--to-name <file-name>]
                               [--max-entries <n>] [--allow-unsafe-path]
                               (--wait-fifo <path> | --wait-exists <path>) [--wait-timeout-ms <n>] [--wait-interval-ms <n>]
          net_op                --op <getaddrinfo|tcp_connect|udp_send> --host <host> [--port <1..65535>] [--numeric]
          dlopen_external       --path <abs> (or set EJ_DLOPEN_PATH)
          jit_map_jit           [--size <bytes>]
          jit_rwx_legacy        [--size <bytes>]
          bookmark_op           --bookmark-b64 <base64> | --bookmark-path <path>
                               [--relative <rel>] [--op <fs_op-op>] [--allow-unsafe-path]
          bookmark_make         --path <abs> [--no-security-scope] [--read-only] [--allow-missing]
          bookmark_roundtrip    --path <abs> [--op <fs_op-op>] [--relative <rel>] [--no-security-scope] [--read-only] [--allow-missing] [--allow-unsafe-path]
          capabilities_snapshot
          sandbox_check         --operation <sandbox-op> [--path <abs>] [--repeat <n>]
          userdefaults_op       --op <read|write|remove|sync> [--key <k>] [--value <v>] [--suite <suite>]
          fs_xattr              --op <get|list|set|remove> --path <abs> [--name <xattr>] [--value <v>] [--allow-write] [--allow-unsafe-path]
          fs_coordinated_op     --op <read|write> (--path <abs> | --path-class <...>) [--allow-unsafe-path]

        tip:
          use "<probe-id> --help" for per-probe usage (help text is returned in JSON stdout)

        payload-class:
          shell_script | command_file | text | webarchive_like

        quarantine-lab options:
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

enum SubstrateExit {
    static func json<T: Encodable>(_ value: T, rc: Int32) -> Never {
        do {
            let data = try encodeJSON(value)
            if let s = String(data: data, encoding: .utf8) {
                print(s)
            } else {
                fputs("failed to encode utf8 json\n", stderr)
            }
            exit(rc)
        } catch {
            fputs("failed to encode json: \(error)\n", stderr)
            exit(2)
        }
    }
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    printUsage()
    exit(2)
}

switch args[1] {
case "probe":
    guard args.count >= 3 else {
        printUsage()
        exit(2)
    }
    let probeId = args[2]
    let probeArgs = Array(args.dropFirst(3))
    let req = RunProbeRequest(plan_id: nil, probe_id: probeId, argv: probeArgs, env_overrides: nil)
    let resp = InProcessProbeCore.run(req)
    SubstrateExit.json(resp, rc: Int32(clamping: resp.rc))

case "quarantine-lab":
    guard args.count >= 3 else {
        printUsage()
        exit(2)
    }

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

    let resp = QuarantineLabLocal().write(request)
    SubstrateExit.json(resp, rc: Int32(clamping: resp.rc))

default:
    printUsage()
    exit(2)
}

// MARK: - Local Quarantine Lab implementation (unsandboxed baseline/policy witness)

enum QuarantineLabError: LocalizedError {
    case invalidPathClass(String)
    case invalidFileName(String)
    case invalidPayloadClass(String)
    case invalidOperation(String)
    case missingExistingPath(String)
    case fileNotFound(String)
    case missingAppSupportDir

    var errorDescription: String? {
        switch self {
        case .invalidPathClass(let v):
            return "invalid path_class: \(v) (expected: tmp|app_support)"
        case .invalidFileName(let v):
            return "invalid file_name: \(v) (must be a single path component)"
        case .invalidPayloadClass(let v):
            return "invalid payload_class: \(v) (expected: shell_script|command_file|text|webarchive_like)"
        case .invalidOperation(let v):
            return "invalid operation: \(v) (expected: create_new|open_only|open_existing_save)"
        case .missingExistingPath(let op):
            return "missing existing_path for operation: \(op)"
        case .fileNotFound(let p):
            return "file not found: \(p)"
        case .missingAppSupportDir:
            return "failed to resolve Application Support directory"
        }
    }
}

final class QuarantineLabLocal {
    private struct QuarantineSnapshot {
        var exists: Bool
        var present: Bool
        var raw: String?
        var error: String?
    }

    func write(_ req: QuarantineWriteRequest) -> QuarantineWriteResponse {
        let serviceBundleId = Bundle.main.bundleIdentifier
        let hasAppSandbox = entitlementBool("com.apple.security.app-sandbox")
        let hasUserSelectedExecutable = entitlementBool("com.apple.security.files.user-selected.executable")

        let operation = req.operation ?? "create_new"
        let payloadClass = req.payload_class

        func badRequest(_ err: String) -> QuarantineWriteResponse {
            QuarantineWriteResponse(
                rc: 2,
                normalized_outcome: "bad_request",
                error: err,
                test_case_id: req.test_case_id,
                selection_mechanism: req.selection_mechanism,
                path_class: req.path_class,
                operation: operation,
                payload_class: payloadClass,
                existing_path: req.existing_path,
                has_app_sandbox: hasAppSandbox,
                has_user_selected_executable: hasUserSelectedExecutable,
                service_bundle_id: serviceBundleId,
                layer_attribution: LayerAttribution(
                    quarantine_delta: "not_written",
                    gatekeeper_signal: "not_tested",
                    other: "seatbelt:process_exec_not_attempted"
                )
            )
        }

        func opError(_ outcome: String, _ err: String, existing: QuarantineSnapshot?, targetBefore: QuarantineSnapshot?, targetAfter: QuarantineSnapshot?, targetPath: String?, writtenPath: String?) -> QuarantineWriteResponse {
            let before = targetBefore ?? QuarantineSnapshot(exists: false, present: false, raw: nil, error: nil)
            let after = targetAfter ?? QuarantineSnapshot(exists: false, present: false, raw: nil, error: nil)
            let qDelta = quarantineDelta(before: before, after: after)
            return QuarantineWriteResponse(
                rc: 1,
                normalized_outcome: outcome,
                error: err,
                test_case_id: req.test_case_id,
                selection_mechanism: req.selection_mechanism,
                path_class: req.path_class,
                operation: operation,
                payload_class: payloadClass,
                existing_path: req.existing_path,
                existing_quarantine_present: existing?.present,
                existing_quarantine_raw: existing?.raw,
                existing_quarantine_parsed: parsedQuarantine(existing?.raw),
                target_path: targetPath,
                target_existed_before: targetBefore?.exists,
                target_existed_after: targetAfter?.exists,
                written_path: writtenPath,
                quarantine_xattr_present: targetAfter?.present,
                quarantine_xattr_raw: targetAfter?.raw,
                quarantine_xattr_parsed: parsedQuarantine(targetAfter?.raw),
                quarantine_before_present: targetBefore?.present,
                quarantine_before_raw: targetBefore?.raw,
                quarantine_before_parsed: parsedQuarantine(targetBefore?.raw),
                quarantine_after_present: targetAfter?.present,
                quarantine_after_raw: targetAfter?.raw,
                quarantine_after_parsed: parsedQuarantine(targetAfter?.raw),
                has_app_sandbox: hasAppSandbox,
                has_user_selected_executable: hasUserSelectedExecutable,
                service_bundle_id: serviceBundleId,
                layer_attribution: LayerAttribution(
                    quarantine_delta: qDelta,
                    gatekeeper_signal: "not_tested",
                    other: "seatbelt:process_exec_not_attempted"
                )
            )
        }

        let outputDirNeeded = (operation == "create_new" || operation == "open_existing_save" || (operation == "open_only" && req.existing_path == nil))
        var outputDir: URL?
        if outputDirNeeded {
            do {
                let dir = try resolveOutputDir(req.path_class)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: nil)
                outputDir = dir
            } catch {
                return opError(
                    "mkdir_failed",
                    "failed to create output dir: \(error)",
                    existing: req.existing_path.map { quarantineSnapshot(path: $0) },
                    targetBefore: nil,
                    targetAfter: nil,
                    targetPath: nil,
                    writtenPath: nil
                )
            }
        }

        let fileName: String
        do {
            fileName = try resolveFileName(req.file_name, payloadClass: payloadClass)
        } catch {
            return badRequest(error.localizedDescription)
        }

        let outputURL = outputDir.map { $0.appendingPathComponent(fileName) }

        switch operation {
        case "create_new": fallthrough
        case "open_existing_save": fallthrough
        case "open_only":
            break
        default:
            return badRequest(QuarantineLabError.invalidOperation(operation).localizedDescription)
        }

        if operation == "open_only" {
            let targetPath = req.existing_path ?? outputURL?.path
            guard let targetPath else {
                return badRequest("missing target path")
            }
            guard FileManager.default.fileExists(atPath: targetPath) else {
                return badRequest(QuarantineLabError.fileNotFound(targetPath).localizedDescription)
            }

            let before = quarantineSnapshot(path: targetPath)
            do {
                let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: targetPath))
                _ = try handle.read(upToCount: 4096)
                try handle.close()
            } catch {
                let after = quarantineSnapshot(path: targetPath)
                return opError(
                    "open_failed",
                    "failed to open/read: \(error)",
                    existing: req.existing_path.map { quarantineSnapshot(path: $0) },
                    targetBefore: before,
                    targetAfter: after,
                    targetPath: targetPath,
                    writtenPath: nil
                )
            }
            let after = quarantineSnapshot(path: targetPath)
            let qDelta = quarantineDelta(before: before, after: after)
            return QuarantineWriteResponse(
                rc: 0,
                normalized_outcome: "opened_only",
                test_case_id: req.test_case_id,
                selection_mechanism: req.selection_mechanism,
                path_class: req.path_class,
                operation: operation,
                payload_class: payloadClass,
                existing_path: req.existing_path,
                target_path: targetPath,
                target_existed_before: before.exists,
                target_existed_after: after.exists,
                mode_octal: posixPermissionsOctal(targetPath),
                is_executable: FileManager.default.isExecutableFile(atPath: targetPath),
                quarantine_xattr_present: after.present,
                quarantine_xattr_raw: after.raw,
                quarantine_xattr_parsed: parsedQuarantine(after.raw),
                quarantine_before_present: before.present,
                quarantine_before_raw: before.raw,
                quarantine_before_parsed: parsedQuarantine(before.raw),
                quarantine_after_present: after.present,
                quarantine_after_raw: after.raw,
                quarantine_after_parsed: parsedQuarantine(after.raw),
                has_app_sandbox: hasAppSandbox,
                has_user_selected_executable: hasUserSelectedExecutable,
                service_bundle_id: serviceBundleId,
                layer_attribution: LayerAttribution(
                    quarantine_delta: qDelta,
                    gatekeeper_signal: "not_tested",
                    other: "seatbelt:process_exec_not_attempted"
                )
            )
        }

        if operation == "open_existing_save" {
            guard let sourcePath = req.existing_path else {
                return badRequest(QuarantineLabError.missingExistingPath(operation).localizedDescription)
            }
            guard FileManager.default.fileExists(atPath: sourcePath) else {
                return badRequest(QuarantineLabError.fileNotFound(sourcePath).localizedDescription)
            }
            guard let destURL = outputURL else {
                return badRequest("missing destination path")
            }
            let destPath = destURL.path

            let existing = quarantineSnapshot(path: sourcePath)
            let before = quarantineSnapshot(path: destPath)

            let sourceData: Data
            do {
                sourceData = try Data(contentsOf: URL(fileURLWithPath: sourcePath))
            } catch {
                let after = quarantineSnapshot(path: destPath)
                return opError(
                    "read_failed",
                    "failed to read source: \(error)",
                    existing: existing,
                    targetBefore: before,
                    targetAfter: after,
                    targetPath: destPath,
                    writtenPath: nil
                )
            }

            do {
                try sourceData.write(to: destURL, options: [.atomic])
            } catch {
                let after = quarantineSnapshot(path: destPath)
                return opError(
                    "write_failed",
                    "failed to write destination: \(error)",
                    existing: existing,
                    targetBefore: before,
                    targetAfter: after,
                    targetPath: destPath,
                    writtenPath: nil
                )
            }

            let makeExecutable = req.make_executable ?? FileManager.default.isExecutableFile(atPath: sourcePath)
            if makeExecutable {
                _ = addExecuteBits(destPath)
            }
            let after = quarantineSnapshot(path: destPath)
            let qDelta = quarantineDelta(before: before, after: after)

            return QuarantineWriteResponse(
                rc: 0,
                normalized_outcome: "opened_existing_saved",
                test_case_id: req.test_case_id,
                selection_mechanism: req.selection_mechanism,
                path_class: req.path_class,
                operation: operation,
                payload_class: payloadClass,
                existing_path: req.existing_path,
                existing_quarantine_present: existing.present,
                existing_quarantine_raw: existing.raw,
                existing_quarantine_parsed: parsedQuarantine(existing.raw),
                target_path: destPath,
                target_existed_before: before.exists,
                target_existed_after: after.exists,
                written_path: destPath,
                mode_octal: posixPermissionsOctal(destPath),
                is_executable: FileManager.default.isExecutableFile(atPath: destPath),
                quarantine_xattr_present: after.present,
                quarantine_xattr_raw: after.raw,
                quarantine_xattr_parsed: parsedQuarantine(after.raw),
                quarantine_before_present: before.present,
                quarantine_before_raw: before.raw,
                quarantine_before_parsed: parsedQuarantine(before.raw),
                quarantine_after_present: after.present,
                quarantine_after_raw: after.raw,
                quarantine_after_parsed: parsedQuarantine(after.raw),
                has_app_sandbox: hasAppSandbox,
                has_user_selected_executable: hasUserSelectedExecutable,
                service_bundle_id: serviceBundleId,
                layer_attribution: LayerAttribution(
                    quarantine_delta: qDelta,
                    gatekeeper_signal: "not_tested",
                    other: "seatbelt:process_exec_not_attempted"
                )
            )
        }

        // create_new
        guard let destURL = outputURL else {
            return badRequest("missing destination path")
        }
        let destPath = destURL.path

        let before = quarantineSnapshot(path: destPath)
        let (payloadData, defaultExec): (Data, Bool)
        do {
            (payloadData, defaultExec) = try makePayload(payloadClass: payloadClass, testCaseId: req.test_case_id)
        } catch {
            return badRequest(error.localizedDescription)
        }

        do {
            try payloadData.write(to: destURL, options: [.atomic])
        } catch {
            let after = quarantineSnapshot(path: destPath)
            return opError(
                "write_failed",
                "failed to write artifact: \(error)",
                existing: req.existing_path.map { quarantineSnapshot(path: $0) },
                targetBefore: before,
                targetAfter: after,
                targetPath: destPath,
                writtenPath: destPath
            )
        }

        let makeExecutable = req.make_executable ?? defaultExec
        if makeExecutable {
            _ = addExecuteBits(destPath)
        }
        let after = quarantineSnapshot(path: destPath)
        let qDelta = quarantineDelta(before: before, after: after)

        return QuarantineWriteResponse(
            rc: 0,
            normalized_outcome: "wrote_new",
            test_case_id: req.test_case_id,
            selection_mechanism: req.selection_mechanism,
            path_class: req.path_class,
            operation: operation,
            payload_class: payloadClass,
            existing_path: req.existing_path,
            target_path: destPath,
            target_existed_before: before.exists,
            target_existed_after: after.exists,
            written_path: destPath,
            mode_octal: posixPermissionsOctal(destPath),
            is_executable: FileManager.default.isExecutableFile(atPath: destPath),
            quarantine_xattr_present: after.present,
            quarantine_xattr_raw: after.raw,
            quarantine_xattr_parsed: parsedQuarantine(after.raw),
            quarantine_before_present: before.present,
            quarantine_before_raw: before.raw,
            quarantine_before_parsed: parsedQuarantine(before.raw),
            quarantine_after_present: after.present,
            quarantine_after_raw: after.raw,
            quarantine_after_parsed: parsedQuarantine(after.raw),
            has_app_sandbox: hasAppSandbox,
            has_user_selected_executable: hasUserSelectedExecutable,
            service_bundle_id: serviceBundleId,
            layer_attribution: LayerAttribution(
                quarantine_delta: qDelta,
                gatekeeper_signal: "not_tested",
                other: "seatbelt:process_exec_not_attempted"
            )
        )
    }

    private func resolveOutputDir(_ pathClass: String?) throws -> URL {
        switch pathClass ?? "tmp" {
        case "tmp":
            return FileManager.default.temporaryDirectory.appendingPathComponent("entitlement-jail-quarantine-lab", isDirectory: true)
        case "app_support":
            guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                throw QuarantineLabError.missingAppSupportDir
            }
            return appSupport.appendingPathComponent("entitlement-jail-quarantine-lab", isDirectory: true)
        default:
            throw QuarantineLabError.invalidPathClass(pathClass ?? "")
        }
    }

    private func resolveFileName(_ requested: String?, payloadClass: String) throws -> String {
        let base: String
        if let requested = requested, !requested.isEmpty {
            guard isSinglePathComponent(requested) else {
                throw QuarantineLabError.invalidFileName(requested)
            }
            base = requested
        } else {
            base = "quarantine-lab"
        }

        let ext: String
        switch payloadClass {
        case "shell_script":
            ext = "sh"
        case "command_file":
            ext = "command"
        case "text":
            ext = "txt"
        case "webarchive_like":
            ext = "webarchive"
        default:
            throw QuarantineLabError.invalidPayloadClass(payloadClass)
        }

        if base.contains(".") {
            return base
        }
        return "\(base).\(ext)"
    }

    private func makePayload(payloadClass: String, testCaseId: String?) throws -> (Data, Bool) {
        let idSuffix = testCaseId.map { " # \(String($0.prefix(80)))" } ?? ""
        switch payloadClass {
        case "shell_script":
            return (Data("#!/bin/sh\necho hello\(idSuffix)\n".utf8), true)
        case "command_file":
            return (Data("#!/bin/sh\necho hello\(idSuffix)\n".utf8), true)
        case "text":
            return (Data("hello\(idSuffix)\n".utf8), false)
        case "webarchive_like":
            let s = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>WebMainResource</key>
              <dict>
                <key>WebResourceData</key>
                <data>SGVsbG8=\n</data>
                <key>WebResourceMIMEType</key>
                <string>text/html</string>
              </dict>
            </dict>
            </plist>
            """
            return (Data(s.utf8), false)
        default:
            throw QuarantineLabError.invalidPayloadClass(payloadClass)
        }
    }

    private func quarantineSnapshot(path: String) -> QuarantineSnapshot {
        let exists = FileManager.default.fileExists(atPath: path)
        if !exists {
            return QuarantineSnapshot(exists: false, present: false, raw: nil, error: nil)
        }
        switch readXattr(path: path, name: "com.apple.quarantine") {
        case .present(let v):
            return QuarantineSnapshot(exists: true, present: true, raw: v, error: nil)
        case .absent:
            return QuarantineSnapshot(exists: true, present: false, raw: nil, error: nil)
        case .error(let e):
            return QuarantineSnapshot(exists: true, present: false, raw: nil, error: e)
        }
    }

    private func quarantineDelta(before: QuarantineSnapshot, after: QuarantineSnapshot) -> String {
        if before.error != nil || after.error != nil {
            return "xattr_error"
        }
        if !before.exists && after.exists {
            return after.present ? "added" : "absent"
        }
        if before.present && !after.present {
            return "removed"
        }
        if !before.present && after.present {
            return "added"
        }
        if before.present && after.present {
            return before.raw == after.raw ? "unchanged" : "changed"
        }
        return "absent"
    }

    private func parseQuarantineXattr(raw: String) -> QuarantineXattrParsed {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let fields = trimmed.split(separator: ";", omittingEmptySubsequences: false).map(String.init)

        let flagsRaw = fields.indices.contains(0) ? fields[0] : nil
        let (flagsInt, flagsHex): (Int?, String?) = {
            guard let flagsRaw else { return (nil, nil) }
            let s = flagsRaw.hasPrefix("0x") ? String(flagsRaw.dropFirst(2)) : flagsRaw
            guard let v = Int(s, radix: 16) else { return (nil, nil) }
            return (v, String(format: "0x%X", v))
        }()

        let timestampRaw = fields.indices.contains(1) ? fields[1] : nil
        let (timestampUnix, timestampIso): (Int?, String?) = {
            guard let timestampRaw else { return (nil, nil) }
            let s = timestampRaw.hasPrefix("0x") ? String(timestampRaw.dropFirst(2)) : timestampRaw

            let hasHexLetter = s.range(of: "[A-Fa-f]", options: .regularExpression) != nil
            let preferHex = s.hasPrefix("0x") || hasHexLetter

            let unix: Int?
            if preferHex {
                unix = Int(s, radix: 16)
            } else {
                unix = Int(s)
            }

            guard let unix else { return (nil, nil) }

            let date = Date(timeIntervalSince1970: TimeInterval(unix))
            let fmt = ISO8601DateFormatter()
            return (unix, fmt.string(from: date))
        }()

        let agent = fields.indices.contains(2) ? fields[2] : nil
        let uuid = fields.indices.contains(3) ? fields[3] : nil

        return QuarantineXattrParsed(
            raw: trimmed,
            fields: fields,
            flags_raw: flagsRaw,
            flags_hex: flagsHex,
            flags_int: flagsInt,
            timestamp_raw: timestampRaw,
            timestamp_unix: timestampUnix,
            timestamp_iso8601: timestampIso,
            agent: agent,
            uuid: uuid
        )
    }

    private func parsedQuarantine(_ raw: String?) -> QuarantineXattrParsed? {
        raw.map { parseQuarantineXattr(raw: $0) }
    }

    private enum XattrRead {
        case absent
        case present(String)
        case error(String)
    }

    private func readXattr(path: String, name: String) -> XattrRead {
        let size = path.withCString { pathPtr in
            name.withCString { namePtr in
                getxattr(pathPtr, namePtr, nil, 0, 0, 0)
            }
        }
        if size < 0 {
            if errno == ENOATTR {
                return .absent
            }
            return .error(String(cString: strerror(errno)))
        }
        if size == 0 {
            return .present("")
        }

        var buffer = [UInt8](repeating: 0, count: Int(size))
        let read = buffer.withUnsafeMutableBytes { bytes in
            path.withCString { pathPtr in
                name.withCString { namePtr in
                    getxattr(pathPtr, namePtr, bytes.baseAddress, bytes.count, 0, 0)
                }
            }
        }
        if read < 0 {
            return .error(String(cString: strerror(errno)))
        }
        return .present(String(decoding: buffer, as: UTF8.self))
    }

    private func addExecuteBits(_ path: String) -> Bool {
        var st = stat()
        if lstat(path, &st) != 0 {
            return false
        }
        let newMode = st.st_mode | mode_t(0o111)
        return chmod(path, newMode) == 0
    }

    private func posixPermissionsOctal(_ path: String) -> String? {
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            guard let n = attrs[.posixPermissions] as? NSNumber else {
                return nil
            }
            return String(format: "0o%03o", n.intValue)
        } catch {
            return nil
        }
    }

    private func isSinglePathComponent(_ s: String) -> Bool {
        if s == "." || s == ".." || s.isEmpty {
            return false
        }
        return !s.contains("/") && !s.contains("\\")
    }

    private func entitlementBool(_ key: String) -> Bool {
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
}
