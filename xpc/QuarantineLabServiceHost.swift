import Foundation
import Security
import Darwin

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

final class QuarantineLabService: NSObject, QuarantineLabProtocol {
    func writeArtifact(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let response: QuarantineWriteResponse
        do {
            var decoded = try decodeJSON(QuarantineWriteRequest.self, from: request)
            if decoded.correlation_id?.isEmpty ?? true {
                decoded.correlation_id = UUID().uuidString
            }
            let enableSignposts = decoded.enable_signposts == true
            let correlationId = decoded.correlation_id

            response = PWSignposts.withEnabled(enableSignposts) {
                PWTraceContext.set(
                    correlationId: correlationId,
                    planId: nil,
                    rowId: nil,
                    probeId: "quarantine_lab"
                )
                defer { PWTraceContext.clear() }

                let op = decoded.operation ?? "create_new"
                let span = PWSignpostSpan(
                    category: PWSignposts.categoryQuarantineService,
                    name: "write_artifact",
                    label: "op=\(op) payload=\(decoded.payload_class)",
                    correlationId: correlationId
                )
                defer { span.end() }

                return write(decoded)
            }
        } catch {
            response = QuarantineWriteResponse(
                rc: 2,
                normalized_outcome: "bad_request",
                error: "bad request: \(error)",
                has_app_sandbox: entitlementBool("com.apple.security.app-sandbox"),
                has_user_selected_executable: entitlementBool("com.apple.security.files.user-selected.executable"),
                service_bundle_id: Bundle.main.bundleIdentifier,
                layer_attribution: LayerAttribution(
                    quarantine_delta: "not_written",
                    gatekeeper_signal: "not_tested",
                    other: "seatbelt:process_exec_not_attempted"
                )
            )
        }

        do {
            reply(try encodeJSON(response))
        } catch {
            let fallback = #"{"schema_version":1,"rc":2,"normalized_outcome":"encode_failed"}"#
            reply(Data(fallback.utf8))
        }
    }

    private struct QuarantineSnapshot {
        var exists: Bool
        var present: Bool
        var raw: String?
        var error: String?
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
            let preferHex = hasHexLetter || s.count <= 8

            let hexCandidate = Int(s, radix: 16)
            let decCandidate = Int(s, radix: 10)

            func plausible(_ t: Int) -> Bool {
                // 2000-01-01T00:00:00Z .. 2100-01-01T00:00:00Z
                t >= 946684800 && t <= 4102444800
            }

            let candidates: [Int?] = preferHex ? [hexCandidate, decCandidate] : [decCandidate, hexCandidate]
            guard let unix = candidates.compactMap({ $0 }).first(where: plausible) ?? candidates.compactMap({ $0 }).first else {
                return (nil, nil)
            }

            let date = Date(timeIntervalSince1970: TimeInterval(unix))
            let fmt = ISO8601DateFormatter()
            fmt.formatOptions = [.withInternetDateTime]
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

    private func write(_ req: QuarantineWriteRequest) -> QuarantineWriteResponse {
        let correlationId = req.correlation_id ?? UUID().uuidString
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
                correlation_id: correlationId,
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
                correlation_id: correlationId,
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
                correlation_id: correlationId,
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
                    writtenPath: destPath
                )
            }

            let defaultExec = FileManager.default.isExecutableFile(atPath: sourcePath)
            let makeExecutable = req.make_executable ?? defaultExec
            if makeExecutable {
                _ = addExecuteBits(destPath)
            }

            let after = quarantineSnapshot(path: destPath)
            let qDelta = quarantineDelta(before: before, after: after)

            return QuarantineWriteResponse(
                rc: 0,
                normalized_outcome: "saved_copy",
                test_case_id: req.test_case_id,
                selection_mechanism: req.selection_mechanism,
                correlation_id: correlationId,
                path_class: req.path_class,
                operation: operation,
                payload_class: payloadClass,
                existing_path: sourcePath,
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
            correlation_id: correlationId,
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
            return FileManager.default.temporaryDirectory.appendingPathComponent("policy-witness-quarantine-lab", isDirectory: true)
        case "app_support":
            guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                throw QuarantineLabError.missingAppSupportDir
            }
            return appSupport.appendingPathComponent("policy-witness-quarantine-lab", isDirectory: true)
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
            base = "artifact-\(UUID().uuidString)"
        }

        switch payloadClass {
        case "command_file":
            return base.hasSuffix(".command") ? base : "\(base).command"
        case "shell_script":
            return base.hasSuffix(".sh") ? base : "\(base).sh"
        case "text":
            return base.hasSuffix(".txt") ? base : "\(base).txt"
        case "webarchive_like":
            return base.hasSuffix(".webarchive") ? base : "\(base).webarchive"
        default:
            throw QuarantineLabError.invalidPayloadClass(payloadClass)
        }
    }

    private func makePayload(payloadClass: String, testCaseId: String?) throws -> (Data, Bool) {
        let tag = testCaseId ?? ""
        switch payloadClass {
        case "shell_script", "command_file":
            let script = """
            #!/bin/sh
            echo "policy-witness quarantine-lab \(tag)"
            exit 0
            """
            return (Data(script.utf8), true)
        case "text":
            return (Data("policy-witness quarantine-lab \(tag)\n".utf8), false)
        case "webarchive_like":
            // Minimal plist-ish payload; intended for quarantine/writing experiments, not for correctness as a WebArchive.
            let html = """
            <!DOCTYPE html>
            <html><body>policy-witness quarantine-lab \(tag)</body></html>
            """
            let b64 = Data(html.utf8).base64EncodedString()
            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>WebMainResource</key>
              <dict>
                <key>WebResourceData</key>
                <data>\(b64)</data>
                <key>WebResourceMIMEType</key>
                <string>text/html</string>
                <key>WebResourceTextEncodingName</key>
                <string>utf-8</string>
              </dict>
            </dict>
            </plist>
            """
            return (Data(plist.utf8), false)
        default:
            throw QuarantineLabError.invalidPayloadClass(payloadClass)
        }
    }

    private enum XattrRead {
        case present(String)
        case absent
        case error(String)
    }

    private func readXattr(path: String, name: String) -> XattrRead {
        let size = path.withCString { pathPtr in
            name.withCString { namePtr in
                getxattr(pathPtr, namePtr, nil, 0, 0, 0)
            }
        }
        if size < 0 {
            if errno == ENOATTR || errno == ENODATA {
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

final class QuarantineLabServiceDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: QuarantineLabProtocol.self)
        newConnection.exportedObject = QuarantineLabService()
        newConnection.resume()
        return true
    }
}
