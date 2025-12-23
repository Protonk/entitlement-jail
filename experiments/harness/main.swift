import Foundation
import Darwin

// MARK: - Models (frozen contract)

struct ProbePlan: Codable {
    var plan_id: String
    var probes: [ProbeRow]
}

struct ProbeRow: Codable {
    var probe_id: String
    var row_id: String?
    var inputs: ProbeInputs
    var expected_side_effects: [String]
    var capture_spec: CaptureSpec
}

struct ProbeInputs: Codable {
    var kind: String
    var argv: [String]?
    var payload_class: String?
}

struct CaptureSpec: Codable {
    var capture_sandbox_log: Bool
}

struct EntitlementLattice: Codable {
    var nodes: [EntitlementNode]
}

struct EntitlementNode: Codable {
    var node_id: String
    var policy_profile: String
    var xpc_probe_service_bundle_id: String
    var xpc_quarantine_service_bundle_id: String?
}

struct ErrnoOrError: Codable {
    var errno: Int?
    var error: String?
}

struct LayerAttributionResult: Codable {
    var seatbelt_deny_op: String?
    var service_refusal: String?
    var quarantine_delta: String?
    var world_shape_change: String?
}

struct SandboxLogCaptureAttempt: Codable {
    var start_iso8601: String
    var end_iso8601: String
    var predicate: String
    var term: String
    var observed_deny: Bool
    var deny_op: String?
    var observation: String
    var excerpt_ref: String?
}

struct SandboxLogCapture: Codable {
    var attempts: [SandboxLogCaptureAttempt]
}

struct PathValue: Codable {
    var raw: String
    var realpath: String?
    var path_class: String
    var realpath_class: String?
}

struct PathEvidence: Codable {
    var effective_path_class: String?
    var paths: [String: PathValue]
}

struct ProbeResult: Codable {
    var rc: Int
    var normalized_outcome: String
    var errno_or_error: ErrnoOrError
    var stdout_ref: String
    var stderr_ref: String
    var layer_attribution: LayerAttributionResult
    var sandbox_log_excerpt_ref: String?
    var sandbox_log_capture: SandboxLogCapture?
    var path_evidence: PathEvidence?
}

struct ResultDelta: Codable {
    var changed_fields: [String]
}

struct ParityResult: Codable {
    var parity_class: String
    var reason: String?
    var baseline_to_policy: ResultDelta
    var baseline_to_entitlement: ResultDelta
}

struct TriRunRow: Codable {
    var row_id: String
    var probe_id: String
    var inputs: ProbeInputs
    var expected_side_effects: [String]
    var capture_spec: CaptureSpec
    var node_id: String

    var baseline: ProbeResult
    var policy: ProbeResult
    var entitlement: ProbeResult

    var baseline_cmd_argv: [String]
    var policy_cmd_argv: [String]
    var entitlement_cmd_argv: [String]?

    var policy_profile_ref: String
    var entitlement_service_bundle_id: String?

    var parity: ParityResult
}

struct Atlas: Codable {
    var plan_id: String
    var created_at_iso8601: String
    var nodes: [EntitlementNode]
    var rows: [TriRunRow]
}

// MARK: - CLI

private func printUsage() {
    let exe = (CommandLine.arguments.first as NSString?)?.lastPathComponent ?? "ej-harness"
    fputs(
        """
        usage:
          \(exe) run [options]

        options:
          --plan <path>            (default: experiments/plans/tri-run-default.json)
          --nodes <path>           (default: experiments/nodes/entitlement-lattice.json)
          --out-dir <dir>          (default: experiments/out/<plan-id>-<timestamp>)
          --substrate <path>       (default: experiments/bin/witness-substrate)
          --entitlement-jail <path> (default: EntitlementJail.app/Contents/MacOS/entitlement-jail)

        notes:
          - Baseline/policy run the substrate (unsandboxed vs `sandbox-exec`).
          - Entitlement runs use `entitlement-jail run-xpc` / `quarantine-lab` against XPC targets.
          - Rows are never dropped: missing services become explicit service_refusal results.
        """,
        stderr
    )
}

struct Args {
    private var args: [String]
    init(_ args: [String]) { self.args = args }

    func value(_ flag: String) -> String? {
        guard let idx = args.firstIndex(of: flag) else { return nil }
        let vIdx = idx + 1
        guard vIdx < args.count else { return nil }
        return args[vIdx]
    }
}

let argv = CommandLine.arguments
guard argv.count >= 2 else {
    printUsage()
    exit(2)
}

guard argv[1] == "run" else {
    printUsage()
    exit(2)
}

let args = Args(Array(argv.dropFirst(2)))

let planPath = args.value("--plan") ?? "experiments/plans/tri-run-default.json"
let nodesPath = args.value("--nodes") ?? "experiments/nodes/entitlement-lattice.json"
let substratePath = args.value("--substrate") ?? "experiments/bin/witness-substrate"
let entitlementJailPath = args.value("--entitlement-jail") ?? "EntitlementJail.app/Contents/MacOS/entitlement-jail"

let plan: ProbePlan = try decodeFileJSON(planPath, as: ProbePlan.self)
let lattice: EntitlementLattice = try decodeFileJSON(nodesPath, as: EntitlementLattice.self)

let outDir: URL = {
    if let p = args.value("--out-dir") {
        return URL(fileURLWithPath: p, isDirectory: true)
    }
    let ts = timestampForPathComponent(Date())
    return URL(fileURLWithPath: "experiments/out/\(plan.plan_id)-\(ts)", isDirectory: true)
}()

try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true, attributes: nil)

let needsTcpServer: Bool = plan.probes.contains { probe in
    guard probe.inputs.kind == "probe", let argv = probe.inputs.argv else {
        return false
    }
    // Only start the calibration server when a probe requests an ephemeral port via `--port 0`.
    for (idx, a) in argv.enumerated() {
        if a == "--port", idx + 1 < argv.count, argv[idx + 1] == "0" {
            return true
        }
    }
    return false
}

let tcpPort: Int
let server: LocalTCPServer?
if needsTcpServer {
    let s = try LocalTCPServer()
    server = s
    tcpPort = s.port
} else {
    server = nil
    tcpPort = 0
}
defer { server?.stop() }

let policyHomeParam = "HOME=\(FileManager.default.homeDirectoryForCurrentUser.path)"

let nodeArtifactsDir = outDir.appendingPathComponent("nodes", isDirectory: true)
try FileManager.default.createDirectory(at: nodeArtifactsDir, withIntermediateDirectories: true, attributes: nil)

var policyProfileRefs: [String: String] = [:]
var policyProfileCopyURLs: [String: URL] = [:]
for node in lattice.nodes {
    let src = resolvePath(node.policy_profile)
    let nodeDir = nodeArtifactsDir.appendingPathComponent(safePathComponent(node.node_id), isDirectory: true)
    try FileManager.default.createDirectory(at: nodeDir, withIntermediateDirectories: true, attributes: nil)
    let dst = nodeDir.appendingPathComponent("policy-profile.sb")
    let ref = try materializeFileCopy(src: src, dst: dst, outDir: outDir)
    policyProfileRefs[node.node_id] = ref
    policyProfileCopyURLs[node.node_id] = dst
}

var rows: [TriRunRow] = []

for probe in plan.probes {
    let rowId = (probe.row_id?.isEmpty == false) ? probe.row_id! : probe.probe_id
    let baselineCmd = try makeBaselineCommand(
        substratePath: substratePath,
        probe: probe,
        tcpPort: tcpPort
    )

    let baselineDir = outDir.appendingPathComponent(safePathComponent(rowId)).appendingPathComponent("baseline", isDirectory: true)
    let baselineResult = try runAndNormalize(
        label: "baseline",
        outDir: outDir,
        runDir: baselineDir,
        cmd: baselineCmd,
        captureSandboxLog: probe.capture_spec.capture_sandbox_log,
        sandboxLogHint: baselineCmd.logHint
    )

    for node in lattice.nodes {
        let policyProfileRef = policyProfileRefs[node.node_id] ?? resolvePath(node.policy_profile).path
        let policyProfilePathForExec = (policyProfileCopyURLs[node.node_id] ?? resolvePath(node.policy_profile)).path
        let policyCmd = CommandSpec(
            argv: ["/usr/bin/sandbox-exec", "-D", policyHomeParam, "-f", policyProfilePathForExec] + baselineCmd.argv,
            logHint: baselineCmd.logHint
        )

        let entitlementCmd = try makeEntitlementCommand(
            entitlementJailPath: entitlementJailPath,
            probe: probe,
            node: node,
            tcpPort: tcpPort,
            planId: plan.plan_id,
            rowId: rowId
        )

        let nodeDir = outDir
            .appendingPathComponent(safePathComponent(rowId))
            .appendingPathComponent(safePathComponent(node.node_id), isDirectory: true)

        let policyDir = nodeDir.appendingPathComponent("policy", isDirectory: true)
        let entitlementDir = nodeDir.appendingPathComponent("entitlement", isDirectory: true)

        let policyResult = try runAndNormalize(
            label: "policy",
            outDir: outDir,
            runDir: policyDir,
            cmd: policyCmd,
            captureSandboxLog: probe.capture_spec.capture_sandbox_log,
            sandboxLogHint: policyCmd.logHint
        )

        let entitlementResult: ProbeResult
        if let entitlementCmd {
            entitlementResult = try runAndNormalize(
                label: "entitlement",
                outDir: outDir,
                runDir: entitlementDir,
                cmd: entitlementCmd,
                captureSandboxLog: probe.capture_spec.capture_sandbox_log,
                sandboxLogHint: entitlementCmd.logHint
            )
        } else {
            try FileManager.default.createDirectory(at: entitlementDir, withIntermediateDirectories: true, attributes: nil)
            entitlementResult = syntheticServiceMissingResult(
                outDir: outDir,
                runDir: entitlementDir,
                serviceKind: probe.inputs.kind,
                nodeId: node.node_id
            )
        }

        let parity = computeParity(baseline: baselineResult, policy: policyResult, entitlement: entitlementResult)

        rows.append(
            TriRunRow(
                row_id: rowId,
                probe_id: probe.probe_id,
                inputs: probe.inputs,
                expected_side_effects: probe.expected_side_effects,
                capture_spec: probe.capture_spec,
                node_id: node.node_id,
                baseline: baselineResult,
                policy: policyResult,
                entitlement: entitlementResult,
                baseline_cmd_argv: baselineCmd.argv,
                policy_cmd_argv: policyCmd.argv,
                entitlement_cmd_argv: entitlementCmd?.argv,
                policy_profile_ref: policyProfileRef,
                entitlement_service_bundle_id: entitlementCmd?.serviceBundleId,
                parity: parity
            )
        )
    }
}

let atlas = Atlas(
    plan_id: plan.plan_id,
    created_at_iso8601: ISO8601DateFormatter().string(from: Date()),
    nodes: lattice.nodes,
    rows: rows
)

let atlasURL = outDir.appendingPathComponent("atlas.json")
try writeJSON(atlas, to: atlasURL)

print(atlasURL.path)

// MARK: - Command planning

struct CommandSpec {
    var argv: [String]
    var logHint: SandboxLogHint?
    var serviceBundleId: String? = nil
}

struct SandboxLogHint {
    var term: String
}

private func makeBaselineCommand(substratePath: String, probe: ProbeRow, tcpPort: Int) throws -> CommandSpec {
    let kind = probe.inputs.kind
    let argv = probe.inputs.argv ?? []

    switch kind {
    case "probe":
        let adjusted = substituteEphemeralPort(argv: argv, port: tcpPort)
        return CommandSpec(argv: [resolvePath(substratePath).path, "probe", probe.probe_id] + adjusted, logHint: SandboxLogHint(term: "witness-substrate"))
    case "quarantine-lab":
        guard let payloadClass = probe.inputs.payload_class else {
            throw HarnessError("probe.inputs.payload_class is required for kind=quarantine-lab")
        }
        return CommandSpec(argv: [resolvePath(substratePath).path, "quarantine-lab", payloadClass] + argv, logHint: SandboxLogHint(term: "witness-substrate"))
    default:
        throw HarnessError("unknown inputs.kind: \(kind)")
    }
}

private func makeEntitlementCommand(
    entitlementJailPath: String,
    probe: ProbeRow,
    node: EntitlementNode,
    tcpPort: Int,
    planId: String,
    rowId: String
) throws -> CommandSpec? {
    let ej = resolvePath(entitlementJailPath).path
    let kind = probe.inputs.kind
    let argv = probe.inputs.argv ?? []

    switch kind {
    case "probe":
        let adjusted = substituteEphemeralPort(argv: argv, port: tcpPort)
        let svc = node.xpc_probe_service_bundle_id
        let hint = SandboxLogHint(term: xpcExecutableName(fromBundleId: svc) ?? svc)
        return CommandSpec(
            argv: [ej, "run-xpc", "--plan-id", planId, "--row-id", rowId, svc, probe.probe_id] + adjusted,
            logHint: hint,
            serviceBundleId: svc
        )
    case "quarantine-lab":
        guard let payloadClass = probe.inputs.payload_class else {
            throw HarnessError("probe.inputs.payload_class is required for kind=quarantine-lab")
        }
        guard let svc = node.xpc_quarantine_service_bundle_id else {
            return nil
        }
        let hint = SandboxLogHint(term: xpcExecutableName(fromBundleId: svc) ?? svc)
        return CommandSpec(
            argv: [ej, "quarantine-lab", svc, payloadClass] + argv,
            logHint: hint,
            serviceBundleId: svc
        )
    default:
        throw HarnessError("unknown inputs.kind: \(kind)")
    }
}

private func substituteEphemeralPort(argv: [String], port: Int) -> [String] {
    guard let idx = argv.firstIndex(of: "--port"), idx + 1 < argv.count, argv[idx + 1] == "0" else {
        return argv
    }
    var out = argv
    out[idx + 1] = "\(port)"
    return out
}

private func xpcExecutableName(fromBundleId bundleId: String) -> String? {
    bundleId.split(separator: ".").last.map(String.init)
}

// MARK: - Execution + normalization

private func runAndNormalize(
    label: String,
    outDir: URL,
    runDir: URL,
    cmd: CommandSpec,
    captureSandboxLog: Bool,
    sandboxLogHint: SandboxLogHint?
) throws -> ProbeResult {
    try FileManager.default.createDirectory(at: runDir, withIntermediateDirectories: true, attributes: nil)

    let stdoutURL = runDir.appendingPathComponent("stdout.txt")
    let stderrURL = runDir.appendingPathComponent("stderr.txt")

    let run = runProcess(cmd.argv)
    try writeData(run.stdout, to: stdoutURL)
    try writeData(run.stderr, to: stderrURL)

    var sandboxLogRef: String?
    var denyOp: String?

    let stdoutText = String(data: run.stdout, encoding: .utf8) ?? ""

    let parsed: ParsedWitnessOutput? = parseWitnessOutput(stdoutText)

    let stderrText = String(data: run.stderr, encoding: .utf8) ?? ""
    let spawnFailed = stderrText.hasPrefix("spawn failed:")

    let normalizedOutcome: String
    if let parsed {
        normalizedOutcome = parsed.normalizedOutcome
    } else if spawnFailed {
        normalizedOutcome = "spawn_failed"
    } else if run.rc == 0 {
        normalizedOutcome = "ok_no_json"
    } else {
        normalizedOutcome = "witness_failed"
    }

    let errnoVal: Int?
    let errStr: String?
    switch parsed {
    case .probe(let r):
        errnoVal = r.errno
        errStr = r.error ?? (r.stderr.isEmpty ? nil : r.stderr)
    case .quarantine(let r):
        errnoVal = nil
        errStr = r.error
    case .none:
        errnoVal = nil
        errStr = "missing_or_unparseable_json"
    }

    let isPermissionShaped = normalizedOutcome == "permission_error" || errnoVal.map { $0 == Int(EPERM) || $0 == Int(EACCES) } ?? false

    let pathEvidence = extractPathEvidence(parsed)

    var logCapture: SandboxLogCapture?
    if let hint = sandboxLogHint {
        let shouldCapture = captureSandboxLog || (label == "entitlement" && isPermissionShaped)
        if shouldCapture {
            let term = sandboxLogTerm(hint: hint.term, parsed: parsed)
            var attempts: [SandboxLogCaptureAttempt] = []

            let predicate1 = sandboxPredicateLoose(term: term)
            let attempt1 = sandboxLogAttempt(
                outDir: outDir,
                runDir: runDir,
                fileName: "sandbox-log.txt",
                start: run.started.addingTimeInterval(-1),
                end: run.ended.addingTimeInterval(1),
                term: term,
                predicate: predicate1
            )
            attempts.append(attempt1)

            denyOp = attempt1.deny_op
            sandboxLogRef = attempt1.excerpt_ref

            if label == "entitlement", isPermissionShaped, denyOp == nil {
                let predicate2 = sandboxPredicateStrict(term: term)
                let attempt2 = sandboxLogAttempt(
                    outDir: outDir,
                    runDir: runDir,
                    fileName: "sandbox-log-retry.txt",
                    start: run.started.addingTimeInterval(-8),
                    end: run.ended.addingTimeInterval(8),
                    term: term,
                    predicate: predicate2
                )
                attempts.append(attempt2)

                if attempt2.deny_op != nil {
                    denyOp = attempt2.deny_op
                    sandboxLogRef = attempt2.excerpt_ref
                }
            }

            logCapture = SandboxLogCapture(attempts: attempts)
        }
    }

    let worldShape = parsedWorldShapeChange(parsed)
    let quarantineDelta = parsedQuarantineDelta(parsed)
    let serviceRefusal = inferredServiceRefusal(label: label, stderr: stderrText, parsed: parsed)

    let seatbeltDenyOp = denyOp

    return ProbeResult(
        rc: run.rc,
        normalized_outcome: normalizedOutcome,
        errno_or_error: ErrnoOrError(errno: errnoVal, error: errStr),
        stdout_ref: rel(outDir, stdoutURL),
        stderr_ref: rel(outDir, stderrURL),
        layer_attribution: LayerAttributionResult(
            seatbelt_deny_op: seatbeltDenyOp,
            service_refusal: serviceRefusal,
            quarantine_delta: quarantineDelta,
            world_shape_change: worldShape
        ),
        sandbox_log_excerpt_ref: sandboxLogRef,
        sandbox_log_capture: logCapture,
        path_evidence: pathEvidence
    )
}

private enum ParsedWitnessOutput {
    case probe(RunProbeResponse)
    case quarantine(QuarantineWriteResponse)

    var normalizedOutcome: String {
        switch self {
        case .probe(let r): r.normalized_outcome
        case .quarantine(let r): r.normalized_outcome
        }
    }
}

private func parseWitnessOutput(_ stdout: String) -> ParsedWitnessOutput? {
    let data = Data(stdout.utf8)
    if let probe = try? decodeJSON(RunProbeResponse.self, from: data) {
        return .probe(probe)
    }
    if let q = try? decodeJSON(QuarantineWriteResponse.self, from: data) {
        return .quarantine(q)
    }
    return nil
}

private func sandboxLogTerm(hint: String, parsed: ParsedWitnessOutput?) -> String {
    guard let pid = parsedPid(parsed) else {
        return hint
    }
    return "\(hint)(\(pid))"
}

private func parsedPid(_ parsed: ParsedWitnessOutput?) -> String? {
    switch parsed {
    case .probe(let r):
        let details = r.details ?? [:]
        if let pid = details["probe_pid"], !pid.isEmpty {
            return pid
        }
        if let pid = details["service_pid"], !pid.isEmpty {
            return pid
        }
        if let pid = details["pid"], !pid.isEmpty {
            return pid
        }
        return nil
    case .quarantine:
        return nil
    case .none:
        return nil
    }
}

private func extractPathEvidence(_ parsed: ParsedWitnessOutput?) -> PathEvidence? {
    var paths: [String: PathValue] = [:]
    var effectiveKey: String?

    func add(_ key: String, _ path: String?) {
        guard let path, !path.isEmpty else { return }
        guard path.hasPrefix("/") else { return }
        paths[key] = makePathValue(path)
    }

    switch parsed {
    case .probe(let r):
        let details = r.details ?? [:]
        add("file_path", details["file_path"])
        add("target_dir", details["target_dir"])
        add("downloads_dir", details["downloads_dir"])
        add("home_dir", details["home_dir"])
        add("tmp_dir", details["tmp_dir"])
        add("cwd", details["cwd"])

        if let v = paths["file_path"], v.realpath != nil { effectiveKey = "file_path" }
        else if paths["target_dir"] != nil { effectiveKey = "target_dir" }
        else if paths["downloads_dir"] != nil { effectiveKey = "downloads_dir" }
        else if paths["home_dir"] != nil { effectiveKey = "home_dir" }
        else if paths["tmp_dir"] != nil { effectiveKey = "tmp_dir" }

    case .quarantine(let r):
        add("existing_path", r.existing_path)
        add("target_path", r.target_path)
        add("written_path", r.written_path)
        if paths["target_path"] != nil { effectiveKey = "target_path" }
        else if paths["written_path"] != nil { effectiveKey = "written_path" }
        else if paths["existing_path"] != nil { effectiveKey = "existing_path" }

    case .none:
        break
    }

    if paths.isEmpty {
        return nil
    }

    let effective: String? = effectiveKey.flatMap { key in
        guard let v = paths[key] else { return nil }
        return v.realpath_class ?? v.path_class
    }

    return PathEvidence(effective_path_class: effective, paths: paths)
}

private func makePathValue(_ raw: String) -> PathValue {
    let real = realpathString(raw)
    return PathValue(
        raw: raw,
        realpath: real,
        path_class: classifyPath(raw),
        realpath_class: real.map(classifyPath)
    )
}

private func classifyPath(_ path: String) -> String {
    if path.contains("/Library/Containers/") {
        return "container_path"
    }
    if path.hasPrefix("/var/folders/") || path.hasPrefix("/private/var/folders/") || path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") {
        return "synthesized_temp_path"
    }
    if path.hasPrefix("/Users/") {
        return "host_path"
    }
    return "other_path"
}

private func realpathString(_ path: String) -> String? {
    var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
    return path.withCString { cstr in
        guard realpath(cstr, &buf) != nil else {
            return nil
        }
        return String(cString: buf)
    }
}

private func parsedWorldShapeChange(_ parsed: ParsedWitnessOutput?) -> String? {
    switch parsed {
    case .probe(let r):
        if let v = r.layer_attribution?.world_shape_change, !v.isEmpty {
            return v
        }
        if let home = r.details?["home_dir"], home.contains("/Library/Containers/") {
            return "home_containerized"
        }
        return nil
    case .quarantine(let r):
        if let path = r.target_path, path.contains("/Library/Containers/") {
            return "containerized_path"
        }
        return nil
    case .none:
        return nil
    }
}

private func parsedQuarantineDelta(_ parsed: ParsedWitnessOutput?) -> String? {
    guard case .quarantine(let r) = parsed else {
        return nil
    }
    if let v = r.layer_attribution?.quarantine_delta, !v.isEmpty {
        return v
    }
    guard let before = r.quarantine_before_present, let after = r.quarantine_after_present else {
        return nil
    }
    if !before && after { return "added" }
    if before && !after { return "removed" }
    if before && after {
        return r.quarantine_before_raw == r.quarantine_after_raw ? "unchanged" : "changed"
    }
    return "absent"
}

private func parsedServiceRefusal(_ parsed: ParsedWitnessOutput?) -> String? {
    switch parsed {
    case .probe(let r):
        if let v = r.layer_attribution?.service_refusal, !v.isEmpty {
            return v
        }
        return nil
    case .quarantine(let r):
        if let v = r.layer_attribution?.service_refusal, !v.isEmpty {
            return v
        }
        return nil
    case .none:
        return nil
    }
}

private func inferredServiceRefusal(label: String, stderr: String, parsed: ParsedWitnessOutput?) -> String? {
    if label != "entitlement" {
        return nil
    }
    if let parsedRefusal = parsedServiceRefusal(parsed) {
        return parsedRefusal
    }
    if parsed != nil { return nil }
    let s = stderr.lowercased()
    if s.contains("xpc connection error") {
        return "xpc_connection_error"
    }
    if s.contains("failed to create xpc proxy") {
        return "xpc_proxy_failed"
    }
    if s.contains("note: xpc mode requires") {
        return "xpc_helper_missing"
    }
    if !stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        return "unknown_service_refusal"
    }
    return nil
}

private func syntheticServiceMissingResult(outDir: URL, runDir: URL, serviceKind: String, nodeId: String) -> ProbeResult {
    let stdoutURL = runDir.appendingPathComponent("stdout.txt")
    let stderrURL = runDir.appendingPathComponent("stderr.txt")

    let msg = "missing xpc service mapping for kind=\(serviceKind) node=\(nodeId)\n"
    try? writeString("", to: stdoutURL)
    try? writeString(msg, to: stderrURL)

    return ProbeResult(
        rc: 1,
        normalized_outcome: "service_missing",
        errno_or_error: ErrnoOrError(errno: nil, error: msg.trimmingCharacters(in: .whitespacesAndNewlines)),
        stdout_ref: rel(outDir, stdoutURL),
        stderr_ref: rel(outDir, stderrURL),
        layer_attribution: LayerAttributionResult(
            seatbelt_deny_op: nil,
            service_refusal: "service_missing",
            quarantine_delta: nil,
            world_shape_change: nil
        ),
        sandbox_log_excerpt_ref: nil,
        sandbox_log_capture: nil,
        path_evidence: nil
    )
}

private func computeParity(baseline: ProbeResult, policy: ProbeResult, entitlement: ProbeResult) -> ParityResult {
    let baselineToPolicy = ResultDelta(changed_fields: deltaFields(from: baseline, to: policy))
    let baselineToEntitlement = ResultDelta(changed_fields: deltaFields(from: baseline, to: entitlement))

    let (parityClass, reason) = parityClassAndReason(policy: policy, entitlement: entitlement)

    return ParityResult(
        parity_class: parityClass,
        reason: reason,
        baseline_to_policy: baselineToPolicy,
        baseline_to_entitlement: baselineToEntitlement
    )
}

private func parityClassAndReason(policy: ProbeResult, entitlement: ProbeResult) -> (String, String?) {
    if ["spawn_failed", "witness_failed"].contains(policy.normalized_outcome) || ["spawn_failed", "witness_failed"].contains(entitlement.normalized_outcome) {
        return ("incomparable", "witness_failed_or_unparseable_output")
    }
    if policy.layer_attribution.quarantine_delta != nil || entitlement.layer_attribution.quarantine_delta != nil {
        if policy.layer_attribution.quarantine_delta != entitlement.layer_attribution.quarantine_delta {
            return ("mismatch_quarantine", "quarantine_delta differs")
        }
    }

    let policyPathClass = policy.path_evidence?.effective_path_class
    let entitlementPathClass = entitlement.path_evidence?.effective_path_class
    let pathClassDiffers = policyPathClass != nil && entitlementPathClass != nil && policyPathClass != entitlementPathClass

    func confounded(_ reason: String) -> (String, String?) {
        guard pathClassDiffers else {
            return ("mismatch_service_mediated", reason)
        }
        return ("path_class_confound", "\(reason); effective_path_class policy=\(policyPathClass!) entitlement=\(entitlementPathClass!)")
    }

    if policy.layer_attribution.seatbelt_deny_op != entitlement.layer_attribution.seatbelt_deny_op {
        if policy.layer_attribution.seatbelt_deny_op != nil || entitlement.layer_attribution.seatbelt_deny_op != nil {
            if pathClassDiffers {
                return ("path_class_confound", "seatbelt_deny_op differs; effective_path_class policy=\(policyPathClass!) entitlement=\(entitlementPathClass!)")
            }
            return ("mismatch_seatbelt", "seatbelt_deny_op differs")
        }
    }
    if policy.layer_attribution.service_refusal != entitlement.layer_attribution.service_refusal {
        if policy.layer_attribution.service_refusal != nil || entitlement.layer_attribution.service_refusal != nil {
            return confounded("service_refusal differs")
        }
    }
    if policy.layer_attribution.world_shape_change != entitlement.layer_attribution.world_shape_change {
        if policy.layer_attribution.world_shape_change != nil || entitlement.layer_attribution.world_shape_change != nil {
            return ("mismatch_world_shape", "world_shape_change differs")
        }
    }
    if policy.normalized_outcome != entitlement.normalized_outcome {
        return confounded("normalized_outcome differs")
    }
    if policy.errno_or_error.errno != entitlement.errno_or_error.errno {
        return confounded("errno differs")
    }
    return ("match", nil)
}

private func deltaFields(from a: ProbeResult, to b: ProbeResult) -> [String] {
    var out: [String] = []
    if a.normalized_outcome != b.normalized_outcome { out.append("normalized_outcome") }
    if a.errno_or_error.errno != b.errno_or_error.errno { out.append("errno") }
    if a.layer_attribution.seatbelt_deny_op != b.layer_attribution.seatbelt_deny_op { out.append("seatbelt_deny_op") }
    if a.layer_attribution.service_refusal != b.layer_attribution.service_refusal { out.append("service_refusal") }
    if a.layer_attribution.quarantine_delta != b.layer_attribution.quarantine_delta { out.append("quarantine_delta") }
    if a.layer_attribution.world_shape_change != b.layer_attribution.world_shape_change { out.append("world_shape_change") }
    if a.path_evidence?.effective_path_class != b.path_evidence?.effective_path_class { out.append("effective_path_class") }
    return out
}

// MARK: - Process execution

struct ProcessRun {
    var rc: Int
    var stdout: Data
    var stderr: Data
    var started: Date
    var ended: Date
}

private func runProcess(_ argv: [String]) -> ProcessRun {
    let started = Date()

    let process = Process()
    process.executableURL = URL(fileURLWithPath: argv[0])
    process.arguments = Array(argv.dropFirst())

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    do {
        try process.run()
    } catch {
        let ended = Date()
        return ProcessRun(
            rc: 127,
            stdout: Data(),
            stderr: Data("spawn failed: \(error)\n".utf8),
            started: started,
            ended: ended
        )
    }

    process.waitUntilExit()
    let ended = Date()

    let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
    let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

    return ProcessRun(
        rc: Int(process.terminationStatus),
        stdout: stdoutData,
        stderr: stderrData,
        started: started,
        ended: ended
    )
}

// MARK: - Sandbox log capture (best-effort)

private func sandboxPredicateLoose(term: String) -> String {
    let termEscaped = term.replacingOccurrences(of: "\"", with: "\\\"")
    return #"(eventMessage CONTAINS[c] "\#(termEscaped)") AND (eventMessage CONTAINS[c] "deny")"#
}

private func sandboxPredicateStrict(term: String) -> String {
    let termEscaped = term.replacingOccurrences(of: "\"", with: "\\\"")
    return #"(eventMessage CONTAINS[c] "Sandbox: \#(termEscaped)") AND (eventMessage CONTAINS[c] "deny")"#
}

private func sandboxLogAttempt(
    outDir: URL,
    runDir: URL,
    fileName: String,
    start: Date,
    end: Date,
    term: String,
    predicate: String
) -> SandboxLogCaptureAttempt {
    let excerpt = fetchSandboxLogExcerpt(start: start, end: end, predicate: predicate)
    let logURL = runDir.appendingPathComponent(fileName)
    try? writeString(excerpt, to: logURL)

    let denyOp = firstDenyOp(in: excerpt)
    let observation = denyOp == nil ? "no_sandbox_deny_observed_in_window" : "deny_observed"

    let iso = ISO8601DateFormatter()
    return SandboxLogCaptureAttempt(
        start_iso8601: iso.string(from: start),
        end_iso8601: iso.string(from: end),
        predicate: predicate,
        term: term,
        observed_deny: denyOp != nil,
        deny_op: denyOp,
        observation: observation,
        excerpt_ref: rel(outDir, logURL)
    )
}

private func fetchSandboxLogExcerpt(start: Date, end: Date, predicate: String) -> String {
    let df = DateFormatter()
    df.dateFormat = "yyyy-MM-dd HH:mm:ss"
    df.timeZone = TimeZone.current

    let startStr = df.string(from: start)
    let endStr = df.string(from: end)

    let cmd = [
        "/usr/bin/log",
        "show",
        "--style",
        "syslog",
        "--start",
        startStr,
        "--end",
        endStr,
        "--predicate",
        predicate,
    ]

    let run = runProcess(cmd)
    return String(data: run.stdout, encoding: .utf8) ?? ""
}

private func firstDenyOp(in log: String) -> String? {
    let patterns = [
        #"deny\(\d+\)\s+([^\s]+)"#,
        #"deny\s+([^\s]+)"#,
    ]
    for pat in patterns {
        if let re = try? NSRegularExpression(pattern: pat) {
            let range = NSRange(log.startIndex..<log.endIndex, in: log)
            if let match = re.firstMatch(in: log, range: range), match.numberOfRanges >= 2 {
                if let r = Range(match.range(at: 1), in: log) {
                    return String(log[r])
                }
            }
        }
    }
    return nil
}

// MARK: - Local TCP server (harness-owned calibration)

final class LocalTCPServer {
    private let fd: Int32
    let port: Int
    private let queue = DispatchQueue(label: "ej-harness.local-tcp-server")
    private var running = true

    init() throws {
        let socketFD = socket(AF_INET, SOCK_STREAM, 0)
        if socketFD < 0 {
            throw HarnessError("socket() failed")
        }

        var opt: Int32 = 1
        _ = setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout.size(ofValue: opt)))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(0).bigEndian
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.stride)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        var addrCopy = addr
        let bindResult: Int32 = withUnsafePointer(to: &addrCopy) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.bind(socketFD, saPtr, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }
        if bindResult != 0 {
            throw HarnessError("bind() failed: \(String(cString: strerror(errno)))")
        }

        if listen(socketFD, 16) != 0 {
            throw HarnessError("listen() failed: \(String(cString: strerror(errno)))")
        }

        var actual = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.stride)
        let getsocknameResult: Int32 = withUnsafeMutablePointer(to: &actual) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.getsockname(socketFD, saPtr, &len)
            }
        }
        if getsocknameResult != 0 {
            throw HarnessError("getsockname() failed: \(String(cString: strerror(errno)))")
        }

        self.fd = socketFD
        self.port = Int(UInt16(bigEndian: actual.sin_port))

        queue.async {
            self.acceptLoop()
        }
    }

    func stop() {
        running = false
        _ = shutdown(fd, SHUT_RDWR)
        close(fd)
    }

    private func acceptLoop() {
        while running {
            var clientAddr = sockaddr()
            var len: socklen_t = socklen_t(MemoryLayout<sockaddr>.stride)
            let client = accept(fd, &clientAddr, &len)
            if client < 0 {
                break
            }
            close(client)
        }
    }
}

// MARK: - Utilities

struct HarnessError: Error, CustomStringConvertible {
    var description: String
    init(_ description: String) { self.description = description }
}

private func decodeFileJSON<T: Decodable>(_ path: String, as type: T.Type) throws -> T {
    let url = URL(fileURLWithPath: path)
    let data = try Data(contentsOf: url)
    return try decodeJSON(type, from: data)
}

private func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
    let data = try encodeJSON(value)
    try data.write(to: url, options: [.atomic])
}

private func writeData(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: [.atomic])
}

private func writeString(_ s: String, to url: URL) throws {
    try Data(s.utf8).write(to: url, options: [.atomic])
}

private func resolvePath(_ p: String) -> URL {
    URL(fileURLWithPath: p)
}

private func rel(_ root: URL, _ path: URL) -> String {
    let rootPath = root.standardizedFileURL.path
    let fullPath = path.standardizedFileURL.path
    if fullPath.hasPrefix(rootPath + "/") {
        return String(fullPath.dropFirst(rootPath.count + 1))
    }
    return fullPath
}

private func safePathComponent(_ s: String) -> String {
    s.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "\\", with: "_")
}

private func timestampForPathComponent(_ d: Date) -> String {
    let df = DateFormatter()
    df.dateFormat = "yyyyMMdd-HHmmss"
    df.timeZone = TimeZone.current
    return df.string(from: d)
}

private func materializeFileCopy(src: URL, dst: URL, outDir: URL) throws -> String {
    do {
        if FileManager.default.fileExists(atPath: dst.path) {
            try FileManager.default.removeItem(at: dst)
        }
        try FileManager.default.copyItem(at: src, to: dst)
    } catch {
        let msg = "copy_failed: \(error)\nsource: \(src.path)\n"
        try writeString(msg, to: dst)
    }
    return rel(outDir, dst)
}
