// ProcBar — a menu bar view of what Claude Code is running: each session, what it is doing right now,
// every helper, server and simulator it started, and what is safe to stop.
// Idle cost: one host_statistics64 call every 5s for the title, plus a CPU-time sample every 15s.
// The full process scan only runs when the menu is opened.

import AppKit
import Darwin

// MARK: - Formatting

func fmtBytes(_ b: UInt64) -> String {
    let gb = Double(b) / 1_073_741_824
    if gb >= 1 { return String(format: "%.1f GB", gb) }
    return String(format: "%.0f MB", Double(b) / 1_048_576)
}

func fmtAgo(_ seconds: TimeInterval) -> String {
    let s = Int(max(0, seconds))
    if s < 60 { return "\(s)s" }
    if s < 3600 { return "\(s / 60)m" }
    if s < 86400 { return "\(s / 3600)h \((s % 3600) / 60)m" }
    return "\(s / 86400)d \((s % 86400) / 3600)h"
}

let home = NSHomeDirectory()
func tilde(_ path: String) -> String { path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path }

// MARK: - System memory

struct MemStats {
    var used: UInt64, total: UInt64, compressed: UInt64, swapUsed: UInt64, pressure: Int32, wired: UInt64 = 0, cached: UInt64 = 0
    var fraction: Double { Double(used) / Double(total) }
    var pressureName: String { pressure >= 4 ? "critical" : pressure >= 2 ? "high" : "normal" }
}

let hostPort = mach_host_self()

func memStats() -> MemStats {
    var vs = vm_statistics64_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
    _ = withUnsafeMutablePointer(to: &vs) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { host_statistics64(hostPort, HOST_VM_INFO64, $0, &count) }
    }
    let page = UInt64(vm_kernel_page_size)
    // Same formula as Activity Monitor's "Memory Used": app memory + wired + compressed.
    let app = UInt64(vs.internal_page_count) &- UInt64(vs.purgeable_count)
    let used = (app + UInt64(vs.wire_count) + UInt64(vs.compressor_page_count)) * page
    var swap = xsw_usage(); var sz = MemoryLayout<xsw_usage>.size
    sysctlbyname("vm.swapusage", &swap, &sz, nil, 0)
    var level: Int32 = 1; var lsz = MemoryLayout<Int32>.size
    sysctlbyname("kern.memorystatus_vm_pressure_level", &level, &lsz, nil, 0)
    return MemStats(used: used, total: ProcessInfo.processInfo.physicalMemory,
                    compressed: UInt64(vs.compressor_page_count) * page, swapUsed: swap.xsu_used, pressure: level,
                    wired: UInt64(vs.wire_count) * page,
                    cached: (UInt64(vs.external_page_count) + UInt64(vs.purgeable_count)) * page)
}

// MARK: - Processes

var timebase: mach_timebase_info_data_t = { var t = mach_timebase_info_data_t(); mach_timebase_info(&t); return t }()
let myUid = getuid()

struct Proc {
    let pid: pid_t, ppid: pid_t, uid: uid_t
    let name: String, path: String
    let mem: UInt64          // physical footprint (what Activity Monitor shows), resident size as fallback
    let cpuNs: UInt64        // total user+system CPU time
    let started: Date
    var args: [String] = []
    var env: [String: String] = [:]
    var cpuPct: Double = 0
    var cmdline: String { args.isEmpty ? path : args.joined(separator: " ") }
}

func allPids() -> [pid_t] {
    let n = proc_listallpids(nil, 0)
    guard n > 0 else { return [] }
    var buf = [pid_t](repeating: 0, count: Int(n) + 64)
    let got = buf.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
    return buf.prefix(Int(max(got, 0))).filter { $0 > 0 }
}

func cString<T>(_ tuple: T) -> String {
    withUnsafeBytes(of: tuple) { raw in
        let bytes = raw.bindMemory(to: UInt8.self)
        let end = bytes.firstIndex(of: 0) ?? bytes.count
        return String(decoding: bytes[..<end], as: UTF8.self)
    }
}

/// CPU time + memory only; cheap enough to sample for every process every few seconds.
func cpuAndMem(_ pid: pid_t) -> (cpuNs: UInt64, mem: UInt64)? {
    var ru = rusage_info_v4()
    let ok = withUnsafeMutablePointer(to: &ru) {
        $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
    }
    if ok == 0 {
        let t = (ru.ri_user_time + ru.ri_system_time) * UInt64(timebase.numer) / UInt64(timebase.denom)
        return (t, ru.ri_phys_footprint)
    }
    var ti = proc_taskinfo()
    let sz = Int32(MemoryLayout<proc_taskinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sz) == sz else { return nil }
    let t = (ti.pti_total_user + ti.pti_total_system) * UInt64(timebase.numer) / UInt64(timebase.denom)
    return (t, ti.pti_resident_size)
}

var argBuf = [UInt8](repeating: 0, count: { var m: Int32 = 0; var s = 4; sysctlbyname("kern.argmax", &m, &s, nil, 0); return Int(max(m, 65536)) }())

func argsAndEnv(_ pid: pid_t) -> ([String], [String: String])? {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = argBuf.count
    guard sysctl(&mib, 3, &argBuf, &size, nil, 0) == 0, size > 4 else { return nil }
    let argc = Int(argBuf.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = 4
    while i < size && argBuf[i] != 0 { i += 1 }   // exec path
    while i < size && argBuf[i] == 0 { i += 1 }   // padding
    var args: [String] = [], env: [String: String] = [:]
    var start = i
    while i < size {
        if argBuf[i] == 0 {
            if i == start { break }  // empty string = end of env
            let s = String(decoding: argBuf[start..<i], as: UTF8.self)
            if args.count < argc { args.append(s) }
            else if let eq = s.firstIndex(of: "=") { env[String(s[..<eq])] = String(s[s.index(after: eq)...]) }
            start = i + 1
        }
        i += 1
    }
    return (args, env)
}

func exePath(_ pid: pid_t) -> String {
    var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return "" }
    return String(cString: buf)
}

func cwd(_ pid: pid_t) -> String? {
    var vpi = proc_vnodepathinfo()
    let sz = Int32(MemoryLayout<proc_vnodepathinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sz) == sz else { return nil }
    let p = cString(vpi.pvi_cdir.vip_path)
    return p.isEmpty ? nil : p
}

func snapshot(prevCpu: [pid_t: (UInt64, Date)]) -> [pid_t: Proc] {
    var out: [pid_t: Proc] = [:]
    let now = Date()
    for pid in allPids() {
        var bsd = proc_bsdinfo()
        let sz = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sz) == sz else { continue }
        let cm = cpuAndMem(pid)
        let path = exePath(pid)
        var name = cString(bsd.pbi_name)
        if name.isEmpty { name = cString(bsd.pbi_comm) }
        var p = Proc(pid: pid, ppid: pid_t(bsd.pbi_ppid), uid: bsd.pbi_uid, name: name, path: path,
                     mem: cm?.mem ?? 0, cpuNs: cm?.cpuNs ?? 0,
                     started: Date(timeIntervalSince1970: TimeInterval(bsd.pbi_start_tvsec)))
        if let (t0, d0) = prevCpu[pid], let cm, cm.cpuNs >= t0 {
            let wall = now.timeIntervalSince(d0)
            if wall > 0.5 { p.cpuPct = Double(cm.cpuNs - t0) / 1e9 / wall * 100 }
        }
        if bsd.pbi_uid == myUid, let (a, e) = argsAndEnv(pid) { p.args = a; p.env = e }
        out[pid] = p
    }
    return out
}

func sampleCpu() -> [pid_t: (UInt64, Date)] {
    let now = Date()
    var m: [pid_t: (UInt64, Date)] = [:]
    for pid in allPids() { if let c = cpuAndMem(pid) { m[pid] = (c.cpuNs, now) } }
    return m
}

func listeningPorts(_ pids: [pid_t]) -> [pid_t: [Int]] {
    guard !pids.isEmpty else { return [:] }
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
    task.arguments = ["-a", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn", "-p", pids.map(String.init).joined(separator: ",")]
    let pipe = Pipe(); task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
    guard (try? task.run()) != nil else { return [:] }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    var out: [pid_t: [Int]] = [:], cur: pid_t = 0
    for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
        if line.hasPrefix("p") { cur = pid_t(line.dropFirst()) ?? 0 }
        else if line.hasPrefix("n"), let port = Int(line.split(separator: ":").last ?? ""), !(out[cur]?.contains(port) ?? false) {
            out[cur, default: []].append(port)
        }
    }
    return out
}

// MARK: - Claude desktop session metadata

struct SessionMeta { var title: String; var lastActivity: Date?; var permissionMode: String?; var transcript: String? }

let sessionsRoot = home + "/Library/Application Support/Claude/claude-code-sessions"
let projectsRoot = home + "/.claude/projects"

/// ~/.claude/projects/<slug>/<id>.jsonl, where the slug is the cwd with every non-alphanumeric character as "-".
func transcriptPath(cwd: String, id: String) -> String? {
    let slug = String(cwd.map { $0.isASCII && ($0.isLetter || $0.isNumber) ? $0 : "-" })
    let direct = "\(projectsRoot)/\(slug)/\(id).jsonl"
    if FileManager.default.fileExists(atPath: direct) { return direct }
    // Worktree sessions can write under the original folder's slug.
    for d in (try? FileManager.default.contentsOfDirectory(atPath: projectsRoot)) ?? [] {
        let f = "\(projectsRoot)/\(d)/\(id).jsonl"
        if FileManager.default.fileExists(atPath: f) { return f }
    }
    return nil
}

/// Terminal sessions have no desktop metadata: take the newest transcript in their folder.
func newestTranscript(cwd: String, since: Date) -> String? {
    let slug = String(cwd.map { $0.isASCII && ($0.isLetter || $0.isNumber) ? $0 : "-" })
    let dir = "\(projectsRoot)/\(slug)"
    let fm = FileManager.default
    return ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).filter { $0.hasSuffix(".jsonl") }
        .compactMap { f -> (String, Date)? in
            guard let m = (try? fm.attributesOfItem(atPath: "\(dir)/\(f)"))?[.modificationDate] as? Date, m >= since else { return nil }
            return ("\(dir)/\(f)", m)
        }.max { $0.1 < $1.1 }?.0
}

func sessionMeta(_ hostId: String) -> SessionMeta? {
    let fm = FileManager.default
    for a in (try? fm.contentsOfDirectory(atPath: sessionsRoot)) ?? [] {
        for b in (try? fm.contentsOfDirectory(atPath: sessionsRoot + "/" + a)) ?? [] {
            let f = "\(sessionsRoot)/\(a)/\(b)/\(hostId).json"
            guard let d = fm.contents(atPath: f),
                  let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
            var last = (j["lastActivityAt"] as? Double).map { Date(timeIntervalSince1970: $0 / 1000) }
            var transcript: String?
            // The CLI transcript is appended on every message/tool call, so its mtime is the freshest signal.
            if let cli = j["cliSessionId"] as? String, let cwd = j["cwd"] as? String, let t = transcriptPath(cwd: cwd, id: cli) {
                transcript = t
                if let m = (try? fm.attributesOfItem(atPath: t))?[.modificationDate] as? Date, m > (last ?? .distantPast) { last = m }
            }
            return SessionMeta(title: j["title"] as? String ?? "Untitled session", lastActivity: last,
                               permissionMode: j["permissionMode"] as? String, transcript: transcript)
        }
    }
    return nil
}

func gitBranch(_ dir: String) -> String? {
    var d = dir
    while d.count > 1 {
        let dotGit = d + "/.git"
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: dotGit, isDirectory: &isDir) {
            var gitDir = dotGit
            if !isDir.boolValue, let s = try? String(contentsOfFile: dotGit, encoding: .utf8), s.hasPrefix("gitdir: ") {
                gitDir = s.dropFirst(8).trimmingCharacters(in: .whitespacesAndNewlines)
            }
            guard let head = try? String(contentsOfFile: gitDir + "/HEAD", encoding: .utf8) else { return nil }
            let h = head.trimmingCharacters(in: .whitespacesAndNewlines)
            return h.hasPrefix("ref: refs/heads/") ? String(h.dropFirst(16)) : String(h.prefix(8))
        }
        d = (d as NSString).deletingLastPathComponent
    }
    return nil
}

// MARK: - What a session is doing (read from the tail of its transcript)

enum Activity {
    case thinking(Date)               // Claude is writing a reply or about to call a tool
    case usingTool(String, String, Date)  // tool name, plain-English summary
    case needsAnswer(Date)            // asked you a question or is showing a plan
    case finished(Date)               // turn ended: waiting for your next message
    case interrupted(Date)            // you pressed stop
    case unknown

    var at: Date? {
        switch self {
        case .thinking(let d), .usingTool(_, _, let d), .needsAnswer(let d), .finished(let d), .interrupted(let d): return d
        case .unknown: return nil
        }
    }
}

let isoFrac: ISO8601DateFormatter = { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; return f }()

func shortPath(_ s: String) -> String { (s as NSString).lastPathComponent }

func clip(_ s: String, _ n: Int) -> String {
    let one = s.split(whereSeparator: \.isNewline).first.map(String.init) ?? s
    return one.count > n ? String(one.prefix(n - 1)) + "…" : one
}

func toolSummary(_ name: String, _ input: [String: Any]) -> String {
    let str = { (k: String) in input[k] as? String ?? "" }
    switch name {
    case "Bash": return "running `\(clip(str("command"), 48))`"
    case "Read": return "reading \(shortPath(str("file_path")))"
    case "Edit", "MultiEdit": return "editing \(shortPath(str("file_path")))"
    case "Write": return "writing \(shortPath(str("file_path")))"
    case "Grep", "Glob": return "searching the code"
    case "WebSearch": return "searching the web"
    case "WebFetch": return "reading a web page"
    case "Agent", "Task": return "running a subagent: \(clip(str("description"), 40))"
    case "Monitor", "ScheduleWakeup": return "waiting on a timer or background job"
    default:
        if name.hasPrefix("mcp__") {
            let parts = name.split(separator: "_", omittingEmptySubsequences: true)
            let tool = parts.last.map(String.init) ?? name
            let server = name.dropFirst(5).components(separatedBy: "__").first ?? ""
            let friendly = server.count > 30 ? "a connector" : server.replacingOccurrences(of: "_", with: " ")
            return "using \(friendly): \(tool.replacingOccurrences(of: "_", with: " "))"
        }
        return "using \(name)"
    }
}

func readActivity(_ path: String) -> Activity {
    guard let fh = FileHandle(forReadingAtPath: path) else { return .unknown }
    defer { try? fh.close() }
    let size = (try? fh.seekToEnd()) ?? 0
    try? fh.seek(toOffset: size > 400_000 ? size - 400_000 : 0)
    let data = fh.readDataToEndOfFile()
    for line in data.split(separator: UInt8(ascii: "\n")).reversed() {
        guard let j = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
              let type = j["type"] as? String, type == "user" || type == "assistant",
              j["isSidechain"] as? Bool != true, j["isMeta"] as? Bool != true,
              let msg = j["message"] as? [String: Any] else { continue }
        let at = (j["timestamp"] as? String).flatMap { isoFrac.date(from: $0) } ?? Date()
        if type == "user" {
            let texts = (msg["content"] as? String).map { [$0] }
                ?? (msg["content"] as? [[String: Any]] ?? []).compactMap { $0["text"] as? String }
            return texts.contains { $0.hasPrefix("[Request interrupted") } ? .interrupted(at) : .thinking(at)
        }
        guard let last = (msg["content"] as? [[String: Any]])?.last else { continue }
        if last["type"] as? String == "tool_use" {
            let name = last["name"] as? String ?? "a tool"
            if name == "AskUserQuestion" || name == "ExitPlanMode" { return .needsAnswer(at) }
            return .usingTool(name, toolSummary(name, last["input"] as? [String: Any] ?? [:]), at)
        }
        return msg["stop_reason"] as? String == "end_turn" ? .finished(at) : .thinking(at)
    }
    return .unknown
}

// MARK: - Naming the things Claude starts

/// The CLI binary has lived at …/MacOS/claude (desktop), ~/.local/bin/claude and
/// …/@anthropic-ai/claude-code/bin/claude.exe (npm). An empty path means the binary was
/// replaced on disk by an update while the session kept running.
func isClaudeBinary(_ path: String, _ name: String) -> Bool {
    let file = (path as NSString).lastPathComponent
    if file == "claude.exe" && path.contains("claude-code") { return true }
    if path.hasSuffix("/MacOS/claude") && path.contains("claude-code") { return true }
    if path.hasSuffix("/bin/claude") { return true }
    return path.isEmpty && (name == "claude" || name == "claude.exe")
}

func isClaudeSession(_ p: Proc) -> Bool {
    isClaudeBinary(p.path, p.name) || p.args.contains { $0.contains("@anthropic-ai/claude-code") }
}

let shells: Set<String> = ["zsh", "bash", "sh", "fish"]

/// Claude's Bash tool runs `zsh -c "source snapshot && … && eval '<command>' …"`: pull out <command>.
func shellCommand(_ p: Proc) -> String? {
    guard let i = p.args.firstIndex(of: "-c"), i + 1 < p.args.count else { return nil }
    let script = p.args[(i + 1)...].joined(separator: " ")
    if let r = script.range(of: "eval '") {
        var out = "", rest = script[r.upperBound...]
        while let q = rest.firstIndex(of: "'") {
            out += rest[..<q]
            rest = rest[rest.index(after: q)...]
            guard rest.hasPrefix("\\''") else { break }   // '\'' is an escaped quote
            out += "'"; rest = rest.dropFirst(3)
        }
        return out
    }
    return script
}

let friendlyMcp: [String: String] = [
    "xcodebuildmcp": "XcodeBuildMCP (Xcode + simulator tools)",
    "blender-mcp": "Blender MCP", "playwright": "Playwright (browser automation)",
    "chrome-devtools-mcp": "Chrome DevTools", "github-mcp-server": "GitHub",
]

func mcpName(_ p: Proc) -> String? {
    guard p.cmdline.lowercased().contains("mcp") else { return nil }
    // npm rewrites its process title, so its whole command line can arrive as one argument.
    let words = p.args.flatMap { $0.split(separator: " ").map(String.init) }
    let arg = words.dropFirst().first { !$0.hasPrefix("-") && $0.lowercased().contains("mcp") } ?? p.name
    var name = shortPath(arg)
    if let at = name.lastIndex(of: "@"), at != name.startIndex { name = String(name[..<at]) }
    for ext in [".js", ".mjs", ".py", ".ts"] where name.hasSuffix(ext) { name = String(name.dropLast(ext.count)) }
    return friendlyMcp[name.lowercased()] ?? name
}

func serverName(_ p: Proc) -> String {
    let lc = p.cmdline.lowercased()
    if lc.contains("http.server") { return "Python web server" }
    if lc.contains("vite") { return "Vite dev server" }
    if lc.contains("next") && lc.contains("dev") { return "Next.js dev server" }
    if lc.contains("expo") || lc.contains("metro") { return "Expo / Metro bundler" }
    if lc.contains("webpack") { return "Webpack dev server" }
    if p.name == "esbuild" { return "esbuild bundler" }
    if p.name.hasPrefix("python") || p.name == "Python" {
        return "Python: " + (p.args.dropFirst().first { !$0.hasPrefix("-") }.map(shortPath) ?? "script")
    }
    if ["node", "bun", "deno", "tsx"].contains(p.name) {
        let script = p.args.dropFirst().filter { !$0.hasPrefix("-") }.prefix(2).map(shortPath).joined(separator: " ")
        return script.isEmpty ? "Node process" : "Node: \(script)"
    }
    return clip(p.cmdline, 50)
}

enum Kind { case agent, plugin, command, background, codeIntel, preview, other }

/// One line in a session: a direct child of Claude (or a server the Claude app started for it), with its whole subtree.
struct Part {
    let proc: Proc, kind: Kind, label: String, explain: String
    var mem: UInt64, cpu: Double, pids: [pid_t], ports: [Int] = []
}

func describePart(_ p: Proc, sessionBusy: Bool) -> (Kind, String, String) {
    if shells.contains(p.name), let cmd = shellCommand(p) {
        return sessionBusy
            ? (.command, "Running `\(clip(cmd, 50))`", "A command Claude is running for the current task.")
            : (.background, "Still running `\(clip(cmd, 46))`",
               "Claude started this in the background and it outlived the task. Usually safe to stop.")
    }
    if let m = mcpName(p) {
        return (.plugin, "Tool plug-in: \(m)",
                "An MCP server that gives Claude extra tools. Sits idle until Claude uses it. Every session starts its own copy.")
    }
    if p.cmdline.contains("lsp") || p.cmdline.contains("language-server") {
        return (.codeIntel, "Code intelligence: \(p.name)", "Helps Claude jump to definitions and see compiler errors.")
    }
    return (.other, serverName(p), "Started by Claude.")
}

func describeAppPart(_ p: Proc) -> String {
    let a = p.cmdline
    if a.contains("--type=gpu-process") { return "Drawing the window (GPU)" }
    if a.contains("--type=renderer") { return "Window contents (chat, panes, previews)" }
    if a.contains("NetworkService") { return "Network" }
    if a.contains("AudioService") { return "Audio" }
    if a.contains("video_capture") { return "Camera / screen capture" }
    if a.contains("node.mojom.NodeService") { return "Background helper (connectors, terminal, previews)" }
    if p.path.contains("claude-ios-sim") { return "iOS simulator viewer panel" }
    if p.name == "chrome-native-host" { return "Claude in Chrome bridge" }
    if shells.contains(p.name) { return "Terminal tab" }
    if p.path.hasPrefix("/Applications/Claude.app/Contents/MacOS/") { return "Main app" }
    return p.name
}

// MARK: - Killing

func descendants(of root: pid_t, children: [pid_t: [pid_t]]) -> [pid_t] {
    var out: [pid_t] = [], stack = [root]
    while let p = stack.popLast() { out.append(p); stack.append(contentsOf: children[p] ?? []) }
    return out
}

/// SIGTERM the whole tree (leaves first), then SIGKILL anything still alive after 2s.
func killTree(_ pids: [pid_t]) {
    let ordered = pids.reversed()
    for p in ordered { kill(p, SIGTERM) }
    DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
        for p in ordered where kill(p, 0) == 0 { kill(p, SIGKILL) }
    }
}

func shutdownSimulator(_ udid: String) {
    let t = Process()
    t.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    t.arguments = ["simctl", "shutdown", udid]
    try? t.run()
}

// MARK: - Model: everything Claude is running, grouped by session

struct SessionInfo {
    let proc: Proc, title: String, folder: String?, branch: String?
    let lastActivity: Date?, permissionMode: String?, fromDesktop: Bool
    let activity: Activity
    var parts: [Part]
    var mem: UInt64 { parts.map(\.mem).reduce(0, +) }
    var cpu: Double { parts.map(\.cpu).reduce(0, +) }
    var pids: [pid_t] { parts.flatMap(\.pids) }
    var leftovers: [Part] { parts.filter { $0.kind == .background || $0.kind == .preview } }

    /// Is Claude in the middle of a turn? A transcript that has gone quiet for 15 minutes mid-turn means
    /// the session hung or is waiting on a permission prompt, not that it's working.
    var isBusy: Bool {
        if parts.contains(where: { $0.kind == .command }) { return true }
        switch activity {
        case .thinking(let d), .usingTool(_, _, let d): return Date().timeIntervalSince(d) < 900 || cpu > 5
        case .needsAnswer, .finished, .interrupted: return false
        case .unknown: return cpu > 5 || (lastActivity.map { Date().timeIntervalSince($0) < 180 } ?? false)
        }
    }
    /// Nothing will be lost by stopping it: the turn is over and has been for a few minutes.
    var isDone: Bool {
        if isBusy { return false }
        if case .needsAnswer = activity { return false }
        let since = activity.at ?? lastActivity ?? proc.started
        return Date().timeIntervalSince(since) > 120
    }
}

struct Simulator { let udid: String, name: String, apps: [String], mem: UInt64, cpu: Double, started: Date }

final class Model {
    var sessions: [SessionInfo] = []
    var orphans: [(part: Part, from: String?, folder: String?)] = []
    var unmatchedPreviews: [(part: Part, folder: String?)] = []
    var simulators: [Simulator] = []
    var app: (mem: UInt64, cpu: Double, parts: [(label: String, mem: UInt64, cpu: Double)]) = (0, 0, [])

    var claudeTotal: UInt64 {
        sessions.map(\.mem).reduce(0, +) + orphans.map(\.part.mem).reduce(0, +)
            + unmatchedPreviews.map(\.part.mem).reduce(0, +) + app.mem
    }

    init() {}

    init(procs: [pid_t: Proc]) {
        var children: [pid_t: [pid_t]] = [:]
        for p in procs.values { children[p.ppid, default: []].append(p.pid) }
        var claimed = Set<pid_t>()
        func tree(_ pid: pid_t) -> [pid_t] { descendants(of: pid, children: children) }
        func mem(_ pids: [pid_t]) -> UInt64 { pids.compactMap { procs[$0]?.mem }.reduce(0, +) }
        func cpu(_ pids: [pid_t]) -> Double { pids.compactMap { procs[$0]?.cpuPct }.reduce(0, +) }

        // Sessions (desktop or terminal): Claude itself plus one part per direct child, subtree folded in.
        func hasClaudeAncestor(_ p: Proc) -> Bool {
            var cur = procs[p.ppid]
            while let c = cur, c.pid > 1 { if isClaudeSession(c) { return true }; cur = procs[c.ppid] }
            return false
        }
        for s in procs.values where isClaudeSession(s) && !hasClaudeAncestor(s) {
            claimed.formUnion(tree(s.pid))
            let meta = s.env["CLAUDE_CODE_HOST_SESSION_ID"].flatMap(sessionMeta)
            let folder = cwd(s.pid)
            let transcript = meta?.transcript ?? folder.flatMap { newestTranscript(cwd: $0, since: s.started) }
            let activity = transcript.map(readActivity) ?? .unknown
            let kids = (children[s.pid] ?? []).compactMap { procs[$0] }
            // A shell child while the turn is over can only be a background command.
            let turnOver: Bool = { switch activity { case .finished, .interrupted, .needsAnswer: return true; default: return false } }()
            var parts = [Part(proc: s, kind: .agent, label: "Claude (the session itself)",
                              explain: "Holds the conversation. Comes back when you reopen the chat.",
                              mem: s.mem, cpu: s.cpuPct, pids: [s.pid])]
            for k in kids {
                let (kind, label, explain) = describePart(k, sessionBusy: !turnOver)
                let t = tree(k.pid)
                parts.append(Part(proc: k, kind: kind, label: label, explain: explain, mem: mem(t), cpu: cpu(t), pids: t))
            }
            let mode = meta?.permissionMode ?? s.args.first { $0.hasPrefix("--permission-mode=") }.map { String($0.dropFirst(18)) }
            sessions.append(SessionInfo(
                proc: s, title: meta?.title ?? (folder.map(shortPath) ?? "Claude Code"),
                folder: folder, branch: folder.flatMap(gitBranch), lastActivity: meta?.lastActivity,
                permissionMode: mode,
                fromDesktop: s.env["CLAUDE_CODE_ENTRYPOINT"] == "claude-desktop" || s.path.contains("Application Support/Claude"),
                activity: activity, parts: parts))
        }

        // Servers the Claude app started for a session (preview panes): `disclaimer` wrappers under the app
        // whose child isn't a session. They run in the project folder, which ties them to a session.
        let mainApp = procs.values.first { $0.path.hasPrefix("/Applications/Claude.app/Contents/MacOS/") && $0.ppid == 1 }
        if let main = mainApp {
            for w in (children[main.pid] ?? []).compactMap({ procs[$0] }) where w.name == "disclaimer" && !claimed.contains(w.pid) {
                guard let child = (children[w.pid] ?? []).compactMap({ procs[$0] }).first,
                      !isClaudeSession(child), !child.path.contains("claude-ios-sim") else { continue }
                let t = tree(w.pid)
                claimed.formUnion(t)
                let dir = cwd(child.pid)
                let part = Part(proc: child, kind: .preview, label: "Preview server: \(serverName(child))",
                                explain: "Started by the Claude app to show a preview of this project.",
                                mem: mem(t), cpu: cpu(t), pids: t)
                let match = sessions.indices.filter { i in
                    guard let f = sessions[i].folder, let d = dir else { return false }
                    return d == f || d.hasPrefix(f + "/")
                }.max { (sessions[$0].folder?.count ?? 0) < (sessions[$1].folder?.count ?? 0) }
                if let i = match { sessions[i].parts.append(part) } else { unmatchedPreviews.append((part, dir)) }
            }
        }
        sessions.sort { ($0.activity.at ?? $0.lastActivity ?? $0.proc.started) > ($1.activity.at ?? $1.lastActivity ?? $1.proc.started) }

        // Left behind: processes still carrying Claude's environment after their session exited (launchd adopted them).
        for p in procs.values where p.uid == myUid && p.ppid == 1 && !claimed.contains(p.pid) && !isClaudeSession(p) {
            let hostId = p.env["CLAUDE_CODE_HOST_SESSION_ID"]
            guard p.env["CLAUDECODE"] == "1" || hostId != nil || p.env["CLAUDE_CODE_SESSION_ID"] != nil else { continue }
            let t = tree(p.pid)
            claimed.formUnion(t)
            var (kind, label, _) = describePart(p, sessionBusy: false)
            if kind == .background || kind == .other { label = serverName(procs[t.last ?? p.pid] ?? p) }
            if shells.contains(p.name), let cmd = shellCommand(p) { label = "`\(clip(cmd, 50))`" }
            orphans.append((Part(proc: p, kind: kind, label: label, explain: "", mem: mem(t), cpu: cpu(t), pids: t),
                            hostId.flatMap(sessionMeta)?.title, cwd(p.pid)))
        }
        orphans.sort { $0.part.mem > $1.part.mem }

        // The Claude app itself: everything else under it.
        if let main = mainApp {
            let t = tree(main.pid).filter { !claimed.contains($0) }
            claimed.formUnion(t)
            var byLabel: [String: (UInt64, Double)] = [:]
            for p in t.compactMap({ procs[$0] }) where p.name != "disclaimer" {
                var label = describeAppPart(p)
                if label == "Terminal tab" {
                    let busy = (children[p.pid] ?? []).compactMap { procs[$0] }.first
                    label = busy.map { "Terminal tab running \(serverName($0))" } ?? "Terminal tabs (idle)"
                }
                byLabel[label, default: (0, 0)].0 += p.mem; byLabel[label, default: (0, 0)].1 += p.cpuPct
            }
            app.parts = byLabel.map { ($0.key, $0.value.0, $0.value.1) }.sorted { $0.mem > $1.mem }
            app.mem = app.parts.map(\.mem).reduce(0, +); app.cpu = app.parts.map(\.cpu).reduce(0, +)
        }

        // Booted iOS simulators (usually from XcodeBuildMCP or the app's simulator panel).
        for p in procs.values where p.name == "launchd_sim" {
            guard let r = p.cmdline.range(of: #"Devices/([0-9A-F-]{36})"#, options: .regularExpression) else { continue }
            let udid = String(p.cmdline[r].dropFirst(8))
            let t = tree(p.pid)
            let plist = NSDictionary(contentsOfFile: "\(home)/Library/Developer/CoreSimulator/Devices/\(udid)/device.plist")
            let apps = t.compactMap { procs[$0] }.filter { $0.path.contains("/Containers/Bundle/Application/") }
                .compactMap { appName($0.path) }
            simulators.append(Simulator(udid: udid, name: plist?["name"] as? String ?? "Simulator", apps: apps,
                                        mem: mem(t), cpu: cpu(t), started: p.started))
        }

        // One lsof call for every port in play.
        let all = sessions.flatMap(\.pids) + orphans.flatMap(\.part.pids) + unmatchedPreviews.flatMap(\.part.pids)
        let ports = listeningPorts(all)
        func withPorts(_ p: Part) -> Part { var q = p; q.ports = p.pids.flatMap { ports[$0] ?? [] }.sorted(); return q }
        for i in sessions.indices { sessions[i].parts = sessions[i].parts.map(withPorts) }
        orphans = orphans.map { (withPorts($0.part), $0.from, $0.folder) }
        unmatchedPreviews = unmatchedPreviews.map { (withPorts($0.part), $0.folder) }
    }
}

func appName(_ path: String) -> String? {
    guard let r = path.range(of: ".app/") else { return nil }
    return shortPath(String(path[..<r.lowerBound]))
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    var cpuSample: [pid_t: (UInt64, Date)] = [:]
    var sessionCount = 0
    var actions: [() -> Void] = []
    var demo: Model?  // made-up sessions for screenshots (`--demo`)

    func applicationDidFinishLaunching(_ n: Notification) {
        menu.delegate = self
        item.menu = menu
        item.button?.imagePosition = .imageLeading
        cpuSample = sampleCpu()
        sessionCount = countSessions()
        updateTitle()
        // Tolerance lets macOS coalesce these wakeups with other timers.
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.updateTitle() }.tolerance = 1
        Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            guard let self else { return }
            DispatchQueue.global(qos: .utility).async {
                let s = sampleCpu(), c = self.countSessions()
                DispatchQueue.main.async { self.cpuSample = s; self.sessionCount = c; self.updateTitle() }
            }
        }.tolerance = 3
    }

    func countSessions() -> Int {
        allPids().filter { pid in
            var buf = [CChar](repeating: 0, count: 64)
            proc_name(pid, &buf, UInt32(buf.count))
            return isClaudeBinary(exePath(pid), String(cString: buf))
        }.count
    }

    let chip: NSImage? = {
        let img = NSImage(systemSymbolName: "memorychip", accessibilityDescription: "Memory")
        img?.isTemplate = true
        return img
    }()
    lazy var tintedChips: [NSColor: NSImage] = [.systemOrange, .systemRed].reduce(into: [:]) { d, c in
        d[c] = chip?.withSymbolConfiguration(.init(paletteColors: [c]))
    }
    var lastTitle = ""

    func updateTitle() {
        let m = memStats()
        let color: NSColor = m.pressure >= 4 ? .systemRed : m.pressure >= 2 || m.fraction > 0.85 ? .systemOrange : .labelColor
        let text = String(format: " %.1fG", Double(m.used) / 1_073_741_824) + (sessionCount > 0 ? "  ✳︎\(sessionCount)" : "")
        // Every assignment makes AppKit re-render the item for each display, so skip when nothing visible changed.
        let key = text + color.description + m.pressureName + fmtBytes(m.total)
        guard key != lastTitle else { return }
        lastTitle = key
        item.button?.image = color == .labelColor ? chip : tintedChips[color]
        item.button?.attributedTitle = NSAttributedString(string: text, attributes: [
            .foregroundColor: color, .font: NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular)])
        item.button?.toolTip = "RAM \(fmtBytes(m.used)) of \(fmtBytes(m.total)) · pressure \(m.pressureName) · \(sessionCount) Claude sessions"
    }

    // MARK: menu building

    func status(_ s: SessionInfo) -> (dot: String, color: NSColor, text: String) {
        let ago = { (d: Date?) in fmtAgo(Date().timeIntervalSince(d ?? s.proc.started)) }
        let bg = s.leftovers.filter { $0.kind == .background }.count
        let bgNote = bg > 0 ? " · \(bg) background command\(bg == 1 ? "" : "s") still running" : ""
        if let c = s.parts.first(where: { $0.kind == .command }) {
            return ("●", .systemGreen, "Working — " + c.label.prefix(1).lowercased() + c.label.dropFirst())
        }
        switch s.activity {
        case .usingTool(let name, let what, let d) where s.isBusy:
            // Bash with no shell running, quiet for a while: the command is waiting on a permission prompt.
            if ["Bash", "Edit", "Write"].contains(name), Date().timeIntervalSince(d) > 30, s.cpu < 2 {
                return ("?", .systemOrange, "Probably waiting for your approval — \(what)")
            }
            return ("●", .systemGreen, "Working — \(what)")
        case .thinking where s.isBusy: return ("●", .systemGreen, "Working — thinking")
        case .needsAnswer(let d): return ("?", .systemOrange, "Asked you a question \(ago(d)) ago — waiting for your answer")
        case .finished(let d): return ("✓", .secondaryLabelColor, "Finished \(ago(d)) ago, waiting for you" + bgNote)
        case .interrupted(let d): return ("■", .secondaryLabelColor, "Stopped by you \(ago(d)) ago" + bgNote)
        case .unknown where s.isBusy: return ("●", .systemGreen, "Working")
        default: return ("○", .secondaryLabelColor, "Idle \(ago(s.activity.at ?? s.lastActivity)) — nothing happening" + bgNote)
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        actions.removeAll()
        let model: Model
        if let demo { model = demo } else {
            let procs = snapshot(prevCpu: cpuSample)
            cpuSample = procs.mapValues { ($0.cpuNs, Date()) }
            model = Model(procs: procs)
        }
        sessionCount = model.sessions.count
        updateTitle()

        let busy = model.sessions.filter(\.isBusy)
        let done = model.sessions.filter(\.isDone)
        let waiting = model.sessions.count - busy.count - done.count
        let cpuTotal = model.sessions.map(\.cpu).reduce(0, +) + model.app.cpu

        header("Claude is using \(fmtBytes(model.claudeTotal)) of RAM" + cpuNote(cpuTotal))
        var counts = ["\(busy.count) working"]
        if waiting > 0 { counts.append("\(waiting) waiting for you") }
        if !done.isEmpty { counts.append("\(done.count) finished") }
        info(model.sessions.isEmpty ? "No Claude Code sessions running" : "\(model.sessions.count) sessions: " + counts.joined(separator: ", "))
        menu.addItem(.separator())

        // Sessions: one two-line row each, with what it's doing and what it's running.
        for s in model.sessions {
            let st = status(s)
            let row = twoLine(dot: st.dot, dotColor: st.color, title: clip(s.title, 46), right: fmtBytes(s.mem), sub: st.text)
            row.submenu = sessionMenu(s)
            menu.addItem(row)
        }

        // Left behind by sessions that already exited.
        if !model.orphans.isEmpty {
            menu.addItem(.separator())
            header("Left running after Claude quit (\(model.orphans.count)) — \(fmtBytes(model.orphans.map(\.part.mem).reduce(0, +)))")
            for o in model.orphans {
                let where_ = o.from.map { "from “\(clip($0, 30))”" } ?? o.folder.map { "in \(tilde($0))" } ?? ""
                let row = twoLine(dot: "!", dotColor: .systemOrange, title: o.part.label + portNote(o.part.ports),
                                  right: fmtBytes(o.part.mem),
                                  sub: "Nothing will stop this · \(where_) · up \(fmtAgo(Date().timeIntervalSince(o.part.proc.started)))")
                let sub = NSMenu()
                subInfo(sub, "The session that started this has exited, so it will run until you stop it or restart.")
                if let f = o.folder { subInfo(sub, "Folder: \(tilde(f))") }
                subInfo(sub, clip(o.part.proc.cmdline, 90))
                sub.addItem(.separator())
                partActions(sub, o.part)
                row.submenu = sub
                menu.addItem(row)
            }
        }

        if !model.unmatchedPreviews.isEmpty {
            menu.addItem(.separator())
            header("Preview servers the Claude app started")
            for p in model.unmatchedPreviews {
                let row = twoLine(dot: "◆", dotColor: .systemBlue, title: p.part.label + portNote(p.part.ports),
                                  right: fmtBytes(p.part.mem), sub: p.folder.map { "In \(tilde($0)) · no open session for this folder" } ?? "")
                let sub = NSMenu(); partActions(sub, p.part); row.submenu = sub
                menu.addItem(row)
            }
        }

        if !model.simulators.isEmpty {
            menu.addItem(.separator())
            header("iOS Simulators running")
            for sim in model.simulators {
                let row = twoLine(dot: "◆", dotColor: .systemBlue, title: sim.name, right: fmtBytes(sim.mem),
                                  sub: (sim.apps.isEmpty ? "No app open" : "Running " + sim.apps.joined(separator: ", "))
                                    + " · booted \(fmtAgo(Date().timeIntervalSince(sim.started))) ago")
                let sub = NSMenu()
                subInfo(sub, "Simulators keep running after Claude's build/test is done.")
                subAction(sub, "Shut down \(sim.name)") { shutdownSimulator(sim.udid) }
                row.submenu = sub
                menu.addItem(row)
            }
            if model.simulators.count > 1 {
                action("Shut down all simulators") { for s in model.simulators { shutdownSimulator(s.udid) } }
            }
        }

        // The one-click cleanup.
        let stopSessions = done
        let stopOrphans = model.orphans.map(\.part)
        let freed = stopSessions.map(\.mem).reduce(0, +) + stopOrphans.map(\.mem).reduce(0, +)
        if !stopSessions.isEmpty || !stopOrphans.isEmpty {
            menu.addItem(.separator())
            var what: [String] = []
            if !stopSessions.isEmpty { what.append("\(stopSessions.count) finished session\(stopSessions.count == 1 ? "" : "s")") }
            if !stopOrphans.isEmpty { what.append("\(stopOrphans.count) leftover\(stopOrphans.count == 1 ? "" : "s")") }
            let i = action("Stop \(what.joined(separator: " + ")) — frees \(fmtBytes(freed))") {
                for s in stopSessions { killTree(s.pids) }
                for o in stopOrphans { killTree(o.pids) }
            }
            i.attributedTitle = NSAttributedString(string: i.title, attributes: [.font: NSFont.boldSystemFont(ofSize: 13)])
            info("Stopped chats stay in the Claude sidebar and pick up where they left off when you open them.")
        }

        // A tip when the same plug-in is duplicated across many sessions.
        var plugins: [String: (count: Int, mem: UInt64)] = [:]
        for p in model.sessions.flatMap(\.parts) where p.kind == .plugin {
            plugins[p.label, default: (0, 0)].count += 1; plugins[p.label, default: (0, 0)].mem += p.mem
        }
        let dupes = plugins.filter { $0.value.count >= 3 }.sorted { $0.value.mem > $1.value.mem }
        if !dupes.isEmpty { menu.addItem(.separator()) }
        for (label, v) in dupes {
            info("Tip: \(v.count) sessions each run their own \(label.replacingOccurrences(of: "Tool plug-in: ", with: "")) (\(fmtBytes(v.mem)) total).")
            info("      Turn it off in projects that don't need it to save that memory.")
        }

        menu.addItem(.separator())
        let appSub = NSMenu()
        subInfo(appSub, "The Claude window and its built-in helpers. Not affected by stopping sessions.")
        appSub.addItem(.separator())
        for p in model.app.parts.prefix(14) { subInfo(appSub, "\(p.label) — \(fmtBytes(p.mem))" + cpuNote(p.cpu)) }
        let appRow = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        appRow.attributedTitle = tabbed("Claude app window" + cpuNote(model.app.cpu), fmtBytes(model.app.mem))
        appRow.submenu = appSub
        menu.addItem(appRow)
        let m = memStats()
        info("Mac memory: \(fmtBytes(m.used)) of \(fmtBytes(m.total)) used · pressure \(m.pressureName)")
        menu.addItem(.separator())
        action("Open Activity Monitor") { NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Activity Monitor.app")) }
        action("Quit ProcBar") { NSApp.terminate(nil) }
    }

    func sessionMenu(_ s: SessionInfo) -> NSMenu {
        let sub = NSMenu()
        let st = status(s)
        subHeader(sub, st.text)
        if let f = s.folder { subInfo(sub, tilde(f) + (s.branch.map { " · branch \($0)" } ?? "")) }
        subInfo(sub, (s.fromDesktop ? "Claude app" : "Terminal") + " · open \(fmtAgo(Date().timeIntervalSince(s.proc.started)))"
                + (s.permissionMode.map { " · \($0) mode" } ?? "") + cpuNote(s.cpu))
        sub.addItem(.separator())
        subHeader(sub, "What it's running")
        for p in s.parts {
            let i = NSMenuItem(title: p.label, action: nil, keyEquivalent: "")
            i.attributedTitle = tabbed(p.label + portNote(p.ports), fmtBytes(p.mem) + (p.cpu >= 1 ? String(format: " · %.0f%%", p.cpu) : ""),
                                       width: 460, size: 12, note: p.explain)
            if p.kind != .agent {
                let ps = NSMenu()
                subInfo(ps, clip(p.proc.cmdline, 100))
                ps.addItem(.separator())
                partActions(ps, p, warn: p.kind == .plugin ? "Claude loses these tools in this chat until it restarts." : nil)
                i.submenu = ps
            }
            sub.addItem(i)
        }
        sub.addItem(.separator())
        subAction(sub, "Stop this session and everything it started (frees \(fmtBytes(s.mem)))") { [weak self] in
            if s.isBusy, self?.confirm("“\(s.title)” is working right now. Stop it anyway?",
                                       "Its current turn will be cut off. The chat stays in the Claude sidebar and restarts when you open it.") != true { return }
            killTree(s.pids)
        }
        if s.fromDesktop { subInfo(sub, "The chat stays in the Claude sidebar and resumes when you open it.") }
        return sub
    }

    func partActions(_ m: NSMenu, _ p: Part, warn: String? = nil) {
        for port in p.ports.prefix(2) {
            subAction(m, "Open http://localhost:\(port)") { NSWorkspace.shared.open(URL(string: "http://localhost:\(port)")!) }
        }
        subAction(m, "Stop (frees \(fmtBytes(p.mem)))") { killTree(p.pids) }
        if let warn { subInfo(m, warn) }
    }

    // MARK: menu helpers

    func cpuNote(_ cpu: Double) -> String { cpu >= 5 ? String(format: " · %.0f%% CPU", cpu) : "" }
    func portNote(_ ports: [Int]) -> String { ports.isEmpty ? "" : " · " + ports.prefix(3).map { ":\($0)" }.joined(separator: " ") }

    func tabbed(_ left: String, _ right: String, bold: Bool = false, width: CGFloat = 440, size: CGFloat = 13, note: String? = nil) -> NSAttributedString {
        let ps = NSMutableParagraphStyle()
        ps.tabStops = [NSTextTab(textAlignment: .right, location: width)]
        let s = NSMutableAttributedString(string: left + "\t" + right, attributes: [
            .paragraphStyle: ps, .font: bold ? NSFont.boldSystemFont(ofSize: size) : NSFont.menuFont(ofSize: size)])
        if let note {
            s.append(NSAttributedString(string: "\n" + note, attributes: [
                .font: NSFont.menuFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor]))
        }
        return s
    }

    /// "● Title ……… 340 MB" over a smaller grey line saying what it's doing.
    func twoLine(dot: String, dotColor: NSColor, title: String, right: String, sub: String) -> NSMenuItem {
        let i = NSMenuItem(title: "\(dot) \(title) — \(right)\n    \(sub)", action: nil, keyEquivalent: "")
        let ps = NSMutableParagraphStyle()
        ps.tabStops = [NSTextTab(textAlignment: .right, location: 440)]
        ps.headIndent = 18
        let s = NSMutableAttributedString(string: dot + "\t", attributes: [.foregroundColor: dotColor, .font: NSFont.boldSystemFont(ofSize: 13)])
        let ps2 = ps.mutableCopy() as! NSMutableParagraphStyle
        ps2.tabStops = [NSTextTab(textAlignment: .left, location: 18), NSTextTab(textAlignment: .right, location: 440)]
        s.append(NSAttributedString(string: title + "\t" + right, attributes: [.font: NSFont.menuFont(ofSize: 13)]))
        s.append(NSAttributedString(string: "\n" + sub, attributes: [.font: NSFont.menuFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor]))
        s.addAttribute(.paragraphStyle, value: ps2, range: NSRange(location: 0, length: s.length))
        i.attributedTitle = s
        return i
    }

    func header(_ s: String) {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        i.attributedTitle = NSAttributedString(string: s, attributes: [.font: NSFont.boldSystemFont(ofSize: 13)])
        menu.addItem(i)
    }
    func info(_ s: String) { subInfo(menu, s) }
    func subHeader(_ m: NSMenu, _ s: String) {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        i.attributedTitle = NSAttributedString(string: s, attributes: [.font: NSFont.boldSystemFont(ofSize: 12)])
        m.addItem(i)
    }
    func subInfo(_ m: NSMenu, _ s: String) {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        i.attributedTitle = NSAttributedString(string: s, attributes: [
            .font: NSFont.menuFont(ofSize: 12), .foregroundColor: NSColor.secondaryLabelColor])
        m.addItem(i)
    }
    @discardableResult func action(_ s: String, _ f: @escaping () -> Void) -> NSMenuItem { subAction(menu, s, f) }
    @discardableResult func subAction(_ m: NSMenu, _ s: String, _ f: @escaping () -> Void) -> NSMenuItem {
        let i = NSMenuItem(title: s, action: #selector(run(_:)), keyEquivalent: "")
        i.target = self
        i.tag = actions.count
        actions.append(f)
        m.addItem(i)
        return i
    }
    @objc func run(_ sender: NSMenuItem) {
        let f = actions[sender.tag]
        // Let the menu close first so alerts and the next refresh behave.
        DispatchQueue.main.async {
            f()
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
                guard let self else { return }
                self.sessionCount = self.countSessions(); self.updateTitle()
            }
        }
    }
    func confirm(_ title: String, _ text: String) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title; a.informativeText = text
        a.addButton(withTitle: "Stop"); a.addButton(withTitle: "Cancel")
        return a.runModal() == .alertFirstButtonReturn
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()

// `ProcBar --dump` prints the menu as text (for debugging without clicking).
if CommandLine.arguments.contains("--dump") {
    delegate.cpuSample = sampleCpu()
    Thread.sleep(forTimeInterval: 2)
    delegate.menuNeedsUpdate(delegate.menu)
    func walk(_ m: NSMenu, _ depth: Int) {
        let pad = String(repeating: "    ", count: depth)
        for i in m.items {
            let text = i.isSeparatorItem ? "—" : (i.attributedTitle?.string ?? i.title).replacingOccurrences(of: "\t", with: "  ")
            print(pad + text.replacingOccurrences(of: "\n", with: "\n" + pad + "  "))
            if let s = i.submenu { walk(s, depth + 1) }
        }
    }
    walk(delegate.menu, 0)
    exit(0)
}

// `ProcBar --demo <dir>` fills the menu with made-up sessions and saves screenshots of it there.
if let i = CommandLine.arguments.firstIndex(of: "--demo") {
    let dir = i + 1 < CommandLine.arguments.count ? CommandLine.arguments[i + 1] : "docs"
    app.setActivationPolicy(.accessory)
    DispatchQueue.main.async { captureDemo(delegate, to: dir) }
    app.run()
}

app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
