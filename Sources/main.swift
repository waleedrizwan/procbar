// ProcBar — a tiny menu bar monitor for RAM, Claude Code sessions and leftover dev processes.
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

struct SessionMeta { var title: String; var lastActivity: Date?; var permissionMode: String? }

let sessionsRoot = home + "/Library/Application Support/Claude/claude-code-sessions"

func sessionMeta(_ hostId: String) -> SessionMeta? {
    let fm = FileManager.default
    for a in (try? fm.contentsOfDirectory(atPath: sessionsRoot)) ?? [] {
        for b in (try? fm.contentsOfDirectory(atPath: sessionsRoot + "/" + a)) ?? [] {
            let f = "\(sessionsRoot)/\(a)/\(b)/\(hostId).json"
            guard let d = fm.contents(atPath: f),
                  let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
            var last = (j["lastActivityAt"] as? Double).map { Date(timeIntervalSince1970: $0 / 1000) }
            // The CLI transcript is appended on every message/tool call, so its mtime is the freshest signal.
            if let cli = j["cliSessionId"] as? String, let cwd = j["cwd"] as? String {
                let slug = cwd.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ".", with: "-")
                let t = "\(home)/.claude/projects/\(slug)/\(cli).jsonl"
                if let m = (try? fm.attributesOfItem(atPath: t))?[.modificationDate] as? Date, m > (last ?? .distantPast) { last = m }
            }
            return SessionMeta(title: j["title"] as? String ?? "Untitled session", lastActivity: last,
                               permissionMode: j["permissionMode"] as? String)
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

// MARK: - Classification ("why is this running?")

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

let devToolNames: Set<String> = ["node", "bun", "deno", "npm", "npx", "pnpm", "yarn", "uv", "uvx", "vite",
                                  "esbuild", "tsx", "ruby", "java", "cargo", "go", "deno", "watchman", "turbo"]

func isDevTool(_ p: Proc) -> Bool {
    let n = p.name.lowercased()
    return devToolNames.contains(n) || n.hasPrefix("python") || p.path.contains("/node_modules/")
}

func describeHelper(_ p: Proc) -> String {
    let cmd = p.cmdline
    let lc = cmd.lowercased()
    if lc.contains("xcodebuildmcp") { return "XcodeBuildMCP server (iOS build tools for Claude)" }
    if lc.contains("blender-mcp") || lc.contains("blender_mcp") { return "Blender MCP server (lets Claude drive Blender)" }
    if lc.contains("mcp") {
        let tool = p.args.first { $0.lowercased().contains("mcp") }.map { ($0 as NSString).lastPathComponent } ?? p.name
        return "MCP server: \(tool)"
    }
    if ["zsh", "bash", "sh"].contains(p.name) { return "Shell running a command for Claude" }
    if lc.contains("vite") { return "Vite dev server" }
    if p.name == "esbuild" { return "esbuild (bundler used by Vite)" }
    if p.name == "node" || p.name == "bun" || p.name == "tsx" {
        let script = p.args.dropFirst().first { !$0.hasPrefix("-") }.map { ($0 as NSString).lastPathComponent } ?? ""
        return script.isEmpty ? "Node process" : "Node: \(p.args.dropFirst().filter { !$0.hasPrefix("-") }.prefix(2).joined(separator: " "))"
    }
    if p.name.hasPrefix("python") {
        let script = p.args.dropFirst().first { !$0.hasPrefix("-") }.map { ($0 as NSString).lastPathComponent } ?? ""
        return "Python: \(script)"
    }
    return p.name
}

func describeClaudeHelper(_ p: Proc) -> String {
    let a = p.cmdline
    if a.contains("--type=gpu-process") { return "GPU process — draws the Claude window" }
    if a.contains("--type=renderer") { return "Window/tab renderer — Claude's UI" }
    if a.contains("NetworkService") { return "Network service" }
    if a.contains("AudioService") { return "Audio service" }
    if a.contains("video_capture") { return "Camera/screen capture service" }
    if a.contains("node.mojom.NodeService") { return "Node helper (extensions, MCP connectors, previews)" }
    if p.path.hasPrefix("/Applications/Claude.app") && p.ppid == 1 { return "Main Claude app" }
    if !p.path.contains("Claude.app") { return describeHelper(p) + " — started by the Claude app" }
    return p.name
}

let knownServices: [String: String] = [
    "mds": "Spotlight — indexing files for search",
    "mds_stores": "Spotlight — writing the search index",
    "mdworker_shared": "Spotlight — reading files to index them",
    "mdworker": "Spotlight — reading files to index them",
    "WindowServer": "Draws everything on screen; busy when apps animate or redraw a lot",
    "kernel_task": "macOS kernel; also throttles CPU when the Mac is hot",
    "duetexpertd": "Siri/app suggestions learning from your usage",
    "photoanalysisd": "Photos library analysis",
    "mediaanalysisd": "Photos/video analysis",
    "bird": "iCloud Drive sync", "cloudd": "iCloud sync",
    "backupd": "Time Machine backup",
    "softwareupdated": "Checking/installing macOS updates",
    "corespotlightd": "Spotlight for app content",
    "trustd": "Checking code signatures and certificates",
    "syspolicyd": "Gatekeeper checking apps you run",
    "XprotectService": "Malware scanning", "XProtect": "Malware scanning",
    "logd": "System logging",
    "launchd": "Starts and manages every process",
    "contactsd": "Contacts sync", "suggestd": "Siri suggestions",
    "fseventsd": "Tracks file changes (heavy during big file writes/npm installs)",
    "MTLCompilerService": "Compiling GPU shaders for an app",
    "coreaudiod": "Audio", "bluetoothd": "Bluetooth",
]

func appBundleName(_ path: String) -> String? {
    guard let r = path.range(of: ".app/") else { return nil }
    return (String(path[..<r.lowerBound]) as NSString).lastPathComponent
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

// MARK: - Menu model

struct SessionInfo {
    let proc: Proc, title: String, folder: String?, branch: String?
    let lastActivity: Date?, permissionMode: String?, fromDesktop: Bool
    let helpers: [(proc: Proc, mem: UInt64)], treeMem: UInt64, treeCpu: Double, treePids: [pid_t]
    let runningCommand: Bool  // a shell child means a tool call is in progress
    var isWorking: Bool {
        runningCommand || treeCpu > 5 || (lastActivity.map { Date().timeIntervalSince($0) < 180 } ?? false)
    }
}

final class Model {
    var sessions: [SessionInfo] = []
    var leftovers: [(proc: Proc, why: String, folder: String?, ports: [Int], pids: [pid_t], mem: UInt64)] = []
    var claudeApp: (mem: UInt64, cpu: Double, parts: [Proc]) = (0, 0, [])
    var apps: [(name: String, mem: UInt64, cpu: Double, bundle: String, pids: [pid_t])] = []
    var busyServices: [(name: String, why: String, cpu: Double, mem: UInt64, count: Int)] = []
    var background: [(name: String, why: String, mem: UInt64, count: Int)] = []

    init(procs: [pid_t: Proc]) {
        var children: [pid_t: [pid_t]] = [:]
        for p in procs.values { children[p.ppid, default: []].append(p.pid) }
        var claimed = Set<pid_t>()

        // Claude Code sessions (desktop or terminal), with every helper they spawned.
        func hasClaudeAncestor(_ p: Proc) -> Bool {
            var cur = procs[p.ppid]
            while let c = cur, c.pid > 1 { if isClaudeSession(c) { return true }; cur = procs[c.ppid] }
            return false
        }
        let sessionProcs = procs.values.filter { isClaudeSession($0) && !hasClaudeAncestor($0) }
        for s in sessionProcs {
            let tree = descendants(of: s.pid, children: children)
            claimed.formUnion(tree)
            // One row per direct child, with its own sub-processes folded into its memory.
            let helpers = (children[s.pid] ?? []).compactMap { procs[$0] }.map { h in
                (proc: h, mem: descendants(of: h.pid, children: children).compactMap { procs[$0]?.mem }.reduce(0, +))
            }
            let runningCommand = helpers.contains { ["zsh", "bash", "sh"].contains($0.proc.name) }
            let hostId = s.env["CLAUDE_CODE_HOST_SESSION_ID"]
            let meta = hostId.flatMap(sessionMeta)
            let folder = cwd(s.pid)
            let fromDesktop = s.env["CLAUDE_CODE_ENTRYPOINT"] == "claude-desktop" || s.path.contains("Application Support/Claude")
            let mem = tree.compactMap { procs[$0]?.mem }.reduce(0, +)
            let cpu = tree.compactMap { procs[$0]?.cpuPct }.reduce(0, +)
            let mode = meta?.permissionMode ?? s.args.first { $0.hasPrefix("--permission-mode=") }.map { String($0.dropFirst(18)) }
            sessions.append(SessionInfo(
                proc: s, title: meta?.title ?? (folder.map { ($0 as NSString).lastPathComponent } ?? "Claude Code"),
                folder: folder, branch: folder.flatMap(gitBranch), lastActivity: meta?.lastActivity,
                permissionMode: mode, fromDesktop: fromDesktop,
                helpers: helpers.sorted { $0.mem > $1.mem }, treeMem: mem, treeCpu: cpu, treePids: tree,
                runningCommand: runningCommand))
        }
        sessions.sort { ($0.lastActivity ?? $0.proc.started) > ($1.lastActivity ?? $1.proc.started) }

        // Claude desktop app itself (and anything it spawned that isn't a session).
        if let main = procs.values.first(where: { $0.path.hasPrefix("/Applications/Claude.app/Contents/MacOS/") }) {
            let tree = descendants(of: main.pid, children: children).filter { !claimed.contains($0) }
            let parts = tree.compactMap { procs[$0] }.filter { $0.name != "disclaimer" }
            claimed.formUnion(tree)
            claudeApp = (parts.map(\.mem).reduce(0, +), parts.map(\.cpuPct).reduce(0, +), parts.sorted { $0.mem > $1.mem })
        }

        // Leftover dev processes: my dev tools whose parent died (adopted by launchd).
        var leftoverPids: [pid_t] = []
        for p in procs.values where p.uid == myUid && p.ppid == 1 && !claimed.contains(p.pid) && isDevTool(p) && appBundleName(p.path) == nil {
            leftoverPids.append(p.pid)
        }
        let ports = listeningPorts(leftoverPids)
        for pid in leftoverPids {
            guard let p = procs[pid] else { continue }
            let tree = descendants(of: pid, children: children)
            claimed.formUnion(tree)
            let folder = cwd(pid)
            leftovers.append((p, describeHelper(p), folder, ports[pid] ?? [], tree, tree.compactMap { procs[$0]?.mem }.reduce(0, +)))
        }
        leftovers.sort { $0.mem > $1.mem }

        // Other apps grouped by bundle; system services that are busy right now.
        var byApp: [String: (mem: UInt64, cpu: Double, bundle: String, pids: [pid_t])] = [:]
        var bySvc: [String: (cpu: Double, mem: UInt64, count: Int)] = [:]
        for p in procs.values where !claimed.contains(p.pid) {
            if let app = appBundleName(p.path), !p.path.hasPrefix("/System/") || p.path.contains("/Applications/") {
                if p.uid != myUid { continue }  // root-owned: unreadable, counted in the system remainder
                var e = byApp[app] ?? (0, 0, String(p.path[..<p.path.range(of: ".app/")!.lowerBound]) + ".app", [])
                e.mem += p.mem; e.cpu += p.cpuPct; e.pids.append(p.pid)
                byApp[app] = e
            } else {
                let key = p.name.hasPrefix("mdworker") ? "mdworker_shared" : p.name
                var e = bySvc[key] ?? (0, 0, 0)
                e.cpu += p.cpuPct; e.mem += p.mem; e.count += 1
                bySvc[key] = e
            }
        }
        apps = byApp.map { ($0.key, $0.value.mem, $0.value.cpu, $0.value.bundle, $0.value.pids) }.sorted { $0.mem > $1.mem }
        var bg: [String: (mem: UInt64, count: Int)] = [:]
        // Everything mine not shown as an app, including Finder/Dock/Control Center (system .app bundles).
        let inApps = Set(byApp.values.flatMap(\.pids))
        for p in procs.values where !claimed.contains(p.pid) && p.uid == myUid && !inApps.contains(p.pid) {
            let key = p.name.hasPrefix("mdworker") ? "mdworker_shared" : p.name
            bg[key, default: (0, 0)].mem += p.mem; bg[key, default: (0, 0)].count += 1
        }
        background = bg.map { k, v in (k, knownServices[k] ?? "", v.mem, v.count) }
            .sorted { $0.mem > $1.mem }
        busyServices = bySvc.filter { $0.value.cpu >= 15 }.map { k, v in
            (k, knownServices[k] ?? "System/background process", v.cpu, v.mem, v.count)
        }.sorted { $0.cpu > $1.cpu }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    var cpuSample: [pid_t: (UInt64, Date)] = [:]
    var sessionCount = 0
    var actions: [() -> Void] = []

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

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        actions.removeAll()
        let procs = snapshot(prevCpu: cpuSample)
        cpuSample = procs.mapValues { ($0.cpuNs, Date()) }
        let model = Model(procs: procs)
        sessionCount = model.sessions.count
        updateTitle()

        let m = memStats()
        // Ledger: every row is a slice of "used", and the rows add up to it exactly.
        let sMem = model.sessions.map(\.treeMem).reduce(0, +)
        let lMem = model.leftovers.map(\.mem).reduce(0, +)
        let shownApps = model.apps.prefix(4)
        let restApps = model.apps.dropFirst(4)
        let bgMem = model.background.map(\.mem).reduce(0, +)
        let mine = model.claudeApp.mem + sMem + lMem + model.apps.map(\.mem).reduce(0, +) + bgMem
        let system = m.used > mine + m.wired ? m.used - mine - m.wired : 0

        header("Memory used: \(fmtBytes(m.used)) of \(fmtBytes(m.total))")
        info("Pressure \(m.pressureName) · swap \(fmtBytes(m.swapUsed)) · every row below adds up to this")

        if model.claudeApp.mem > 0 {
            let sub = NSMenu()
            subInfo(sub, "The Claude desktop app window and its built-in services")
            for p in model.claudeApp.parts.prefix(14) {
                subInfo(sub, "\(describeClaudeHelper(p)) — \(fmtBytes(p.mem))" + (p.cpuPct >= 1 ? String(format: " · %.0f%% CPU", p.cpuPct) : ""))
            }
            ledger("Claude app" + cpuNote(model.claudeApp.cpu), model.claudeApp.mem, sub)
        }
        if !model.sessions.isEmpty { ledger("Claude Code sessions (\(model.sessions.count)) — details below", sMem) }
        if !model.leftovers.isEmpty { ledger("Leftover dev processes (\(model.leftovers.count)) — details below", lMem) }
        for a in shownApps { ledger(a.name + cpuNote(a.cpu), a.mem, appMenu(a.bundle, a.pids)) }
        if !restApps.isEmpty {
            let sub = NSMenu()
            for a in restApps.prefix(40) {
                let row = NSMenuItem(title: "\(a.name) — \(fmtBytes(a.mem))", action: nil, keyEquivalent: "")
                row.submenu = appMenu(a.bundle, a.pids)
                sub.addItem(row)
            }
            ledger("Other apps (\(restApps.count))", restApps.map(\.mem).reduce(0, +), sub)
        }
        let bgSub = NSMenu()
        subInfo(bgSub, "Small processes with no window: menu bar items, helpers, agents, shells")
        bgSub.addItem(.separator())
        for b in model.background.prefix(30) {
            subInfo(bgSub, "\(b.name)\(b.count > 1 ? " ×\(b.count)" : "") — \(fmtBytes(b.mem))" + (b.why.isEmpty ? "" : " · \(b.why)"))
        }
        if model.background.count > 30 {
            let rest = model.background.dropFirst(30)
            subInfo(bgSub, "…and \(rest.count) more — \(fmtBytes(rest.map(\.mem).reduce(0, +)))")
        }
        ledger("Background processes (\(model.background.map(\.count).reduce(0, +)))", bgMem, bgSub)
        let wSub = NSMenu()
        subInfo(wSub, "Memory the macOS kernel and graphics chip have locked in place.")
        subInfo(wSub, "On Apple Silicon the GPU shares RAM, so graphics for Chrome tabs,")
        subInfo(wSub, "games and app windows are counted here, not under the app.")
        ledger("Graphics (GPU) + macOS kernel", m.wired, wSub)
        let sysSub = NSMenu()
        subInfo(sysSub, "System-owned processes (WindowServer, Spotlight, etc.) that")
        subInfo(sysSub, "macOS won't let other apps measure one by one, plus shared memory.")
        subInfo(sysSub, "Includes \(fmtBytes(m.compressed)) of compressed memory.")
        ledger("macOS system processes", system, sysSub)
        let total = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        total.attributedTitle = tabbed("Total", fmtBytes(model.claudeApp.mem + sMem + lMem + model.apps.map(\.mem).reduce(0, +) + bgMem + m.wired + system), bold: true)
        menu.addItem(total)
        info("Not counted: \(fmtBytes(m.cached)) of cached files (freed instantly when an app needs it)")
        var load = [Double](repeating: 0, count: 3); getloadavg(&load, 3)
        info(String(format: "CPU load %.1f on %d cores — above %d means things are waiting", load[0],
                    ProcessInfo.processInfo.activeProcessorCount, ProcessInfo.processInfo.activeProcessorCount))
        menu.addItem(.separator())

        // Claude sessions
        header("Claude Code sessions (\(model.sessions.count)) — \(fmtBytes(sMem))")
        if model.sessions.isEmpty { info("None running") }
        for s in model.sessions {
            let state = s.isWorking ? "● working" : "○ idle " + fmtAgo(Date().timeIntervalSince(s.lastActivity ?? s.proc.started))
            let row = NSMenuItem(title: "\(s.title) — \(fmtBytes(s.treeMem)) · \(state)", action: nil, keyEquivalent: "")
            let sub = NSMenu()
            subInfo(sub, "Why: Claude Code session " + (s.fromDesktop ? "kept alive by the Claude app (open in its sidebar)" : "started from a terminal"))
            if let f = s.folder { subInfo(sub, "Folder: \(tilde(f))" + (s.branch.map { " (branch \($0))" } ?? "")) }
            subInfo(sub, "Running \(fmtAgo(Date().timeIntervalSince(s.proc.started)))" +
                    (s.lastActivity.map { " · last activity \(fmtAgo(Date().timeIntervalSince($0))) ago" } ?? "") +
                    String(format: " · CPU %.0f%%", s.treeCpu))
            if let pm = s.permissionMode { subInfo(sub, "Permission mode: \(pm)") }
            subInfo(sub, "Claude itself: \(fmtBytes(s.proc.mem)) (pid \(s.proc.pid))")
            if !s.helpers.isEmpty {
                sub.addItem(.separator())
                subHeader(sub, "Helpers it started (\(s.helpers.count))")
                for h in s.helpers { subInfo(sub, "\(describeHelper(h.proc)) — \(fmtBytes(h.mem))") }
            }
            sub.addItem(.separator())
            subAction(sub, "Force Quit session + helpers (frees \(fmtBytes(s.treeMem)))") { [weak self] in
                if s.isWorking, self?.confirm("“\(s.title)” looks busy right now. Force quit it anyway?",
                                              "Its current turn will be cut off. The session stays in the Claude sidebar and restarts when you open it.") != true { return }
                killTree(s.treePids)
            }
            row.submenu = sub
            menu.addItem(row)
        }
        let idle = model.sessions.filter { !$0.isWorking }
        if idle.count > 0 {
            action("Force Quit \(idle.count) idle session\(idle.count == 1 ? "" : "s") (frees \(fmtBytes(idle.map(\.treeMem).reduce(0, +))))") {
                for s in idle { killTree(s.treePids) }
            }
        }
        menu.addItem(.separator())

        // Leftovers
        if !model.leftovers.isEmpty {
            header("Leftover dev processes (\(model.leftovers.count)) — \(fmtBytes(model.leftovers.map(\.mem).reduce(0, +)))")
            for l in model.leftovers {
                let port = l.ports.isEmpty ? "" : " · :" + l.ports.map(String.init).joined(separator: ", :")
                let row = NSMenuItem(title: "\(l.why)\(port) — \(fmtBytes(l.mem))", action: nil, keyEquivalent: "")
                let sub = NSMenu()
                subInfo(sub, "Why: whatever started it (a closed session or terminal) is gone, so nothing will stop it")
                if let f = l.folder { subInfo(sub, "Folder: \(tilde(f))") }
                subInfo(sub, "Running \(fmtAgo(Date().timeIntervalSince(l.proc.started))) · pid \(l.proc.pid)" + String(format: " · CPU %.0f%%", l.proc.cpuPct))
                subInfo(sub, String(l.proc.cmdline.prefix(90)))
                if let port = l.ports.first {
                    subAction(sub, "Open http://localhost:\(port)") { NSWorkspace.shared.open(URL(string: "http://localhost:\(port)")!) }
                }
                sub.addItem(.separator())
                subAction(sub, "Force Quit") { killTree(l.pids) }
                row.submenu = sub
                menu.addItem(row)
            }
            action("Force Quit all leftovers") { for l in model.leftovers { killTree(l.pids) } }
            menu.addItem(.separator())
        }

        if !model.busyServices.isEmpty {
            header("Busy system services")
            for s in model.busyServices.prefix(5) {
                let count = s.count > 1 ? " ×\(s.count)" : ""
                info(String(format: "%@%@ — %.0f%% CPU: %@", s.name, count, s.cpu, s.why))
            }
            menu.addItem(.separator())
        }

        action("Open Activity Monitor") { NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Activity Monitor.app")) }
        action("Quit ProcBar") { NSApp.terminate(nil) }
    }

    // MARK: menu helpers

    func cpuNote(_ cpu: Double) -> String { cpu >= 5 ? String(format: " · %.0f%% CPU", cpu) : "" }

    func tabbed(_ left: String, _ right: String, bold: Bool = false) -> NSAttributedString {
        let ps = NSMutableParagraphStyle()
        ps.tabStops = [NSTextTab(textAlignment: .right, location: 420)]
        return NSAttributedString(string: left + "\t" + right, attributes: [
            .paragraphStyle: ps,
            .font: bold ? NSFont.boldSystemFont(ofSize: 13) : NSFont.menuFont(ofSize: 13)])
    }

    func ledger(_ name: String, _ bytes: UInt64, _ sub: NSMenu? = nil) {
        let i = NSMenuItem(title: name, action: nil, keyEquivalent: "")
        i.attributedTitle = tabbed("    " + name, fmtBytes(bytes))
        i.submenu = sub
        menu.addItem(i)
    }

    /// Targets the app by bundle, not by pid: the group's pids include helpers, renderers and widget extensions,
    /// and killing one of those leaves the app running. With no main app (e.g. only widgets), kill the whole group.
    func appMenu(_ bundle: String, _ pids: [pid_t]) -> NSMenu {
        let sub = NSMenu()
        func running() -> NSRunningApplication? {
            NSWorkspace.shared.runningApplications.first { $0.bundleURL?.path == bundle }
        }
        subAction(sub, "Quit") { if running()?.terminate() == nil { for p in pids { kill(p, SIGTERM) } } }
        subAction(sub, "Force Quit") { if running()?.forceTerminate() != true { for p in pids { kill(p, SIGKILL) } } }
        return sub
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
    func action(_ s: String, _ f: @escaping () -> Void) { subAction(menu, s, f) }
    func subAction(_ m: NSMenu, _ s: String, _ f: @escaping () -> Void) {
        let i = NSMenuItem(title: s, action: #selector(run(_:)), keyEquivalent: "")
        i.target = self
        i.tag = actions.count
        actions.append(f)
        m.addItem(i)
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
        a.addButton(withTitle: "Force Quit"); a.addButton(withTitle: "Cancel")
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
        for i in m.items {
            print(String(repeating: "    ", count: depth) + (i.isSeparatorItem ? "—" : i.title))
            if let s = i.submenu { walk(s, depth + 1) }
        }
    }
    walk(delegate.menu, 0)
    exit(0)
}

app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
