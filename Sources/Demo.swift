// Made-up sessions for README screenshots, so real project names never end up in a picture.

import AppKit

private let mb: UInt64 = 1_048_576

private func fake(_ pid: pid_t, _ name: String, _ cmd: String, mem: UInt64, cpu: Double = 0, age: TimeInterval) -> Proc {
    var p = Proc(pid: pid, ppid: 1, uid: myUid, name: name, path: "", mem: mem * mb, cpuNs: 0, started: Date(timeIntervalSinceNow: -age))
    p.args = cmd.split(separator: " ").map(String.init)
    p.cpuPct = cpu
    return p
}

private func part(_ p: Proc, _ kind: Kind, _ label: String, _ explain: String, ports: [Int] = []) -> Part {
    Part(proc: p, kind: kind, label: label, explain: explain, mem: p.mem, cpu: p.cpuPct, pids: [p.pid], ports: ports)
}

private func session(_ pid: pid_t, _ title: String, folder: String, branch: String?, activity: Activity,
                     agentMem: UInt64, cpu: Double = 0, age: TimeInterval, extra: [Part]) -> SessionInfo {
    let agent = fake(pid, "claude", "claude", mem: agentMem, cpu: cpu, age: age)
    let mcp = fake(pid + 1, "node", "npm exec xcodebuildmcp@latest mcp", mem: 120 + UInt64(pid % 7) * 3, age: age)
    let (_, label, explain) = describePart(mcp, sessionBusy: false)
    return SessionInfo(proc: agent, title: title, folder: home + "/code/" + folder, branch: branch, lastActivity: activity.at,
                       permissionMode: "auto", fromDesktop: true, activity: activity,
                       parts: [part(agent, .agent, "Claude (the session itself)", "Holds the conversation. Comes back when you reopen the chat."),
                               part(mcp, .plugin, label, explain)] + extra)
}

func demoModel() -> Model {
    let m = Model()
    let ago = { (s: TimeInterval) in Date(timeIntervalSinceNow: -s) }
    let test = fake(110, "zsh", "zsh -c npm test -- --watch=false", mem: 210, cpu: 85, age: 40)
    let vite = fake(130, "zsh", "zsh -c npm run dev", mem: 96, age: 3100)
    let preview = fake(140, "Python", "Python -m http.server -d site 8765", mem: 12, age: 2400)
    m.sessions = [
        session(100, "Add offline mode to the notes app", folder: "notes-app", branch: "offline-mode",
                activity: .usingTool("Bash", "running `npm test -- --watch=false`", ago(40)), agentMem: 238, cpu: 4, age: 1900,
                extra: [part(test, .command, "Running `npm test -- --watch=false`", "A command Claude is running for the current task.")]),
        session(120, "Pick a charting library", folder: "dashboard", branch: "main",
                activity: .needsAnswer(ago(260)), agentMem: 201, age: 900, extra: []),
        session(125, "Landing page redesign", folder: "website", branch: "redesign",
                activity: .finished(ago(840)), agentMem: 214, age: 3600,
                extra: [part(vite, .background, "Still running `npm run dev`",
                             "Claude started this in the background and it outlived the task. Usually safe to stop.", ports: [5173]),
                        part(preview, .preview, "Preview server: Python web server", "Started by the Claude app to show a preview of this project.", ports: [8765])]),
        session(150, "Fix flaky login test", folder: "api", branch: "main",
                activity: .finished(ago(2 * 3600 + 720)), agentMem: 187, age: 3 * 3600, extra: []),
        session(160, "Swift concurrency warnings", folder: "ios-app", branch: "swift6",
                activity: .interrupted(ago(5 * 3600)), agentMem: 176, age: 6 * 3600,
                extra: [part(fake(161, "sourcekit-lsp", "sourcekit-lsp", mem: 6, age: 6 * 3600), .codeIntel,
                             "Code intelligence: sourcekit-lsp", "Helps Claude jump to definitions and see compiler errors.")]),
    ]
    let orphan = fake(170, "node", "node node_modules/.bin/next dev", mem: 412, age: 26 * 3600)
    m.orphans = [(part(orphan, .other, "Next.js dev server", "", ports: [3000]), "Checkout page bug", home + "/code/shop")]
    m.simulators = [Simulator(udid: "", name: "iPhone 17 Pro", apps: ["NotesApp"], mem: 1_310 * mb, cpu: 3, started: ago(2 * 3600))]
    m.app = (1_740 * mb, 6, [("Window contents (chat, panes, previews)", 980 * mb, 4), ("Main app", 330 * mb, 1),
                            ("Background helper (connectors, terminal, previews)", 240 * mb, 0), ("Drawing the window (GPU)", 190 * mb, 1)])
    return m
}

/// Pops the menu (and one session's details) on screen and saves each with `screencapture`.
func captureDemo(_ d: AppDelegate, to dir: String) {
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    d.demo = demoModel()
    let menu = d.menu  // the menu helpers always write to the delegate's own menu
    d.menuNeedsUpdate(menu)
    NSApp.appearance = NSAppearance(named: CommandLine.arguments.contains("--light") ? .aqua : .darkAqua)
    func shoot(_ m: NSMenu, _ name: String) {
        let t = Timer(timeInterval: 0.8, repeats: false) { _ in
            let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
            let mine = windows.filter { $0[kCGWindowOwnerPID as String] as? pid_t == getpid() }
            let area = { (w: [String: Any]) -> CGFloat in
                let b = w[kCGWindowBounds as String] as? [String: CGFloat] ?? [:]
                return (b["Width"] ?? 0) * (b["Height"] ?? 0)
            }
            if let id = mine.max(by: { area($0) < area($1) })?[kCGWindowNumber as String] as? Int {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                p.arguments = ["-x", "-o", "-l\(id)", "\(dir)/\(name).png"]
                try? p.run(); p.waitUntilExit()
                print("saved \(dir)/\(name).png")
            }
            m.cancelTracking()
        }
        RunLoop.main.add(t, forMode: .common)
        RunLoop.main.add(t, forMode: .eventTracking)
        m.popUp(positioning: nil, at: NSPoint(x: 80, y: (NSScreen.main?.visibleFrame.maxY ?? 900) - 10), in: nil)
    }
    shoot(menu, "menu")
    if let detail = menu.items.first(where: { $0.title.contains("Landing page") })?.submenu {
        detail.supermenu?.setSubmenu(nil, for: detail.supermenu!.items.first { $0.submenu === detail }!)
        shoot(detail, "session")
    }
    exit(0)
}
