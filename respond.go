package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// ResponseConfig controls which active defense actions fire on alert.
type ResponseConfig struct {
	DisconnectNetwork bool
	KillReaders       bool
	AlertLog          string // path to forensic log file ("" = disabled)
	LockScreen        bool
}

func (r ResponseConfig) anyEnabled() bool {
	return r.DisconnectNetwork || r.KillReaders || r.AlertLog != "" || r.LockScreen
}

// --- Action 1: Disconnect networking ---

func respondDisconnectNetwork() {
	if os.Getuid() != 0 {
		log.Printf("[disconnect] skipping: requires root")
		return
	}

	// Disable Wi-Fi specifically
	if out, err := exec.Command("networksetup", "-setairportpower", "en0", "off").CombinedOutput(); err != nil {
		log.Printf("[disconnect] Wi-Fi off failed: %v %s", err, out)
	} else {
		log.Printf("[disconnect] Wi-Fi disabled (en0)")
	}

	// Disable all network services
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		log.Printf("[disconnect] list services failed: %v", err)
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		if out, err := exec.Command("networksetup", "-setnetworkserviceenabled", line, "off").CombinedOutput(); err != nil {
			log.Printf("[disconnect] disable %q failed: %v %s", line, err, out)
		} else {
			log.Printf("[disconnect] disabled: %s", line)
		}
	}
}

// --- Action 2: Kill reader processes ---

// boundaryProcesses are process names we don't want to kill — they represent
// the user's session boundary. We kill the process just below these.
var boundaryProcesses = map[string]bool{
	"launchd":     true,
	"loginwindow": true,
	"sshd":        true,
	"Terminal":    true,
	"iTerm2":      true,
	"iTerm":       true,
	"tmux":        true,
	"screen":      true,
}

// findKillTarget walks up from readerPID to find the right process to kill.
// Returns the PID just below the first boundary process, or readerPID itself
// if no boundary is found.
func findKillTarget(readerPID int) (targetPID int, targetName string, chain string) {
	prev := readerPID
	prevName := strings.TrimSpace(psField(readerPID, "comm"))
	pid := readerPID
	visited := map[int]bool{}

	var chainParts []string
	chainParts = append(chainParts, fmt.Sprintf("%s(%d)", prevName, pid))

	for {
		visited[pid] = true
		ppidStr := strings.TrimSpace(psField(pid, "ppid"))
		ppid := 0
		fmt.Sscanf(ppidStr, "%d", &ppid)
		if ppid <= 0 || ppid == pid || visited[ppid] {
			break
		}
		parentName := strings.TrimSpace(psField(ppid, "comm"))
		if parentName == "" {
			break
		}
		chainParts = append(chainParts, fmt.Sprintf("%s(%d)", parentName, ppid))
		if boundaryProcesses[parentName] {
			return prev, prevName, strings.Join(chainParts, " → ")
		}
		prev = ppid
		prevName = parentName
		pid = ppid
	}
	// No boundary found; kill the original reader
	return readerPID, prevName, strings.Join(chainParts, " → ")
}

func respondKillReaders(al Alert, pids []int) {
	if len(pids) == 0 {
		log.Printf("[kill] no reader PIDs identified for %s%s", al.Mount, al.Path)
		return
	}

	killed := map[int]bool{}
	for _, pid := range pids {
		target, name, chain := findKillTarget(pid)
		if killed[target] {
			continue
		}
		log.Printf("[kill] chain: %s", chain)
		log.Printf("[kill] killing %s(%d) for reading %s%s", name, target, al.Mount, al.Path)
		if err := syscall.Kill(target, syscall.SIGKILL); err != nil {
			log.Printf("[kill] kill %d failed: %v", target, err)
		} else {
			log.Printf("[kill] killed %s(%d)", name, target)
		}
		killed[target] = true
	}
}

// --- Action 3: Forensic alert log ---

func respondAlertLog(al Alert, lsofOut string, trees []string, logPath string) {
	entry := formatAlertEntry(al, lsofOut, trees)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[alert-log] write failed: %v", err)
		return
	}
	f.WriteString(entry)
	f.Close()
	log.Printf("[alert-log] written to %s", logPath)

	// Copy to clipboard
	copyToClipboard(entry)
}

func formatAlertEntry(al Alert, lsofOut string, trees []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== CANARY ALERT %s ===\n", al.Time.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintf(&b, "Severity:  %s\n", al.Severity)
	fmt.Fprintf(&b, "Operation: %s\n", al.Operation)
	fmt.Fprintf(&b, "File:      %s%s\n", al.Mount, al.Path)
	if len(trees) > 0 {
		b.WriteString("\nProcess Tree:\n")
		for _, t := range trees {
			fmt.Fprintf(&b, "  %s\n", t)
		}
	}
	if lsofOut != "" {
		fmt.Fprintf(&b, "\nlsof output:\n%s\n", lsofOut)
	}
	b.WriteString("==========================================\n")
	return b.String()
}

func copyToClipboard(text string) {
	var cmd *exec.Cmd
	if os.Getuid() == 0 {
		user := consoleUser()
		if user == "" || user == "root" {
			return
		}
		cmd = exec.Command("sudo", "-u", user, "pbcopy")
	} else {
		cmd = exec.Command("pbcopy")
	}
	cmd.Stdin = strings.NewReader(text)
	cmd.Run()
}

// --- Action 4: Full-screen lockscreen overlay ---

func respondLockScreen(al Alert, trees []string) {
	treeStr := "(process identification unavailable)"
	if len(trees) > 0 {
		treeStr = strings.Join(trees, "\n    ")
	}

	// Build the JXA (JavaScript for Automation) script that creates a
	// full-screen NSWindow via the ObjC bridge. This uses only osascript
	// which ships with every macOS — no Swift, no signing, no quarantine.
	script := fmt.Sprintf(`
ObjC.import('Cocoa');

var app = $.NSApplication.sharedApplication;
app.setActivationPolicy($.NSApplicationActivationPolicyRegular);

var screen = $.NSScreen.mainScreen;
var frame = screen.frame;

var window = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer(
    frame,
    0,  // borderless
    $.NSBackingStoreBuffered,
    false
);
window.setLevel(25);  // above screenSaver level
window.setCollectionBehavior($.NSWindowCollectionBehaviorCanJoinAllSpaces);
window.setOpaque(true);
window.setBackgroundColor($.NSColor.colorWithRedGreenBlueAlpha(0.6, 0.0, 0.0, 1.0));

var view = $.NSView.alloc.initWithFrame(frame);
window.setContentView(view);

var message = %q;

var label = $.NSTextField.wrappingLabelWithString(message);
label.setTextColor($.NSColor.whiteColor);
label.setFont($.NSFont.monospacedSystemFontOfSizeWeight(20, 0.7));
label.setAlignment($.NSTextAlignmentCenter);
label.setBackgroundColor($.NSColor.clearColor);
label.setBezeled(false);
label.setEditable(false);
label.setFrame({
    origin: { x: 40, y: frame.size.height * 0.25 },
    size: { width: frame.size.width - 80, height: frame.size.height * 0.6 }
});
view.addSubview(label);

var button = $.NSButton.alloc.initWithFrame({
    origin: { x: frame.size.width/2 - 120, y: 60 },
    size: { width: 240, height: 44 }
});
button.setTitle("Dismiss (I understand)");
button.setBezelStyle($.NSBezelStyleRounded);
button.setTarget(app);
button.setAction("terminate:");
view.addSubview(button);

window.makeKeyAndOrderFront(null);
app.activateIgnoringOtherApps(true);
app.run();
`,
		fmt.Sprintf("CANARY ALERT\n\nA honeypot file was accessed!\n\nSeverity:  %s\nOperation: %s\nFile:      %s%s\n\nProcess tree:\n    %s\n\nClick Dismiss to continue.",
			al.Severity, al.Operation, al.Mount, al.Path, treeStr),
	)

	runAsConsoleUser("osascript", "-l", "JavaScript", "-e", script)
}

// runAsConsoleUser runs a command as the GUI user (needed when running as root).
func runAsConsoleUser(name string, args ...string) {
	if os.Getuid() == 0 {
		user := consoleUser()
		if user == "" || user == "root" {
			return
		}
		sudoArgs := append([]string{"-u", user, name}, args...)
		exec.Command("sudo", sudoArgs...).Run()
	} else {
		exec.Command(name, args...).Run()
	}
}
