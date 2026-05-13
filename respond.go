package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
)

// ResponseConfig controls which active defense actions fire on alert.
type ResponseConfig struct {
	DisconnectNetwork bool
	KillReaders       bool
	AlertLog          string // path to forensic log file ("" = disabled)
	LockScreen        bool
	Tarpit            bool
}

func (r ResponseConfig) anyEnabled() bool {
	return r.DisconnectNetwork || r.KillReaders || r.AlertLog != "" || r.LockScreen
}

// buildPlainSummary creates a human-readable summary of what happened and what
// canary did about it. Used in both the alert log and the lockscreen overlay.
func buildPlainSummary(al Alert, trees []string, actions []string) string {
	var b strings.Builder
	b.WriteString("One of your canary files was just accessed.\n\n")
	fmt.Fprintf(&b, "File: %s%s\n", al.Mount, al.Path)
	fmt.Fprintf(&b, "Time: %s\n", al.Time.Format("2006-01-02 3:04:05 PM"))

	if len(trees) > 0 {
		b.WriteString("\nProcess tree:\n")
		for _, t := range trees {
			// Each tree is already multi-line with indentation; indent the whole block
			for _, line := range strings.Split(t, "\n") {
				fmt.Fprintf(&b, "  %s\n", line)
			}
		}
	} else {
		b.WriteString("\nProcess: could not be identified\n")
	}

	if len(actions) > 0 {
		b.WriteString("\nActions taken:\n")
		for _, a := range actions {
			fmt.Fprintf(&b, "  - %s\n", a)
		}
	}

	return b.String()
}

// --- Action 1: Disconnect networking ---

// networkDisconnected tracks whether we've disabled networking so we can
// re-enable it on shutdown.
var networkDisconnected bool

// wifiInterfaces finds all Wi-Fi hardware ports (usually just en0, but
// some Macs have additional Wi-Fi adapters).
func wifiInterfaces() []string {
	out, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return []string{"en0"} // fallback
	}
	var ifaces []string
	var nextIsDevice bool
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") && strings.Contains(line, "Wi-Fi") {
			nextIsDevice = true
			continue
		}
		if nextIsDevice && strings.HasPrefix(line, "Device:") {
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev != "" {
				ifaces = append(ifaces, dev)
			}
			nextIsDevice = false
		}
	}
	if len(ifaces) == 0 {
		return []string{"en0"}
	}
	return ifaces
}

// respondDisconnectNetwork turns off Wi-Fi power on all Wi-Fi interfaces.
// This is intentionally user-recoverable: the user can re-enable Wi-Fi from
// the menu bar icon or System Settings without admin credentials. We avoid
// `networksetup -setnetworkserviceenabled off` because that greys out the UI
// toggle and requires admin to reverse.
func respondDisconnectNetwork() {
	if os.Getuid() != 0 {
		log.Printf("[disconnect] skipping: requires root")
		return
	}
	for _, iface := range wifiInterfaces() {
		if out, err := exec.Command("networksetup", "-setairportpower", iface, "off").CombinedOutput(); err != nil {
			log.Printf("[disconnect] Wi-Fi off failed (%s): %v %s", iface, err, out)
		} else {
			log.Printf("[disconnect] Wi-Fi disabled (%s)", iface)
		}
	}
	networkDisconnected = true
}

// respondReconnectNetwork re-enables Wi-Fi power. Called on shutdown to
// restore connectivity after a disconnect response.
func respondReconnectNetwork() {
	if !networkDisconnected {
		return
	}
	log.Println("[reconnect] re-enabling Wi-Fi...")
	for _, iface := range wifiInterfaces() {
		if out, err := exec.Command("networksetup", "-setairportpower", iface, "on").CombinedOutput(); err != nil {
			log.Printf("[reconnect] Wi-Fi on failed (%s): %v %s", iface, err, out)
		} else {
			log.Printf("[reconnect] Wi-Fi re-enabled (%s)", iface)
		}
	}
	networkDisconnected = false
}

// --- Action 2: Kill reader processes ---

// boundaryProcesses are process names we don't want to kill — they represent
// the user's session boundary. We kill the process just below these.
// boundaryProcesses are processes we never kill — they represent session
// infrastructure above the shell. We kill the process just below these,
// which is typically the shell itself (ending the attacker's session).
var boundaryProcesses = map[string]bool{
	// System / session infrastructure
	"launchd":     true,
	"loginwindow": true,
	"sshd":        true,
	// Terminal emulators
	"Terminal": true,
	"iTerm2":   true,
	"iTerm":    true,
	// Terminal multiplexers
	"tmux":   true,
	"screen": true,
	// Login helpers
	"login": true,
}

// isBoundaryProcess checks both the short name and the full path's basename.
func isBoundaryProcess(name string) bool {
	if boundaryProcesses[name] {
		return true
	}
	// Full path: "/usr/bin/login" → check "login"
	base := path.Base(name)
	if boundaryProcesses[base] {
		return true
	}
	return false
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
		if isBoundaryProcess(parentName) {
			return prev, prevName, strings.Join(chainParts, " → ")
		}
		prev = ppid
		prevName = parentName
		pid = ppid
	}
	// No boundary found; kill the original reader
	return readerPID, prevName, strings.Join(chainParts, " → ")
}

// respondKillReaders kills the identified reader processes and returns a
// human-readable description of what was killed for use in the actions summary.
func respondKillReaders(al Alert, pids []int) string {
	if len(pids) == 0 {
		log.Printf("[kill] no reader PIDs identified for %s%s", al.Mount, al.Path)
		return ""
	}

	killed := map[int]bool{}
	var descriptions []string
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
			readerName := strings.TrimSpace(psField(pid, "comm"))
			if readerName == "" {
				readerName = "unknown"
			}
			if target == pid {
				descriptions = append(descriptions, fmt.Sprintf("Killed the process reading this file: %s (PID %d).", readerName, pid))
			} else {
				descriptions = append(descriptions, fmt.Sprintf("Killed the process reading this file (%s, PID %d) and its parents, up to and including %s (PID %d).", readerName, pid, name, target))
			}
		}
		killed[target] = true
	}
	return strings.Join(descriptions, " ")
}

// --- Action 3: Forensic alert log ---

func respondAlertLog(al Alert, lsofOut string, trees []string, actions []string, logPath string) {
	summary := buildPlainSummary(al, trees, actions)

	var b strings.Builder
	fmt.Fprintf(&b, "\n========================================\n")
	b.WriteString(summary)
	if lsofOut != "" {
		fmt.Fprintf(&b, "\nRaw lsof output:\n%s\n", lsofOut)
	}
	fmt.Fprintf(&b, "========================================\n")
	entry := b.String()

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

func respondLockScreen(al Alert, trees []string, actions []string) *os.Process {
	summary := buildPlainSummary(al, trees, actions)
	message := summary + "\nClick Dismiss to close this alert."

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
label.setAlignment($.NSTextAlignmentLeft);
label.setBackgroundColor($.NSColor.clearColor);
label.setBezeled(false);
label.setEditable(false);
label.setFrame({
    origin: { x: 80, y: frame.size.height * 0.2 },
    size: { width: frame.size.width - 160, height: frame.size.height * 0.65 }
});
view.addSubview(label);

var buttonY = frame.size.height * 0.2 - 60;
var button = $.NSButton.alloc.initWithFrame({
    origin: { x: 80, y: buttonY },
    size: { width: 280, height: 44 }
});
button.setTitle("Dismiss (I understand)");
button.setBezelStyle($.NSBezelStyleRegularSquare);
button.setBordered(false);
button.setFont($.NSFont.systemFontOfSizeWeight(16, 0.5));
button.setContentTintColor($.NSColor.whiteColor);
button.setTarget(app);
button.setAction("terminate:");
view.addSubview(button);

window.makeKeyAndOrderFront(null);
app.activateIgnoringOtherApps(true);
app.run();
`, message)

	return startAsConsoleUser("osascript", "-l", "JavaScript", "-e", script)
}

// startAsConsoleUser starts a command as the GUI user (needed when running as root).
// Returns the process so the caller can track whether it's still alive.
func startAsConsoleUser(name string, args ...string) *os.Process {
	var cmd *exec.Cmd
	if os.Getuid() == 0 {
		user := consoleUser()
		if user == "" || user == "root" {
			return nil
		}
		sudoArgs := append([]string{"-u", user, name}, args...)
		cmd = exec.Command("sudo", sudoArgs...)
	} else {
		cmd = exec.Command(name, args...)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[lockscreen] failed to start: %v", err)
		return nil
	}
	return cmd.Process
}
