package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Alert struct {
	Time      time.Time
	Severity  Severity
	Operation string // READ, WRITE, DELETE, READDIR, MKDIR
	Path      string // path within canary tree
	Mount     string // mount point on host filesystem
	Message   string
}

type Alerter struct {
	notify        bool
	verbose       bool
	resp          ResponseConfig
	cooldown      map[string]time.Time
	mu            sync.Mutex
	lockScreenProc *os.Process // non-nil while lockscreen osascript is alive
	lockScreenMu   sync.Mutex
}

func NewAlerter(notify, verbose bool, resp ResponseConfig) *Alerter {
	return &Alerter{
		notify:   notify,
		verbose:  verbose,
		resp:     resp,
		cooldown: make(map[string]time.Time),
	}
}

const alertCooldown = 30 * time.Second

func (a *Alerter) Alert(al Alert) {
	al.Time = time.Now()

	if al.Severity == SevNone {
		return
	}

	a.mu.Lock()
	key := al.Operation + ":" + al.Mount + al.Path
	if last, ok := a.cooldown[key]; ok && time.Since(last) < alertCooldown {
		a.mu.Unlock()
		if a.verbose {
			log.Printf("  (suppressed duplicate: %s %s%s)", al.Operation, al.Mount, al.Path)
		}
		return
	}
	a.cooldown[key] = al.Time
	a.mu.Unlock()

	// Log to stderr
	log.Printf("[%s] %s %s%s - %s",
		al.Severity, al.Operation, al.Mount, al.Path, al.Message)

	// macOS notification
	if a.notify && al.Severity >= SevWarning {
		go macNotify(al)
	}

	// Process identification + response actions
	if al.Severity >= SevWarning {
		go a.identifyAndRespond(al)
	}
}

// identifyAndRespond runs lsof to identify the reader, logs the results,
// then fires any enabled response actions in sequence. It collects a
// plain-language list of what was done, which gets included in the alert
// log and lockscreen overlay.
func (a *Alerter) identifyAndRespond(al Alert) {
	lsofOut, pids, trees := collectLsof(al)

	// Log lsof output and process trees (existing behavior)
	if lsofOut != "" {
		log.Printf("  lsof %s%s:\n%s", al.Mount, al.Path, lsofOut)
		for _, t := range trees {
			log.Printf("  process tree: %s", t)
		}
	}

	// Execute response actions and collect plain-language descriptions
	var actions []string

	if a.resp.KillReaders {
		if desc := respondKillReaders(al, pids); desc != "" {
			actions = append(actions, desc)
		}
	}
	if a.resp.DisconnectNetwork {
		respondDisconnectNetwork()
		actions = append(actions, "Disconnected all network interfaces to isolate this machine.")
	}
	if a.resp.Tarpit {
		actions = append(actions, "Tarpit mode is active — the file read was deliberately slowed to a crawl to waste the attacker's time.")
	}
	if a.resp.AlertLog != "" {
		respondAlertLog(al, lsofOut, trees, actions, a.resp.AlertLog)
		actions = append(actions, fmt.Sprintf("A detailed report was saved to %s and copied to your clipboard.", a.resp.AlertLog))
		actions = append(actions, "Send this report to your system administrator immediately.")
	}
	if a.resp.LockScreen {
		a.lockScreenMu.Lock()
		// Check if a previous lockscreen process is still alive
		if a.lockScreenProc != nil {
			// Signal 0 checks if process exists without killing it
			if a.lockScreenProc.Signal(syscall.Signal(0)) == nil {
				a.lockScreenMu.Unlock()
				log.Printf("[lockscreen] skipping — already displayed")
				return
			}
			// Process is gone (crashed or dismissed); allow a new one
			a.lockScreenProc = nil
		}
		a.lockScreenMu.Unlock()

		proc := respondLockScreen(al, trees, actions)

		a.lockScreenMu.Lock()
		a.lockScreenProc = proc
		a.lockScreenMu.Unlock()

		if proc != nil {
			// Wait for dismiss/crash in background, then clear the ref
			go func() {
				proc.Wait()
				a.lockScreenMu.Lock()
				if a.lockScreenProc == proc {
					a.lockScreenProc = nil
				}
				a.lockScreenMu.Unlock()
			}()
		}
	}
}

// collectLsof runs lsof on the alert's file path with a timeout to avoid
// deadlocking on WebDAV mounts. Returns the raw output, parsed PIDs, and
// formatted process trees.
func collectLsof(al Alert) (output string, pids []int, trees []string) {
	fullPath := al.Mount + al.Path
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "lsof", fullPath).CombinedOutput()
	if err != nil || len(out) == 0 {
		return "", nil, nil
	}

	output = string(out)
	pids = parseLsofPIDs(output)
	for _, pid := range pids {
		if t := processTree(pid); t != "" {
			trees = append(trees, t)
		}
	}
	return output, pids, trees
}

// parseLsofPIDs extracts unique PIDs from lsof output, skipping the header
// and our own process.
func parseLsofPIDs(output string) []int {
	myPID := os.Getpid()
	seen := map[int]bool{}
	var pids []int
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || pid == myPID || seen[pid] {
			continue
		}
		seen[pid] = true
		pids = append(pids, pid)
	}
	return pids
}

// processTree walks from pid up to PID 1, returning an ASCII tree like:
//
//	/sbin/launchd (PID 1)
//	└── /usr/sbin/sshd (PID 66499)
//	    └── /bin/bash (PID 66500)
//	        └── /usr/local/bin/gcat (PID 66575)
func processTree(pid int) string {
	type proc struct {
		pid   int
		path  string
		etime string // elapsed time, e.g. "00:05" or "1-02:30:00"
	}
	var chain []proc
	visited := map[int]bool{}
	for pid > 0 && !visited[pid] {
		visited[pid] = true
		path := execPath(pid)
		if path == "" {
			break
		}
		etime := strings.TrimSpace(psField(pid, "etime"))
		chain = append(chain, proc{pid, path, etime})
		ppidStr := strings.TrimSpace(psField(pid, "ppid"))
		ppid, err := strconv.Atoi(ppidStr)
		if err != nil || ppid == pid {
			break
		}
		pid = ppid
	}
	if len(chain) == 0 {
		return ""
	}

	// chain is leaf-first; reverse to show root ancestor at the top
	var lines []string
	for i := len(chain) - 1; i >= 0; i-- {
		p := chain[i]
		depth := len(chain) - 1 - i
		var prefix string
		if depth == 0 {
			prefix = ""
		} else {
			prefix = strings.Repeat("    ", depth-1) + "└── "
		}
		detail := fmt.Sprintf("%s%s (PID %d", prefix, p.path, p.pid)
		if p.etime != "" {
			detail += fmt.Sprintf(", running %s", humanizeEtime(p.etime))
		}
		detail += ")"
		lines = append(lines, detail)
	}
	return strings.Join(lines, "\n")
}

// execPath returns the full executable path for a PID by parsing ps args output.
// Falls back to the short command name if args is unavailable.
func execPath(pid int) string {
	args := strings.TrimSpace(psField(pid, "args"))
	if args != "" {
		// args looks like "/usr/bin/bash -l" — take the first token
		if i := strings.IndexByte(args, ' '); i > 0 {
			args = args[:i]
		}
		if strings.HasPrefix(args, "/") {
			return args
		}
	}
	// Fall back to short name
	return strings.TrimSpace(psField(pid, "comm"))
}

// humanizeEtime converts ps etime format into plain English.
// ps etime formats: "00:05" (mm:ss), "01:30:05" (hh:mm:ss), "2-01:30:05" (days-hh:mm:ss)
func humanizeEtime(etime string) string {
	var days, hours, minutes, seconds int

	// Split off days if present: "2-01:30:05" → days=2, rest="01:30:05"
	rest := etime
	if i := strings.Index(rest, "-"); i >= 0 {
		fmt.Sscanf(rest[:i], "%d", &days)
		rest = rest[i+1:]
	}

	parts := strings.Split(rest, ":")
	switch len(parts) {
	case 3: // hh:mm:ss
		fmt.Sscanf(parts[0], "%d", &hours)
		fmt.Sscanf(parts[1], "%d", &minutes)
		fmt.Sscanf(parts[2], "%d", &seconds)
	case 2: // mm:ss
		fmt.Sscanf(parts[0], "%d", &minutes)
		fmt.Sscanf(parts[1], "%d", &seconds)
	default:
		return etime // can't parse, return as-is
	}

	var out []string
	if days > 0 {
		out = append(out, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		out = append(out, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		out = append(out, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(out) == 0 {
		out = append(out, fmt.Sprintf("%ds", seconds))
	}
	return strings.Join(out, " ")
}

func psField(pid int, field string) string {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", field+"=").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// consoleUser returns the currently logged-in GUI user.
// When running as root, we need to send notifications as this user
// since root has no connection to the user's notification center.
func consoleUser() string {
	out, err := exec.Command("stat", "-f", "%Su", "/dev/console").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func macNotify(al Alert) {
	title := fmt.Sprintf("Canary [%s]", al.Severity)
	msg := fmt.Sprintf("%s: %s%s", al.Operation, al.Mount, al.Path)
	script := fmt.Sprintf(
		`display notification %q with title %q sound name "Sosumi"`,
		msg, title)

	if os.Getuid() == 0 {
		// Running as root — deliver notification via the console user's session
		user := consoleUser()
		if user == "" || user == "root" {
			return
		}
		exec.Command("sudo", "-u", user, "osascript", "-e", script).Run()
	} else {
		exec.Command("osascript", "-e", script).Run()
	}
}
