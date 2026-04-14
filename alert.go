package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
	notify   bool
	verbose  bool
	cooldown map[string]time.Time
	mu       sync.Mutex
}

func NewAlerter(notify, verbose bool) *Alerter {
	return &Alerter{
		notify:   notify,
		verbose:  verbose,
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

	// Try to identify accessing process via lsof (best-effort)
	if al.Severity >= SevWarning {
		go a.identifyProcess(al)
	}

	// macOS notification
	if a.notify && al.Severity >= SevWarning {
		go macNotify(al)
	}
}

func (a *Alerter) identifyProcess(al Alert) {
	fullPath := al.Mount + al.Path
	out, err := exec.Command("lsof", fullPath).CombinedOutput()
	if err != nil || len(out) == 0 {
		return
	}
	log.Printf("  lsof %s:\n%s", fullPath, out)

	// Parse PIDs from lsof output and print process trees
	pids := parseLsofPIDs(string(out))
	for _, pid := range pids {
		tree := processTree(pid)
		if tree != "" {
			log.Printf("  process tree: %s", tree)
		}
	}
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

// processTree walks from pid up to PID 1, returning a string like:
//
//	gcat(66575) → bash(66500) → sshd(66499) → launchd(1)
func processTree(pid int) string {
	var chain []string
	visited := map[int]bool{}
	for pid > 0 && !visited[pid] {
		visited[pid] = true
		comm := strings.TrimSpace(psField(pid, "comm"))
		if comm == "" {
			break
		}
		chain = append(chain, fmt.Sprintf("%s(%d)", comm, pid))
		ppidStr := strings.TrimSpace(psField(pid, "ppid"))
		ppid, err := strconv.Atoi(ppidStr)
		if err != nil || ppid == pid {
			break
		}
		pid = ppid
	}
	return strings.Join(chain, " → ")
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
