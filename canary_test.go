package main

import (
	"strings"
	"testing"
	"time"
)

// --- humanizeEtime ---

func TestHumanizeEtime(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"00:05", "5s"},
		{"01:30", "1m 30s"},
		{"00:00", "0s"},
		{"01:30:05", "1h 30m 5s"},
		{"00:00:00", "0s"},
		{"2-01:30:05", "2d 1h 30m 5s"},
		{"1-00:00:00", "1d"},   // 0 hours/minutes/seconds suppressed when days present
		{"garbage", "garbage"}, // unparseable passthrough
	}
	for _, c := range cases {
		got := humanizeEtime(c.in)
		if got != c.want {
			t.Errorf("humanizeEtime(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- parseLsofPIDs ---

func TestParseLsofPIDs(t *testing.T) {
	// Typical lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
	lsofOut := `COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
bash      1001   alice   cwd    DIR    1,4      128    2 /tmp
cat       1002   alice   txt    REG    1,4    12345    3 /tmp/foo
cat       1002   alice   mem    REG    1,4    12345    3 /tmp/foo
python    1003   alice    4r   REG    1,4     1024    4 /tmp/bar
`
	pids := parseLsofPIDs(lsofOut)

	// Should deduplicate: 1001, 1002, 1003, excluding own PID
	if len(pids) != 3 {
		t.Fatalf("expected 3 unique PIDs, got %d: %v", len(pids), pids)
	}
	seen := map[int]bool{}
	for _, p := range pids {
		if seen[p] {
			t.Errorf("duplicate PID %d in output", p)
		}
		seen[p] = true
	}
	for _, want := range []int{1001, 1002, 1003} {
		if !seen[want] {
			t.Errorf("expected PID %d in output", want)
		}
	}
}

func TestParseLsofPIDsEmpty(t *testing.T) {
	if pids := parseLsofPIDs(""); len(pids) != 0 {
		t.Errorf("expected empty, got %v", pids)
	}
}

func TestParseLsofPIDsHeaderOnly(t *testing.T) {
	// The header line has a non-numeric PID field — should produce nothing
	if pids := parseLsofPIDs("COMMAND PID USER\n"); len(pids) != 0 {
		t.Errorf("expected empty from header-only, got %v", pids)
	}
}

// --- isBoundaryProcess ---

func TestIsBoundaryProcess(t *testing.T) {
	boundary := []string{"launchd", "sshd", "Terminal", "iTerm2", "tmux", "screen", "login", "loginwindow", "iTerm"}
	for _, name := range boundary {
		if !isBoundaryProcess(name) {
			t.Errorf("isBoundaryProcess(%q) should be true", name)
		}
	}

	// Full paths should also match
	if !isBoundaryProcess("/usr/bin/login") {
		t.Error("isBoundaryProcess(\"/usr/bin/login\") should be true")
	}
	if !isBoundaryProcess("/usr/sbin/sshd") {
		t.Error("isBoundaryProcess(\"/usr/sbin/sshd\") should be true")
	}

	notBoundary := []string{"bash", "cat", "python3", "curl", "vim", ""}
	for _, name := range notBoundary {
		if isBoundaryProcess(name) {
			t.Errorf("isBoundaryProcess(%q) should be false", name)
		}
	}
}

// --- buildPlainSummary ---

func TestBuildPlainSummaryIncludesKeyFields(t *testing.T) {
	al := Alert{
		Time:      time.Date(2026, 5, 13, 14, 30, 0, 0, time.UTC),
		Severity:  SevCritical,
		Operation: "READ",
		Path:      "/passwords.txt",
		Mount:     "/home/user/.secrets",
		Message:   "canary file read",
	}
	summary := buildPlainSummary(al, nil, nil)

	mustContain := []string{
		"canary file",
		al.Mount + al.Path,
		"2026-05-13",
		"Process: could not be identified",
	}
	for _, s := range mustContain {
		if !strings.Contains(summary, s) {
			t.Errorf("summary missing %q\nGot:\n%s", s, summary)
		}
	}
}

func TestBuildPlainSummaryWithTreesAndActions(t *testing.T) {
	al := Alert{
		Time:      time.Now(),
		Operation: "READ",
		Path:      "/secret.key",
		Mount:     "/mnt/canary",
	}
	trees := []string{"/sbin/launchd (PID 1)\n└── /bin/bash (PID 42)"}
	actions := []string{"Killed bash (PID 42).", "Disconnected network."}

	summary := buildPlainSummary(al, trees, actions)

	for _, want := range []string{"Process tree:", "launchd", "bash", "Actions taken:", "Killed bash", "Disconnected network"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q\nGot:\n%s", want, summary)
		}
	}
}
