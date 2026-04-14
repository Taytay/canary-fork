package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	mode := flag.String("mode", "webdav", "server mode: webdav or nfs")
	port := flag.Int("port", 0, "server port (0 = random)")
	verbose := flag.Bool("v", false, "verbose logging (show suppressed duplicates)")
	notify := flag.Bool("notify", true, "send macOS notifications on alerts")
	tarpit := flag.Bool("tarpit", false, "drip file contents extremely slowly, trapping readers")
	logFile := flag.String("log", "", "log to file instead of stderr")

	// Response actions
	disconnectNetwork := flag.Bool("disconnect-network", false, "on alert, disable all network interfaces (requires root)")
	killReaders := flag.Bool("kill-reader-processes", true, "on alert, kill the shell/process tree reading the canary file")
	alertLog := flag.String("alert-log", "", "path for forensic alert log (default: ~/Desktop/canary-alert.log)")
	lockScreen := flag.Bool("lockscreen", false, "on alert, show a full-screen warning overlay")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: canary [flags] <mountpoint> [mountpoint...]\n\n")
		fmt.Fprintf(os.Stderr, "Mount canary filesystems that alert on access.\n\n")
		fmt.Fprintf(os.Stderr, "Modes:\n")
		fmt.Fprintf(os.Stderr, "  webdav  No root needed. Runs as current user. (default)\n")
		fmt.Fprintf(os.Stderr, "  nfs     Requires root. Server invisible to unprivileged attackers.\n")
		fmt.Fprintf(os.Stderr, "          Mount appears as normal NFS in mount table.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  canary ~/.secrets.d\n")
		fmt.Fprintf(os.Stderr, "  canary ~/.secrets.d ~/.aws-backup ~/credentials\n")
		fmt.Fprintf(os.Stderr, "  canary -tarpit ~/.secrets.d\n")
		fmt.Fprintf(os.Stderr, "  sudo canary -mode nfs -kill-readers -lockscreen ~/.secrets.d\n")
		fmt.Fprintf(os.Stderr, "  sudo canary -mode nfs -disconnect-network -alert-log /var/log/canary-alerts.log ~/.secrets.d\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	mounts := flag.Args()
	if len(mounts) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Log to file if requested (useful for NFS mode — hides logs from unprivileged users)
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Expand ~ in paths
	home, _ := os.UserHomeDir()
	for i, m := range mounts {
		if strings.HasPrefix(m, "~/") {
			mounts[i] = filepath.Join(home, m[2:])
		}
	}

	// Default alert-log to ~/Desktop/canary-alert.log
	if *alertLog == "" {
		*alertLog = filepath.Join(home, "Desktop", "canary-alert.txt")
	}

	tree := DefaultTree()

	resp := ResponseConfig{
		DisconnectNetwork: *disconnectNetwork,
		KillReaders:       *killReaders,
		AlertLog:          *alertLog,
		LockScreen:        *lockScreen,
		Tarpit:            *tarpit,
	}

	if *disconnectNetwork && os.Getuid() != 0 {
		log.Println("warning: -disconnect-network requires root; will skip at alert time")
	}

	alerter := NewAlerter(*notify, *verbose, resp)

	switch *mode {
	case "webdav":
		runWebDAV(tree, alerter, mounts, *port, *tarpit)
	case "nfs":
		runNFS(tree, alerter, mounts, *port, *tarpit)
	default:
		log.Fatalf("unknown mode: %s (use webdav or nfs)", *mode)
	}
}

func runWebDAV(tree *VNode, alerter *Alerter, mounts []string, port int, tarpit bool) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port

	handler := NewWebDAVHandler(tree, alerter, mounts, tarpit)
	server := &http.Server{Handler: handler}
	go server.Serve(listener)

	log.Printf("[webdav] server on 127.0.0.1:%d", actualPort)

	var mounted []string
	for i, mp := range mounts {
		if err := os.MkdirAll(mp, 0700); err != nil {
			log.Printf("mkdir %s: %v", mp, err)
			unmountAll(mounted)
			os.Exit(1)
		}
		url := fmt.Sprintf("http://127.0.0.1:%d/m/%d/", actualPort, i)
		cmd := exec.Command("mount_webdav", "-S", url, mp)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("mount %s failed: %v %s", mp, err, string(out))
			unmountAll(mounted)
			os.Exit(1)
		}
		mounted = append(mounted, mp)
		log.Printf("mounted: %s", mp)
	}

	log.Println("canary active — Ctrl+C to stop")
	waitForSignal()

	log.Println("shutting down...")
	close(handler.done) // interrupt any active tarpit loops
	unmountAll(mounted)
	server.Close()
}

func runNFS(tree *VNode, alerter *Alerter, mounts []string, port int, tarpit bool) {
	if os.Getuid() != 0 {
		log.Fatal("nfs mode requires root (mount_nfs needs root).\n" +
			"Run with: sudo canary -mode nfs ...")
	}

	if len(mounts) > 1 {
		log.Println("nfs mode: only first mount point is used (run multiple instances for more)")
		mounts = mounts[:1]
	}
	mp := mounts[0]

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port

	nfs := NewNFSServer(tree, alerter, mp, tarpit)
	go nfs.Serve(listener)

	log.Printf("[nfs] server on 127.0.0.1:%d", actualPort)

	if err := os.MkdirAll(mp, 0755); err != nil {
		log.Fatalf("mkdir %s: %v", mp, err)
	}

	// Mount NFS — specify both port and mountport to avoid needing portmapper
	mountArgs := fmt.Sprintf("vers=3,tcp,port=%d,mountport=%d,locallocks,noresvport", actualPort, actualPort)
	cmd := exec.Command("mount_nfs", "-o", mountArgs, "localhost:/canary", mp)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("mount_nfs %s failed: %v %s", mp, err, string(out))
	}
	log.Printf("mounted: %s (nfs)", mp)
	log.Println("canary active — Ctrl+C to stop")

	waitForSignal()

	log.Println("shutting down...")
	close(nfs.done)
	unmountAll([]string{mp})
	listener.Close()
}

func waitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println()
}

func unmountAll(mounts []string) {
	for _, mp := range mounts {
		if err := exec.Command("umount", mp).Run(); err != nil {
			log.Printf("unmount %s: %v (trying force)", mp, err)
			exec.Command("diskutil", "unmount", "force", mp).Run()
		} else {
			log.Printf("unmounted: %s", mp)
		}
	}
}
