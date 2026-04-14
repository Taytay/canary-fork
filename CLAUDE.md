# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
go build -buildvcs=false -o canary .   # -buildvcs=false needed if git VCS status unavailable
make                                   # also works (may need: GOFLAGS=-buildvcs=false make)
make install                           # installs to /usr/local/bin (PREFIX overridable)
make clean                             # removes built binary
```

No third-party dependencies — standard library only. Requires Go 1.22+.

There are no tests in this project.

## Architecture

Canary is a macOS filesystem honeypot (~1400 lines). It runs a local server (WebDAV or NFS) that serves a virtual directory of fake secret files, mounts it at user-specified paths, and fires alerts when anything touches those files.

**Key flow:** `main.go` parses flags and delegates to either `runWebDAV()` or `runNFS()`, which start a server, mount the filesystem, and block on signal.

### Core components

- **`tree.go`** — `VNode` is the virtual file tree. `DefaultTree()` defines all canary bait files and their severity levels. To add a canary file, add a `File()` call here.
- **`server.go`** — WebDAV protocol handler over `net/http`. Routes requests by mount index (`/m/{idx}/path`). `isNoise()` filters macOS system file probes (`.DS_Store`, Spotlight, etc.).
- **`nfs.go`** — NFSv3 + MOUNT protocol handler. Implements the wire protocol directly (no FUSE/libfuse). Uses `handleMap` to map file handles (uint64) to VNodes.
- **`rpc.go`** — Sun RPC framing and XDR serialization/deserialization used by the NFS mode.
- **`alert.go`** — `Alerter` deduplicates alerts (30s cooldown per path+op), logs them, runs `lsof` to identify the accessing process, and sends macOS notifications via `osascript`.

### Two server modes

| | WebDAV (default) | NFS |
|---|---|---|
| Root required | No | Yes |
| Server visible to attacker | Yes (same UID) | No (runs as root) |
| Multiple mount points | Yes | One per instance |

Both modes suppress alerts during a warmup period after mount (3s WebDAV, 5s NFS) to avoid false positives from the OS probing the new mount.
