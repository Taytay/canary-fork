package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"path"
	"sync"
	"time"
)

// NFS3 / MOUNT3 constants
const (
	mountProgram = 100005
	mountVersion = 3
	nfsProgram   = 100003
	nfsVersion   = 3

	// MOUNT procedures
	mountProcNull   = 0
	mountProcMnt    = 1
	mountProcUmnt   = 3
	mountProcExport = 5

	// NFS procedures
	nfsProcNull        = 0
	nfsProcGetattr     = 1
	nfsProcSetattr     = 2
	nfsProcLookup      = 3
	nfsProcAccess      = 4
	nfsProcRead        = 6
	nfsProcWrite       = 7
	nfsProcCreate      = 8
	nfsProcMkdir       = 9
	nfsProcRemove      = 12
	nfsProcRmdir       = 13
	nfsProcRename      = 14
	nfsProcReaddir     = 16
	nfsProcReaddirplus = 17
	nfsProcFsstat      = 18
	nfsProcFsinfo      = 19
	nfsProcPathconf    = 20

	// NFS3 status
	nfs3OK         = 0
	nfs3ErrNoent   = 2
	nfs3ErrIO      = 5
	nfs3ErrAcces   = 13
	nfs3ErrIsDir   = 21
	nfs3ErrROFS    = 30
	nfs3ErrStale   = 70
	nfs3ErrNotSupp = 10004

	// File types
	nf3Reg = 1
	nf3Dir = 2
)

// --- File handle mapping ---

type handleMap struct {
	mu     sync.RWMutex
	nodes  map[uint64]*VNode
	paths  map[uint64]string
	byPath map[string]uint64
	nextID uint64
}

func newHandleMap(root *VNode) *handleMap {
	hm := &handleMap{
		nodes:  make(map[uint64]*VNode),
		paths:  make(map[uint64]string),
		byPath: make(map[string]uint64),
		nextID: 1,
	}
	hm.populate(root, "/")
	return hm
}

func (hm *handleMap) populate(node *VNode, p string) {
	id := hm.nextID
	hm.nextID++
	hm.nodes[id] = node
	hm.paths[id] = p
	hm.byPath[p] = id
	if node.IsDir {
		for _, c := range node.Children {
			hm.populate(c, path.Join(p, c.Name))
		}
	}
}

func (hm *handleMap) lookup(h []byte) (*VNode, uint64, string) {
	if len(h) != 8 {
		return nil, 0, ""
	}
	id := binary.BigEndian.Uint64(h)
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.nodes[id], id, hm.paths[id]
}

func (hm *handleMap) handleBytes(p string) ([]byte, uint64) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	id := hm.byPath[p]
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], id)
	return h[:], id
}

// --- NFS server ---

type NFSServer struct {
	tree    *VNode
	alerter *Alerter
	mount   string
	handles *handleMap
	tarpit  bool
	readyAt time.Time
}

func NewNFSServer(tree *VNode, alerter *Alerter, mountPoint string, tarpit bool) *NFSServer {
	return &NFSServer{
		tree:    tree,
		alerter: alerter,
		mount:   mountPoint,
		handles: newHandleMap(tree),
		tarpit:  tarpit,
		readyAt: time.Now().Add(5 * time.Second),
	}
}

func (s *NFSServer) ready() bool {
	return time.Now().After(s.readyAt)
}

func (s *NFSServer) Serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *NFSServer) handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		data, err := rpcReadRecord(conn)
		if err != nil {
			return
		}
		call, err := parseRPCCall(data)
		if err != nil {
			log.Printf("nfs: bad rpc: %v", err)
			return
		}

		var reply []byte
		switch call.program {
		case mountProgram:
			reply = s.handleMountProc(call)
		case nfsProgram:
			reply = s.handleNFSProc(call)
		default:
			reply = buildRPCError(call.xid, 2) // PROG_UNAVAIL
		}

		if err := rpcWriteRecord(conn, reply); err != nil {
			return
		}
	}
}

// --- MOUNT protocol ---

func (s *NFSServer) handleMountProc(call *rpcCall) []byte {
	var body []byte
	switch call.procedure {
	case mountProcNull:
		// empty reply
	case mountProcMnt:
		_ = call.body.String() // export path
		w := &xdrWriter{}
		w.PutUint32(0) // MNT3_OK
		rootHandle, _ := s.handles.handleBytes("/")
		w.PutOpaque(rootHandle)
		w.PutUint32(1) // 1 auth flavor
		w.PutUint32(0) // AUTH_NONE
		body = w.Bytes()
	case mountProcUmnt:
		// empty reply
	case mountProcExport:
		w := &xdrWriter{}
		w.PutUint32(1) // value follows
		w.PutString("/canary")
		w.PutUint32(1) // group follows
		w.PutString("localhost")
		w.PutUint32(0) // no more groups
		w.PutUint32(0) // no more exports
		body = w.Bytes()
	default:
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrNotSupp)
		body = w.Bytes()
	}
	return buildRPCReply(call.xid, body)
}

// --- NFS protocol ---

var nfsWriteProcs = map[uint32]string{
	nfsProcSetattr: "SETATTR",
	nfsProcWrite:   "WRITE",
	nfsProcCreate:  "CREATE",
	nfsProcMkdir:   "MKDIR",
	nfsProcRemove:  "REMOVE",
	nfsProcRmdir:   "RMDIR",
	nfsProcRename:  "RENAME",
}

func (s *NFSServer) handleNFSProc(call *rpcCall) []byte {
	var body []byte
	switch call.procedure {
	case nfsProcNull:
		// empty
	case nfsProcGetattr:
		body = s.nfsGetattr(call.body)
	case nfsProcLookup:
		body = s.nfsLookup(call.body)
	case nfsProcAccess:
		body = s.nfsAccess(call.body)
	case nfsProcRead:
		body = s.nfsRead(call.body)
	case nfsProcReaddir:
		body = s.nfsReaddir(call.body)
	case nfsProcReaddirplus:
		body = s.nfsReaddirplus(call.body)
	case nfsProcFsstat:
		body = s.nfsFsstat(call.body)
	case nfsProcFsinfo:
		body = s.nfsFsinfo(call.body)
	case nfsProcPathconf:
		body = s.nfsPathconf(call.body)
	default:
		// Write operations → ROFS + alert
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrROFS)
		w.PutUint32(0) // no post-op attrs
		body = w.Bytes()

		if s.ready() {
			name := nfsWriteProcs[call.procedure]
			if name == "" {
				name = fmt.Sprintf("NFS_PROC_%d", call.procedure)
			}
			s.alerter.Alert(Alert{
				Severity:  SevCritical,
				Operation: name,
				Mount:     s.mount,
				Path:      "/",
				Message:   fmt.Sprintf("write attempt via NFS: %s", name),
			})
		}
	}
	return buildRPCReply(call.xid, body)
}

// --- NFS3 attribute helpers ---

func (s *NFSServer) writeAttrs(w *xdrWriter, node *VNode, id uint64) {
	if node.IsDir {
		w.PutUint32(nf3Dir)
		w.PutUint32(0o755)
	} else {
		w.PutUint32(nf3Reg)
		w.PutUint32(0o644)
	}
	w.PutUint32(1)                         // nlink
	w.PutUint32(0)                         // uid
	w.PutUint32(0)                         // gid
	w.PutUint64(uint64(len(node.Content))) // size
	w.PutUint64(uint64(len(node.Content))) // used
	w.PutUint32(0)                         // rdev.specdata1
	w.PutUint32(0)                         // rdev.specdata2
	w.PutUint64(1)                         // fsid
	w.PutUint64(id)                        // fileid
	t := uint32(node.ModTime.Unix())
	w.PutUint32(t)
	w.PutUint32(0) // atime
	w.PutUint32(t)
	w.PutUint32(0) // mtime
	w.PutUint32(t)
	w.PutUint32(0) // ctime
}

func (s *NFSServer) postOpAttrs(w *xdrWriter, node *VNode, id uint64) {
	if node == nil {
		w.PutUint32(0) // no attrs
		return
	}
	w.PutUint32(1) // attrs follow
	s.writeAttrs(w, node, id)
}

// --- NFS3 procedures ---

func (s *NFSServer) nfsGetattr(r *xdrReader) []byte {
	handle := r.Opaque()
	node, id, _ := s.handles.lookup(handle)
	if node == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}
	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.writeAttrs(w, node, id)
	return w.Bytes()
}

func (s *NFSServer) nfsLookup(r *xdrReader) []byte {
	dirHandle := r.Opaque()
	name := r.String()

	dirNode, dirID, dirPath := s.handles.lookup(dirHandle)
	if dirNode == nil || !dirNode.IsDir {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		w.PutUint32(0)
		return w.Bytes()
	}

	child := dirNode.Lookup(name)
	if child == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrNoent)
		s.postOpAttrs(w, dirNode, dirID)
		return w.Bytes()
	}

	childPath := path.Join(dirPath, name)
	childHandle, childID := s.handles.handleBytes(childPath)

	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	w.PutOpaque(childHandle)
	s.postOpAttrs(w, child, childID)
	s.postOpAttrs(w, dirNode, dirID)
	return w.Bytes()
}

func (s *NFSServer) nfsAccess(r *xdrReader) []byte {
	handle := r.Opaque()
	access := r.Uint32()

	node, id, _ := s.handles.lookup(handle)
	if node == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}

	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint32(access) // grant all requested access
	return w.Bytes()
}

func (s *NFSServer) nfsRead(r *xdrReader) []byte {
	handle := r.Opaque()
	offset := r.Uint64()
	count := r.Uint32()

	node, id, nodePath := s.handles.lookup(handle)
	if node == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}
	if node.IsDir {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrIsDir)
		s.postOpAttrs(w, node, id)
		return w.Bytes()
	}

	if s.ready() {
		s.alerter.Alert(Alert{
			Severity:  node.Severity,
			Operation: "READ",
			Path:      nodePath,
			Mount:     s.mount,
			Message:   fmt.Sprintf("canary file read: %s", nodePath),
		})
	}

	if s.tarpit {
		time.Sleep(tarpitDelay)
	}

	data := node.Content
	if int(offset) >= len(data) {
		data = nil
	} else {
		data = data[offset:]
		if len(data) > int(count) {
			data = data[:count]
		}
		if s.tarpit && len(data) > tarpitChunk {
			data = data[:tarpitChunk]
		}
	}

	eof := uint32(0)
	if int(offset)+len(data) >= len(node.Content) {
		eof = 1
	}

	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint32(uint32(len(data)))
	w.PutUint32(eof)
	w.PutOpaque(data)
	return w.Bytes()
}

func (s *NFSServer) nfsReaddir(r *xdrReader) []byte {
	handle := r.Opaque()
	cookie := r.Uint64()
	_ = r.Uint64() // cookieverf
	_ = r.Uint32() // count

	node, id, nodePath := s.handles.lookup(handle)
	if node == nil || !node.IsDir {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}

	if s.ready() && cookie == 0 {
		s.alerter.Alert(Alert{
			Severity:  SevInfo,
			Operation: "READDIR",
			Path:      nodePath,
			Mount:     s.mount,
			Message:   "directory enumeration",
		})
	}

	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint64(0) // cookieverf

	idx := uint64(0)
	for _, child := range node.Children {
		idx++
		if idx <= cookie {
			continue
		}
		childPath := path.Join(nodePath, child.Name)
		_, childID := s.handles.handleBytes(childPath)

		w.PutUint32(1) // entry follows
		w.PutUint64(childID)
		w.PutString(child.Name)
		w.PutUint64(idx) // cookie
	}
	w.PutUint32(0) // no more entries
	w.PutUint32(1) // eof
	return w.Bytes()
}

func (s *NFSServer) nfsReaddirplus(r *xdrReader) []byte {
	handle := r.Opaque()
	cookie := r.Uint64()
	_ = r.Uint64() // cookieverf
	_ = r.Uint32() // dircount
	_ = r.Uint32() // maxcount

	node, id, nodePath := s.handles.lookup(handle)
	if node == nil || !node.IsDir {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}

	if s.ready() && cookie == 0 {
		s.alerter.Alert(Alert{
			Severity:  SevInfo,
			Operation: "READDIR",
			Path:      nodePath,
			Mount:     s.mount,
			Message:   "directory enumeration",
		})
	}

	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint64(0) // cookieverf

	idx := uint64(0)
	for _, child := range node.Children {
		idx++
		if idx <= cookie {
			continue
		}
		childPath := path.Join(nodePath, child.Name)
		childHandle, childID := s.handles.handleBytes(childPath)

		w.PutUint32(1) // entry follows
		w.PutUint64(childID)
		w.PutString(child.Name)
		w.PutUint64(idx) // cookie
		s.postOpAttrs(w, child, childID)
		w.PutUint32(1) // handle follows
		w.PutOpaque(childHandle)
	}
	w.PutUint32(0) // no more entries
	w.PutUint32(1) // eof
	return w.Bytes()
}

func (s *NFSServer) nfsFsstat(r *xdrReader) []byte {
	handle := r.Opaque()
	node, id, _ := s.handles.lookup(handle)
	if node == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}
	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint64(1 << 30) // tbytes
	w.PutUint64(1 << 29) // fbytes
	w.PutUint64(1 << 29) // abytes
	w.PutUint64(1000)     // tfiles
	w.PutUint64(500)      // ffiles
	w.PutUint64(500)      // afiles
	w.PutUint32(0)        // invarsec
	return w.Bytes()
}

func (s *NFSServer) nfsFsinfo(r *xdrReader) []byte {
	handle := r.Opaque()
	node, id, _ := s.handles.lookup(handle)
	if node == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}
	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint32(65536)    // rtmax
	w.PutUint32(8192)     // rtpref
	w.PutUint32(1)        // rtmult
	w.PutUint32(65536)    // wtmax
	w.PutUint32(8192)     // wtpref
	w.PutUint32(1)        // wtmult
	w.PutUint32(65536)    // dtpref
	w.PutUint64(1 << 62)  // maxfilesize
	w.PutUint32(1)        // time_delta seconds
	w.PutUint32(0)        // time_delta nseconds
	w.PutUint32(0x0001 | 0x0008) // properties: FSF3_LINK | FSF3_HOMOGENEOUS
	return w.Bytes()
}

func (s *NFSServer) nfsPathconf(r *xdrReader) []byte {
	handle := r.Opaque()
	node, id, _ := s.handles.lookup(handle)
	if node == nil {
		w := &xdrWriter{}
		w.PutUint32(nfs3ErrStale)
		return w.Bytes()
	}
	w := &xdrWriter{}
	w.PutUint32(nfs3OK)
	s.postOpAttrs(w, node, id)
	w.PutUint32(1)   // linkmax
	w.PutUint32(255) // name_max
	w.PutUint32(1)   // no_trunc
	w.PutUint32(0)   // chown_restricted
	w.PutUint32(1)   // case_insensitive
	w.PutUint32(1)   // case_preserving
	return w.Bytes()
}
