package main

import (
	"fmt"
	"html"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// tarpitChunk is how many bytes to send per drip in tarpit mode.
const tarpitChunk = 1

// tarpitDelay is the pause between each drip.
const tarpitDelay = 2 * time.Second

type WebDAVHandler struct {
	trees   []*VNode
	alerter *Alerter
	mounts  []string
	tarpit  bool
	readyAt time.Time // suppress alerts during mount warmup
}

func NewWebDAVHandler(tree *VNode, alerter *Alerter, mounts []string, tarpit bool) *WebDAVHandler {
	trees := make([]*VNode, len(mounts))
	for i := range mounts {
		trees[i] = tree
	}
	return &WebDAVHandler{
		trees:   trees,
		alerter: alerter,
		mounts:  mounts,
		tarpit:  tarpit,
		readyAt: time.Now().Add(3 * time.Second),
	}
}

func (h *WebDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Route: /m/{index}/rest/of/path
	p := strings.TrimPrefix(r.URL.Path, "/m/")
	slashIdx := strings.Index(p, "/")
	if slashIdx < 0 {
		http.Error(w, "bad path", 400)
		return
	}
	idx, err := strconv.Atoi(p[:slashIdx])
	if err != nil || idx < 0 || idx >= len(h.trees) {
		http.Error(w, "bad mount index", 400)
		return
	}

	tree := h.trees[idx]
	mount := h.mounts[idx]
	reqPath := path.Clean(p[slashIdx:])
	if reqPath == "" || reqPath == "." {
		reqPath = "/"
	}

	// Noise filter: macOS system files
	if isNoise(reqPath) {
		http.Error(w, "not found", 404)
		return
	}

	switch r.Method {
	case "OPTIONS":
		h.handleOptions(w)
	case "PROPFIND":
		h.handlePropfind(w, r, tree, mount, reqPath, idx)
	case "GET", "HEAD":
		h.handleGet(w, r, tree, mount, reqPath)
	case "PUT":
		h.handleWrite(w, mount, reqPath, "WRITE")
	case "DELETE":
		h.handleWrite(w, mount, reqPath, "DELETE")
	case "MKCOL":
		h.handleWrite(w, mount, reqPath, "MKDIR")
	case "LOCK":
		h.handleLock(w, reqPath, idx)
	case "UNLOCK":
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}

func isNoise(reqPath string) bool {
	base := path.Base(reqPath)
	switch {
	case base == ".DS_Store",
		base == ".Trashes",
		base == ".fseventsd",
		strings.HasPrefix(base, "._"),
		strings.Contains(reqPath, ".Spotlight-V100"):
		return true
	}
	return false
}

func (h *WebDAVHandler) ready() bool {
	return time.Now().After(h.readyAt)
}

func (h *WebDAVHandler) handleOptions(w http.ResponseWriter) {
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, LOCK, UNLOCK")
	w.WriteHeader(200)
}

func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request, tree *VNode, mount, reqPath string, idx int) {
	node := tree.Resolve(reqPath)
	if node == nil {
		http.Error(w, "not found", 404)
		return
	}

	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "infinity"
	}

	// Alert on directory enumeration (not during warmup, not depth-0 keepalives)
	if h.ready() && node.IsDir && depth != "0" {
		h.alerter.Alert(Alert{
			Severity:  SevInfo,
			Operation: "READDIR",
			Path:      reqPath,
			Mount:     mount,
			Message:   "directory enumeration",
		})
	}

	prefix := fmt.Sprintf("/m/%d", idx)
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	buf.WriteString(`<D:multistatus xmlns:D="DAV:">` + "\n")
	writePropResponse(&buf, prefix, reqPath, node)
	if node.IsDir && depth != "0" {
		for _, child := range node.Children {
			childPath := path.Join(reqPath, child.Name)
			writePropResponse(&buf, prefix, childPath, child)
		}
	}
	buf.WriteString("</D:multistatus>\n")

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(207)
	w.Write([]byte(buf.String()))
}

func writePropResponse(buf *strings.Builder, prefix, reqPath string, node *VNode) {
	href := html.EscapeString(prefix + reqPath)
	modTime := node.ModTime.UTC().Format(http.TimeFormat)
	etag := fmt.Sprintf(`"%x-%x"`, node.ModTime.Unix(), len(node.Content))

	buf.WriteString("  <D:response>\n")
	fmt.Fprintf(buf, "    <D:href>%s</D:href>\n", href)
	buf.WriteString("    <D:propstat>\n")
	buf.WriteString("      <D:prop>\n")

	if node.IsDir {
		buf.WriteString("        <D:resourcetype><D:collection/></D:resourcetype>\n")
	} else {
		buf.WriteString("        <D:resourcetype/>\n")
		fmt.Fprintf(buf, "        <D:getcontentlength>%d</D:getcontentlength>\n", len(node.Content))
		buf.WriteString("        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n")
	}

	fmt.Fprintf(buf, "        <D:displayname>%s</D:displayname>\n", html.EscapeString(node.Name))
	fmt.Fprintf(buf, "        <D:getlastmodified>%s</D:getlastmodified>\n", modTime)
	fmt.Fprintf(buf, "        <D:getetag>%s</D:getetag>\n", etag)
	buf.WriteString("      </D:prop>\n")
	buf.WriteString("      <D:status>HTTP/1.1 200 OK</D:status>\n")
	buf.WriteString("    </D:propstat>\n")
	buf.WriteString("  </D:response>\n")
}

func (h *WebDAVHandler) handleGet(w http.ResponseWriter, r *http.Request, tree *VNode, mount, reqPath string) {
	node := tree.Resolve(reqPath)
	if node == nil {
		http.Error(w, "not found", 404)
		return
	}
	if node.IsDir {
		http.Error(w, "is a directory", 403)
		return
	}

	if h.ready() {
		h.alerter.Alert(Alert{
			Severity:  node.Severity,
			Operation: "READ",
			Path:      reqPath,
			Mount:     mount,
			Message:   fmt.Sprintf("canary file read: %s", reqPath),
		})
	}

	if h.tarpit && len(node.Content) > 0 && r.Method == "GET" {
		h.serveTarpit(w, node)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(node.Content)))
	w.Header().Set("Last-Modified", node.ModTime.UTC().Format(http.TimeFormat))
	if r.Method == "GET" {
		w.Write(node.Content)
	}
}

// serveTarpit drips file content extremely slowly, one small chunk at a time.
// The goal is to trap automated credential scrapers — the content looks real
// so they keep waiting, but it takes forever to finish.
func (h *WebDAVHandler) serveTarpit(w http.ResponseWriter, node *VNode) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(node.Content)))
	w.Header().Set("Last-Modified", node.ModTime.UTC().Format(http.TimeFormat))
	w.WriteHeader(200)

	flusher, canFlush := w.(http.Flusher)
	data := node.Content
	sent := 0

	for sent < len(data) {
		end := sent + tarpitChunk
		if end > len(data) {
			end = len(data)
		}
		_, err := w.Write(data[sent:end])
		if err != nil {
			return // client disconnected
		}
		if canFlush {
			flusher.Flush()
		}
		sent = end
		if sent < len(data) {
			time.Sleep(tarpitDelay)
		}
	}
}

func (h *WebDAVHandler) handleWrite(w http.ResponseWriter, mount, reqPath, op string) {
	if h.ready() {
		h.alerter.Alert(Alert{
			Severity:  SevCritical,
			Operation: op,
			Path:      reqPath,
			Mount:     mount,
			Message:   fmt.Sprintf("%s attempt on canary: %s", strings.ToLower(op), reqPath),
		})
	}
	switch op {
	case "DELETE":
		w.WriteHeader(204)
	default:
		w.WriteHeader(201)
	}
}

func (h *WebDAVHandler) handleLock(w http.ResponseWriter, reqPath string, idx int) {
	token := fmt.Sprintf("opaquelocktoken:canary-%d-%d", idx, time.Now().UnixNano())
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
  <D:lockdiscovery>
    <D:activelock>
      <D:locktype><D:write/></D:locktype>
      <D:lockscope><D:exclusive/></D:lockscope>
      <D:depth>0</D:depth>
      <D:owner>canary</D:owner>
      <D:timeout>Second-3600</D:timeout>
      <D:locktoken><D:href>%s</D:href></D:locktoken>
    </D:activelock>
  </D:lockdiscovery>
</D:prop>`, token)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Lock-Token", "<"+token+">")
	w.WriteHeader(200)
	w.Write([]byte(body))
}
