// Package fakeutopia is a scriptable fake of the Utopia client's JSON-RPC API
// for tests. It records every request it receives and can inject the faults
// that matter for at-most-once forwarding (ADR-0003): delays, hangs,
// connections dropped before or after the request is read, garbage responses
// and upstream errors.
//
// Assumptions about the real API that still need confirming (method registry
// open questions) are kept in this file so they are easy to update.
package fakeutopia

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// APIPath is where the Utopia client serves its API.
const APIPath = "/api/1.0/"

// Request is one request received by the fake.
type Request struct {
	Method  string
	Params  map[string]any
	Filters map[string]any
	TokenOK bool
	// Raw is the request body exactly as received.
	Raw []byte
	// Responded is true if a complete response was written.
	Responded bool
	At        time.Time
}

type kind int

const (
	kindResult kind = iota + 1
	kindRaw
	kindDropAfterRead
	kindHang
)

// Behavior is how the fake answers one request.
type Behavior struct {
	kind   kind
	result any
	status int
	body   []byte
	delay  time.Duration
}

// Result answers with {"result": v, "resultExtraInfo": {"elapsed": "0"}}.
func Result(v any) Behavior { return Behavior{kind: kindResult, result: v} }

// Raw answers with the given status and body, unchanged.
func Raw(status int, body string) Behavior {
	return Behavior{kind: kindRaw, status: status, body: []byte(body)}
}

// UpstreamError answers like a failed Utopia call.
//
// ASSUMPTION: the real error envelope is undocumented (open question 5).
func UpstreamError(msg string) Behavior {
	b, _ := json.Marshal(map[string]any{"error": msg, "resultExtraInfo": map[string]string{"elapsed": "0"}})
	return Behavior{kind: kindRaw, status: http.StatusOK, body: b}
}

// Garbage answers 200 with a body that is not JSON.
func Garbage() Behavior { return Raw(http.StatusOK, "\x00not json{") }

// DropAfterRead reads the whole request, then closes the connection without
// answering. The caller cannot know whether the call took effect.
func DropAfterRead() Behavior { return Behavior{kind: kindDropAfterRead} }

// Hang reads the request and never answers, until the client gives up or the
// server is closed.
func Hang() Behavior { return Behavior{kind: kindHang} }

// After delays b by d.
func After(d time.Duration, b Behavior) Behavior {
	b.delay = d
	return b
}

// Server is a running fake Utopia client.
type Server struct {
	// URL is the API endpoint, including APIPath.
	URL   string
	token string

	ts   *httptest.Server
	done chan struct{}

	mu        sync.Mutex
	scripts   map[string][]Behavior
	defaults  map[string]Behavior
	requests  []Request
	dropConns bool
	drops     int
	closeOnce sync.Once
}

// New starts a fake that accepts token and stops when the test ends.
func New(t testing.TB, token string) *Server {
	t.Helper()
	s := &Server{
		token:    token,
		done:     make(chan struct{}),
		scripts:  map[string][]Behavior{},
		defaults: map[string]Behavior{},
	}
	s.ts = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.ts.Listener = &dropListener{Listener: s.ts.Listener, s: s}
	s.ts.Start()
	s.URL = s.ts.URL + APIPath
	t.Cleanup(s.Close)
	return s
}

// Close stops the server, releasing any hanging requests.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ts.CloseClientConnections()
		s.ts.Close()
	})
}

// Script queues behaviors for method, used in order, one per request. When
// the queue is empty the method's default applies.
func (s *Server) Script(method string, bs ...Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scripts[method] = append(s.scripts[method], bs...)
}

// SetDefault sets the behavior for method when nothing is scripted.
func (s *Server) SetDefault(method string, b Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaults[method] = b
}

// DropConnections makes the server accept and immediately close every new
// connection, before reading anything. The client may still have written its
// request into the socket, so this is NOT a reliable "not sent" signal.
// For a guaranteed "not sent", use RefusedURL.
func (s *Server) DropConnections(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropConns = on
}

// Drops returns how many connections were dropped by DropConnections.
func (s *Server) Drops() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.drops
}

// Requests returns a copy of every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Count returns how many requests for method were received.
func (s *Server) Count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.Method == method {
			n++
		}
	}
	return n
}

func (s *Server) next(method string) (Behavior, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q := s.scripts[method]; len(q) > 0 {
		s.scripts[method] = q[1:]
		return q[0], true
	}
	b, ok := s.defaults[method]
	return b, ok
}

func (s *Server) record(r Request) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
	return len(s.requests) - 1
}

func (s *Server) markResponded(i int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[i].Responded = true
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || (r.URL.Path != APIPath && r.URL.Path != "/api/1.0") {
		http.NotFound(w, r)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	var env struct {
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
		Filters map[string]any `json:"filters"`
		Token   string         `json:"token"`
	}
	parseErr := json.Unmarshal(raw, &env)
	idx := s.record(Request{
		Method: env.Method, Params: env.Params, Filters: env.Filters,
		TokenOK: env.Token == s.token, Raw: raw, At: time.Now(),
	})

	var b Behavior
	switch {
	case parseErr != nil:
		b = Raw(http.StatusBadRequest, `{"error":"invalid json"}`)
	case env.Token != s.token:
		// ASSUMPTION: the real client's response to a bad token is undocumented.
		b = Raw(http.StatusForbidden, `{"error":"invalid token"}`)
	default:
		var ok bool
		if b, ok = s.next(env.Method); !ok {
			b = Raw(http.StatusInternalServerError, `{"error":"fakeutopia: no behavior scripted for method"}`)
		}
	}

	if b.delay > 0 {
		select {
		case <-time.After(b.delay):
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		}
	}

	switch b.kind {
	case kindResult:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result":          b.result,
			"resultExtraInfo": map[string]string{"elapsed": "0"},
		})
	case kindRaw:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(b.status)
		_, _ = w.Write(b.body)
	case kindDropAfterRead:
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
		return
	case kindHang:
		select {
		case <-r.Context().Done():
		case <-s.done:
		}
		return
	}
	s.markResponded(idx)
}

type dropListener struct {
	net.Listener
	s *Server
}

func (l *dropListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.s.mu.Lock()
		drop := l.s.dropConns
		if drop {
			l.s.drops++
		}
		l.s.mu.Unlock()
		if !drop {
			return c, nil
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // send RST instead of FIN
		}
		_ = c.Close()
	}
}

// RefusedURL returns an API URL on a local port where nothing listens, so
// connecting fails before any byte is sent: the only reliable "not sent".
func RefusedURL(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr + APIPath
}
