package fakeutopia

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"
)

const token = "test-token"

type outcome struct {
	status  int
	body    []byte
	err     error
	wrote   bool // the request was fully written to the connection
	elapsed time.Duration
}

func call(t *testing.T, url, method, tok string, timeout time.Duration) outcome {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"method": method, "params": map[string]any{"currency": "CRP"}, "token": tok})
	return post(t, url, body, timeout)
}

func post(t *testing.T, url string, body []byte, timeout time.Duration) outcome {
	t.Helper()
	var o outcome
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(i httptrace.WroteRequestInfo) { o.wrote = i.Err == nil },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	start := time.Now()
	resp, err := client.Do(req)
	o.elapsed = time.Since(start)
	if err != nil {
		o.err = err
		return o
	}
	defer resp.Body.Close()
	o.status = resp.StatusCode
	o.body, o.err = io.ReadAll(resp.Body)
	return o
}

func TestResult(t *testing.T) {
	s := New(t, token)
	s.Script("getBalance", Result(42.5))

	o := call(t, s.URL, "getBalance", token, time.Second)
	if o.err != nil || o.status != http.StatusOK {
		t.Fatalf("status %d, err %v", o.status, o.err)
	}
	var resp struct {
		Result float64 `json:"result"`
	}
	if err := json.Unmarshal(o.body, &resp); err != nil || resp.Result != 42.5 {
		t.Fatalf("body %s, err %v", o.body, err)
	}

	reqs := s.Requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != "getBalance" || !r.TokenOK || !r.Responded || r.Params["currency"] != "CRP" {
		t.Fatalf("unexpected record: %+v", r)
	}
}

func TestScriptOrderThenDefault(t *testing.T) {
	s := New(t, token)
	s.Script("getBalance", Result(1.0), Result(2.0))
	s.SetDefault("getBalance", Result(9.0))

	for _, want := range []string{"1", "2", "9", "9"} {
		o := call(t, s.URL, "getBalance", token, time.Second)
		var resp struct {
			Result json.Number `json:"result"`
		}
		_ = json.Unmarshal(o.body, &resp)
		if resp.Result.String() != want {
			t.Fatalf("result %s, want %s", resp.Result, want)
		}
	}
	if s.Count("getBalance") != 4 {
		t.Fatalf("count %d, want 4", s.Count("getBalance"))
	}
}

func TestUnscriptedMethodFailsLoudly(t *testing.T) {
	s := New(t, token)
	if o := call(t, s.URL, "sendPayment", token, time.Second); o.status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", o.status)
	}
}

func TestBadToken(t *testing.T) {
	s := New(t, token)
	s.SetDefault("getBalance", Result(1.0))
	o := call(t, s.URL, "getBalance", "wrong", time.Second)
	if o.status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", o.status)
	}
	if r := s.Requests()[0]; r.TokenOK {
		t.Fatal("bad token recorded as OK")
	}
}

func TestInvalidJSON(t *testing.T) {
	s := New(t, token)
	o := post(t, s.URL, []byte("{nope"), time.Second)
	if o.status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", o.status)
	}
	if r := s.Requests()[0]; string(r.Raw) != "{nope" {
		t.Fatalf("raw body not recorded: %q", r.Raw)
	}
}

func TestUpstreamErrorAndGarbage(t *testing.T) {
	s := New(t, token)
	s.Script("sendPayment", UpstreamError("Corresponded source card is not present"), Garbage())

	o := call(t, s.URL, "sendPayment", token, time.Second)
	if o.status != http.StatusOK || !bytes.Contains(o.body, []byte("source card")) {
		t.Fatalf("upstream error: status %d body %s", o.status, o.body)
	}
	o = call(t, s.URL, "sendPayment", token, time.Second)
	if o.status != http.StatusOK || json.Valid(o.body) {
		t.Fatalf("garbage: status %d body %q", o.status, o.body)
	}
}

// The request reached the server, but the client gets no answer: the case
// that must become outcome_unknown.
func TestDropAfterRead(t *testing.T) {
	s := New(t, token)
	s.Script("sendPayment", DropAfterRead())

	o := call(t, s.URL, "sendPayment", token, time.Second)
	if o.err == nil {
		t.Fatal("expected a client error")
	}
	if !o.wrote {
		t.Fatal("client should have written the request")
	}
	if s.Count("sendPayment") != 1 || s.Requests()[0].Responded {
		t.Fatalf("expected one recorded, unanswered request: %+v", s.Requests())
	}
}

func TestHangTimesOutAndCloseReleases(t *testing.T) {
	s := New(t, token)
	s.SetDefault("sendPayment", Hang())

	o := call(t, s.URL, "sendPayment", token, 100*time.Millisecond)
	if o.err == nil || !o.wrote {
		t.Fatalf("expected a timeout after writing: err %v wrote %v", o.err, o.wrote)
	}
	if s.Count("sendPayment") != 1 || s.Requests()[0].Responded {
		t.Fatal("expected one recorded, unanswered request")
	}

	// A hanging request that the client never abandons must not block Close.
	body := []byte(`{"method":"sendPayment","token":"` + token + `"}`)
	released := make(chan error, 1)
	go func() {
		resp, err := http.Post(s.URL, "application/json", bytes.NewReader(body))
		if err == nil {
			resp.Body.Close()
		}
		released <- err
	}()
	waitFor(t, func() bool { return s.Count("sendPayment") == 2 })
	start := time.Now()
	s.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case err := <-released:
		if err == nil {
			t.Fatal("hanging request got a response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hanging client was not released by Close")
	}
}

func TestDelay(t *testing.T) {
	s := New(t, token)
	s.SetDefault("getBalance", After(200*time.Millisecond, Result(1.0)))

	if o := call(t, s.URL, "getBalance", token, 50*time.Millisecond); o.err == nil {
		t.Fatal("expected a timeout")
	}
	o := call(t, s.URL, "getBalance", token, 2*time.Second)
	if o.err != nil || o.status != http.StatusOK || o.elapsed < 200*time.Millisecond {
		t.Fatalf("status %d err %v elapsed %v", o.status, o.err, o.elapsed)
	}
}

// Dropping on accept never reaches the handler, but the client may still
// believe it wrote the request. This is why only a refused connection counts
// as "not sent".
func TestDropConnections(t *testing.T) {
	s := New(t, token)
	s.SetDefault("sendPayment", Result("ok"))
	s.DropConnections(true)

	if o := call(t, s.URL, "sendPayment", token, time.Second); o.err == nil {
		t.Fatal("expected a client error")
	}
	if s.Count("sendPayment") != 0 || s.Drops() == 0 {
		t.Fatalf("count %d drops %d", s.Count("sendPayment"), s.Drops())
	}

	s.DropConnections(false)
	if o := call(t, s.URL, "sendPayment", token, time.Second); o.err != nil || o.status != http.StatusOK {
		t.Fatalf("after re-enabling: status %d err %v", o.status, o.err)
	}
}

func TestRefusedURL(t *testing.T) {
	o := call(t, RefusedURL(t), "sendPayment", token, time.Second)
	if o.err == nil {
		t.Fatal("expected a connection error")
	}
	if o.wrote {
		t.Fatal("nothing should have been written to a refused connection")
	}
}

func TestOnlyPostToAPIPath(t *testing.T) {
	s := New(t, token)
	resp, err := http.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET status %d, want 404", resp.StatusCode)
	}
	if o := post(t, s.URL+"other", []byte("{}"), time.Second); o.status != http.StatusNotFound {
		t.Fatalf("wrong path status %d, want 404", o.status)
	}
	if n := len(s.Requests()); n != 0 {
		t.Fatalf("recorded %d requests, want 0", n)
	}
}

func TestConcurrentRequests(t *testing.T) {
	s := New(t, token)
	s.SetDefault("getBalance", Result(1.0))
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			call(t, s.URL, "getBalance", token, 5*time.Second)
		}()
	}
	wg.Wait()
	if n := s.Count("getBalance"); n != 50 {
		t.Fatalf("count %d, want 50", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
