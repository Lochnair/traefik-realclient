package realclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func keyFor(url, cache string) feedKey {
	return feedKey{URL: url, Format: "lines", Interval: time.Hour, Minimum: 1, CacheDir: cache}
}
func TestFeedFormats(t *testing.T) {
	for _, tc := range []struct {
		format, body string
		min          int
		valid        bool
	}{{"lines", "\ufeff# header\r\n192.0.2.1\r\n192.0.2.1/32\n::ffff:192.0.2.1/128\n10.1.2.3/8", 2, true}, {"json-array", "[\"192.0.2.1\",\"2001:db8::1\"] \n", 2, true}, {"lines", "192.0.2.1\nbad", 1, false}, {"json-array", "[\"192.0.2.1\"] []", 1, false}, {"json-array", "[42]", 1, false}, {"json-array", "null", 1, false}, {"lines", "", 1, false}, {"lines", "192.0.2.1\n192.0.2.1/32", 2, false}, {"lines", "192.0.2.1 # inline", 1, false}, {"lines", strings.Repeat(" ", maxFeedBytes+1), 1, false}} {
		_, err := decodeFeed([]byte(tc.body), tc.format, tc.min)
		if (err == nil) != tc.valid {
			t.Fatalf("%s %q: %v", tc.format, tc.body[:minInt(len(tc.body), 60)], err)
		}
	}
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func TestHTTPAndCacheTransactions(t *testing.T) {
	var mu sync.Mutex
	body := "192.0.2.1"
	tag := "\"one\""
	status := 200
	var conditional, ua string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		conditional = r.Header.Get("If-None-Match")
		ua = r.Header.Get("User-Agent")
		w.Header().Set("ETag", tag)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	w := newWorker(keyFor(server.URL, t.TempDir()))
	w.client = server.Client()
	if err := w.refresh(); err != nil {
		t.Fatal(err)
	}
	first := w.value.Load().(feedSnapshot)
	cacheBefore, _ := os.ReadFile(w.cachePath())
	if first.etag != "\"one\"" || !w.contains(netip.MustParseAddr("192.0.2.1")) || ua != "traefik-realclient/1" {
		t.Fatal(first, ua)
	}
	mu.Lock()
	body = "bad"
	tag = "\"poison\""
	mu.Unlock()
	if err := w.refresh(); err == nil {
		t.Fatal("invalid update accepted")
	}
	cacheAfter, _ := os.ReadFile(w.cachePath())
	if string(cacheBefore) != string(cacheAfter) || w.value.Load().(feedSnapshot).etag != first.etag || conditional != "\"one\"" {
		t.Fatal("LKG transaction")
	}
	mu.Lock()
	status = 304
	mu.Unlock()
	if err := w.refresh(); err != nil {
		t.Fatal(err)
	}
	if w.value.Load().(feedSnapshot).etag != first.etag {
		t.Fatal("304 changed validator")
	}
	mu.Lock()
	status = 200
	body = "192.0.2.2"
	tag = ""
	mu.Unlock()
	if err := w.refresh(); err != nil {
		t.Fatal(err)
	}
	if w.value.Load().(feedSnapshot).etag != "" || w.contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("200 replacement")
	}
	loaded := newWorker(w.key)
	if err := loaded.loadCache(); err != nil {
		t.Fatal(err)
	}
	if !loaded.contains(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("cache load")
	}
	// An interrupted temp write never changes the final cache file.
	os.WriteFile(filepath.Join(w.key.CacheDir, ".realclient-interrupted"), []byte("{"), 0600)
	if err := loaded.loadCache(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(w.cachePath())
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("cache permissions")
	}
	mu.Lock()
	status = 503
	mu.Unlock()
	if err := w.refresh(); err == nil {
		t.Fatal("HTTP error accepted")
	}
	mu.Lock()
	status = 200
	body = strings.Repeat("x", maxFeedBytes+1)
	mu.Unlock()
	if err := w.refresh(); err == nil {
		t.Fatal("oversize accepted")
	}
	// A valid in-memory update survives a persistence failure.
	os.Remove(w.cachePath())
	os.Remove(filepath.Join(w.key.CacheDir, ".realclient-interrupted"))
	os.Remove(w.key.CacheDir)
	os.WriteFile(w.key.CacheDir, []byte("not a directory"), 0600)
	mu.Lock()
	body = "192.0.2.3"
	mu.Unlock()
	if err := w.refresh(); err != nil || !w.contains(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("persistence affected memory", err)
	}
}
func TestUnconditional304TLSRedirectTimeout(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") != "" {
			t.Error("validator without set")
		}
		if calls == 1 {
			w.WriteHeader(304)
		} else {
			fmt.Fprint(w, "192.0.2.1")
		}
	}))
	defer server.Close()
	w := newWorker(keyFor(server.URL, ""))
	if err := w.refresh(); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	w.client = server.Client()
	if err := w.refresh(); err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", server.URL)
		w.WriteHeader(302)
	}))
	defer redirect.Close()
	w = newWorker(keyFor(redirect.URL, ""))
	if err := w.refresh(); err == nil {
		t.Fatal("redirect accepted")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	w = newWorker(keyFor(slow.URL, ""))
	w.client.Timeout = 20 * time.Millisecond
	if err := w.refresh(); err == nil {
		t.Fatal("timeout accepted")
	}
}
func TestCacheValidation(t *testing.T) {
	k := keyFor("https://example.invalid/feed", t.TempDir())
	w := newWorker(k)
	record := cacheRecord{Version: cacheVersion, Key: k, Entries: []string{"192.0.2.1"}, ETag: "one", Validated: time.Now().Add(-365 * 24 * time.Hour)}
	for _, change := range []string{"valid", "version", "key", "entry", "minimum", "zeroTime", "trailing", "size"} {
		r := record
		switch change {
		case "version":
			r.Version++
		case "key":
			r.Key.URL += "2"
		case "entry":
			r.Entries = []string{"bad"}
		case "minimum":
			r.Entries = nil
		case "zeroTime":
			r.Validated = time.Time{}
		}
		body, _ := json.Marshal(r)
		if change == "trailing" {
			body = append(body, []byte(" {}")...)
		}
		if change == "size" {
			body = []byte(strings.Repeat(" ", maxCacheBytes+1))
		}
		os.WriteFile(w.cachePath(), body, 0600)
		err := w.loadCache()
		if (err == nil) != (change == "valid") {
			t.Fatal(change, err)
		}
	}
}
func TestRegistryAndAsynchronousCache(t *testing.T) {
	// A FIFO blocks cache loading without introducing a production test hook.
	dir := t.TempDir()
	k := keyFor("https://127.0.0.1:1/feed", dir)
	path := newWorker(k).cachePath()
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	var acquired *feedWorker
	done := make(chan struct{})
	go func() { acquired = acquireWorker(k); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("constructor waited for cache")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if acquireWorker(k) != acquired {
				t.Error("duplicate worker")
			}
		}()
	}
	wg.Wait()
	file, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString("bad")
	file.Close()
	changed := k
	changed.Minimum = 2
	if acquireWorker(changed) == acquired {
		t.Fatal("policy merged")
	}
	// Validate all sources before any worker is acquired.
	cfg := &Config{Sources: []SourceConfig{{Name: text("good"), Preset: text("bunny")}, {Name: text("bad")}}}
	workersMu.Lock()
	before := len(workers)
	workersMu.Unlock()
	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "bad"); err == nil {
		t.Fatal("invalid accepted")
	}
	workersMu.Lock()
	after := len(workers)
	workersMu.Unlock()
	if before != after {
		t.Fatal("invalid config started worker")
	}
}
func TestSnapshotReadersAndPartialFeeds(t *testing.T) {
	w := newWorker(keyFor("https://example.invalid/a", ""))
	empty := newWorker(keyFor("https://example.invalid/b", ""))
	a, _ := decodeFeed([]byte("192.0.2.1"), "lines", 1)
	b, _ := decodeFeed([]byte("192.0.2.2"), "lines", 1)
	var stop int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.LoadInt32(&stop) == 0 {
				snapshot := w.value.Load().(feedSnapshot)
				if len(snapshot.entries) > 0 && len(snapshot.set.exact) != 1 {
					t.Error("partial snapshot")
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		w.value.Store(a)
		w.value.Store(b)
	}
	atomic.StoreInt32(&stop, 1)
	wg.Wait()
	c := explicit()
	s, err := compileConfig(&Config{Sources: []SourceConfig{c}})
	if err != nil {
		t.Fatal(err)
	}
	s.sources[0].static = addressSet{}
	s.sources[0].specs = []feedKey{w.key, empty.key}
	s.sources[0].feeds = []addressSource{w, empty}
	r := request("192.0.2.2:5")
	r.Header.Set("X-Client", "10.0.0.1")
	m := &middleware{next: http.NotFoundHandler(), settings: s}
	m.ServeHTTP(httptest.NewRecorder(), r)
	if r.Header.Get("X-Real-Ip") != "10.0.0.1" {
		t.Fatal("partial family union")
	}
}

// A below-minimum update is rejected without disturbing the accepted snapshot,
// its validator, or a cache file that still satisfies the minimum on reload.
func TestBelowMinimumRetainsAccepted(t *testing.T) {
	var mu sync.Mutex
	body, tag := "192.0.2.1\n192.0.2.2", "\"v1\""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("ETag", tag)
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	k := feedKey{URL: server.URL, Format: "lines", Interval: time.Hour, Minimum: 2, CacheDir: t.TempDir()}
	w := newWorker(k)
	w.client = server.Client()
	if err := w.refresh(); err != nil {
		t.Fatal(err)
	}
	accepted := w.value.Load().(feedSnapshot)
	cacheBefore, _ := os.ReadFile(w.cachePath())
	mu.Lock()
	body, tag = "192.0.2.9", "\"v2\""
	mu.Unlock()
	if err := w.refresh(); err == nil {
		t.Fatal("below-minimum update accepted")
	}
	got := w.value.Load().(feedSnapshot)
	cacheAfter, _ := os.ReadFile(w.cachePath())
	if got.etag != accepted.etag || !w.contains(netip.MustParseAddr("192.0.2.1")) ||
		w.contains(netip.MustParseAddr("192.0.2.9")) || string(cacheBefore) != string(cacheAfter) {
		t.Fatal("last-known-good not retained")
	}
	reloaded := newWorker(k)
	if err := reloaded.loadCache(); err != nil || !reloaded.contains(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("retained cache no longer reloads", err)
	}
}

// Failure diagnostics distinguish an empty snapshot from retained LKG, include
// the LKG validation age, and rate-limit repeated warnings per worker (§6.4).
func TestFeedFailureDiagnostics(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	w := newWorker(keyFor("https://example.invalid/d", ""))
	id := w.id[:12]
	w.warn(fmt.Errorf("boom"))
	if !w.failed || !strings.Contains(buf.String(), id+" feed failure") || !strings.Contains(buf.String(), "snapshot empty") {
		t.Fatalf("empty-snapshot diagnostic missing: %q", buf.String())
	}
	buf.Reset()
	w.warn(fmt.Errorf("boom"))
	if strings.Contains(buf.String(), id) {
		t.Fatalf("repeat warning not rate-limited: %q", buf.String())
	}

	accepted, _ := decodeFeed([]byte("192.0.2.1"), "lines", 1)
	accepted.validated = time.Now().Add(-90 * time.Minute)
	w.value.Store(accepted)
	w.lastWarning = time.Time{}
	buf.Reset()
	w.warn(fmt.Errorf("boom"))
	if !strings.Contains(buf.String(), id+" feed failure") || !strings.Contains(buf.String(), "retaining LKG age=") {
		t.Fatalf("LKG-age diagnostic missing: %q", buf.String())
	}
}

// New validates before acquiring workers, shares one worker per effective spec
// across sources/reloads, separates every distinguishing dimension, and never
// wires worker lifetime to the router-construction context it is handed.
func TestNewWorkerSharingAndLifetime(t *testing.T) {
	dir := t.TempDir()
	feed := func(mut func(*FeedConfig)) FeedConfig {
		f := FeedConfig{URL: text("https://127.0.0.1:1/f"), Format: text("lines"), RefreshInterval: text("1h"), MinEntries: 1}
		if mut != nil {
			mut(&f)
		}
		return f
	}
	src := func(name string, f FeedConfig) SourceConfig {
		return SourceConfig{Name: text(name), Trust: &TrustConfig{Feeds: &[]FeedConfig{f}}, Extract: &HeaderConfig{Header: text("X-Client"), Mode: text("single")}}
	}
	count := func() int {
		workersMu.Lock()
		defer workersMu.Unlock()
		return len(workers)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := count()
	h, err := New(ctx, http.NotFoundHandler(), &Config{FeedCacheDir: text(dir),
		Sources: []SourceConfig{src("a", feed(nil)), src("b", feed(nil))}}, "alias")
	if err != nil {
		t.Fatal(err)
	}
	if got := count() - before; got != 1 {
		t.Fatalf("identical specs across sources produced %d workers", got)
	}
	shared := h.(*middleware).settings.sources[0].feeds[0].(*feedWorker)
	if shared.value.Load().(feedSnapshot).set.exact == nil {
		t.Fatal("worker exposed before an initialized snapshot")
	}
	if acquireWorker(shared.key) != shared {
		t.Fatal("canceled context detached the running worker")
	}

	before = count()
	if _, err := New(context.Background(), http.NotFoundHandler(), &Config{FeedCacheDir: text(dir), Sources: []SourceConfig{
		src("url", feed(func(f *FeedConfig) { f.URL = text("https://127.0.0.1:1/g") })),
		src("format", feed(func(f *FeedConfig) { f.Format = text("json-array") })),
		src("interval", feed(func(f *FeedConfig) { f.RefreshInterval = text("2h") })),
		src("minimum", feed(func(f *FeedConfig) { f.MinEntries = 2 })),
	}}, "alias"); err != nil {
		t.Fatal(err)
	}
	if got := count() - before; got != 4 {
		t.Fatalf("distinguishing dimensions produced %d workers", got)
	}

	before = count()
	if _, err := New(context.Background(), http.NotFoundHandler(), &Config{FeedCacheDir: text(t.TempDir()), Sources: []SourceConfig{src("a", feed(nil))}}, "alias"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), http.NotFoundHandler(), &Config{FeedCacheDir: text(dir), Sources: []SourceConfig{src("a", feed(nil))}}, "alias"); err != nil {
		t.Fatal(err)
	}
	if got := count() - before; got != 1 {
		t.Fatalf("cacheDir separation with identical reload produced %d workers", got)
	}
}
