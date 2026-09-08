// Package realclientv0 tests isolated runtime primitives, not feed workers.
package realclientv0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Values []string
	Nested map[string]interface{}
}

func CreateConfig() *Config { return &Config{} }

type key struct {
	URL      string
	Format   string
	Interval time.Duration
	Minimum  int
	Cache    string
}
type snapshot struct {
	Addresses map[netip.Addr]bool
	Prefixes  map[netip.Prefix]bool
	Tick      int
}
type worker struct {
	value atomic.Value
	ready chan struct{}
}

var registryMu sync.Mutex
var registry = make(map[key]*worker)

func acquire(k key) *worker {
	registryMu.Lock()
	defer registryMu.Unlock()
	if w := registry[k]; w != nil {
		return w
	}
	w := &worker{ready: make(chan struct{})}
	w.value.Store(snapshot{Addresses: make(map[netip.Addr]bool), Prefixes: make(map[netip.Prefix]bool)})
	registry[k] = w
	go func() {
		// Finite publication loop: no feed fetching, cache or production lifecycle.
		for tick := 1; tick <= 4; tick++ {
			addr := netip.MustParseAddr("192.0.2.1")
			prefix := netip.MustParsePrefix("192.0.2.0/24")
			w.value.Store(snapshot{Addresses: map[netip.Addr]bool{addr: true}, Prefixes: map[netip.Prefix]bool{prefix: true}, Tick: tick})
		}
		close(w.ready)
	}()
	return w
}

func inspect(cfg *Config) (map[string]interface{}, error) {
	before, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	base := key{URL: "https://example.invalid/feed", Format: "lines", Interval: time.Second, Minimum: 1}
	const count = 24
	workers := make([]*worker, count)
	copies := make([]*Config, count)
	errors := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			// Deep copy the borrowed decoded object into independent construction data.
			data, e := json.Marshal(cfg)
			if e != nil {
				errors <- e
				return
			}
			var internal Config
			if e = json.Unmarshal(data, &internal); e != nil {
				errors <- e
				return
			}
			copies[index] = &internal
			workers[index] = acquire(base)
		}(i)
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		return nil, e
	}
	for i := 1; i < count; i++ {
		if workers[i] != workers[0] {
			return nil, fmt.Errorf("same key acquired multiple workers")
		}
		if !reflect.DeepEqual(copies[i], copies[0]) {
			return nil, fmt.Errorf("independent settings differ")
		}
	}
	// Test only independent scratch construction data, never decoded configuration.
	if len(copies[0].Values) > 0 {
		copies[0].Values[0] = "scratch-change"
	}
	copies[0].Nested["scratch"] = "change"
	copies[0].Nested["inner"].(map[string]interface{})["value"] = "nested-change"
	if reflect.DeepEqual(copies[0], copies[1]) {
		return nil, fmt.Errorf("copies unexpectedly equal after scratch mutation")
	}
	after, _ := json.Marshal(cfg)
	if string(before) != string(after) {
		return nil, fmt.Errorf("borrowed input mutated")
	}
	var original Config
	if err := json.Unmarshal(before, &original); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(cfg, &original) {
		return nil, fmt.Errorf("borrowed nested data changed")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	// The construction context does not own this package-global primitive.
	<-canceled.Done()
	<-workers[0].ready
	final := workers[0].value.Load().(snapshot)
	addr := netip.MustParseAddr("192.0.2.1")
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	if !final.Addresses[addr] || !final.Prefixes[prefix] || final.Tick != 4 {
		return nil, fmt.Errorf("invalid atomic snapshot")
	}
	variants := []key{base, base, base, base, base}
	variants[0].URL += "2"
	variants[1].Format = "json-array"
	variants[2].Interval = 2 * time.Second
	variants[3].Minimum = 2
	variants[4].Cache = "/unused"
	for _, k := range variants {
		if acquire(k) == workers[0] {
			return nil, fmt.Errorf("different keys shared")
		}
	}
	registryMu.Lock()
	total := len(registry)
	registryMu.Unlock()
	if total != 6 {
		return nil, fmt.Errorf("registry count %d, want 6", total)
	}
	return map[string]interface{}{"sameKeyConstructions": count, "registryWorkers": total, "inputUnchanged": true, "independentCopies": true, "netipMapKeys": true, "atomicSnapshotTick": final.Tick, "canceledContextIndependent": true}, nil
}

type probe struct {
	result []byte
	cfg    *Config
}

func New(_ context.Context, _ http.Handler, cfg *Config, _ string) (http.Handler, error) {
	result, err := inspect(cfg)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	return &probe{result: data, cfg: cfg}, err
}
func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Call the actual interpreted New concurrently, not only a native surrogate.
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := New(context.Background(), http.NotFoundHandler(), p.cfg, "interpreted-concurrent")
			if err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("X-V0-Concurrent-New", "8")
	w.Header().Set("Content-Type", "application/json")
	w.Write(p.result)
}
