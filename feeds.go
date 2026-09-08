package realclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxFeedBytes = 4 * 1024 * 1024
const maxCacheBytes = 8 * 1024 * 1024
const cacheVersion = 1

type feedSnapshot struct {
	set       addressSet
	entries   []string
	etag      string
	validated time.Time
}
type feedWorker struct {
	key    feedKey
	id     string
	client *http.Client
	value  atomic.Value
	// Only the serial worker loop accesses diagnostic state.
	failed       bool
	lastWarning  time.Time
	cacheWarning time.Time
	cacheFailed  bool
}

var workersMu sync.Mutex
var workers = make(map[feedKey]*feedWorker)

func newWorker(key feedKey) *feedWorker {
	encoded, _ := json.Marshal(struct {
		Version int
		Key     feedKey
	}{cacheVersion, key})
	sum := sha256.Sum256(encoded)
	w := &feedWorker{key: key, id: hex.EncodeToString(sum[:]), client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	w.value.Store(feedSnapshot{set: addressSet{exact: make(map[netip.Addr]bool)}})
	return w
}
func acquireWorker(key feedKey) *feedWorker {
	workersMu.Lock()
	defer workersMu.Unlock()
	if w := workers[key]; w != nil {
		return w
	}
	w := newWorker(key)
	workers[key] = w
	log.Printf("realclient: worker=%s format=%s interval=%s minEntries=%d cache=%t started", w.id[:12], key.Format, key.Interval, key.Minimum, key.CacheDir != "")
	go w.run()
	return w
}
func (w *feedWorker) contains(addr netip.Addr) bool {
	return w.value.Load().(feedSnapshot).set.contains(addr)
}
func (w *feedWorker) run() {
	if w.key.CacheDir != "" {
		if err := w.loadCache(); err != nil && !os.IsNotExist(err) {
			w.warnCache("load")
		}
	}
	for {
		err := w.refresh()
		delay := w.key.Interval
		if err != nil {
			delay = 2 * time.Minute
			w.warn(err)
		} else if w.failed {
			log.Printf("realclient: worker=%s recovered", w.id[:12])
			w.failed = false
		}
		// Both success and failure schedules get the same +/-10%% jitter.
		time.Sleep(time.Duration(float64(delay) * (0.9 + rand.Float64()*0.2)))
	}
}
func (w *feedWorker) warn(err error) {
	now := time.Now()
	w.failed = true
	if !w.lastWarning.IsZero() && now.Sub(w.lastWarning) < time.Minute {
		return
	}
	w.lastWarning = now
	s := w.value.Load().(feedSnapshot)
	if s.validated.IsZero() {
		log.Printf("realclient: worker=%s feed failure (%s); snapshot empty", w.id[:12], err)
	} else {
		log.Printf("realclient: worker=%s feed failure (%s); retaining LKG age=%s", w.id[:12], err, now.Sub(s.validated).Round(time.Second))
	}
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read failed")
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("size limit exceeded")
	}
	return data, nil
}
func decodeFeed(body []byte, format string, minimum int) (feedSnapshot, error) {
	if len(body) > maxFeedBytes {
		return feedSnapshot{}, fmt.Errorf("size limit exceeded")
	}
	var entries []string
	switch format {
	case "lines":
		for _, line := range strings.Split(strings.TrimPrefix(string(body), "\ufeff"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			entries = append(entries, line)
		}
	case "json-array":
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&entries); err != nil {
			return feedSnapshot{}, fmt.Errorf("invalid JSON array")
		}
		var extra interface{}
		if err := decoder.Decode(&extra); err != io.EOF {
			return feedSnapshot{}, fmt.Errorf("trailing JSON data")
		}
	default:
		return feedSnapshot{}, fmt.Errorf("unknown format")
	}
	set, err := parseSet(entries, minimum)
	if err != nil {
		return feedSnapshot{}, err
	}
	// Canonical serialized entries contain no duplicates and revalidate on load.
	normalized := make([]string, 0, len(set.exact)+len(set.prefixes))
	for addr := range set.exact {
		normalized = append(normalized, addr.String())
	}
	for _, prefix := range set.prefixes {
		normalized = append(normalized, prefix.String())
	}
	sort.Strings(normalized)
	return feedSnapshot{set: set, entries: normalized}, nil
}
func (w *feedWorker) refresh() error {
	old := w.value.Load().(feedSnapshot)
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.key.URL, nil)
		if err != nil {
			cancel()
			return fmt.Errorf("request construction failed")
		}
		req.Header.Set("User-Agent", "traefik-realclient/1")
		if attempt == 0 && !old.validated.IsZero() && old.etag != "" {
			req.Header.Set("If-None-Match", old.etag)
		}
		response, err := w.client.Do(req)
		if err != nil {
			cancel()
			return fmt.Errorf("HTTP transport failed")
		}
		if response.StatusCode == http.StatusNotModified {
			response.Body.Close()
			cancel()
			if old.validated.IsZero() {
				if attempt == 0 {
					continue
				}
				return fmt.Errorf("304 without representation")
			}
			next := old
			next.validated = time.Now().UTC()
			w.publish(next)
			return nil
		}
		if response.StatusCode != http.StatusOK {
			status := response.StatusCode
			response.Body.Close()
			cancel()
			return fmt.Errorf("HTTP status %d", status)
		}
		body, err := readBounded(response.Body, maxFeedBytes)
		response.Body.Close()
		cancel()
		if err != nil {
			return err
		}
		next, err := decodeFeed(body, w.key.Format, w.key.Minimum)
		if err != nil {
			return err
		}
		next.etag = response.Header.Get("ETag")
		next.validated = time.Now().UTC()
		w.publish(next)
		return nil
	}
	return fmt.Errorf("unusable response")
}
func (w *feedWorker) publish(next feedSnapshot) {
	w.value.Store(next)
	if w.key.CacheDir != "" {
		if err := w.saveCache(next); err != nil {
			w.warnCache("write")
		} else if w.cacheFailed {
			log.Printf("realclient: worker=%s cache recovered", w.id[:12])
			w.cacheFailed = false
		}
	}
}

type cacheRecord struct {
	Version   int
	Key       feedKey
	Entries   []string
	ETag      string
	Validated time.Time
}

func (w *feedWorker) cachePath() string { return filepath.Join(w.key.CacheDir, w.id+".json") }
func (w *feedWorker) loadCache() error {
	file, err := os.Open(w.cachePath())
	if err != nil {
		return err
	}
	defer file.Close()
	body, err := readBounded(file, maxCacheBytes)
	if err != nil {
		return err
	}
	var record cacheRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("invalid cache")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing cache data")
	}
	if record.Version != cacheVersion || record.Key != w.key || record.Validated.IsZero() {
		return fmt.Errorf("cache identity invalid")
	}
	set, err := parseSet(record.Entries, w.key.Minimum)
	if err != nil {
		return err
	}
	w.value.Store(feedSnapshot{set: set, entries: append([]string(nil), record.Entries...), etag: record.ETag, validated: record.Validated})
	return nil
}
func (w *feedWorker) saveCache(snapshot feedSnapshot) error {
	record := cacheRecord{Version: cacheVersion, Key: w.key, Entries: snapshot.entries, ETag: snapshot.etag, Validated: snapshot.validated}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(body) > maxCacheBytes {
		return fmt.Errorf("cache size limit")
	}
	if err := os.MkdirAll(w.key.CacheDir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(w.key.CacheDir, ".realclient-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, w.cachePath())
}

func (w *feedWorker) warnCache(operation string) {
	w.cacheFailed = true
	now := time.Now()
	if !w.cacheWarning.IsZero() && now.Sub(w.cacheWarning) < time.Minute {
		return
	}
	w.cacheWarning = now
	log.Printf("realclient: worker=%s cache %s unavailable; memory retained", w.id[:12], operation)
}
