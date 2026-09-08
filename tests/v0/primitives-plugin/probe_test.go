package realclientv0

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

func TestConcurrentRepeatedConstruction(t *testing.T) {
	cfg := &Config{Values: []string{"original"}, Nested: map[string]interface{}{"inner": map[string]interface{}{"value": "original"}}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "native-concurrent"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
