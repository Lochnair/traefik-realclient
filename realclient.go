package realclient

import (
	"context"
	"log"
	"net/http"
)

// New validates the complete borrowed config before acquiring background workers.
// Workers intentionally outlive router construction contexts and handler reloads.
func New(_ context.Context, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	compiled, err := compileConfig(cfg)
	if err != nil {
		return nil, err
	}
	for i := range compiled.sources {
		s := &compiled.sources[i]
		if len(s.static.exact) == 0 && len(s.static.prefixes) == 0 && len(s.specs) == 0 {
			log.Printf("realclient: source=%q has no peer-address predicate; independent provenance required", s.name)
		}
		for _, key := range s.specs {
			s.feeds = append(s.feeds, acquireWorker(key))
		}
	}
	return &middleware{next: next, settings: compiled}, nil
}
