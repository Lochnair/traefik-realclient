// Package realclientv0 is a V0 observation probe, not a resolver.
package realclientv0

import (
	"context"
	"encoding/json"
	"net/http"
)

// CreateConfig exercises the proposed raw map through Traefik's actual adapter.
func CreateConfig() *map[string]interface{} {
	cfg := make(map[string]interface{})
	return &cfg
}

type probe struct{ config []byte }

// New snapshots the supplied config without mutating any shared input.
func New(_ context.Context, _ http.Handler, cfg *map[string]interface{}, _ string) (http.Handler, error) {
	data, err := json.Marshal(*cfg)
	if err != nil {
		return nil, err
	}
	return &probe{config: data}, nil
}

func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(p.config)
}
