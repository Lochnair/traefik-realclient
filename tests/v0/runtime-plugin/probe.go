// Package realclientv0 probes Traefik's request boundary, not the V1 resolver.
package realclientv0

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
)

type Config struct {
	Inputs   []string
	Selector string
}

func CreateConfig() *Config { return &Config{} }

type probe struct {
	next     http.Handler
	inputs   []string
	selector string
}

func New(_ context.Context, next http.Handler, c *Config, _ string) (http.Handler, error) {
	return &probe{next: next, inputs: append([]string(nil), c.Inputs...), selector: c.Selector}, nil
}
func (p *probe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	originalTLS := r.TLS
	originalState, _ := json.Marshal(r.TLS)
	// Observe pre-mutation inputs. Source selection is deliberately only a fixture:
	// ordered bare-IP headers, optionally gate the first one with a fixed selector.
	before, _ := json.Marshal(struct {
		Peer    string
		Headers http.Header
		TLS     bool
		Proto   string
	}{r.RemoteAddr, r.Header, r.TLS != nil, r.Proto})
	r.Header.Set("X-V0-Before", string(before))
	peer, port, _ := net.SplitHostPort(r.RemoteAddr)
	effective := peer
	selected := "peer"
	for i, header := range p.inputs {
		if i == 0 && p.selector != "" && r.Header.Get(p.selector) != "yes" {
			continue
		}
		values := r.Header.Values(header)
		if len(values) != 1 {
			continue
		}
		addr, err := netip.ParseAddr(values[0])
		if err != nil {
			continue
		}
		effective = addr.Unmap().String()
		port = "0"
		selected = header
		break
	}
	r.RemoteAddr = net.JoinHostPort(effective, port)
	r.Header.Del("X-Forwarded-For")
	r.Header.Set("X-Real-Ip", effective)
	r.Header.Set("X-V0-Selected", selected)
	r.Header.Set("X-V0-After-Peer", r.RemoteAddr)
	currentState, _ := json.Marshal(r.TLS)
	if r.TLS != originalTLS || string(originalState) != string(currentState) {
		panic("V0 mutation changed TLS state")
	}
	r.Header.Set("X-V0-Tls-Preserved", "true")
	p.next.ServeHTTP(w, r)
}
