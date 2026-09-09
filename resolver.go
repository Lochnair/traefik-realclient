package realclient

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

var identityHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip", "X-Client-Ip", "X-Cluster-Client-Ip", "X-Original-Forwarded-For", "X-Originating-Ip", "True-Client-Ip", "Cf-Connecting-Ip", "Cf-Connecting-Ipv6", "Cf-Pseudo-Ipv4", "Fastly-Client-Ip", "Fly-Client-Ip", "X-Azure-Clientip", "X-Azure-Socketip", "X-Appengine-User-Ip", "Proxy-Client-Ip", "WL-Proxy-Client-Ip", "X-ProxyUser-Ip"}
var forwardingHeaders = []string{"X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Scheme", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Forwarded-Method", "X-Forwarded-Tls-Client-Cert", "X-Forwarded-Tls-Client-Cert-Info", "Cf-Visitor"}
var ownedHeaders = []string{"X-Realclient-Verified", "X-Realclient-Source"}

func headerAlias(name string) string { return strings.ToLower(strings.ReplaceAll(name, "_", "-")) }
func singleHeader(r *http.Request, name string) (string, bool) {
	// Cardinality remains strict even for manually assembled noncanonical maps.
	var value string
	count := 0
	for key, values := range r.Header {
		if strings.EqualFold(key, name) {
			for _, v := range values {
				value = v
				count++
			}
		}
	}
	return value, count == 1 && value != ""
}
func (p predicate) matches(r *http.Request) bool {
	var value string
	var ok bool
	if p.header == "Host" {
		value, ok = r.Host, r.Host != ""
	} else {
		value, ok = singleHeader(r, p.header)
	}
	if !ok {
		return false
	}
	if p.kind != "exact" {
		var err error
		value, err = hostname(value)
		if err != nil {
			return false
		}
	}
	for _, expected := range p.values {
		if value == expected || p.kind == "hostSuffixes" && strings.HasSuffix(value, "."+expected) {
			return true
		}
	}
	return false
}
func (s source) matches(r *http.Request, peer netip.Addr) bool {
	if len(s.static.exact) > 0 || len(s.static.prefixes) > 0 || len(s.specs) > 0 {
		found := s.static.contains(peer)
		for _, feed := range s.feeds {
			if feed.contains(peer) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, p := range s.predicates {
		if !p.matches(r) {
			return false
		}
	}
	return true
}
func schemeToken(value string) string {
	switch strings.ToLower(strings.Trim(value, " \t")) {
	case "http", "ws":
		return "http"
	case "https", "wss":
		return "https"
	}
	return ""
}
func (h headerRule) schemeValue(r *http.Request) string {
	if h.header == "" {
		return ""
	}
	value, ok := singleHeader(r, h.header)
	if !ok {
		return ""
	}
	tokens := []string{value}
	if h.mode == "uniform-list" {
		tokens = strings.Split(value, ",")
	}
	result := ""
	for _, token := range tokens {
		s := schemeToken(token)
		if s == "" || result != "" && result != s {
			return ""
		}
		result = s
	}
	return result
}
func websocket(r *http.Request) bool {
	upgrade, ok := singleHeader(r, "Upgrade")
	if !ok || !strings.EqualFold(strings.Trim(upgrade, " \t"), "websocket") {
		return false
	}
	for _, line := range r.Header.Values("Connection") {
		for _, token := range strings.Split(line, ",") {
			if strings.EqualFold(strings.Trim(token, " \t"), "upgrade") {
				return true
			}
		}
	}
	return false
}

type middleware struct {
	next     http.Handler
	settings settings
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peer, port, err := parsePeer(r.RemoteAddr)
	if err != nil {
		m.clear(r)
		http.Error(w, "client address unavailable", http.StatusInternalServerError)
		return
	}
	effective := peer
	resolvedSource := ""
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	for _, s := range m.settings.sources {
		if !s.matches(r, peer) {
			continue
		}
		value, ok := singleHeader(r, s.extract.header)
		if !ok {
			continue
		}
		ip, err := clientIP(value)
		if err != nil {
			continue
		}
		effective, port = ip, "0"
		resolvedSource = s.name
		if original := s.scheme.schemeValue(r); original != "" {
			scheme = original
		}
		break
	}
	isWebsocket := websocket(r)
	m.clear(r)
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.RemoteAddr = net.JoinHostPort(effective.String(), port)
	r.Header.Set("X-Real-Ip", effective.String())
	if resolvedSource != "" {
		r.Header.Set("X-Realclient-Verified", "true")
		r.Header.Set("X-Realclient-Source", resolvedSource)
	}
	forwardedScheme := scheme
	if isWebsocket {
		if scheme == "https" {
			forwardedScheme = "wss"
		} else {
			forwardedScheme = "ws"
		}
	}
	for _, name := range []string{"X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Scheme"} {
		r.Header.Set(name, forwardedScheme)
	}
	if r.Host != "" {
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
	_, authorityPort, err := splitAuthority(r.Host)
	if err != nil || authorityPort == "" {
		authorityPort = "80"
		if scheme == "https" {
			authorityPort = "443"
		}
	}
	r.Header.Set("X-Forwarded-Port", authorityPort)
	m.next.ServeHTTP(w, r)
}
func (m *middleware) clear(r *http.Request) {
	for name := range r.Header {
		if m.settings.remove[headerAlias(name)] {
			delete(r.Header, name)
		}
	}
}
