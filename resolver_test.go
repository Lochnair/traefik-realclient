package realclient

import (
	"crypto/tls"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func list(values ...string) *[]string { return &values }
func explicit() SourceConfig {
	return SourceConfig{Name: text("source"), Trust: &TrustConfig{Static: list("0.0.0.0/0", "::/0")}, Extract: &HeaderConfig{Header: text("X-Client"), Mode: text("single")}, Scheme: &HeaderConfig{Header: text("X-Proto"), Mode: text("uniform-list")}}
}
func apply(t *testing.T, c *Config, r *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	s, err := compileConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })
	w := httptest.NewRecorder()
	(&middleware{next: next, settings: s}).ServeHTTP(w, r)
	return w, called
}
func request(peer string) *http.Request {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.RemoteAddr = peer
	return r
}
func TestPeerAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		valid       bool
	}{{"127.0.0.1:34", "127.0.0.1:34", true}, {"[::ffff:192.0.2.1]:00080", "192.0.2.1:80", true}, {"[fe80::1%en0]:42", "[fe80::1]:42", true}, {"0.0.0.0:0", "0.0.0.0:0", true}, {"[::]:0", "[::]:0", true}, {"192.0.2.1:", "", false}, {"192.0.2.1:-1", "", false}, {"192.0.2.1:65536", "", false}, {"hostname:1", "", false}, {"::1:80", "", false}} {
		t.Run(tc.input, func(t *testing.T) {
			r := request(tc.input)
			r.Header.Set("X-Real-Ip", "forged")
			r.Header.Set("X-Realclient-Verified", "forged")
			r.Header.Set("X-Realclient-Source", "forged")
			w, called := apply(t, CreateConfig(), r)
			if called != tc.valid {
				t.Fatalf("called %v", called)
			}
			if tc.valid {
				if r.RemoteAddr != tc.want {
					t.Fatal(r.RemoteAddr)
				}
			} else if w.Code != 500 || strings.Contains(w.Body.String(), tc.input) || r.Header.Get("X-Real-Ip") != "" ||
				r.Header.Get("X-Realclient-Verified") != "" || r.Header.Get("X-Realclient-Source") != "" {
				t.Fatal("bad integration error")
			}
		})
	}
	for _, value := range []string{"10.0.0.1", "127.0.0.1", "169.254.0.1", "100.64.1.1", "192.0.2.1", "::1", "fe80::1%en0", "::ffff:192.0.2.1", "\t192.0.2.1 "} {
		r := request("203.0.113.1:45")
		r.Header.Set("X-Client", value)
		_, called := apply(t, &Config{Sources: []SourceConfig{explicit()}}, r)
		a, _ := clientIP(value)
		if !called || r.Header.Get("X-Real-Ip") != a.String() || !strings.HasSuffix(r.RemoteAddr, ":0") {
			t.Fatal(value, r.RemoteAddr)
		}
	}
	for _, value := range []string{"", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "[::1]", "192.0.2.1:8", "\"192.0.2.1\"", "192.0.2.1, 192.0.2.2", "example.com"} {
		r := request("203.0.113.1:45")
		r.Header.Set("X-Client", value)
		apply(t, &Config{Sources: []SourceConfig{explicit()}}, r)
		if r.RemoteAddr != "203.0.113.1:45" {
			t.Fatal(value, r.RemoteAddr)
		}
	}
}
func TestSets(t *testing.T) {
	set, err := parseSet([]string{"192.0.2.1", "192.0.2.1/32", "::ffff:192.0.2.1/128", "192.0.3.9/24", "::/0"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.exact) != 1 || len(set.prefixes) != 2 {
		t.Fatal(set)
	}
	if !set.contains(netip.MustParseAddr("192.0.3.1")) || set.contains(netip.MustParseAddr("198.51.100.1")) || !set.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("family/prefix")
	}
	for _, v := range []string{"::ffff:192.0.2.1/80", "fe80::1%en0/64", "bad"} {
		if _, err := parseEntry(v); err == nil {
			t.Fatal(v)
		}
	}
}
func TestFirstSuccessAndPredicates(t *testing.T) {
	for _, kind := range []string{"static", "headerIn", "hostExact", "hostSuffixes"} {
		t.Run(kind, func(t *testing.T) {
			c := explicit()
			c.Trust = &TrustConfig{}
			switch kind {
			case "static":
				c.Trust.Static = list("203.0.113.0/24")
			case "headerIn":
				c.Trust.HeaderIn = &HeaderInConfig{Name: text("X-Zone"), Values: list("001, 002")}
			case "hostExact":
				c.Trust.HostExact = &HostExactConfig{Header: text("Host"), Values: list("EXAMPLE.COM.:443")}
			case "hostSuffixes":
				c.Trust.HostSuffixes = &HostSuffixesConfig{Header: text("X-Host"), Suffixes: list("example.com")}
			}
			r := request("203.0.113.1:4")
			r.Header.Set("X-Zone", "001, 002")
			r.Header.Set("X-Host", "a.example.com.")
			r.Header.Set("X-Client", "192.0.2.2")
			apply(t, &Config{Sources: []SourceConfig{c}}, r)
			if r.Header.Get("X-Real-Ip") != "192.0.2.2" {
				t.Fatal(kind)
			}
		})
	}
	first := explicit()
	first.Trust.HeaderIn = &HeaderInConfig{Name: text("X-Zone"), Values: list("one")}
	second := explicit()
	second.Name = text("second")
	second.Extract.Header = text("X-Second")
	for _, tc := range []struct{ zone, first, expected string }{{"two", "192.0.2.1", "192.0.2.2"}, {"one", "bad", "192.0.2.2"}, {"one", "192.0.2.1", "192.0.2.1"}} {
		r := request("203.0.113.1:4")
		r.Header.Set("X-Zone", tc.zone)
		r.Header.Set("X-Client", tc.first)
		r.Header.Set("X-Second", "192.0.2.2")
		apply(t, &Config{Sources: []SourceConfig{first, second}}, r)
		if r.Header.Get("X-Real-Ip") != tc.expected || r.Header.Get("X-Second") != "" {
			t.Fatal(tc, r.Header)
		}
	}
	r := request("203.0.113.1:4")
	r.Header["X-Client"] = []string{"192.0.2.1", "192.0.2.1"}
	apply(t, &Config{Sources: []SourceConfig{explicit()}}, r)
	if r.RemoteAddr != "203.0.113.1:4" {
		t.Fatal("duplicates accepted")
	}
}
func TestHostnames(t *testing.T) {
	for _, v := range []string{"example.com", "EXAMPLE.COM.:443", "xn--bcher-kva.example", "localhost"} {
		if _, err := hostname(v); err != nil {
			t.Fatal(v, err)
		}
	}
	for _, v := range []string{"", "a..com", "-a.com", "a-.com", "example.com:0", "example.com:", "example.com:65536", "example.com:+1", "a.com..", "[::1]:443", "192.0.2.1", "bücher.com", "a.com,b.com", "https://a.com", "a.com/a", "a@b.com", "*.a.com"} {
		if _, err := hostname(v); err == nil {
			t.Fatal(v)
		}
	}
	p := predicate{kind: "hostSuffixes", header: "X-Host", values: []string{"example.com"}}
	r := request("127.0.0.1:1")
	r.Header.Set("X-Host", "evil-example.com")
	if p.matches(r) {
		t.Fatal("suffix boundary")
	}
	r.Header["X-Host"] = []string{"example.com", "example.com"}
	if p.matches(r) {
		t.Fatal("duplicate host")
	}
}
func TestSchemeAndNormalization(t *testing.T) {
	for _, tlsOn := range []bool{false, true} {
		for _, tc := range []struct{ value, want string }{{"http", "http"}, {"https", "https"}, {"WSS, https", "https"}, {"https, http", ""}, {"https,", ""}, {"", ""}, {"ftp", ""}} {
			r := request("203.0.113.1:4")
			if tlsOn {
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			}
			originalTLS := r.TLS
			r.Header.Set("X-Client", "192.0.2.1")
			r.Header.Set("X-Proto", tc.value)
			r.Header.Set("X-Forwarded-Server", "keep")
			r.Header.Set("CF-IPCountry", "NO")
			r.Header.Set("CDN-Host", "keep")
			r.Header.Set("X-Forwarded-Client-Cert", "delegate")
			for _, name := range append(append([]string{}, identityHeaders...), forwardingHeaders...) {
				r.Header[strings.ReplaceAll(strings.ToLower(name), "-", "_")] = []string{"forged"}
			}
			apply(t, &Config{Sources: []SourceConfig{explicit()}}, r)
			want := tc.want
			if want == "" {
				want = "http"
				if tlsOn {
					want = "https"
				}
			}
			for _, h := range []string{"X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Scheme"} {
				if r.Header.Get(h) != want {
					t.Fatal(tlsOn, tc, h, r.Header)
				}
			}
			if r.TLS != originalTLS || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-Ip") != "192.0.2.1" || r.Header.Get("X-Forwarded-Server") != "keep" || r.Header.Get("Cf-Ipcountry") != "NO" || r.Header.Get("X-Forwarded-Client-Cert") != "delegate" {
				t.Fatal(r.Header)
			}
			for name := range r.Header {
				if strings.Contains(name, "_") {
					t.Fatal("alias survived", name)
				}
			}
		}
	}
	for _, upgrade := range []string{"websocket", "h2c", ""} {
		r := request("127.0.0.1:5")
		r.Header.Set("Connection", "keep-alive, Upgrade")
		r.Header.Set("Upgrade", upgrade)
		apply(t, CreateConfig(), r)
		want := "http"
		if upgrade == "websocket" {
			want = "ws"
		}
		if r.Header.Get("X-Scheme") != want {
			t.Fatal(upgrade)
		}
	}
}

// What a backend behind Traefik's non-rewriting path observes: canonical
// identity, deleted competing/forwarded-request inputs, rebuilt authority
// metadata, overlapping-source precedence, and independent scheme fallback.
func TestBackendObservedForwarding(t *testing.T) {
	// Resolved source: authority host/port rebuilt, request-forwarding headers dropped.
	r := httptest.NewRequest("GET", "https://app.example.com:8443/a?b=c", nil)
	r.RemoteAddr = "203.0.113.7:5"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	r.Header.Set("X-Client", "192.0.2.50")
	r.Header.Set("X-Proto", "http")
	for _, h := range []string{"X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Forwarded-Method"} {
		r.Header.Set(h, "forged")
	}
	if _, called := apply(t, &Config{Sources: []SourceConfig{explicit()}}, r); !called {
		t.Fatal("not called")
	}
	if r.RemoteAddr != "192.0.2.50:0" || r.Header.Get("X-Real-Ip") != "192.0.2.50" {
		t.Fatal("identity", r.RemoteAddr, r.Header.Get("X-Real-Ip"))
	}
	if r.Header.Get("X-Realclient-Verified") != "true" || r.Header.Get("X-Realclient-Source") != "source" {
		t.Fatal("provenance", r.Header)
	}
	if r.Header.Get("X-Forwarded-Host") != "app.example.com:8443" || r.Header.Get("X-Forwarded-Port") != "8443" {
		t.Fatal("authority", r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Port"))
	}
	// Scheme metadata (http) is authoritative over the TLS peer transport, and
	// drives the default port only when the authority carries none.
	if r.Header.Get("X-Forwarded-Proto") != "http" {
		t.Fatal("scheme not independent of peer transport")
	}
	for _, h := range []string{"X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Forwarded-Method", "X-Forwarded-For"} {
		if r.Header.Get(h) != "" {
			t.Fatal("stale forwarding header", h)
		}
	}

	// Peer fallback: canonical peer tuple, scheme from transport, default port.
	r = request("[::ffff:198.51.100.9]:6100")
	r.Header.Set("X-Realclient-Verified", "forged")
	r.Header.Set("X-Realclient-Source", "forged")
	if _, called := apply(t, CreateConfig(), r); !called {
		t.Fatal("not called")
	}
	if r.RemoteAddr != "198.51.100.9:6100" || r.Header.Get("X-Real-Ip") != "198.51.100.9" ||
		r.Header.Get("X-Forwarded-Proto") != "http" || r.Header.Get("X-Forwarded-Port") != "80" {
		t.Fatal("fallback tuple", r.RemoteAddr, r.Header)
	}
	if r.Header.Get("X-Realclient-Verified") != "" || r.Header.Get("X-Realclient-Source") != "" {
		t.Fatal("fallback provenance", r.Header)
	}

	// Overlapping sources both match the peer; the first extracts a malformed
	// value, so the second wins and supplies its own scheme.
	a := explicit()
	a.Name = text("a")
	b := explicit()
	b.Name, b.Extract = text("b"), &HeaderConfig{Header: text("X-B"), Mode: text("single")}
	b.Scheme = &HeaderConfig{Header: text("X-BProto"), Mode: text("single")}
	r = request("203.0.113.7:5")
	r.Header.Set("X-Client", "not-an-ip")
	r.Header.Set("X-B", "192.0.2.77")
	r.Header.Set("X-BProto", "https")
	apply(t, &Config{Sources: []SourceConfig{a, b}}, r)
	if r.Header.Get("X-Real-Ip") != "192.0.2.77" || r.Header.Get("X-Forwarded-Proto") != "https" ||
		r.Header.Get("X-B") != "" || r.Header.Get("X-Client") != "" ||
		r.Header.Get("X-Realclient-Source") != "b" {
		t.Fatal("overlap precedence", r.Header)
	}

	// A duplicate scheme-header instance is not usable; the extracted IP is kept
	// and scheme falls back to peer transport.
	r = request("203.0.113.7:5")
	r.Header.Set("X-Client", "192.0.2.88")
	r.Header["X-Proto"] = []string{"https", "https"}
	apply(t, &Config{Sources: []SourceConfig{explicit()}}, r)
	if r.Header.Get("X-Real-Ip") != "192.0.2.88" || r.Header.Get("X-Forwarded-Proto") != "http" {
		t.Fatal("duplicate scheme header", r.Header)
	}
}

func TestConfigImmutabilityAndValidation(t *testing.T) {
	c := &Config{Sources: []SourceConfig{{Name: text("bunny"), Preset: text("bunny"), Trust: &TrustConfig{HeaderIn: &HeaderInConfig{Name: text("X-Zone"), Values: list("001")}}}}}
	s, err := compileConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.sources[0].specs) != 2 || s.sources[0].scheme.header != "" {
		t.Fatal("preset")
	}
	(*c.Sources[0].Trust.HeaderIn.Values)[0] = "changed"
	if s.sources[0].predicates[0].values[0] != "001" {
		t.Fatal("borrowed alias")
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := compileConfig(c); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, v := range []interface{}{"1", 1, int64(2), uint64(3), float64(4)} {
		if _, err := minimum(v); err != nil {
			t.Fatal(v)
		}
	}
	for _, v := range []interface{}{"-1", "+1", " 1", "1e1", "1.0", "18446744073709551616", 1.5, math.NaN(), math.Inf(1), true, 100001} {
		if _, err := minimum(v); err == nil {
			t.Fatal(v)
		}
	}
	for _, where := range []string{"top", "source", "trust", "extract", "scheme", "feed", "header", "host", "suffix"} {
		t.Run(where, func(t *testing.T) {
			x := explicit()
			bad := map[string]interface{}{"headerEquals": "bad"}
			cfg := &Config{Sources: []SourceConfig{x}}
			switch where {
			case "top":
				cfg.Unknown = bad
			case "source":
				cfg.Sources[0].Unknown = bad
			case "trust":
				x.Trust.Unknown = bad
			case "extract":
				x.Extract.Unknown = bad
			case "scheme":
				x.Scheme.Unknown = bad
			case "feed":
				x.Trust.Feeds = &[]FeedConfig{{Unknown: bad}}
			case "header":
				x.Trust.HeaderIn = &HeaderInConfig{Unknown: bad}
			case "host":
				x.Trust.HostExact = &HostExactConfig{Unknown: bad}
			case "suffix":
				x.Trust.HostSuffixes = &HostSuffixesConfig{Unknown: bad}
			}
			if _, err := compileConfig(cfg); err == nil {
				t.Fatal("unknown accepted")
			}
		})
	}
	x := explicit()
	x.Trust.Static = list()
	if _, err := compileConfig(&Config{Sources: []SourceConfig{x}}); err == nil {
		t.Fatal("empty accepted")
	}
	before := CreateConfig()
	after := CreateConfig()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("defaults")
	}
}

func TestOwnedOutputConfigurationCollisions(t *testing.T) {
	for _, owned := range []string{"X-Realclient-Verified", "X-Realclient-Source"} {
		for _, field := range []string{"extract", "scheme", "headerIn", "hostExact", "hostSuffixes"} {
			t.Run(owned+"/"+field, func(t *testing.T) {
				x := explicit()
				header := owned
				if owned == "X-Realclient-Verified" && field == "hostSuffixes" {
					header = "x_REALCLIENT_verified"
				}
				switch field {
				case "extract":
					x.Extract.Header = text(header)
				case "scheme":
					x.Scheme.Header = text(header)
				case "headerIn":
					x.Trust.HeaderIn = &HeaderInConfig{Name: text(header), Values: list("value")}
				case "hostExact":
					x.Trust.HostExact = &HostExactConfig{Header: text(header), Values: list("example.com")}
				case "hostSuffixes":
					x.Trust.HostSuffixes = &HostSuffixesConfig{Header: text(header), Suffixes: list("example.com")}
				}
				if _, err := compileConfig(&Config{Sources: []SourceConfig{x}}); err == nil || !strings.Contains(err.Error(), "owned output header") {
					t.Fatal("owned output accepted", err)
				}
			})
		}
	}
}

func TestSourceNameHeaderValueValidation(t *testing.T) {
	for _, name := range []string{"bunny", "cloudflare-edge", "internal proxy 1", "edge\tprimary"} {
		t.Run("valid/"+name, func(t *testing.T) {
			x := explicit()
			x.Name = text(name)
			if _, err := compileConfig(&Config{Sources: []SourceConfig{x}}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct{ name, value string }{{"cr", "edge\rname"}, {"lf", "edge\nname"}, {"nul", "edge\x00name"}, {"control", "edge\x1fname"}, {"del", "edge\x7fname"}} {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			x := explicit()
			x.Name = text(tc.value)
			if _, err := compileConfig(&Config{Sources: []SourceConfig{x}}); err == nil {
				t.Fatal("unsafe source name accepted")
			}
		})
	}
}

func TestPresetUsesConfiguredSourceName(t *testing.T) {
	x := SourceConfig{Name: text("configured-edge"), Preset: text("cloudflare"), Trust: &TrustConfig{Static: list("203.0.113.0/24")}}
	r := request("203.0.113.1:443")
	r.Header.Set("Cf-Connecting-Ip", "192.0.2.9")
	apply(t, &Config{Sources: []SourceConfig{x}}, r)
	if r.Header.Get("X-Real-Ip") != "192.0.2.9" || r.Header.Get("X-Realclient-Verified") != "true" || r.Header.Get("X-Realclient-Source") != "configured-edge" {
		t.Fatal(r.Header)
	}
}
