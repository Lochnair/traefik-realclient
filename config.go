// Package realclient resolves client identity behind explicitly trusted upstreams.
package realclient

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config is borrowed, decoded Traefik configuration. Null has omission semantics.
type Config struct {
	Sources      []SourceConfig         `json:"sources,omitempty"`
	FeedCacheDir *string                `json:"feedCacheDir,omitempty"`
	Unknown      map[string]interface{} `mapstructure:",remain" json:"-"`
}
type SourceConfig struct {
	Name    *string                `json:"name,omitempty"`
	Preset  *string                `json:"preset,omitempty"`
	Trust   *TrustConfig           `json:"trust,omitempty"`
	Extract *HeaderConfig          `json:"extract,omitempty"`
	Scheme  *HeaderConfig          `json:"scheme,omitempty"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"-"`
}
type TrustConfig struct {
	Static       *[]string              `json:"static,omitempty"`
	Feeds        *[]FeedConfig          `json:"feeds,omitempty"`
	HeaderIn     *HeaderInConfig        `json:"headerIn,omitempty"`
	HostExact    *HostExactConfig       `json:"hostExact,omitempty"`
	HostSuffixes *HostSuffixesConfig    `json:"hostSuffixes,omitempty"`
	Unknown      map[string]interface{} `mapstructure:",remain" json:"-"`
}
type HeaderConfig struct {
	Header  *string                `json:"header,omitempty"`
	Mode    *string                `json:"mode,omitempty"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"-"`
}
type HeaderInConfig struct {
	Name    *string                `json:"name,omitempty"`
	Values  *[]string              `json:"values,omitempty"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"-"`
}
type HostExactConfig struct {
	Header  *string                `json:"header,omitempty"`
	Values  *[]string              `json:"values,omitempty"`
	Unknown map[string]interface{} `mapstructure:",remain" json:"-"`
}
type HostSuffixesConfig struct {
	Header   *string                `json:"header,omitempty"`
	Suffixes *[]string              `json:"suffixes,omitempty"`
	Unknown  map[string]interface{} `mapstructure:",remain" json:"-"`
}
type FeedConfig struct {
	URL             *string                `json:"url,omitempty"`
	Format          *string                `json:"format,omitempty"`
	RefreshInterval *string                `json:"refreshInterval,omitempty"`
	MinEntries      interface{}            `json:"minEntries,omitempty"`
	Unknown         map[string]interface{} `mapstructure:",remain" json:"-"`
}

// CreateConfig returns an empty typed target for Traefik's existing decoder.
func CreateConfig() *Config { return &Config{} }

type feedKey struct {
	URL, Format string
	Interval    time.Duration
	Minimum     int
	CacheDir    string
}
type headerRule struct{ header, mode string }
type predicate struct {
	header string
	values []string
	kind   string
}
type source struct {
	name            string
	static          addressSet
	feeds           []*feedWorker
	specs           []feedKey
	predicates      []predicate
	extract, scheme headerRule
}
type settings struct {
	sources []source
	remove  map[string]bool
}

func validateDecoded(v reflect.Value, path string) error {
	if v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		if v.Elem().Kind() == reflect.Slice && v.Elem().Len() == 0 {
			return fmt.Errorf("%s: supplied lists must be non-empty", path)
		}
		return validateDecoded(v.Elem(), path)
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			if name == "Unknown" {
				if v.Field(i).Len() != 0 {
					var names []string
					for _, key := range v.Field(i).MapKeys() {
						names = append(names, key.String())
					}
					sort.Strings(names)
					return fmt.Errorf("%s: unsupported fields %s; use the V1 sources/trust/extract/scheme schema", path, strings.Join(names, ", "))
				}
			} else if err := validateDecoded(v.Field(i), path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if !v.IsNil() && v.Len() == 0 {
			return fmt.Errorf("%s: supplied lists must be non-empty", path)
		}
		for i := 0; i < v.Len(); i++ {
			if err := validateDecoded(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
func required(value *string, field string) (string, error) {
	if value == nil || *value == "" {
		return "", fmt.Errorf("%s is required and must be non-empty", field)
	}
	return *value, nil
}
func compileConfig(cfg *Config) (settings, error) {
	var result settings
	if cfg == nil {
		return result, fmt.Errorf("configuration is nil")
	}
	if err := validateDecoded(reflect.ValueOf(cfg), "config"); err != nil {
		return result, err
	}
	cacheDir := ""
	if cfg.FeedCacheDir != nil && *cfg.FeedCacheDir != "" {
		if !filepath.IsAbs(*cfg.FeedCacheDir) {
			return result, fmt.Errorf("feedCacheDir must be absolute")
		}
		cacheDir = filepath.Clean(*cfg.FeedCacheDir)
	}
	result.remove = make(map[string]bool)
	for _, name := range identityHeaders {
		result.remove[headerAlias(name)] = true
	}
	for _, name := range forwardingHeaders {
		result.remove[headerAlias(name)] = true
	}
	names := make(map[string]bool)
	for _, supplied := range cfg.Sources {
		name, err := required(supplied.Name, "source.name")
		if err != nil {
			return settings{}, err
		}
		if names[name] {
			return settings{}, fmt.Errorf("duplicate source name %q", name)
		}
		names[name] = true
		expanded, err := expandPreset(supplied)
		if err != nil {
			return settings{}, fmt.Errorf("source %q: %w", name, err)
		}
		s, err := compileSource(expanded, cacheDir)
		if err != nil {
			return settings{}, fmt.Errorf("source %q: %w", name, err)
		}
		s.name = name
		result.sources = append(result.sources, s)
		result.remove[headerAlias(s.extract.header)] = true
		if s.scheme.header != "" {
			result.remove[headerAlias(s.scheme.header)] = true
		}
	}
	return result, nil
}
func compileSource(c SourceConfig, cacheDir string) (source, error) {
	var s source
	var err error
	s.extract, err = compileHeader(c.Extract, false)
	if err != nil {
		return s, err
	}
	if c.Scheme != nil {
		s.scheme, err = compileHeader(c.Scheme, true)
		if err != nil {
			return s, err
		}
	}
	if c.Trust == nil {
		return s, fmt.Errorf("trust requires at least one predicate")
	}
	t := c.Trust
	if t.Static != nil {
		s.static, err = parseSet(*t.Static, 1)
		if err != nil {
			return s, fmt.Errorf("static: %w", err)
		}
	}
	if t.Feeds != nil {
		for _, f := range *t.Feeds {
			spec, e := compileFeed(f, cacheDir)
			if e != nil {
				return s, e
			}
			s.specs = append(s.specs, spec)
		}
	}
	if t.HeaderIn != nil {
		h, e := required(t.HeaderIn.Name, "headerIn.name")
		if e != nil {
			return s, e
		}
		if !validHeader(h) || strings.EqualFold(h, "Host") {
			return s, fmt.Errorf("invalid headerIn header")
		}
		if t.HeaderIn.Values == nil {
			return s, fmt.Errorf("headerIn.values required")
		}
		p := predicate{header: http.CanonicalHeaderKey(h), kind: "exact"}
		for _, value := range *t.HeaderIn.Values {
			if value == "" {
				return s, fmt.Errorf("headerIn values must be non-empty")
			}
			p.values = append(p.values, value)
		}
		s.predicates = append(s.predicates, p)
	}
	if t.HostExact != nil {
		p, e := compileHost(t.HostExact.Header, t.HostExact.Values, "hostExact")
		if e != nil {
			return s, e
		}
		s.predicates = append(s.predicates, p)
	}
	if t.HostSuffixes != nil {
		p, e := compileHost(t.HostSuffixes.Header, t.HostSuffixes.Suffixes, "hostSuffixes")
		if e != nil {
			return s, e
		}
		s.predicates = append(s.predicates, p)
	}
	if t.Static == nil && t.Feeds == nil && len(s.predicates) == 0 {
		return s, fmt.Errorf("trust requires at least one predicate")
	}
	return s, nil
}
func compileHost(header *string, values *[]string, kind string) (predicate, error) {
	p := predicate{kind: kind}
	h, err := required(header, kind+".header")
	if err != nil {
		return p, err
	}
	if !validHeader(h) {
		return p, fmt.Errorf("invalid %s header", kind)
	}
	p.header = http.CanonicalHeaderKey(h)
	if values == nil {
		return p, fmt.Errorf("%s values required", kind)
	}
	for _, v := range *values {
		host, e := hostname(v)
		if e != nil {
			return p, fmt.Errorf("invalid %s hostname", kind)
		}
		p.values = append(p.values, host)
	}
	return p, nil
}
func compileHeader(c *HeaderConfig, scheme bool) (headerRule, error) {
	var rule headerRule
	if c == nil {
		return rule, fmt.Errorf("extract object required")
	}
	h, err := required(c.Header, "header")
	if err != nil {
		return rule, err
	}
	mode, err := required(c.Mode, "mode")
	if err != nil {
		return rule, err
	}
	if !validHeader(h) || reservedInput(headerAlias(h)) {
		return rule, fmt.Errorf("invalid or reserved input header %q", h)
	}
	alias := headerAlias(h)
	if scheme {
		if mode != "single" && mode != "uniform-list" {
			return rule, fmt.Errorf("unknown scheme mode %q", mode)
		}
		for _, name := range []string{"X-Real-Ip", "X-Forwarded-For"} {
			if alias == headerAlias(name) {
				return rule, fmt.Errorf("scheme input conflicts with identity output")
			}
		}
	} else {
		if mode != "single" {
			return rule, fmt.Errorf("unknown extraction mode %q", mode)
		}
		for _, name := range []string{"X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Scheme", "X-Forwarded-Host", "X-Forwarded-Port"} {
			if alias == headerAlias(name) {
				return rule, fmt.Errorf("identity input conflicts with forwarding output")
			}
		}
	}
	return headerRule{http.CanonicalHeaderKey(h), mode}, nil
}
func compileFeed(c FeedConfig, cacheDir string) (feedKey, error) {
	k := feedKey{Interval: 30 * time.Minute, Minimum: 1, CacheDir: cacheDir}
	raw, err := required(c.URL, "feed.url")
	if err != nil {
		return k, err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return k, fmt.Errorf("feed URL must be absolute HTTPS without userinfo or fragment")
	}
	k.URL = raw
	k.Format, err = required(c.Format, "feed.format")
	if err != nil {
		return k, err
	}
	if k.Format != "lines" && k.Format != "json-array" {
		return k, fmt.Errorf("unknown feed format")
	}
	if c.RefreshInterval != nil {
		k.Interval, err = time.ParseDuration(*c.RefreshInterval)
		if err != nil || k.Interval < time.Second {
			return k, fmt.Errorf("refreshInterval must be a duration of at least 1s")
		}
	}
	if c.MinEntries != nil {
		k.Minimum, err = minimum(c.MinEntries)
		if err != nil {
			return k, err
		}
	}
	return k, nil
}
func minimum(value interface{}) (int, error) {
	invalid := fmt.Errorf("minEntries must be an integer from 1 to 100000")
	if text, ok := value.(string); ok {
		if text == "" {
			return 0, invalid
		}
		for _, r := range text {
			if r < '0' || r > '9' {
				return 0, invalid
			}
		}
		n, err := strconv.ParseUint(text, 10, 64)
		if err != nil || n < 1 || n > 100000 {
			return 0, invalid
		}
		return int(n), nil
	}
	v := reflect.ValueOf(value)
	var n float64
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n = float64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n = float64(v.Uint())
	case reflect.Float32, reflect.Float64:
		n = v.Float()
	default:
		return 0, invalid
	}
	if math.IsNaN(n) || math.IsInf(n, 0) || n < 1 || n > 100000 || math.Trunc(n) != n {
		return 0, invalid
	}
	return int(n), nil
}
func validHeader(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r > 127 || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}
func reservedInput(name string) bool {
	switch name {
	case "host", "connection", "upgrade", "transfer-encoding", "content-length", "te", "trailer", "keep-alive", "proxy-connection":
		return true
	}
	return false
}
func errPreset(name string) error { return fmt.Errorf("unknown preset %q", name) }
