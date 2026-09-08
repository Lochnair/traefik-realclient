package realclient

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type addressSet struct {
	exact    map[netip.Addr]bool
	prefixes []netip.Prefix
}

func canonical(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }
func clientIP(value string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.Trim(value, " \t"))
	if err != nil {
		return netip.Addr{}, err
	}
	a = canonical(a)
	if a.IsUnspecified() || a.IsMulticast() || a.String() == "255.255.255.255" {
		return netip.Addr{}, fmt.Errorf("prohibited identity")
	}
	return a, nil
}
func decimalPort(value string, zero bool) (string, error) {
	if value == "" {
		return "", fmt.Errorf("empty port")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("invalid port")
		}
	}
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || (!zero && n == 0) {
		return "", fmt.Errorf("invalid port")
	}
	return strconv.FormatUint(n, 10), nil
}
func parsePeer(value string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, "", err
	}
	port, err = decimalPort(port, true)
	if err != nil {
		return netip.Addr{}, "", err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return a, "", err
	}
	return canonical(a), port, nil
}
func parseEntry(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		a, err := clientIP(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return p, err
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("ambiguous mapped prefix")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}
func parseSet(entries []string, minimum int) (addressSet, error) {
	set := addressSet{exact: make(map[netip.Addr]bool)}
	seen := make(map[netip.Prefix]bool)
	for _, entry := range entries {
		p, err := parseEntry(entry)
		if err != nil {
			return addressSet{}, fmt.Errorf("invalid IP or prefix")
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		if len(seen) > 100000 {
			return addressSet{}, fmt.Errorf("too many distinct entries")
		}
		if p.Bits() == p.Addr().BitLen() {
			set.exact[p.Addr()] = true
		} else {
			set.prefixes = append(set.prefixes, p)
		}
	}
	if len(seen) < minimum {
		return addressSet{}, fmt.Errorf("below minEntries")
	}
	return set, nil
}
func (s addressSet) contains(a netip.Addr) bool {
	if s.exact[a] {
		return true
	}
	for _, p := range s.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// splitAuthority validates syntax/port only. Hostname selection and forwarding
// output deliberately apply different host policies after this shared split.
func splitAuthority(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return "", "", fmt.Errorf("unclosed bracket")
		}
		host := value[1:end]
		if _, err := netip.ParseAddr(host); err != nil {
			return "", "", err
		}
		tail := value[end+1:]
		if tail == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(tail, ":") {
			return "", "", fmt.Errorf("invalid authority")
		}
		port, err := decimalPort(tail[1:], false)
		return host, port, err
	}
	if strings.Count(value, ":") > 1 {
		return "", "", fmt.Errorf("unbracketed IPv6")
	}
	if colon := strings.LastIndexByte(value, ':'); colon >= 0 {
		port, err := decimalPort(value[colon+1:], false)
		if value[:colon] == "" {
			return "", "", fmt.Errorf("empty host")
		}
		return value[:colon], port, err
	}
	return value, "", nil
}
func hostname(value string) (string, error) {
	value = strings.Trim(value, " \t")
	for _, r := range value {
		if r <= 32 || r >= 127 || strings.ContainsRune(",/@?#\\", r) {
			return "", fmt.Errorf("invalid hostname")
		}
	}
	host, _, err := splitAuthority(value)
	if err != nil {
		return "", err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("IP is not a hostname")
	}
	if len(host) == 0 || len(host) > 253 {
		return "", fmt.Errorf("invalid hostname length")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("invalid DNS label")
			}
		}
	}
	return host, nil
}
