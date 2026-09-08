// Dependency-free native HTTP/2 streaming client for the V1 runtime suite.
// Verifies that a response body streams through Traefik + the real plugin
// (first chunk observed before the backend is released) over a negotiated
// HTTP/2 connection, carrying the resolved identity.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

func main() {
	streamURL, releaseURL, authority := os.Args[1], os.Args[2], os.Args[3]
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: authority},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", streamURL, nil)
	must(err)
	req.Host = authority
	req.Header.Set("X-Real-Ip", "198.51.100.90")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	must(err)
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		fail("HTTP/2 not negotiated: " + resp.Proto)
	}
	r := bufio.NewReader(resp.Body)
	first := readN(r, 6)
	rel, err := http.Get(releaseURL)
	must(err)
	rel.Body.Close()
	second := readN(r, 7)

	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"proto":     resp.Proto,
		"first":     string(first),
		"second":    string(second),
		"effective": resp.Header.Get("X-Effective"),
		"xff":       resp.Header.Get("X-Fwd-For"),
	})
	if string(first) != "first\n" || string(second) != "second\n" {
		os.Exit(1)
	}
}

func readN(r *bufio.Reader, n int) []byte {
	buf := make([]byte, n)
	for got := 0; got < n; {
		m, err := r.Read(buf[got:])
		if m > 0 {
			got += m
		}
		if err != nil {
			fail("short read")
		}
	}
	return buf
}
func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}
func fail(msg string) {
	json.NewEncoder(os.Stdout).Encode(map[string]any{"error": msg})
	os.Exit(1)
}
