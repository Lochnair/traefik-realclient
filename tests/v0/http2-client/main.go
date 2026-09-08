// A dependency-free native HTTP/2 streaming client for the V0 fixture.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "a.example"}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", os.Args[1], nil)
	if err != nil {
		panic(err)
	}
	req.Host = "a.example"
	req.Header.Set("X-Custom-Ip", "198.51.100.2")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		panic("HTTP/2 was not negotiated")
	}
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		panic(fmt.Sprintf("first chunk: %q %v", first, err))
	}
	release, err := http.Get(os.Args[2])
	if err != nil {
		panic(err)
	}
	release.Body.Close()
	second, err := reader.ReadString('\n')
	if err != nil || second != "second\n" {
		panic(fmt.Sprintf("second chunk: %q %v", second, err))
	}
	json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"protocol": resp.Proto, "firstBeforeRelease": true, "second": second, "effective": resp.Header.Get("X-V0-Effective")})
}
