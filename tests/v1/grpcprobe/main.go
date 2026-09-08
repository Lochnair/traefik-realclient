// grpcprobe drives native bidirectional gRPC streaming through Traefik and the
// real plugin. It starts an in-process h2c gRPC backend that echoes messages and
// reflects the observed x-real-ip / x-forwarded-proto metadata, then dials the
// Traefik TLS entrypoint as the "real client" and verifies interleaved
// streaming plus grpc trailers.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
)

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return v.([]byte), nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	p := v.(*[]byte)
	*p = append((*p)[:0], data...)
	return nil
}
func (rawCodec) Name() string { return "raw" }

var streamDesc = grpc.StreamDesc{
	StreamName:    "Echo",
	ServerStreams: true,
	ClientStreams: true,
}

func echoHandler(_ any, ss grpc.ServerStream) error {
	md, _ := metadata.FromIncomingContext(ss.Context())
	get := func(k string) string {
		if v := md.Get(k); len(v) == 1 {
			return v[0]
		}
		return ""
	}
	if err := ss.SendHeader(metadata.Pairs(
		"observed-real-ip", get("x-real-ip"),
		"observed-proto", get("x-forwarded-proto"),
		"observed-xff", get("x-forwarded-for"),
	)); err != nil {
		return err
	}
	for {
		var msg []byte
		if err := ss.RecvMsg(&msg); err != nil {
			return nil // client half-closed -> clean grpc-status 0 trailer
		}
		if err := ss.SendMsg(append([]byte("echo:"), msg...)); err != nil {
			return err
		}
	}
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: "probe.Echo",
	HandlerType: (*any)(nil),
	Streams:     []grpc.StreamDesc{{StreamName: "Echo", Handler: echoHandler, ServerStreams: true, ClientStreams: true}},
}

func main() {
	encoding.RegisterCodec(rawCodec{})
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: grpcprobe <traefik-https-addr> <backend-listen-addr> <authority>")
		os.Exit(2)
	}
	target, backendAddr, authority := os.Args[1], os.Args[2], os.Args[3] // target: host:port

	lis, err := net.Listen("tcp", backendAddr)
	must(err)
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
	srv.RegisterService(&serviceDesc, new(int))
	go srv.Serve(lis)
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, target,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		grpc.WithAuthority(authority),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	must(err)
	defer conn.Close()

	callCtx := metadata.AppendToOutgoingContext(ctx,
		"x-real-ip", "198.51.100.77", "x-forwarded-proto", "https")
	stream, err := conn.NewStream(callCtx, &streamDesc, "/probe.Echo/Echo")
	must(err)

	// Interleaved: send one, receive its echo, only then send the next.
	var order []string
	for _, m := range []string{"one", "two", "three"} {
		must(stream.SendMsg([]byte(m)))
		var got []byte
		must(stream.RecvMsg(&got))
		order = append(order, string(got))
	}
	must(stream.CloseSend())
	var tail []byte
	endErr := stream.RecvMsg(&tail)
	if endErr == nil {
		fail("unexpected extra message")
	}
	if endErr != io.EOF {
		fail("stream did not end cleanly: " + endErr.Error())
	}
	hdr, err := stream.Header()
	must(err)

	out := map[string]any{
		"echoes":           order,
		"observed_real_ip": first(hdr, "observed-real-ip"),
		"observed_proto":   first(hdr, "observed-proto"),
		"observed_xff":     first(hdr, "observed-xff"),
		"grpc_status_ok":   endErr == io.EOF,
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

func first(md metadata.MD, k string) string {
	if v := md.Get(k); len(v) > 0 {
		return v[0]
	}
	return ""
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
