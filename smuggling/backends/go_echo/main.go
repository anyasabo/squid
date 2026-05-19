// Go net/http echo server for HTTP smuggling differential tests.
//
// Returns a JSON response with the parsed request details as interpreted
// by Go's strict RFC-compliant HTTP parser. Differences between this
// output and the raw echo server reveal how Go would interpret a
// request that Squid forwarded.
//
// Listens on :8889 by default (override with $GO_ECHO_PORT).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type EchoResponse struct {
	Method        string              `json:"method"`
	URL           string              `json:"url"`
	Proto         string              `json:"proto"`
	Headers       map[string][]string `json:"headers"`
	ContentLength int64               `json:"content_length"`
	Body          string              `json:"body"`
	BodyLen       int                 `json:"body_len"`
	Host          string              `json:"host"`
	RemoteAddr    string              `json:"remote_addr"`
	TransferEnc   []string            `json:"transfer_encoding"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	defer r.Body.Close()

	resp := EchoResponse{
		Method:        r.Method,
		URL:           r.RequestURI,
		Proto:         r.Proto,
		Headers:       r.Header,
		ContentLength: r.ContentLength,
		Body:          string(body),
		BodyLen:       len(body),
		Host:          r.Host,
		RemoteAddr:    r.RemoteAddr,
		TransferEnc:   r.TransferEncoding,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	port := os.Getenv("GO_ECHO_PORT")
	if port == "" {
		port = "8889"
	}
	fmt.Printf("[go-echo] listening on :%s\n", port)
	http.HandleFunc("/", handler)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}
