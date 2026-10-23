// A deterministic HTTP/3-only DNS server for the issue 4027 reproducer.
// It never forwards DNS requests or opens a TCP listener.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

const maxDNSMessage = 65535

func main() {
	addr := flag.String("addr", "192.0.2.1:443", "UDP listen address")
	cert := flag.String("cert", "server.crt", "TLS certificate PEM path")
	key := flag.String("key", "server.key", "TLS private key PEM path")
	packetSize := flag.Uint("packet-size", 1200, "server QUIC initial UDP payload size")
	disablePMTUD := flag.Bool("disable-pmtud", true, "disable server path MTU probing to isolate the client")
	flag.Parse()
	if *packetSize < 1200 || *packetSize > 65527 {
		log.Fatal("packet-size must be between 1200 and 65527")
	}
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", serveDNS)
	server := &http3.Server{
		Addr: *addr,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		QUICConfig: &quic.Config{
			InitialPacketSize:       uint16(*packetSize),
			DisablePathMTUDiscovery: *disablePMTUD,
			HandshakeIdleTimeout:    10 * time.Second,
			MaxIdleTimeout:          60 * time.Second,
		},
		Handler:        mux,
		MaxHeaderBytes: 16384,
		IdleTimeout:    60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
	}()
	log.Printf("HTTP/3 DNS addr=%s initial_udp_payload=%d disable_pmtud=%t answer=example.com./A/192.0.2.123/TTL60", *addr, *packetSize, *disablePMTUD)
	if err := server.ListenAndServeTLS(*cert, *key); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func serveDNS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dns-query" {
		http.NotFound(w, r)
		return
	}
	wire, err := readDNSMessage(r)
	if err != nil {
		var inputErr *requestError
		if errors.As(err, &inputErr) {
			if inputErr.status == http.StatusMethodNotAllowed {
				w.Header().Set("Allow", "GET, POST")
			}
			http.Error(w, inputErr.message, inputErr.status)
		} else {
			http.Error(w, "invalid DNS request", http.StatusBadRequest)
		}
		return
	}
	var request dns.Msg
	if err := request.Unpack(wire); err != nil || request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		http.Error(w, "expected one standard DNS question", http.StatusBadRequest)
		return
	}
	question := request.Question[0]
	response := new(dns.Msg)
	response.SetReply(&request)
	response.Authoritative = true
	response.RecursionAvailable = false
	response.Compress = true
	switch {
	case question.Qclass != dns.ClassINET:
		response.Rcode = dns.RcodeRefused
	case !strings.EqualFold(question.Name, "example.com."):
		response.Rcode = dns.RcodeNameError
	case question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY:
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 123),
		}}
	}
	answer, err := response.Pack()
	if err != nil {
		http.Error(w, "DNS encoding failure", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(answer); err != nil {
		log.Printf("response write error: %v", err)
		return
	}
	log.Printf("query proto=%s name=%s type=%d rcode=%d answers=%d", r.Proto, question.Name, question.Qtype, response.Rcode, len(response.Answer))
}

type requestError struct {
	status  int
	message string
}

func (e *requestError) Error() string { return e.message }

func readDNSMessage(r *http.Request) ([]byte, error) {
	var wire []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		encoded := r.URL.Query().Get("dns")
		if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maxDNSMessage) {
			return nil, &requestError{http.StatusBadRequest, "invalid dns query parameter"}
		}
		wire, err = base64.RawURLEncoding.DecodeString(encoded)
	case http.MethodPost:
		mediaType, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if parseErr != nil || mediaType != "application/dns-message" {
			return nil, &requestError{http.StatusUnsupportedMediaType, "expected application/dns-message"}
		}
		wire, err = io.ReadAll(io.LimitReader(r.Body, maxDNSMessage+1))
	default:
		return nil, &requestError{http.StatusMethodNotAllowed, "expected GET or POST"}
	}
	if err != nil || len(wire) < 12 || len(wire) > maxDNSMessage {
		return nil, &requestError{http.StatusBadRequest, fmt.Sprintf("invalid DNS message length or encoding (%d bytes)", len(wire))}
	}
	return wire, nil
}
