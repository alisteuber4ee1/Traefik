package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func generateSelfSignedCert() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, nil
}

func TestHTTP3GracefulShutdown(t *testing.T) {
	tlsConfig, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	// 1. Dynamic Router Resolution
	backend1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend1"))
	})
	backend2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend2"))
	})

	router := NewDynamicRouter(backend1)

	// Start server on a random port
	server := NewHTTP3Server("127.0.0.1:0", router, tlsConfig, 2*time.Second)
	
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen on UDP: %v", err)
	}
	portStr := conn.LocalAddr().String()
	conn.Close()

	server.server.Addr = portStr

	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Create HTTP/3 client
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: clientTLSConfig,
	}
	defer roundTripper.Close()
	client := &http.Client{
		Transport: roundTripper,
	}

	url := "https://" + portStr + "/"

	// Send first request (should route to backend1)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "backend1" {
		t.Errorf("expected backend1, got %s", body)
	}

	// Update router to backend2
	router.UpdateHandler(backend2)

	// Send second request on the same connection (should route to backend2)
	resp, err = client.Get(url)
	if err != nil {
		t.Fatalf("second request failed: %v", err) 
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "backend2" {
		t.Errorf("expected backend2, got %s", body)
	}

	// 2. Graceful Connection Teardown & GOAWAY Propagation
	sem := make(chan struct{})
	router.UpdateHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(sem)
		time.Sleep(1 * time.Second)
		w.Write([]byte("long-running-done"))
	}))

	longReqErrChan := make(chan error, 1)
	var longReqResp *http.Response
	go func() {
		var err error
		longReqResp, err = client.Get(url)
		longReqErrChan <- err
	}()

	<-sem

	// Trigger graceful shutdown
	shutdownErrChan := make(chan error, 1)
	go func() {
		shutdownErrChan <- server.Shutdown()
	}()

	// Wait for the long-running request to complete
	err = <-longReqErrChan
	if err != nil {
		t.Fatalf("long-running request failed: %v", err)
	}
	body, _ = io.ReadAll(longReqResp.Body)
	longReqResp.Body.Close()
	if string(body) != "long-running-done" {
		t.Errorf("expected long-running-done, got %s", body)
	}

	// Verify that the server shutdown completed successfully
	err = <-shutdownErrChan
	if err != nil {
		t.Errorf("shutdown failed: %v", err)
	}

	// Verify that new requests fail
	_, err = client.Get(url)
	if err == nil {
		t.Error("expected request to fail after shutdown, but it succeeded")
	}
}