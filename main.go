package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// DynamicRouter dynamically routes requests to the active handler.
type DynamicRouter struct {
	mu      sync.RWMutex
	handler http.Handler
}

// NewDynamicRouter creates a new DynamicRouter.
func NewDynamicRouter(initialHandler http.Handler) *DynamicRouter {
	return &DynamicRouter{
		handler: initialHandler,
	}
}

// ServeHTTP routes the request to the current handler.
func (r *DynamicRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	h := r.handler
	r.mu.RUnlock()
	if h != nil {
		h.ServeHTTP(w, req)
	} else {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}
}

// UpdateHandler updates the routing target.
func (r *DynamicRouter) UpdateHandler(newHandler http.Handler) {
	r.mu.Lock()
	r.handler = newHandler
	r.mu.Unlock()
}

// HTTP3Server wraps http3.Server to manage its lifecycle and graceful shutdown.
type HTTP3Server struct {
	server       *http3.Server
	graceTimeout time.Duration
}

// NewHTTP3Server creates a new HTTP3Server.
func NewHTTP3Server(addr string, handler http.Handler, tlsConfig *tls.Config, graceTimeout time.Duration) *HTTP3Server {
	return &HTTP3Server{
		server: &http3.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsConfig,
		},
		graceTimeout: graceTimeout,
	}
}

// Start starts the HTTP/3 server.
func (s *HTTP3Server) Start() error {
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP/3 server.
// It sends a GOAWAY frame to active clients and waits for active streams to complete.
func (s *HTTP3Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.graceTimeout)
	defer cancel()

	// CloseGracefully sends GOAWAY and waits for active streams to finish or timeout.
	errChan := make(chan error, 1)
	go func() {
		errChan <- s.server.CloseGracefully(s.graceTimeout)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		// If the context times out, force close the server.
		s.server.Close()
		return ctx.Err()
	}
}

func main() {
	fmt.Println("Hello, Bounty Hunter!")
}