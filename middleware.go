package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func basicAuth(next http.Handler, creds string) http.Handler {
	splitCreds := strings.SplitN(creds, ":", 2)
	if len(splitCreds) != 2 {
		log.Println("No credentials provided, basic auth disabled")
		return next
	}

	expectedUsername, expectedPassword := []byte(splitCreds[0]), []byte(splitCreds[1])

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the Basic Authentication credentials
		user, password, hasAuth := r.BasicAuth()

		if !hasAuth || subtle.ConstantTimeCompare(expectedUsername, []byte(user)) != 1 || subtle.ConstantTimeCompare(expectedPassword, []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func logging(enabled bool, next http.Handler) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		crw := newCustomResponseWriter(w)
		next.ServeHTTP(crw, r)

		addr := r.RemoteAddr

		log.Printf(`(%s) "%s %s %s" %d %d %s`, addr, r.Method, r.RequestURI, r.Proto, crw.status, crw.size, time.Since(start))
	})
}

type customResponseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (c *customResponseWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *customResponseWriter) Write(b []byte) (int, error) {
	size, err := c.ResponseWriter.Write(b)
	c.size += size
	return size, err
}

func (c *customResponseWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *customResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := c.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement the Hijacker interface")
}

func newCustomResponseWriter(w http.ResponseWriter) *customResponseWriter {
	// When WriteHeader is not called, it's safe to assume the status will be 200.
	return &customResponseWriter{
		ResponseWriter: w,
		status:         200,
	}
}
