package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	port := flag.String("p", "8100", "port to serve on")
	verbose := flag.Bool("v", false, "verbose logging of requests")
	directory := flag.String("d", ".", "the directory of static file to host")
	flag.Parse()

	cacrt := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			CommonName:         "Testing CA",
			OrganizationalUnit: []string{"Development"},
			Organization:       []string{"Example Company"},
			Country:            []string{"Australia"},
			Province:           []string{"Queensland"},
			Locality:           []string{"Brisbane"},
			StreetAddress:      []string{"Queen St"},
			PostalCode:         []string{"4000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	caB, err := x509.CreateCertificate(rand.Reader, cacrt, cacrt, pub, priv)
	if err != nil {
		panic(err)
	}

	certOut := bytes.NewBuffer(nil)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caB})

	keyOut := bytes.NewBuffer(nil)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	catls, err := tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
	if err != nil {
		panic(err)
	}

	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "Certificate",
			OrganizationalUnit: []string{"Development"},
			Organization:       []string{"Example Company"},
			Country:            []string{"Australia"},
			Province:           []string{"Queensland"},
			Locality:           []string{"Brisbane"},
			StreetAddress:      []string{"Queen Street"},
			PostalCode:         []string{"4000"},
		},
		IPAddresses:  getIPs(),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	cert_b, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)
	cert_bOut := bytes.NewBuffer(nil)
	pem.Encode(cert_bOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert_b})

	finaltls, err := tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
	if err != nil {
		panic(err)
	}

	http.Handle("/", logging(*verbose, http.FileServer(http.Dir(*directory))))

	listener, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		panic(err)
	}

	log.Printf("Serving %s on HTTP(s) port: %s\n", *directory, *port)

	if err := http.Serve(&SplitListener{Listener: listener, Config: &tls.Config{
		Certificates: []tls.Certificate{finaltls},
	}}, nil); err != nil {
		panic(err)
	}
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

func getIPs() (ips []net.IP) {
	faces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, i := range faces {
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ips = append(ips, v.IP)
			case *net.IPAddr:
				ips = append(ips, v.IP)
			}
		}
	}
	return ips
}

// SplitListener reads the first byte off the wire to figure out if it's a tls connection or http connection
// Exporting purely so it can be recycled in the hybridconsul registry at a later date
type SplitListener struct {
	net.Listener
	Config *tls.Config
}

// Accept implements the listener interface
func (l SplitListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	preamble := make([]byte, 1)
	_, err = c.Read(preamble)
	if err != nil {
		c.Close()
		if err != io.EOF {
			return nil, err
		}
	}

	cc := &conn{
		Conn:     c,
		preamble: preamble,
		err:      err,
	}

	if preamble[0] == 22 {
		// HTTPS
		return tls.Server(cc, l.Config), nil
	}
	// HTTP
	return cc, nil
}

type conn struct {
	net.Conn
	preamble []byte
	err      error
}

func (c *conn) Read(b []byte) (int, error) {
	if c.preamble != nil {
		b[0] = c.preamble[0]
		c.preamble = nil
		if len(b) > 1 && c.err == nil {
			n, err := c.Conn.Read(b[1:])
			if err != nil {
				c.Conn.Close()
			}
			return n + 1, err
		}
		return 1, c.err
	}
	return c.Conn.Read(b)
}
