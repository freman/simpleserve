package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
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
	creds := flag.String("c", "", "credentials in the form of user:pass")

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

	http.Handle("/", logging(*verbose, basicAuth(http.FileServer(http.Dir(*directory)), *creds)))

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
