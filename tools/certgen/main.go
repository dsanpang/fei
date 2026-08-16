package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := "./certs"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.MkdirAll(outDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	caKey, caCert, caCertPEM, err := generateCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA: %v\n", err)
		os.Exit(1)
	}
	writePEM(outDir, "ca-cert.pem", "CERTIFICATE", caCertPEM)
	fmt.Println("[+] CA certificate generated")

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server key: %v\n", err)
		os.Exit(1)
	}
	serverCertDER, err := generateServerCert(caKey, caCert, serverKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server cert: %v\n", err)
		os.Exit(1)
	}
	writePEM(outDir, "server-cert.pem", "CERTIFICATE", serverCertDER)
	writeKeyPEM(outDir, "server-key.pem", serverKey)
	fmt.Println("[+] Server certificate generated")

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client key: %v\n", err)
		os.Exit(1)
	}
	clientCertDER, err := generateClientCert(caKey, caCert, clientKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client cert: %v\n", err)
		os.Exit(1)
	}
	writePEM(outDir, "client-cert.pem", "CERTIFICATE", clientCertDER)
	writeKeyPEM(outDir, "client-key.pem", clientKey)
	fmt.Println("[+] Client certificate generated")

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		fmt.Fprintf(os.Stderr, "psk: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(outDir, "psk.bin"), psk, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "psk write: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Pre-shared key (32 bytes) written to psk.bin")

	fmt.Printf("\nAll certificates written to %s/\n", outDir)
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Fei Platform CA"},
			CommonName:   "Fei Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	return caKey, cert, certDER, nil
}

func generateServerCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, serverKey *ecdsa.PrivateKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Fei Platform"},
			CommonName:   "Fei Gateway",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost", "fei-gateway"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	return x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
}

func generateClientCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, clientKey *ecdsa.PrivateKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Fei Platform"},
			CommonName:   "Fei Agent",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	return x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
}

func writePEM(dir, filename, blockType string, data []byte) {
	path := filepath.Join(dir, filename)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}

func writeKeyPEM(dir, filename string, key *ecdsa.PrivateKey) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal key: %v\n", err)
		os.Exit(1)
	}
	writePEM(dir, filename, "EC PRIVATE KEY", keyBytes)
}
