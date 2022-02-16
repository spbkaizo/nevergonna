package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

var host = "foo.kaizo.lan"
var certPath = "./cert.pem"
var keyPath = "./key.pem"

func main() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s@%d", host, time.Now().Unix()),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	foo := pkix.Extension{}
	foo.Id = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 13, 37}
	foo.Critical = false
	// whoop whoop whoop.... here comes the money shot...
	rick, err := ioutil.ReadFile("foo.mp3")
	foo.Value = rick
	template.ExtraExtensions = []pkix.Extension{foo}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Generate cert
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("%v", err)
	}

	// Generate key
	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Fatalf("%v", err)
	}

	// Write cert
	if err := os.MkdirAll(filepath.Dir(certPath), os.FileMode(0755)); err != nil {
		log.Fatalf("%v", err)
	}
	if err := ioutil.WriteFile(certPath, certBuffer.Bytes(), os.FileMode(0644)); err != nil {
		log.Fatalf("%v", err)
	}

	// Write key
	if err := os.MkdirAll(filepath.Dir(keyPath), os.FileMode(0755)); err != nil {
		log.Fatalf("%v", err)
	}
	if err := ioutil.WriteFile(keyPath, keyBuffer.Bytes(), os.FileMode(0600)); err != nil {
		log.Fatalf("%v", err)
	}

}
