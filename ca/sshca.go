package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

var CA_Key gossh.Signer

func init() {
	privateKey, err := ioutil.ReadFile("ca_key")
	if err != nil {
		panic(err)
	}
	CA_Key, err = gossh.ParsePrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
}

func main() {
	server := &ssh.Server{
		Addr: ":2222",
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			// Accept public keys as long as the user (hostname) matches the key that's been given
			hostname := ctx.User()
			log.Println("Checking host key", hostname)
			if err := checkHostKey(hostname, key); err != nil {
				return false
			}
			return true
		},
		Handler: func(s ssh.Session) {
			defer s.Close()
			if s.PublicKey() == nil {
				fmt.Fprintln(s, "Sorry, none of the public keys you presented matched the hostname you're trying to issue a certificate for")
				return
			}
			log.Println("Signing cert for", s.User())
			cert, err := signCertificate(s.User(), s.PublicKey())
			if err != nil {
				log.Println("Signing failed", s.User(), err)
				fmt.Fprintln(s, "Error:", err)
				return
			}
			log.Println("Returning cert")
			s.Write(gossh.MarshalAuthorizedKey(cert))
		},
	}
	fmt.Println(string(gossh.MarshalAuthorizedKey(CA_Key.PublicKey())))
	server.AddHostKey(&selfSignedKey{Signer: CA_Key})
	log.Fatal(server.ListenAndServe())
}

type selfSignedKey struct {
	once      sync.Once
	publicKey gossh.PublicKey
	gossh.Signer
}

func (s *selfSignedKey) PublicKey() gossh.PublicKey {
	s.once.Do(func() {
		s.publicKey, _ = signCertificate("sshca.bradleyjkemp.dev", s.Signer.PublicKey())
	})
	return s.publicKey
}

func signCertificate(hostname string, pub gossh.PublicKey) (*gossh.Certificate, error) {
	cert := &gossh.Certificate{
		Key:             pub,
		Serial:          uint64(time.Now().UnixNano()),
		CertType:        gossh.HostCert,
		ValidPrincipals: []string{hostname}, // This certificate is only valid for the hostname given
		KeyId:           fmt.Sprintf("%s: issued by sshca.bradleyjkemp.dev", hostname),
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(90 * 24 * time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, CA_Key); err != nil {
		return nil, err
	}
	return cert, nil
}

var sentinelError = fmt.Errorf("not_an_error")

func checkHostKey(hostname string, pub gossh.PublicKey) error {
	keyMatches := false
	log.Println("Dialing", hostname)
	client, err := gossh.Dial("tcp", hostname+":22", &gossh.ClientConfig{
		Timeout:           5 * time.Second,
		HostKeyAlgorithms: []string{pub.Type()}, // force requesting the same type of key as the key we're checking
		HostKeyCallback: func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			log.Println("Key callback", hostname, key.Type())
			keyMatches = string(key.Marshal()) == string(pub.Marshal())
			return sentinelError // always return an error to kill the connection
		},
	})
	if err != nil && errors.Is(err, sentinelError) {
		return err
	}
	if client != nil {
		log.Println("Closing client", hostname)
		client.Close()
	}
	if keyMatches {
		return nil
	}
	return fmt.Errorf("key presented by host doesn't match")
}
