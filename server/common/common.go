package common

import (
	"crypto/rand"
	"io"
	"net"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20"
	"proxy/utils/context"
)

type Server interface {
	Start(l net.Listener)
	Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *TargetAddr, error)
}

type Remote interface {
	Handshake(ctx *context.Context, target *TargetAddr) (io.ReadWriter, error)
}

type CipherStream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Chacha20Stream 加密链接
type Chacha20Stream struct {
	key     []byte
	encoder *chacha20.Cipher
	decoder *chacha20.Cipher
	conn    net.Conn
}

func NewChacha20Stream(key []byte, conn net.Conn) (*Chacha20Stream, error) {
	s := &Chacha20Stream{
		key:  key, // should be exactly 32 bytes
		conn: conn,
	}

	var err error
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	s.encoder, err = chacha20.NewUnauthenticatedCipher(s.key, nonce)
	if err != nil {
		return nil, err
	}

	if n, err := s.conn.Write(nonce); err != nil || n != len(nonce) {
		return nil, errors.New("write nonce failed: " + err.Error())
	}
	return s, nil
}

func (s *Chacha20Stream) Read(p []byte) (int, error) {
	if s.decoder == nil {
		nonce := make([]byte, chacha20.NonceSizeX)
		if n, err := io.ReadAtLeast(s.conn, nonce, len(nonce)); err != nil || n != len(nonce) {
			return n, errors.New("can't read nonce from stream: " + err.Error())
		}
		decoder, err := chacha20.NewUnauthenticatedCipher(s.key, nonce)
		if err != nil {
			return 0, errors.New("generate decoder failed: " + err.Error())
		}
		s.decoder = decoder
	}

	n, err := s.conn.Read(p)
	if err != nil || n == 0 {
		return n, err
	}

	dst := make([]byte, n)
	pn := p[:n]
	s.decoder.XORKeyStream(dst, pn)
	copy(pn, dst)
	return n, nil
}

func (s *Chacha20Stream) Write(p []byte) (int, error) {
	dst := make([]byte, len(p))
	s.encoder.XORKeyStream(dst, p)
	return s.conn.Write(dst)
}

func (s *Chacha20Stream) Close() error {
	return s.conn.Close()
}

// TargetAddr An Addr represents an address that you want to access by proxy. Either Name or IP is used exclusively.
type TargetAddr struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

// Return host:port string
func (a *TargetAddr) String() string {
	port := strconv.Itoa(a.Port)
	if a.IP == nil {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// Host Returned host string
func (a *TargetAddr) Host() string {
	if a.IP == nil {
		return a.Name
	}
	return a.IP.String()
}

func NewTargetAddr(addr string) (*TargetAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)

	target := &TargetAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else {
		target.Name = host
	}
	return target, nil
}
