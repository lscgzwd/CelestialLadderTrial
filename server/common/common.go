package common

import (
	"io"
	"net"
)

type Server interface {
	Handshake(conn net.Conn) (io.ReadWriter, string, error)
}

type Remote interface {
	Handshake(conn net.Conn, target string) (io.ReadWriter, error)
}
