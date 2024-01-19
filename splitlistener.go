package main

import (
	"crypto/tls"
	"io"
	"net"
)

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
