//go:build linux

package servicecheck

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBindFailureDoesNotConnectUsingDefaultRoute(t *testing.T) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, err = ProbeTCP(context.Background(), "awgm-no-such-if", netip.MustParseAddr("127.0.0.1"), l.Addr().(*net.TCPAddr).Port)
	if err == nil {
		t.Fatal("binding failure silently used default route")
	}
	l.SetDeadline(time.Now().Add(30 * time.Millisecond))
	if c, err := l.Accept(); err == nil {
		c.Close()
		t.Fatal("default-path listener received a connection")
	}
}
