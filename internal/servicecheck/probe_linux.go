//go:build linux

package servicecheck

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// ProbeTCP sends no application data and pins the numeric address and interface.
// Binding errors are terminal: never fall back to a working WAN connection.
func ProbeTCP(ctx context.Context, iface string, ip netip.Addr, port int) (time.Duration, error) {
	if iface == "" || !ip.IsValid() || port < 1 || port > 65535 {
		return 0, ErrInput
	}
	d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return bindErr
	}}
	network := "tcp4"
	if ip.Is6() {
		network = "tcp6"
	}
	start := time.Now()
	c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return time.Since(start), nil
}
