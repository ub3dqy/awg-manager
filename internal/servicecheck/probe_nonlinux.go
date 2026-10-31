//go:build !linux

package servicecheck

import (
	"context"
	"net/netip"
	"time"
)

// A development build must not silently substitute its ordinary network path.
func ProbeTCP(context.Context, string, netip.Addr, int) (time.Duration, error) {
	return 0, ErrUnsupported
}
