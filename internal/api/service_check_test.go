package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hoaxisr/awg-manager/internal/servicecheck"
)

type fakeServiceCheck struct {
	calls int
	err   error
}

func (f *fakeServiceCheck) Options(context.Context) (servicecheck.Options, error) {
	return servicecheck.Options{}, f.err
}
func (f *fakeServiceCheck) Run(context.Context, servicecheck.Request) (servicecheck.Report, error) {
	f.calls++
	return servicecheck.Report{}, f.err
}

func TestServiceCheckRejectsMalformedBodiesBeforeRunning(t *testing.T) {
	for _, body := range []string{`{"target":"a"} {}`, `{"target":"a","unexpected":true}`, strings.Repeat("x", 4097)} {
		f := &fakeServiceCheck{}
		h := NewServiceCheckHandler(f)
		w := httptest.NewRecorder()
		h.Run(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != 400 || f.calls != 0 {
			t.Fatalf("status=%d calls=%d", w.Code, f.calls)
		}
	}
}

func TestServiceCheckStatusAndMethods(t *testing.T) {
	for _, row := range []struct {
		err    error
		status int
	}{{nil, 200}, {servicecheck.ErrInput, 400}, {servicecheck.ErrBusy, 409}, {servicecheck.ErrUnavailable, 503}} {
		f := &fakeServiceCheck{err: row.err}
		h := NewServiceCheckHandler(f)
		w := httptest.NewRecorder()
		h.Run(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"clientIP":"192.168.1.20","target":"service.test","dnsProfile":"Policy0","port":443}`)))
		if w.Code != row.status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status=%d header=%v", w.Code, w.Header())
		}
	}
	h := NewServiceCheckHandler(&fakeServiceCheck{})
	w := httptest.NewRecorder()
	h.Run(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
