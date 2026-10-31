package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hoaxisr/awg-manager/internal/updater"
)

func TestManualPreviewUpdateEndpoints(t *testing.T) {
	s := updater.New("2.19.23+ub3dqy.1", nil, nil, t.TempDir(), nil, updater.WithManualSelfUpdates())
	h := NewUpdateHandler(s, nil)
	for _, path := range []string{"/check", "/check?force=true"} {
		w := httptest.NewRecorder()
		h.Check(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"warning":"fork_manual_updates"`) || !strings.Contains(w.Body.String(), `"available":false`) {
			t.Fatalf("check %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.Apply(w, httptest.NewRequest("POST", "/apply", nil))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "MANUAL_UPDATES_REQUIRED") {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/changelog?to=2.19.23", "/changelog?from=2.0.0&to=2.19.23"} {
		w := httptest.NewRecorder()
		h.Changelog(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 409 || !strings.Contains(w.Body.String(), "MANUAL_UPDATES_REQUIRED") {
			t.Fatalf("changelog %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
