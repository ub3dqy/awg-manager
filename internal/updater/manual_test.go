package updater

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/hoaxisr/awg-manager/internal/downloader"
	"github.com/hoaxisr/awg-manager/internal/storage"
)

func TestManualSelfUpdatesNeverContactFeedOrInstallStaleCachedUpdate(t *testing.T) {
	dir := t.TempDir()
	settings := storage.NewSettingsStore(dir)
	if err := settings.Update(func(s *storage.Settings) error {
		s.Updates.CheckEnabled = true
		s.Updates.StatsEnabled = true
		s.Updates.AutoInstallEnabled = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := New("2.19.23+ub3dqy.1", settings, &recordingAppLogger{}, dir, nil, WithManualSelfUpdates())
	s.SetDownloader(&fakeDownloader{
		readAllFn: func(context.Context, downloader.Request) ([]byte, downloader.ResponseMeta, error) {
			t.Fatal("preview contacted update feed or changelog")
			return nil, downloader.ResponseMeta{}, nil
		},
		downloadFileFn: func(context.Context, downloader.FileRequest) (downloader.FileResult, error) {
			t.Fatal("preview downloaded an installation package")
			return downloader.FileResult{}, nil
		},
	})
	// An old cached result must not bypass the distribution policy.
	s.cached = &UpdateInfo{Available: true, DownloadURL: "http://repo.hoaxisr.ru/old.ipk", LatestVersion: "99.0.0"}
	ctx := context.Background()
	s.doCheck()
	for _, info := range []*UpdateInfo{s.GetCached(), s.CheckNow(ctx)} {
		if info.Available || info.DownloadURL != "" || info.Checking || info.Warning != ManualUpdatesWarning || info.CurrentVersion != s.version {
			t.Fatalf("unsafe or misleading preview result: %+v", info)
		}
	}
	if err := s.ApplyUpgrade(ctx); !errors.Is(err, ErrManualUpdates) {
		t.Fatalf("cached apply was not blocked: %v", err)
	}
	if _, err := s.GetChangelog(ctx, "1.0.0", "99.0.0"); !errors.Is(err, ErrManualUpdates) {
		t.Fatalf("remote changelog was not blocked: %v", err)
	}
	if _, err := s.GetChangelogMinor(ctx, "2.19.23"); !errors.Is(err, ErrManualUpdates) {
		t.Fatalf("remote minor changelog was not blocked: %v", err)
	}
	s.runAutoInstallActions(ctx)
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := func(rows []os.DirEntry) []string {
		result := []string{}
		for _, row := range rows {
			result = append(result, row.Name())
		}
		return result
	}
	if !reflect.DeepEqual(names(before), names(after)) || s.isUpgrading() {
		t.Fatalf("manual update checks created files or started upgrade: %v -> %v", names(before), names(after))
	}
	if s.changelog.url != "" {
		t.Fatal("preview kept a remote changelog URL")
	}
}

func TestManualSelfUpdatesPreserveSeparateManagedSingboxUpdate(t *testing.T) {
	su := &fakeSingboxUpdater{installed: true, updateAvailable: true, current: "1.0.0", required: "1.1.0", versionAfterUpdate: "1.1.0"}
	s := New("2.19.23+ub3dqy.1", nil, &recordingAppLogger{}, t.TempDir(), su, WithManualSelfUpdates())
	s.SetDownloader(&fakeDownloader{readAllFn: func(context.Context, downloader.Request) ([]byte, downloader.ResponseMeta, error) {
		t.Fatal("manager update feed was queried")
		return nil, downloader.ResponseMeta{}, nil
	}})
	s.runAutoInstallActions(context.Background())
	if su.updateCalls != 1 {
		t.Fatalf("separate managed sing-box update calls = %d, want 1", su.updateCalls)
	}
}
