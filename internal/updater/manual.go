package updater

import (
	"errors"
	"time"
)

// ManualUpdatesWarning is a stable UI code, not a translated message.
const ManualUpdatesWarning = "fork_manual_updates"

var ErrManualUpdates = errors.New("эта пробная версия AWG Manager обновляется вручную из https://github.com/ub3dqy/awg-manager")

// Option configures a service before its workers start.
type Option func(*Service)

// WithManualSelfUpdates isolates a preview distribution from the original
// project's self-update feed. Managed sing-box updates are a separate feature.
// The setting is immutable after New and does not rewrite stored preferences.
func WithManualSelfUpdates() Option {
	return func(s *Service) { s.manualSelfUpdates = true }
}

func (s *Service) manualUpdateInfo() *UpdateInfo {
	return &UpdateInfo{
		CurrentVersion: s.version,
		CheckedAt:      time.Now(),
		Warning:        ManualUpdatesWarning,
	}
}
