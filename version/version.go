package version

import "runtime/debug"

// Version is the current version of intel-dcapd.
// It can be set at build time using -ldflags.
var Version = "unknown"

func init() {
	// If version was set at build time, don't override it
	if Version != "unknown" {
		return
	}

	// Try to get version from build info
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// Look for VCS revision in build settings
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			if len(setting.Value) >= 7 {
				Version = "git-" + setting.Value[:7]
			}
		}
	}
}
