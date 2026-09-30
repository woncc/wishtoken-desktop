// Package version carries build metadata injected through -ldflags.
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version of this build (set by the release pipeline).
	Version = "0.3.0-team"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build date in RFC3339.
	Date = "unknown"
)

// String returns a one-line human readable description of the build.
func String() string {
	return fmt.Sprintf("gptbridge %s (%s, %s, %s/%s, %s)", Version, Commit, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// UserAgent is the value the bridge uses for its own outbound requests
// (token refresh, usage probes) where no client identity must be preserved.
func UserAgent() string {
	return "gptbridge/" + Version
}
