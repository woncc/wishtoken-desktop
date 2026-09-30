//go:build !windows && !darwin && !linux

package localcodex

import "fmt"

func Launch(o Options) (int, error) {
	return 0, fmt.Errorf("one-click terminal launch is available on Windows, macOS and Linux")
}
