// Package ownerfile replaces a path with an owner-only file.
//
// The temporary file is created in the destination directory and renamed over
// the path, so a symlink is not followed and an existing permissive mode is
// not preserved.
package ownerfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Write replaces path with data. The parent directory is created owner-only
// when it does not already exist. An empty path is rejected.
func Write(path string, data []byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("empty output path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".owner-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
