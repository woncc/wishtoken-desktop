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

// OpenAppend opens path for appending. A symlink is removed rather than
// followed, and the resulting file is owner-only. Existing regular-file
// contents are preserved.
func OpenAppend(path string) (*os.File, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("empty output path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	case err == nil && !info.Mode().IsRegular():
		return nil, fmt.Errorf("output path is not a regular file")
	case err != nil && !os.IsNotExist(err):
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("refusing to append through a symlink")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
