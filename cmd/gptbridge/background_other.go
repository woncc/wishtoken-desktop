//go:build !windows

package main

import "os/exec"

func backgroundProcess(cmd *exec.Cmd) {}
