package main

import (
	"syscall"
	"unsafe"
)

func showStartupError(message string) {
	title, _ := syscall.UTF16PtrFromString("GPTBridge Cockpit")
	body, _ := syscall.UTF16PtrFromString(message)
	_, _, _ = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
}
