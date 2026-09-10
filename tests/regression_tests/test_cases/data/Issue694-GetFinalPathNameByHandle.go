// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Supporting probe from https://github.com/microsoft/mxc/issues/694.

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	volumeNameDOS = 0x0
	volumeNameNT  = 0x2
)

func getFinalPath(proc *syscall.Proc, handle syscall.Handle, flags uintptr) (string, error) {
	buf := make([]uint16, 1024)
	ret, _, callErr := proc.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		flags,
	)
	if ret == 0 {
		return "", callErr
	}
	if int(ret) > len(buf) {
		// Buffer too small; grow and retry.
		buf = make([]uint16, ret)
		ret, _, callErr = proc.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			flags,
		)
		if ret == 0 {
			return "", callErr
		}
	}
	return syscall.UTF16ToString(buf[:ret]), nil
}

func main() {
	// Open config.json in the current directory.
	path, err := syscall.UTF16PtrFromString("config.json")
	if err != nil {
		fmt.Println("UTF16PtrFromString error:", err)
		return
	}

	handle, err := syscall.CreateFile(
		path,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		fmt.Println("CreateFile error:", err)
		return
	}
	defer syscall.CloseHandle(handle)

	// Resolve GetFinalPathNameByHandleW from kernel32 (no x/sys).
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	proc := kernel32.MustFindProc("GetFinalPathNameByHandleW")

	// VOLUME_NAME_DOS (default): e.g. \\?\C:\...
	if p, err := getFinalPath(proc, handle, volumeNameDOS); err != nil {
		fmt.Println("VOLUME_NAME_DOS error:", err)
	} else {
		fmt.Println("VOLUME_NAME_DOS:", p)
	}

	// VOLUME_NAME_NT: e.g. \Device\HarddiskVolumeX\...
	if p, err := getFinalPath(proc, handle, volumeNameNT); err != nil {
		fmt.Println("VOLUME_NAME_NT error:", err)
	} else {
		fmt.Println("VOLUME_NAME_NT:", p)
	}
}
