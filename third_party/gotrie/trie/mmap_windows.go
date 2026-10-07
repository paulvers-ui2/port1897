// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build windows

package trie

import (
	"os"
	"syscall"
	"unsafe"
)

// mmapFile maps f read-only. The mapping handle is closed right away; the
// view keeps the file mapped until munmap.
func mmapFile(f *os.File, size int) ([]byte, error) {
	if size <= 0 {
		return nil, syscall.EINVAL
	}
	h, err := syscall.CreateFileMapping(syscall.Handle(f.Fd()), nil, syscall.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, os.NewSyscallError("CreateFileMapping", err)
	}
	defer syscall.CloseHandle(h)

	addr, err := syscall.MapViewOfFile(h, syscall.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		return nil, os.NewSyscallError("MapViewOfFile", err)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), size), nil
}

func munmap(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.UnmapViewOfFile(uintptr(unsafe.Pointer(&b[0])))
}
