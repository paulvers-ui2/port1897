//go:build linux

package owner

import (
	"os"
	"syscall"
)

func ownedBy(st os.FileInfo, uid uint32) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uid
}
