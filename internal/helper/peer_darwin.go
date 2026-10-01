//go:build darwin

package helper

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// solLocal and localPeerCred are Darwin's SOL_LOCAL and LOCAL_PEERCRED.
const (
	solLocal      = 0
	localPeerCred = 1
)

// PeerUID is the user on the other end of a local socket, from the kernel.
// It cannot be forged by the client, which is the whole point.
func PeerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	// struct xucred: u_int cr_version; uid_t cr_uid; short cr_ngroups;
	// gid_t cr_groups[16] (76 bytes with padding).
	var buf [76]byte
	size := uint32(len(buf))
	var serr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, serr = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil {
		return -1, err
	}
	if serr != 0 {
		return -1, fmt.Errorf("LOCAL_PEERCRED: %w", serr)
	}
	return int(binary.LittleEndian.Uint32(buf[4:8])), nil
}
