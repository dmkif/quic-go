//go:build linux

package quic

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

var (
	errGSO          = &os.SyscallError{Err: unix.EIO}
	errNotPermitted = &os.SyscallError{Syscall: "sendmsg", Err: unix.EPERM}
)

func TestForcingReceiveBufferSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Must be root to force change the receive buffer size")
	}

	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	syscallConn, err := c.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)

	const small = 256 << 10 // 256 KB
	require.NoError(t, forceSetReceiveBuffer(syscallConn, small))

	size, err := inspectReadBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*small, size)

	const large = 32 << 20 // 32 MB
	require.NoError(t, forceSetReceiveBuffer(syscallConn, large))
	size, err = inspectReadBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*large, size)
}

func TestForcingSendBufferSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Must be root to force change the send buffer size")
	}

	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	syscallConn, err := c.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)

	const small = 256 << 10 // 256 KB
	require.NoError(t, forceSetSendBuffer(syscallConn, small))

	size, err := inspectWriteBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*small, size)

	const large = 32 << 20 // 32 MB
	require.NoError(t, forceSetSendBuffer(syscallConn, large))
	size, err = inspectWriteBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*large, size)
}

func TestGSOError(t *testing.T) {
	require.True(t, isGSOError(errGSO))
	require.False(t, isGSOError(nil))
	require.False(t, isGSOError(errors.New("test")))
}

func TestParseIPv4PktInfo(t *testing.T) {
	generateBody := func(ifIndex uint32, ip [4]byte) []byte {
		b := make([]byte, 12)
		switch runtime.GOARCH {
		case "s390x", "ppc64", "mips", "mips64":
			binary.BigEndian.PutUint32(b, ifIndex)
		default:
			binary.LittleEndian.PutUint32(b, ifIndex)
		}
		copy(b[8:12], ip[:])
		return b
	}

	tests := []struct {
		name    string
		body    []byte
		wantIP  netip.Addr
		wantIdx uint32
		wantOk  bool
	}{
		{
			name:    "valid data",
			body:    generateBody(42, [4]byte{192, 0, 2, 1}),
			wantIP:  netip.AddrFrom4([4]byte{192, 0, 2, 1}),
			wantIdx: 42,
			wantOk:  true,
		},
		{
			name:    "invalid length",
			body:    make([]byte, 8),
			wantIP:  netip.Addr{},
			wantIdx: 0,
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotIdx, gotOk := parseIPv4PktInfo(tt.body)
			if gotOk != tt.wantOk {
				t.Errorf("parseIPv4PktInfo() ok = %v, want %v", gotOk, tt.wantOk)
			}
			if gotIP != tt.wantIP {
				t.Errorf("parseIPv4PktInfo() ip = %v, want %v", gotIP, tt.wantIP)
			}
			if gotIdx != tt.wantIdx {
				t.Errorf("parseIPv4PktInfo() ifIndex = %v, want %v", gotIdx, tt.wantIdx)
			}
		})
	}
}
