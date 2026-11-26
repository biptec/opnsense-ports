//go:build freebsd

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type bpfManager struct {
	mu      sync.Mutex
	handles map[string]*bpfHandle
	closed  bool
}

type bpfHandle struct {
	mu     sync.Mutex
	file   *os.File
	fd     int
	device string
	mac    [6]byte
	buf    []byte
}

func newBPFManager() *bpfManager {
	return &bpfManager{handles: map[string]*bpfHandle{}}
}

func (m *bpfManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for key, h := range m.handles {
		_ = h.file.Close()
		delete(m.handles, key)
	}
}

func (m *bpfManager) Invalidate(device string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h := m.handles[device]; h != nil {
		_ = h.file.Close()
		delete(m.handles, device)
	}
}

func (m *bpfManager) Probe(ctx context.Context, device, target string, timeout time.Duration) (bool, error) {
	addr, err := netip.ParseAddr(target)
	if err != nil || !addr.Is4() || addr.Zone() != "" {
		return false, fmt.Errorf("invalid ARP target %q", target)
	}
	h, err := m.handle(device)
	if err != nil {
		return false, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	ok, err := h.probe(ctx, addr, timeout)
	if err != nil {
		m.Invalidate(device)
	}
	return ok, err
}

func (m *bpfManager) handle(device string) (*bpfHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, os.ErrClosed
	}
	if h := m.handles[device]; h != nil {
		return h, nil
	}
	h, err := openBPF(device)
	if err != nil {
		return nil, err
	}
	m.handles[device] = h
	return h, nil
}

func openBPF(device string) (*bpfHandle, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("%s: unsupported hardware address %s", device, iface.HardwareAddr)
	}

	f, err := os.OpenFile("/dev/bpf", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*bpfHandle, error) {
		_ = f.Close()
		return nil, err
	}
	fd := int(f.Fd())
	if err := bpfSetInterface(fd, device); err != nil {
		return fail(err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fail(fmt.Errorf("BIOCIMMEDIATE %s: %w", device, err))
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSHDRCMPLT, 1); err != nil {
		return fail(fmt.Errorf("BIOCSHDRCMPLT %s: %w", device, err))
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return fail(fmt.Errorf("BIOCGDLT %s: %w", device, err))
	}
	const dltEthernet = 1
	if dlt != dltEthernet {
		return fail(fmt.Errorf("%s: unsupported BPF DLT %d", device, dlt))
	}
	if err := bpfSetARPFilter(fd); err != nil {
		return fail(err)
	}
	bufLen, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		return fail(fmt.Errorf("BIOCGBLEN %s: %w", device, err))
	}
	if bufLen < unix.SizeofBpfHdr+42 {
		bufLen = 4096
	}

	h := &bpfHandle{file: f, fd: fd, device: device, buf: make([]byte, bufLen)}
	copy(h.mac[:], iface.HardwareAddr)
	return h, nil
}

func bpfSetInterface(fd int, device string) error {
	if len(device) == 0 || len(device) >= 16 {
		return fmt.Errorf("invalid BPF interface %q", device)
	}
	var ifr ifreqData
	copy(ifr.Name[:], device)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("BIOCSETIF %s: %w", device, errno)
	}
	return nil
}

func bpfSetARPFilter(fd int) error {
	// Keep this byte-for-byte equivalent to FreeBSD tcpdump -ddd arp.
	// This isolates packet capture semantics from our userspace ARP reply parser.
	insns := []unix.BpfInsn{
		{Code: 40, Jt: 0, Jf: 0, K: 12},
		{Code: 21, Jt: 0, Jf: 1, K: 2054},
		{Code: 6, Jt: 0, Jf: 0, K: 262144},
		{Code: 6, Jt: 0, Jf: 0, K: 0},
	}
	program := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETF), uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return fmt.Errorf("BIOCSETF: %w", errno)
	}
	return nil
}

func bpfFlush(fd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCFLUSH), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (h *bpfHandle) probe(ctx context.Context, target netip.Addr, timeout time.Duration) (bool, error) {
	if err := bpfFlush(h.fd); err != nil {
		return false, fmt.Errorf("BPF flush %s: %w", h.device, err)
	}
	request := makeARPRequest(h.mac, target)
	if _, err := h.file.Write(request); err != nil {
		return false, fmt.Errorf("BPF write %s: %w", h.device, err)
	}

	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		if err := bpfSetReadTimeout(h.fd, remaining); err != nil {
			return false, err
		}

		n, err := h.file.Read(h.buf)
		if err != nil {
			if errorsIsTimeout(err) {
				return false, nil
			}
			stats, statsErr := bpfStats(h.fd)
			if statsErr == nil {
				return false, fmt.Errorf("BPF read %s: %w (recv=%d drop=%d)", h.device, err, stats.Recv, stats.Drop)
			}
			return false, fmt.Errorf("BPF read %s: %w (stats: %v)", h.device, err, statsErr)
		}
		if n == 0 {
			continue
		}
		if bpfContainsARPReply(h.buf[:n], h.mac, target) {
			return true, nil
		}
	}
}

func bpfStats(fd int) (unix.BpfStat, error) {
	var stats unix.BpfStat
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCGSTATS), uintptr(unsafe.Pointer(&stats)))
	if errno != 0 {
		return unix.BpfStat{}, errno
	}
	return stats, nil
}

func bpfSetReadTimeout(fd int, timeout time.Duration) error {
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSRTIMEOUT), uintptr(unsafe.Pointer(&tv)))
	if errno != 0 {
		return fmt.Errorf("BIOCSRTIMEOUT: %w", errno)
	}
	return nil
}

func errorsIsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if err == os.ErrDeadlineExceeded || err == io.EOF {
		return true
	}
	if errno, ok := err.(*os.PathError); ok {
		return errno.Err == unix.EAGAIN || errno.Err == unix.EWOULDBLOCK
	}
	return err == unix.EAGAIN || err == unix.EWOULDBLOCK
}

func makeARPRequest(mac [6]byte, target netip.Addr) []byte {
	// Ethernet requires a minimum on-wire payload.  arping pads the ARP probe;
	// do the same so BPF writes are accepted by all Ethernet-like interfaces.
	frame := make([]byte, 60)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], mac[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	copy(frame[22:28], mac[:])
	// Sender IPv4 stays 0.0.0.0: exact arping -0 semantics.
	// Target hardware address stays all zeroes.
	ip := target.As4()
	copy(frame[38:42], ip[:])
	return frame
}

func bpfContainsARPReply(buf []byte, localMAC [6]byte, target netip.Addr) bool {
	for offset := 0; offset+unix.SizeofBpfHdr <= len(buf); {
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[offset]))
		hdrLen := int(hdr.Hdrlen)
		capLen := int(hdr.Caplen)
		headerFieldsLen := int(unsafe.Offsetof(hdr.Hdrlen) + unsafe.Sizeof(hdr.Hdrlen))
		if hdrLen < headerFieldsLen || capLen < 0 || offset+hdrLen+capLen > len(buf) {
			return false
		}
		packet := buf[offset+hdrLen : offset+hdrLen+capLen]
		if isARPReply(packet, localMAC, target) {
			return true
		}
		record := hdrLen + capLen
		word := int(unsafe.Sizeof(uintptr(0)))
		record = (record + word - 1) & ^(word - 1)
		if record <= 0 {
			return false
		}
		offset += record
	}
	return false
}

func isARPReply(packet []byte, localMAC [6]byte, target netip.Addr) bool {
	if len(packet) < 42 {
		return false
	}
	etherType := binary.BigEndian.Uint16(packet[12:14])
	arpOffset := 14
	if etherType == 0x8100 || etherType == 0x88a8 {
		if len(packet) < 46 {
			return false
		}
		etherType = binary.BigEndian.Uint16(packet[16:18])
		arpOffset = 18
	}
	if etherType != 0x0806 || len(packet) < arpOffset+28 {
		return false
	}
	arp := packet[arpOffset:]
	if binary.BigEndian.Uint16(arp[0:2]) != 1 ||
		binary.BigEndian.Uint16(arp[2:4]) != 0x0800 ||
		arp[4] != 6 || arp[5] != 4 ||
		binary.BigEndian.Uint16(arp[6:8]) != 2 {
		return false
	}
	expected := target.As4()
	if string(arp[14:18]) != string(expected[:]) {
		return false
	}
	// arping -0 accepts a response to the probe even though sender IP is zero;
	// require the reply to target this interface's MAC to avoid peer-path replies.
	return string(arp[18:24]) == string(localMAC[:])
}
