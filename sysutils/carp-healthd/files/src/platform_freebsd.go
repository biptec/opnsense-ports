//go:build freebsd

package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	siocsvh = uintptr(0xc02069f5)
	siocgvh = uintptr(0xc02069f6)
)

type ifreqData struct {
	Name [16]byte
	Data uintptr
	Pad  [8]byte
}

type carpReq struct {
	Count   int32
	VHID    int32
	State   int32
	Advskew int32
	Advbase int32
	Key     [20]byte
}

type freeBSDPlatform struct {
	carpFD int
	probes *bpfManager

	mu       sync.Mutex
	routeFD  int
	closed   bool
	eventRun bool
}

func newNativePlatform() (Platform, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	return &freeBSDPlatform{
		carpFD:  fd,
		probes:  newBPFManager(),
		routeFD: -1,
	}, nil
}

func (p *freeBSDPlatform) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.routeFD >= 0 {
		_ = unix.Close(p.routeFD)
		p.routeFD = -1
	}
	if p.carpFD >= 0 {
		_ = unix.Close(p.carpFD)
		p.carpFD = -1
	}
	p.probes.Close()
	return nil
}

func (p *freeBSDPlatform) GetCARP(device string, vhid int) (CarpRuntime, error) {
	req, err := p.getCARPReq(device, vhid)
	if err != nil {
		return CarpRuntime{}, err
	}
	return CarpRuntime{State: carpStateName(int(req.State)), Advskew: int(req.Advskew)}, nil
}

func (p *freeBSDPlatform) SetCARPAdvskew(device string, vhid int, advskew int) (CarpRuntime, error) {
	if advskew < 0 || advskew >= 255 {
		return CarpRuntime{}, fmt.Errorf("invalid CARP advskew %d", advskew)
	}
	req, err := p.getCARPReq(device, vhid)
	if err != nil {
		return CarpRuntime{}, err
	}
	req.Advskew = int32(advskew)
	if err := p.carpIoctl(device, siocsvh, &req); err != nil {
		return CarpRuntime{}, err
	}
	verify, err := p.getCARPReq(device, vhid)
	if err != nil {
		return CarpRuntime{}, err
	}
	if int(verify.Advskew) != advskew {
		return CarpRuntime{}, fmt.Errorf("CARP %s/%d advskew verify: got %d want %d", device, vhid, verify.Advskew, advskew)
	}
	return CarpRuntime{State: carpStateName(int(verify.State)), Advskew: int(verify.Advskew)}, nil
}

func (p *freeBSDPlatform) getCARPReq(device string, vhid int) (carpReq, error) {
	req := carpReq{Count: 1, VHID: int32(vhid)}
	if err := p.carpIoctl(device, siocgvh, &req); err != nil {
		return carpReq{}, err
	}
	if int(req.VHID) != vhid {
		return carpReq{}, fmt.Errorf("CARP %s returned VHID %d, expected %d", device, req.VHID, vhid)
	}
	return req, nil
}

func (p *freeBSDPlatform) carpIoctl(device string, request uintptr, req *carpReq) error {
	if len(device) == 0 || len(device) >= len(ifreqData{}.Name) {
		return fmt.Errorf("invalid interface name %q", device)
	}
	var ifr ifreqData
	copy(ifr.Name[:], device)
	ifr.Data = uintptr(unsafe.Pointer(req))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(p.carpFD), request, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("CARP ioctl %s/%d: %w", device, req.VHID, errno)
	}
	return nil
}

func carpStateName(state int) string {
	switch state {
	case 0:
		return "INIT"
	case 1:
		return "BACKUP"
	case 2:
		return "MASTER"
	default:
		return "UNKNOWN"
	}
}

func (p *freeBSDPlatform) ProbeARP(ctx context.Context, device, target string, timeout time.Duration) (bool, error) {
	return p.probes.Probe(ctx, device, target, timeout)
}

func (p *freeBSDPlatform) Events(ctx context.Context) <-chan NativeEvent {
	out := make(chan NativeEvent, 32)
	p.mu.Lock()
	if p.eventRun {
		p.mu.Unlock()
		close(out)
		return out
	}
	p.eventRun = true
	p.mu.Unlock()

	emit := func(event NativeEvent) {
		select {
		case out <- event:
		default:
			select {
			case out <- NativeEvent{Kind: "resync"}:
			default:
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.devdLoop(ctx, emit)
	}()
	go func() {
		defer wg.Done()
		p.routeLoop(ctx, emit)
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (p *freeBSDPlatform) devdLoop(ctx context.Context, emit func(NativeEvent)) {
	addr := &net.UnixAddr{Name: "/var/run/devd.seqpacket.pipe", Net: "unixpacket"}
	first := true
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := net.DialUnix("unixpacket", nil, addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
				continue
			}
		}
		if !first {
			emit(NativeEvent{Kind: "resync"})
		}
		first = false
		buf := make([]byte, 8192)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := conn.ReadFromUnix(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if ctx.Err() != nil {
						_ = conn.Close()
						return
					}
					continue
				}
				break
			}
			if event, ok := parseDevdEvent(string(buf[:n])); ok {
				if event.Kind == "ifnet" && event.Device != "" {
					p.probes.Invalidate(event.Device)
				}
				emit(event)
			}
		}
		_ = conn.Close()
	}
}

func parseDevdEvent(line string) (NativeEvent, bool) {
	fields := map[string]string{}
	for _, part := range strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "!"))) {
		if i := strings.IndexByte(part, '='); i > 0 {
			fields[part[:i]] = strings.Trim(part[i+1:], "\"")
		}
	}
	switch fields["system"] {
	case "CARP":
		sub := fields["subsystem"]
		at := strings.IndexByte(sub, '@')
		if at <= 0 || at == len(sub)-1 {
			return NativeEvent{}, false
		}
		vhid, err := strconv.Atoi(sub[:at])
		if err != nil {
			return NativeEvent{}, false
		}
		return NativeEvent{Kind: "carp", Device: sub[at+1:], VHID: vhid, State: fields["type"]}, true
	case "IFNET":
		return NativeEvent{Kind: "ifnet", Device: fields["subsystem"], State: fields["type"]}, true
	default:
		return NativeEvent{}, false
	}
}

func (p *freeBSDPlatform) routeLoop(ctx context.Context, emit func(NativeEvent)) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		emit(NativeEvent{Kind: "resync"})
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = unix.Close(fd)
		return
	}
	p.routeFD = fd
	p.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = unix.Close(fd)
	}()

	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if err == unix.EINTR {
				continue
			}
			emit(NativeEvent{Kind: "resync"})
			return
		}
		if n > 0 && pfRouteBufferNeedsAudit(buf[:n]) {
			emit(NativeEvent{Kind: "route"})
		}
	}
}
