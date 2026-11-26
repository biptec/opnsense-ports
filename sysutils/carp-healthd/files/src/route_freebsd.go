//go:build freebsd

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	bsdroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var routeSeq atomic.Int32

func (p *freeBSDPlatform) GetRoute(spec RouteSpec) (string, bool, error) {
	msg, err := routeRequest(unix.RTM_GET, spec)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return "", false, nil
		}
		return "", false, err
	}
	prefix, ok := prefixFromRouteMessage(msg)
	if !ok {
		return "", false, nil
	}
	want, err := routeSpecPrefix(spec)
	if err != nil {
		return "", false, err
	}
	if prefix != want {
		return "", false, nil
	}
	if len(msg.Addrs) <= unix.RTAX_GATEWAY || msg.Addrs[unix.RTAX_GATEWAY] == nil {
		return "", true, nil
	}
	gateway, err := routeAddrString(msg.Addrs[unix.RTAX_GATEWAY])
	if err != nil {
		return "", true, nil
	}
	return gateway, true, nil
}

func (p *freeBSDPlatform) AddRoute(spec RouteSpec) error {
	_, err := routeRequest(unix.RTM_ADD, spec)
	return err
}

func (p *freeBSDPlatform) DeleteRoute(spec RouteSpec) error {
	_, err := routeRequest(unix.RTM_DELETE, spec)
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func routeRequest(msgType int, spec RouteSpec) (*bsdroute.RouteMessage, error) {
	prefix, err := routeSpecPrefix(spec)
	if err != nil {
		return nil, err
	}
	gateway, gatewayIndex, err := routeGatewayAddr(spec.Gateway)
	if err != nil {
		return nil, err
	}

	addrs := make([]bsdroute.Addr, unix.RTAX_MAX)
	dst, err := routeAddr(prefix.Addr())
	if err != nil {
		return nil, err
	}
	addrs[unix.RTAX_DST] = dst
	if gateway != nil {
		addrs[unix.RTAX_GATEWAY] = gateway
	}
	if spec.RouteType != "host" {
		mask, err := routeMaskAddr(prefix)
		if err != nil {
			return nil, err
		}
		addrs[unix.RTAX_NETMASK] = mask
	}

	flags := unix.RTF_UP
	if gateway != nil {
		flags |= unix.RTF_GATEWAY
	}
	if msgType == unix.RTM_ADD || msgType == unix.RTM_DELETE {
		flags |= unix.RTF_STATIC
	}
	if spec.RouteType == "host" {
		flags |= unix.RTF_HOST
	}

	seq := int(routeSeq.Add(1))
	req := &bsdroute.RouteMessage{
		Version: syscall.RTM_VERSION,
		Type:    msgType,
		Flags:   flags,
		Index:   gatewayIndex,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}
	raw, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal route request: %w", err)
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("open route socket: %w", err)
	}
	defer unix.Close(fd)

	tv := unix.NsecToTimeval((2 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("route receive timeout: %w", err)
	}
	if _, err := unix.Write(fd, raw); err != nil {
		return nil, fmt.Errorf("write route request: %w", err)
	}

	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return nil, fmt.Errorf("route request timeout: %w", err)
			}
			return nil, fmt.Errorf("read route response: %w", err)
		}
		msgs, err := bsdroute.ParseRIB(bsdroute.RIBTypeRoute, buf[:n])
		if err != nil {
			return nil, fmt.Errorf("parse route response: %w", err)
		}
		for _, parsed := range msgs {
			rm, ok := parsed.(*bsdroute.RouteMessage)
			if !ok || rm.ID != uintptr(os.Getpid()) || rm.Seq != seq {
				continue
			}
			if rm.Err != nil {
				return nil, rm.Err
			}
			return rm, nil
		}
	}
}

func routeSpecPrefix(spec RouteSpec) (netip.Prefix, error) {
	value := spec.Destination
	if spec.RouteType == "host" {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid host route destination %q: %w", value, err)
		}
		if addr.Zone() != "" {
			addr = addr.WithZone("")
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid network route destination %q: %w", value, err)
	}
	return prefix.Masked(), nil
}

func routeAddr(addr netip.Addr) (bsdroute.Addr, error) {
	if addr.Is4() {
		ip := addr.As4()
		return &bsdroute.Inet4Addr{IP: ip}, nil
	}
	if addr.Is6() {
		ip := addr.As16()
		zoneID := 0
		if zone := addr.Zone(); zone != "" {
			iface, err := net.InterfaceByName(zone)
			if err != nil {
				return nil, fmt.Errorf("resolve IPv6 zone %q: %w", zone, err)
			}
			zoneID = iface.Index
		}
		return &bsdroute.Inet6Addr{IP: ip, ZoneID: zoneID}, nil
	}
	return nil, fmt.Errorf("unsupported route address %v", addr)
}

func routeGatewayAddr(value string) (bsdroute.Addr, int, error) {
	if value == "" {
		return nil, 0, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid route gateway %q: %w", value, err)
	}
	routeAddrValue, err := routeAddr(addr)
	if err != nil {
		return nil, 0, err
	}
	index := 0
	if zone := addr.Zone(); zone != "" {
		iface, err := net.InterfaceByName(zone)
		if err != nil {
			return nil, 0, err
		}
		index = iface.Index
	}
	return routeAddrValue, index, nil
}

func routeMaskAddr(prefix netip.Prefix) (bsdroute.Addr, error) {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		mask := net.CIDRMask(bits, 32)
		var ip [4]byte
		copy(ip[:], mask)
		return &bsdroute.Inet4Addr{IP: ip}, nil
	}
	if prefix.Addr().Is6() {
		mask := net.CIDRMask(bits, 128)
		var ip [16]byte
		copy(ip[:], mask)
		return &bsdroute.Inet6Addr{IP: ip}, nil
	}
	return nil, fmt.Errorf("unsupported prefix %v", prefix)
}

func prefixFromRouteMessage(msg *bsdroute.RouteMessage) (netip.Prefix, bool) {
	if len(msg.Addrs) <= unix.RTAX_DST || msg.Addrs[unix.RTAX_DST] == nil {
		return netip.Prefix{}, false
	}
	dst, err := addrFromRouteAddr(msg.Addrs[unix.RTAX_DST])
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := dst.BitLen()
	if msg.Flags&unix.RTF_HOST == 0 && len(msg.Addrs) > unix.RTAX_NETMASK && msg.Addrs[unix.RTAX_NETMASK] != nil {
		maskAddr, err := addrFromRouteAddr(msg.Addrs[unix.RTAX_NETMASK])
		if err == nil {
			mask := net.IPMask(maskAddr.AsSlice())
			ones, total := mask.Size()
			if ones >= 0 && total == bits {
				bits = ones
			}
		}
	}
	return netip.PrefixFrom(dst.WithZone(""), bits).Masked(), true
}

func addrFromRouteAddr(addr bsdroute.Addr) (netip.Addr, error) {
	switch a := addr.(type) {
	case *bsdroute.Inet4Addr:
		return netip.AddrFrom4(a.IP), nil
	case *bsdroute.Inet6Addr:
		ip := netip.AddrFrom16(a.IP)
		if a.ZoneID > 0 {
			iface, err := net.InterfaceByIndex(a.ZoneID)
			if err == nil {
				ip = ip.WithZone(iface.Name)
			}
		}
		return ip, nil
	default:
		return netip.Addr{}, fmt.Errorf("unsupported route address %T", addr)
	}
}

func routeAddrString(addr bsdroute.Addr) (string, error) {
	ip, err := addrFromRouteAddr(addr)
	if err != nil {
		if link, ok := addr.(*bsdroute.LinkAddr); ok {
			if link.Name != "" {
				return "link#" + link.Name, nil
			}
			if link.Index > 0 {
				return fmt.Sprintf("link#%d", link.Index), nil
			}
		}
		return "", err
	}
	return ip.String(), nil
}
