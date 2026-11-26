//go:build freebsd

package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestBPFParserAcceptsSerializedHeaderWithoutStructPadding(t *testing.T) {
	local := [6]byte{0x58, 0x9c, 0xfc, 0x10, 0xaf, 0x87}
	peer := [6]byte{0x58, 0x9c, 0xfc, 0x10, 0x7d, 0x08}
	target := netip.MustParseAddr("192.0.2.2")

	var hdr unix.BpfHdr
	headerFieldsLen := int(unsafe.Offsetof(hdr.Hdrlen) + unsafe.Sizeof(hdr.Hdrlen))
	if headerFieldsLen >= unix.SizeofBpfHdr {
		t.Fatalf("test requires serialized BPF header shorter than padded userspace struct: fields=%d struct=%d", headerFieldsLen, unix.SizeofBpfHdr)
	}

	frame := make([]byte, 60)
	copy(frame[0:6], local[:])
	copy(frame[6:12], peer[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18], frame[19] = 6, 4
	binary.BigEndian.PutUint16(frame[20:22], 2)
	copy(frame[22:28], peer[:])
	ip := target.As4()
	copy(frame[28:32], ip[:])
	copy(frame[32:38], local[:])
	// Target protocol address for an arping -0 response is 0.0.0.0.

	recordLen := headerFieldsLen + len(frame)
	aligned := (recordLen + int(unsafe.Sizeof(uintptr(0))) - 1) & ^(int(unsafe.Sizeof(uintptr(0))) - 1)
	buf := make([]byte, aligned)
	header := (*unix.BpfHdr)(unsafe.Pointer(&buf[0]))
	header.Caplen = uint32(len(frame))
	header.Datalen = uint32(len(frame))
	header.Hdrlen = uint16(headerFieldsLen)
	copy(buf[headerFieldsLen:], frame)

	if !bpfContainsARPReply(buf, local, target) {
		t.Fatal("valid ARP reply with bh_hdrlen excluding struct padding was rejected")
	}
}

func TestNativeRouteLifecycle(t *testing.T) {
	if os.Getenv("CARP_HEALTHD_NATIVE_TEST") != "1" {
		t.Skip("set CARP_HEALTHD_NATIVE_TEST=1 inside disposable FreeBSD VNET")
	}
	gw4 := os.Getenv("CARP_HEALTHD_TEST_GW4")
	if gw4 == "" {
		t.Fatal("CARP_HEALTHD_TEST_GW4 is required")
	}
	gw6 := os.Getenv("CARP_HEALTHD_TEST_GW6")
	gw6LinkLocal := os.Getenv("CARP_HEALTHD_TEST_GW6_LINKLOCAL")

	platform, err := newNativePlatform()
	if err != nil {
		t.Fatal(err)
	}
	defer platform.Close()

	specs := []RouteSpec{
		{Family: "inet", RouteType: "host", Destination: "198.51.100.7", Gateway: gw4},
		{Family: "inet", RouteType: "network", Destination: "198.51.100.128/25", Gateway: gw4},
	}
	if gw6 != "" {
		specs = append(specs,
			RouteSpec{Family: "inet6", RouteType: "host", Destination: "2001:db8:ffff::7", Gateway: gw6},
			RouteSpec{Family: "inet6", RouteType: "network", Destination: "2001:db8:ffff:1::/64", Gateway: gw6},
		)
	}
	if gw6LinkLocal != "" {
		specs = append(specs,
			RouteSpec{Family: "inet6", RouteType: "host", Destination: "2001:db8:ffff:2::7", Gateway: gw6LinkLocal},
			RouteSpec{Family: "inet6", RouteType: "network", Destination: "2001:db8:ffff:3::/64", Gateway: gw6LinkLocal},
		)
	}

	for _, spec := range specs {
		spec := spec
		t.Run(spec.Family+"-"+spec.RouteType, func(t *testing.T) {
			if gateway, present, err := platform.GetRoute(spec); err != nil {
				t.Fatalf("initial GetRoute: %v", err)
			} else if present {
				t.Fatalf("test route already exists via %q", gateway)
			}

			if err := platform.AddRoute(spec); err != nil {
				t.Fatalf("AddRoute: %v", err)
			}
			t.Cleanup(func() {
				_ = platform.DeleteRoute(spec)
			})

			gateway, present, err := platform.GetRoute(spec)
			if err != nil {
				t.Fatalf("GetRoute after add: %v", err)
			}
			if !present {
				t.Fatal("route missing after add")
			}
			want := spec.Gateway
			if addr, err := netip.ParseAddr(want); err == nil && addr.Is6() && addr.Zone() != "" {
				// Route Netlink/PF_ROUTE may normalize the textual zone to the
				// local interface name; verify address and zone separately.
				gotAddr, err := netip.ParseAddr(gateway)
				if err != nil {
					t.Fatalf("gateway %q is not an address: %v", gateway, err)
				}
				if gotAddr.WithZone("") != addr.WithZone("") {
					t.Fatalf("gateway address=%s want=%s", gotAddr, addr)
				}
				if gotAddr.Zone() == "" {
					t.Fatalf("scoped IPv6 gateway lost zone: %q", gateway)
				}
			} else if gateway != want {
				t.Fatalf("gateway=%q want=%q", gateway, want)
			}

			if err := platform.DeleteRoute(spec); err != nil {
				t.Fatalf("DeleteRoute: %v", err)
			}
			if gateway, present, err := platform.GetRoute(spec); err != nil {
				t.Fatalf("GetRoute after delete: %v", err)
			} else if present {
				t.Fatalf("route still present after delete via %q", gateway)
			}
		})
	}
}

func TestRouteMaskRoundTrip(t *testing.T) {
	for _, value := range []string{"198.51.100.128/25", "2001:db8:ffff:1::/64"} {
		prefix := netip.MustParsePrefix(value)
		mask, err := routeMaskAddr(prefix)
		if err != nil {
			t.Fatal(err)
		}
		got, err := addrFromRouteAddr(mask)
		if err != nil {
			t.Fatal(err)
		}
		ones, bits := net.IPMask(got.AsSlice()).Size()
		if ones != prefix.Bits() || bits != prefix.Addr().BitLen() {
			t.Fatalf("%s mask round-trip=%d/%d", value, ones, bits)
		}
	}
}
