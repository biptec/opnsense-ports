package main

import (
	"encoding/binary"
	"testing"
)

func pfRouteMessage(messageType byte, size int) []byte {
	if size < 4 {
		size = 4
	}
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[:2], uint16(size))
	buf[2] = 5
	buf[3] = messageType
	return buf
}

func TestRouteMessageNeedsAudit(t *testing.T) {
	for _, messageType := range []byte{
		freebsdRTMAdd,
		freebsdRTMDelete,
		freebsdRTMChange,
		freebsdRTMRedirect,
		freebsdRTMNewAddr,
		freebsdRTMDelAddr,
		freebsdRTMIfInfo,
	} {
		if !routeMessageNeedsAudit(messageType) {
			t.Fatalf("message type %#x must trigger route audit", messageType)
		}
	}
	for _, messageType := range []byte{0x4, 0x5, 0x7, 0x8, 0xb} {
		if routeMessageNeedsAudit(messageType) {
			t.Fatalf("non-change message type %#x must not trigger route audit", messageType)
		}
	}
}

func TestPFRouteBufferIgnoresRTMGET(t *testing.T) {
	if pfRouteBufferNeedsAudit(pfRouteMessage(0x4, 248)) {
		t.Fatal("RTM_GET response must not trigger route audit")
	}
}

func TestPFRouteBufferFindsMutationAfterNonChange(t *testing.T) {
	buf := append(pfRouteMessage(0x4, 200), pfRouteMessage(freebsdRTMChange, 248)...)
	if !pfRouteBufferNeedsAudit(buf) {
		t.Fatal("route mutation after RTM_GET must trigger route audit")
	}
}

func TestPFRouteBufferFailsSafeOnMalformedMessage(t *testing.T) {
	buf := []byte{0xf8, 0x00, 0x05, 0x04}
	if !pfRouteBufferNeedsAudit(buf) {
		t.Fatal("truncated routing message must fail safe to an audit")
	}
}
