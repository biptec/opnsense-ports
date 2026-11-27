package main

import "encoding/binary"

const (
	freebsdRTMAdd      = 0x1
	freebsdRTMDelete   = 0x2
	freebsdRTMChange   = 0x3
	freebsdRTMRedirect = 0x6
	freebsdRTMNewAddr  = 0xc
	freebsdRTMDelAddr  = 0xd
	freebsdRTMIfInfo   = 0xe
)

func routeMessageNeedsAudit(messageType byte) bool {
	switch messageType {
	case freebsdRTMAdd,
		freebsdRTMDelete,
		freebsdRTMChange,
		freebsdRTMRedirect,
		freebsdRTMNewAddr,
		freebsdRTMDelAddr,
		freebsdRTMIfInfo:
		return true
	default:
		return false
	}
}

// pfRouteBufferNeedsAudit scans one routing-socket read. FreeBSD routing
// messages start with uint16 rtm_msglen, byte rtm_version, byte rtm_type.
// A malformed/truncated buffer fails safe and requests one audit.
func pfRouteBufferNeedsAudit(buf []byte) bool {
	for len(buf) > 0 {
		if len(buf) < 4 {
			return true
		}
		messageLen := int(binary.LittleEndian.Uint16(buf[:2]))
		if messageLen < 4 || messageLen > len(buf) {
			return true
		}
		if routeMessageNeedsAudit(buf[3]) {
			return true
		}
		buf = buf[messageLen:]
	}
	return false
}
