//go:build !freebsd

package main

func newNativePlatform() (Platform, error) {
	return unsupportedPlatform{}, errUnsupportedPlatform
}
