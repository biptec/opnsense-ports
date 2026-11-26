package main

import (
	"context"
	"time"
)

type Platform interface {
	GetCARP(device string, vhid int) (CarpRuntime, error)
	SetCARPAdvskew(device string, vhid int, advskew int) (CarpRuntime, error)
	ProbeARP(ctx context.Context, device, target string, timeout time.Duration) (bool, error)
	GetRoute(spec RouteSpec) (gateway string, present bool, err error)
	AddRoute(spec RouteSpec) error
	DeleteRoute(spec RouteSpec) error
	Events(ctx context.Context) <-chan NativeEvent
	Close() error
}

type unsupportedPlatform struct{}

func (unsupportedPlatform) GetCARP(string, int) (CarpRuntime, error) {
	return CarpRuntime{}, errUnsupportedPlatform
}
func (unsupportedPlatform) SetCARPAdvskew(string, int, int) (CarpRuntime, error) {
	return CarpRuntime{}, errUnsupportedPlatform
}
func (unsupportedPlatform) ProbeARP(context.Context, string, string, time.Duration) (bool, error) {
	return false, errUnsupportedPlatform
}
func (unsupportedPlatform) GetRoute(RouteSpec) (string, bool, error) {
	return "", false, errUnsupportedPlatform
}
func (unsupportedPlatform) AddRoute(RouteSpec) error    { return errUnsupportedPlatform }
func (unsupportedPlatform) DeleteRoute(RouteSpec) error { return errUnsupportedPlatform }
func (unsupportedPlatform) Events(context.Context) <-chan NativeEvent {
	ch := make(chan NativeEvent)
	close(ch)
	return ch
}
func (unsupportedPlatform) Close() error { return nil }
