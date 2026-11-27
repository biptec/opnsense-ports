package main

import "fmt"

func resetOwnedActions(platform Platform, state RuntimeState) error {
	var first error
	for _, item := range state.VHIDs {
		if item.Device == "" || item.ConfiguredAdvskew == nil {
			continue
		}
		runtime, err := platform.GetCARP(item.Device, item.VHID)
		if err != nil {
			continue
		}
		if runtime.Advskew != *item.ConfiguredAdvskew {
			if _, err := platform.SetCARPAdvskew(item.Device, item.VHID, *item.ConfiguredAdvskew); err != nil && first == nil {
				first = fmt.Errorf("restore %s/%d advskew: %w", item.Device, item.VHID, err)
			}
		}
	}
	for _, item := range state.Routes {
		if !item.Managed || item.Destination == "" || item.Gateway == "" {
			continue
		}
		spec := routeSpecFromState(item)
		gateway, present, err := platform.GetRoute(spec)
		if err != nil {
			if first == nil {
				first = fmt.Errorf("read owned route %s: %w", item.Destination, err)
			}
			continue
		}
		if present && gateway == item.Gateway {
			if err := platform.DeleteRoute(spec); err != nil && first == nil {
				first = fmt.Errorf("delete owned route %s: %w", item.Destination, err)
			}
		}
	}
	return first
}
