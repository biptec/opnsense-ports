package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type wireGlobalState struct {
	Active     bool `json:"active"`
	CheckCount int  `json:"check_count"`
	Ready      bool `json:"ready"`
	Healthy    bool `json:"healthy"`
}

type wireVHIDState struct {
	Key               string   `json:"key"`
	Interface         string   `json:"interface"`
	Device            string   `json:"device"`
	VHID              int      `json:"vhid"`
	Checks            []string `json:"checks"`
	Ready             bool     `json:"ready"`
	Healthy           bool     `json:"healthy"`
	DesiredDemoted    bool     `json:"desired_demoted"`
	DesiredAdvskew    *int     `json:"desired_advskew"`
	ConfiguredAdvskew *int     `json:"configured_advskew"`
	CurrentAdvskew    *int     `json:"current_advskew"`
	CarpState         string   `json:"carp_state"`
	ControlOK         bool     `json:"control_ok"`
	Retired           bool     `json:"retired"`
	Error             string   `json:"error"`
}

type wireRouteState struct {
	Key              string `json:"key"`
	CheckUUID        string `json:"check_uuid"`
	Check            string `json:"check"`
	Family           string `json:"family"`
	RouteType        string `json:"route_type"`
	Trigger          string `json:"trigger"`
	Destination      string `json:"destination"`
	Gateway          string `json:"gateway"`
	DesiredInstalled bool   `json:"desired_installed"`
	Installed        bool   `json:"installed"`
	Managed          bool   `json:"managed"`
	ControlOK        bool   `json:"control_ok"`
	Retired          bool   `json:"retired"`
	Error            string `json:"error"`
}

type wireCheckState struct {
	UUID                  string           `json:"uuid"`
	Name                  string           `json:"name"`
	Interface             string           `json:"interface"`
	Device                string           `json:"device"`
	Target                string           `json:"target"`
	Scope                 string           `json:"scope"`
	VHID                  int              `json:"vhid"`
	VHIDTargets           []string         `json:"vhid_targets"`
	ConfiguredVHIDTargets []string         `json:"configured_vhid_targets"`
	FailureAdvskew        int              `json:"failure_advskew"`
	VHIDStates            []wireVHIDState  `json:"vhid_states"`
	FallbackRoutes        []wireRouteState `json:"fallback_routes"`
	CarpState             string           `json:"carp_state"`
	ConfiguredAdvskew     *int             `json:"configured_advskew"`
	CurrentAdvskew        *int             `json:"current_advskew"`
	ControlOK             bool             `json:"control_ok"`
	Healthy               *bool            `json:"healthy"`
	Failures              int              `json:"failures"`
	Successes             int              `json:"successes"`
}

type wireRuntimeState struct {
	Status          string           `json:"status"`
	Enabled         bool             `json:"enabled"`
	Ready           bool             `json:"ready"`
	Healthy         bool             `json:"healthy"`
	ProbeHealthy    bool             `json:"probe_healthy"`
	ControlOK       bool             `json:"control_ok"`
	Running         bool             `json:"running,omitempty"`
	Timestamp       float64          `json:"timestamp"`
	ConfigSignature string           `json:"config_signature"`
	Global          wireGlobalState  `json:"global"`
	VHIDs           []wireVHIDState  `json:"vhids"`
	Routes          []wireRouteState `json:"routes"`
	Checks          []wireCheckState `json:"checks"`
}

func toWireVHID(v VHIDState) wireVHIDState {
	return wireVHIDState{
		Key: v.Key, Interface: v.Interface, Device: v.Device, VHID: v.VHID,
		Checks: v.Checks, Ready: v.Ready, Healthy: v.Healthy,
		DesiredDemoted: v.DesiredDemoted, DesiredAdvskew: v.DesiredAdvskew,
		ConfiguredAdvskew: v.ConfiguredAdvskew, CurrentAdvskew: v.CurrentAdvskew,
		CarpState: v.CarpState, ControlOK: v.ControlOK, Retired: v.Retired, Error: v.Error,
	}
}

func fromWireVHID(v wireVHIDState) VHIDState {
	return VHIDState{
		Key: v.Key, Interface: v.Interface, Device: v.Device, VHID: v.VHID,
		Checks: v.Checks, Ready: v.Ready, Healthy: v.Healthy,
		DesiredDemoted: v.DesiredDemoted, DesiredAdvskew: v.DesiredAdvskew,
		ConfiguredAdvskew: v.ConfiguredAdvskew, CurrentAdvskew: v.CurrentAdvskew,
		CarpState: v.CarpState, ControlOK: v.ControlOK, Retired: v.Retired, Error: v.Error,
	}
}

func toWireRoute(v RouteState) wireRouteState {
	return wireRouteState{
		Key: v.Key, CheckUUID: v.CheckUUID, Check: v.Check, Family: v.Family,
		RouteType: v.RouteType, Trigger: v.Trigger, Destination: v.Destination,
		Gateway: v.Gateway, DesiredInstalled: v.DesiredInstalled, Installed: v.Installed,
		Managed: v.Managed, ControlOK: v.ControlOK, Retired: v.Retired, Error: v.Error,
	}
}

func fromWireRoute(v wireRouteState) RouteState {
	return RouteState{
		Key: v.Key, CheckUUID: v.CheckUUID, Check: v.Check, Family: v.Family,
		RouteType: v.RouteType, Trigger: v.Trigger, Destination: v.Destination,
		Gateway: v.Gateway, DesiredInstalled: v.DesiredInstalled, Installed: v.Installed,
		Managed: v.Managed, ControlOK: v.ControlOK, Retired: v.Retired, Error: v.Error,
	}
}

func toWireState(s RuntimeState) wireRuntimeState {
	w := wireRuntimeState{
		Status: s.Status, Enabled: s.Enabled, Ready: s.Ready, Healthy: s.Healthy,
		ProbeHealthy: s.ProbeHealthy, ControlOK: s.ControlOK, Running: s.Running,
		Timestamp: s.Timestamp, ConfigSignature: s.ConfigSignature,
		Global: wireGlobalState{
			Active: s.Global.Active, CheckCount: s.Global.CheckCount,
			Ready: s.Global.Ready, Healthy: s.Global.Healthy,
		},
	}
	for _, v := range s.VHIDs {
		w.VHIDs = append(w.VHIDs, toWireVHID(v))
	}
	for _, r := range s.Routes {
		w.Routes = append(w.Routes, toWireRoute(r))
	}
	for _, c := range s.Checks {
		wc := wireCheckState{
			UUID: c.UUID, Name: c.Name, Interface: c.Interface, Device: c.Device,
			Target: c.Target, Scope: c.Scope, VHID: c.VHID, VHIDTargets: c.VHIDTargets,
			ConfiguredVHIDTargets: c.ConfiguredVHIDTargets, FailureAdvskew: c.FailureAdvskew,
			CarpState: c.CarpState, ConfiguredAdvskew: c.ConfiguredAdvskew,
			CurrentAdvskew: c.CurrentAdvskew, ControlOK: c.ControlOK, Healthy: c.Healthy,
			Failures: c.Failures, Successes: c.Successes,
		}
		for _, v := range c.VHIDStates {
			wc.VHIDStates = append(wc.VHIDStates, toWireVHID(v))
		}
		for _, r := range c.FallbackRoutes {
			wc.FallbackRoutes = append(wc.FallbackRoutes, toWireRoute(r))
		}
		w.Checks = append(w.Checks, wc)
	}
	return w
}

func fromWireState(w wireRuntimeState) RuntimeState {
	s := RuntimeState{
		Status: w.Status, Enabled: w.Enabled, Ready: w.Ready, Healthy: w.Healthy,
		ProbeHealthy: w.ProbeHealthy, ControlOK: w.ControlOK, Running: w.Running,
		Timestamp: w.Timestamp, ConfigSignature: w.ConfigSignature,
		Global: GlobalState{
			Active: w.Global.Active, CheckCount: w.Global.CheckCount,
			Ready: w.Global.Ready, Healthy: w.Global.Healthy,
		},
	}
	for _, v := range w.VHIDs {
		s.VHIDs = append(s.VHIDs, fromWireVHID(v))
	}
	for _, r := range w.Routes {
		s.Routes = append(s.Routes, fromWireRoute(r))
	}
	for _, c := range w.Checks {
		cs := CheckState{
			UUID: c.UUID, Name: c.Name, Interface: c.Interface, Device: c.Device,
			Target: c.Target, Scope: c.Scope, VHID: c.VHID, VHIDTargets: c.VHIDTargets,
			ConfiguredVHIDTargets: c.ConfiguredVHIDTargets, FailureAdvskew: c.FailureAdvskew,
			CarpState: c.CarpState, ConfiguredAdvskew: c.ConfiguredAdvskew,
			CurrentAdvskew: c.CurrentAdvskew, ControlOK: c.ControlOK, Healthy: c.Healthy,
			Failures: c.Failures, Successes: c.Successes,
		}
		for _, v := range c.VHIDStates {
			cs.VHIDStates = append(cs.VHIDStates, fromWireVHID(v))
		}
		for _, r := range c.FallbackRoutes {
			cs.FallbackRoutes = append(cs.FallbackRoutes, fromWireRoute(r))
		}
		s.Checks = append(s.Checks, cs)
	}
	return s
}

func marshalState(s RuntimeState) ([]byte, error) {
	return json.Marshal(toWireState(s))
}

func readPersistedState(path string) (RuntimeState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuntimeState{}, err
	}
	var wire wireRuntimeState
	if err := json.Unmarshal(data, &wire); err != nil {
		return RuntimeState{}, err
	}
	return fromWireState(wire), nil
}

func writeStateAtomic(path string, s RuntimeState) error {
	data, err := marshalState(s)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".carp-health-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func controlFingerprint(s RuntimeState) (string, error) {
	payload := struct {
		ConfigSignature string
		VHIDs           []wireVHIDState
		Routes          []wireRouteState
	}{
		ConfigSignature: s.ConfigSignature,
	}
	for _, v := range s.VHIDs {
		payload.VHIDs = append(payload.VHIDs, toWireVHID(v))
	}
	for _, r := range s.Routes {
		payload.Routes = append(payload.Routes, toWireRoute(r))
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func stateIsCurrent(cfg Config, s RuntimeState, now time.Time) bool {
	if s.ConfigSignature != cfg.Signature || s.Timestamp <= 0 {
		return false
	}
	maxAge := 5 * time.Second
	if candidate := cfg.Interval * 3; candidate > maxAge {
		maxAge = candidate
	}
	ts := time.Unix(0, int64(s.Timestamp*float64(time.Second)))
	age := now.Sub(ts)
	return age >= -time.Second && age <= maxAge
}

func staleStatus(cfg Config, running bool) RuntimeState {
	globalChecks := 0
	for _, check := range cfg.Checks {
		if check.Scope == "global" {
			globalChecks++
		}
	}
	globalActive := cfg.Enabled && globalChecks > 0
	return RuntimeState{
		Status: "ok", Enabled: cfg.Enabled, Ready: !cfg.Enabled,
		Healthy: !cfg.Enabled, ProbeHealthy: !cfg.Enabled, ControlOK: !cfg.Enabled,
		Running: running, Timestamp: 0, ConfigSignature: cfg.Signature,
		Global: GlobalState{
			Active: globalActive, CheckCount: globalChecks,
			Ready: !globalActive, Healthy: !globalActive,
		},
	}
}

func globalExitCode(cfg Config, state RuntimeState, now time.Time) int {
	if !cfg.Enabled {
		return 0
	}
	hasGlobal := false
	for _, check := range cfg.Checks {
		if check.Scope == "global" {
			hasGlobal = true
			break
		}
	}
	if !hasGlobal {
		return 0
	}
	if !stateIsCurrent(cfg, state, now) {
		return 1
	}
	if !state.Global.Ready || !state.Global.Healthy {
		return 1
	}
	return 0
}

func readStateOrEmpty(path string) RuntimeState {
	state, err := readPersistedState(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			_ = fmt.Sprintf("%v", err)
		}
		return RuntimeState{}
	}
	return state
}
