package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type mockPlatform struct {
	mu         sync.Mutex
	carp       map[string]CarpRuntime
	routes     map[string]string
	probes     map[string]bool
	probeCalls map[string]int
	getRoutes  int
	events     chan NativeEvent
}

func newMockPlatform() *mockPlatform {
	return &mockPlatform{
		carp:       map[string]CarpRuntime{},
		routes:     map[string]string{},
		probes:     map[string]bool{},
		probeCalls: map[string]int{},
		events:     make(chan NativeEvent, 8),
	}
}

func carpMockKey(device string, vhid int) string {
	return device + ":" + itoa(vhid)
}

func routeMockKey(spec RouteSpec) string {
	return spec.Family + ":" + spec.RouteType + ":" + spec.Destination
}

func (m *mockPlatform) GetCARP(device string, vhid int) (CarpRuntime, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.carp[carpMockKey(device, vhid)]
	if !ok {
		return CarpRuntime{}, errors.New("missing CARP")
	}
	return value, nil
}

func (m *mockPlatform) SetCARPAdvskew(device string, vhid int, advskew int) (CarpRuntime, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := carpMockKey(device, vhid)
	value, ok := m.carp[key]
	if !ok {
		return CarpRuntime{}, errors.New("missing CARP")
	}
	value.Advskew = advskew
	m.carp[key] = value
	return value, nil
}

func (m *mockPlatform) ProbeARP(_ context.Context, device, target string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := device + ":" + target
	m.probeCalls[key]++
	return m.probes[key], nil
}

func (m *mockPlatform) GetRoute(spec RouteSpec) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getRoutes++
	value, ok := m.routes[routeMockKey(spec)]
	return value, ok, nil
}

func (m *mockPlatform) AddRoute(spec RouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := routeMockKey(spec)
	if _, exists := m.routes[key]; exists {
		return errors.New("route exists")
	}
	m.routes[key] = spec.Gateway
	return nil
}

func (m *mockPlatform) DeleteRoute(spec RouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := routeMockKey(spec)
	if m.routes[key] == spec.Gateway {
		delete(m.routes, key)
	}
	return nil
}

func (m *mockPlatform) Events(context.Context) <-chan NativeEvent {
	return m.events
}

func (m *mockPlatform) Close() error { return nil }

func testConfig() Config {
	cfg, err := parseConfig([]byte(sampleConfigXML))
	if err != nil {
		panic(err)
	}
	return cfg
}

func TestHealthTrackerThresholdParity(t *testing.T) {
	check := Check{UUID: "a"}
	tracker := NewHealthTracker(2, 2)
	ready, healthy := tracker.Update([]Check{check}, map[string]bool{"a": false})
	if ready || healthy {
		t.Fatalf("first failure must remain unknown/fail-closed: ready=%v healthy=%v", ready, healthy)
	}
	ready, healthy = tracker.Update([]Check{check}, map[string]bool{"a": false})
	if !ready || healthy {
		t.Fatalf("second failure must become unhealthy: ready=%v healthy=%v", ready, healthy)
	}
	ready, healthy = tracker.Update([]Check{check}, map[string]bool{"a": true})
	if !ready || healthy {
		t.Fatalf("first recovery sample must remain unhealthy: ready=%v healthy=%v", ready, healthy)
	}
	ready, healthy = tracker.Update([]Check{check}, map[string]bool{"a": true})
	if !ready || !healthy {
		t.Fatalf("second recovery sample must become healthy: ready=%v healthy=%v", ready, healthy)
	}
}

func TestProbeDeduplicatesPhysicalDeviceTarget(t *testing.T) {
	cfg := testConfig()
	platform := newMockPlatform()
	platform.probes["vlan02:192.0.2.2"] = true
	controller := NewController(cfg, platform, t.TempDir()+"/state.json")
	results := controller.probeAll(context.Background())
	if !results["a"] || !results["b"] {
		t.Fatalf("logical results=%v", results)
	}
	if got := platform.probeCalls["vlan02:192.0.2.2"]; got != 1 {
		t.Fatalf("physical probes=%d want 1", got)
	}
}

func TestStrongestAdvskewWinsAndIsVerified(t *testing.T) {
	cfg := testConfig()
	platform := newMockPlatform()
	platform.carp["vlan02:51"] = CarpRuntime{State: "MASTER", Advskew: 10}
	platform.carp["vlan03:52"] = CarpRuntime{State: "BACKUP", Advskew: 100}
	controller := NewController(cfg, platform, t.TempDir()+"/state.json")
	controller.tracker.Update(cfg.Checks, map[string]bool{"a": false, "b": false})
	rows := controller.reconcileVHIDs(RuntimeState{})
	byKey := map[string]VHIDState{}
	for _, row := range rows {
		byKey[row.Key] = row
	}
	if got := *byKey["opt2:51"].DesiredAdvskew; got != 254 {
		t.Fatalf("opt2 desired advskew=%d want 254", got)
	}
	if got := platform.carp["vlan02:51"].Advskew; got != 254 {
		t.Fatalf("opt2 runtime advskew=%d want 254", got)
	}
	if got := *byKey["opt3:52"].DesiredAdvskew; got != 254 {
		t.Fatalf("opt3 desired advskew=%d want 254", got)
	}
}

func TestBackupRoutesRequireTimerNotRepeatedEvents(t *testing.T) {
	cfg := testConfig()
	platform := newMockPlatform()
	platform.carp["vlan02:51"] = CarpRuntime{State: "BACKUP", Advskew: 10}
	platform.carp["vlan03:52"] = CarpRuntime{State: "BACKUP", Advskew: 100}
	controller := NewController(cfg, platform, t.TempDir()+"/state.json")
	controller.tracker.Update(cfg.Checks, map[string]bool{"a": true, "b": true})
	vhids := controller.reconcileVHIDs(RuntimeState{})

	first := controller.reconcileRoutes(RuntimeState{}, vhids, false)
	for _, row := range first {
		if row.Trigger == "backup" && row.DesiredInstalled {
			t.Fatalf("backup route became eligible without stable timer: %+v", row)
		}
	}

	for key := range controller.backupSince {
		controller.backupSince[key] = time.Now().Add(-2 * cfg.Interval)
	}
	second := controller.reconcileRoutes(RuntimeState{Routes: first}, vhids, false)
	found := false
	for _, row := range second {
		if row.Trigger == "backup" {
			found = true
			if !row.DesiredInstalled || !row.Installed || !row.Managed || !row.ControlOK {
				t.Fatalf("stable backup route not installed: %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("expected backup route specs")
	}
}

func TestUnchangedRoutesDoNotPollEveryProbeTick(t *testing.T) {
	cfg := testConfig()
	platform := newMockPlatform()
	platform.carp["vlan02:51"] = CarpRuntime{State: "MASTER", Advskew: 10}
	platform.carp["vlan03:52"] = CarpRuntime{State: "MASTER", Advskew: 100}
	controller := NewController(cfg, platform, t.TempDir()+"/state.json")
	controller.tracker.Update(cfg.Checks, map[string]bool{"a": false, "b": true})
	vhids := controller.reconcileVHIDs(RuntimeState{})

	first := controller.reconcileRoutes(RuntimeState{}, vhids, true)
	before := platform.getRoutes
	second := controller.reconcileRoutes(RuntimeState{Routes: first}, vhids, false)
	if platform.getRoutes != before {
		t.Fatalf("unchanged probe tick performed route query: before=%d after=%d", before, platform.getRoutes)
	}
	if len(second) != len(first) {
		t.Fatalf("route state changed unexpectedly: %d -> %d", len(first), len(second))
	}
}

func TestPreexistingMatchingRouteIsNeverClaimedOrRemoved(t *testing.T) {
	cfg := testConfig()
	platform := newMockPlatform()
	platform.carp["vlan02:51"] = CarpRuntime{State: "MASTER", Advskew: 10}
	platform.carp["vlan03:52"] = CarpRuntime{State: "MASTER", Advskew: 100}
	platform.routes["inet:host:192.0.2.99"] = "10.0.0.1"
	controller := NewController(cfg, platform, t.TempDir()+"/state.json")
	controller.tracker.Update(cfg.Checks, map[string]bool{"a": false, "b": true})
	vhids := controller.reconcileVHIDs(RuntimeState{})

	failed := controller.reconcileRoutes(RuntimeState{}, vhids, true)
	var owned RouteState
	for _, row := range failed {
		if row.Destination == "192.0.2.99" {
			owned = row
		}
	}
	if !owned.Installed || owned.Managed || !owned.ControlOK {
		t.Fatalf("preexisting route ownership wrong: %+v", owned)
	}

	controller.tracker.Update(cfg.Checks, map[string]bool{"a": true, "b": true})
	recovered := controller.reconcileRoutes(RuntimeState{Routes: failed}, vhids, true)
	if got := platform.routes["inet:host:192.0.2.99"]; got != "10.0.0.1" {
		t.Fatalf("preexisting route was removed: %q", got)
	}
	for _, row := range recovered {
		if row.Destination == "192.0.2.99" && row.Managed {
			t.Fatalf("preexisting route became managed: %+v", row)
		}
	}
}

func TestGlobalCheckerFailClosedAndNoGlobalNoDemotion(t *testing.T) {
	cfg := testConfig()
	state := staleStatus(cfg, false)
	if code := globalExitCode(cfg, state, time.Now()); code != 0 {
		t.Fatalf("config has no global checks; code=%d want 0", code)
	}

	global := cfg
	global.Checks = []Check{{UUID: "g", Name: "global", Scope: "global"}}
	global.Signature = "global"
	if code := globalExitCode(global, staleStatus(global, false), time.Now()); code != 1 {
		t.Fatalf("stale global state code=%d want 1", code)
	}
}
