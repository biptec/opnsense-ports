package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"sync"
	"time"
)

type Controller struct {
	mu             sync.RWMutex
	cfg            Config
	tracker        *HealthTracker
	platform       Platform
	statePath      string
	state          RuntimeState
	previous       RuntimeState
	persistHash    string
	lastGlobal     string
	triggerService func() bool
	backupSince    map[string]time.Time
}

func NewController(cfg Config, platform Platform, statePath string) *Controller {
	prev := readStateOrEmpty(statePath)
	hash, _ := controlFingerprint(prev)
	return &Controller{
		cfg:            cfg,
		tracker:        NewHealthTracker(cfg.FailureThreshold, cfg.RecoveryThreshold),
		platform:       platform,
		statePath:      statePath,
		previous:       prev,
		persistHash:    hash,
		triggerService: triggerCarpServiceStatus,
		backupSince:    map[string]time.Time{},
	}
}

func (c *Controller) Snapshot() RuntimeState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

func (c *Controller) Run(ctx context.Context) error {
	events := c.platform.Events(ctx)

	if err := c.initialize(ctx); err != nil {
		return err
	}
	if err := c.probeAndReconcile(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.probeAndReconcile(ctx); err != nil {
				c.recordControllerError(err)
			}
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			ready, healthy := c.currentProbeHealth()
			auditRoutes := event.Kind == "route" || event.Kind == "resync" || event.Kind == "ifnet"
			if err := c.reconcile(ctx, ready, healthy, auditRoutes); err != nil {
				c.recordControllerError(err)
			}
		}
	}
}

func (c *Controller) initialize(ctx context.Context) error {
	if !c.cfg.Enabled {
		c.tracker.Records = map[string]*HealthRecord{}
	}
	return c.reconcile(ctx, !c.cfg.Enabled || len(c.cfg.Checks) == 0, !c.cfg.Enabled || len(c.cfg.Checks) == 0, true)
}

func (c *Controller) probeAndReconcile(ctx context.Context) error {
	if !c.cfg.Enabled {
		c.tracker.Records = map[string]*HealthRecord{}
		return c.reconcile(ctx, true, true, false)
	}
	results := c.probeAll(ctx)
	ready, healthy := c.tracker.Update(c.cfg.Checks, results)
	return c.reconcile(ctx, ready, healthy, false)
}

func (c *Controller) currentProbeHealth() (bool, bool) {
	if !c.cfg.Enabled || len(c.cfg.Checks) == 0 {
		return true, true
	}
	return healthForChecks(c.cfg.Checks, c.tracker)
}

func (c *Controller) probeAll(ctx context.Context) map[string]bool {
	type pair struct {
		device string
		target string
	}
	pairs := map[pair][]string{}
	for _, check := range c.cfg.Checks {
		key := pair{device: check.Device, target: check.Target}
		pairs[key] = append(pairs[key], check.UUID)
	}

	results := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for key, ids := range pairs {
		key := key
		ids := append([]string(nil), ids...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := false
			if key.device != "" && key.target != "" {
				probeCtx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				success, err := c.platform.ProbeARP(probeCtx, key.device, key.target, time.Second)
				if err != nil {
					log.Printf("ARP probe %s/%s: %v", key.device, key.target, err)
				}
				ok = err == nil && success
			}
			mu.Lock()
			for _, id := range ids {
				results[id] = ok
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}

func (c *Controller) reconcile(ctx context.Context, ready, probeHealthy bool, auditRoutes bool) error {
	_ = ctx
	prev := c.previous
	vhids := c.reconcileVHIDs(prev)
	routes := c.reconcileRoutes(prev, vhids, auditRoutes)
	state := c.buildState(ready, probeHealthy, vhids, routes, time.Now())
	state.Running = true

	c.mu.Lock()
	c.state = state
	c.mu.Unlock()

	if err := c.persistIfControlChanged(state); err != nil {
		return err
	}
	c.reconcileServiceStatus(state.Global)
	c.previous = state
	return nil
}

func (c *Controller) reconcileVHIDs(previous RuntimeState) []VHIDState {
	_, desired := scopeHealth(c.cfg, c.tracker)
	currentKeys := map[string]bool{}
	for key := range desired {
		currentKeys[key] = true
	}
	var result []VHIDState

	for _, old := range previous.VHIDs {
		if old.Key == "" || currentKeys[old.Key] {
			continue
		}
		if old.Device == "" || old.ConfiguredAdvskew == nil {
			continue
		}
		runtime, err := c.platform.GetCARP(old.Device, old.VHID)
		if err != nil {
			continue
		}
		controlOK := true
		if runtime.Advskew != *old.ConfiguredAdvskew {
			runtime, err = c.platform.SetCARPAdvskew(old.Device, old.VHID, *old.ConfiguredAdvskew)
			controlOK = err == nil && runtime.Advskew == *old.ConfiguredAdvskew
		}
		if !controlOK {
			result = append(result, VHIDState{
				Key: old.Key, Interface: old.Interface, Device: old.Device, VHID: old.VHID,
				Checks: []string{}, Ready: true, Healthy: true, DesiredDemoted: false,
				DesiredAdvskew: old.ConfiguredAdvskew, ConfiguredAdvskew: old.ConfiguredAdvskew,
				CurrentAdvskew: intPtr(runtime.Advskew), CarpState: runtime.State,
				ControlOK: false, Retired: true, Error: "Failed to restore previous VHID priority",
			})
		}
	}

	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := desired[key]
		carp, ok := findCarpVhid(c.cfg, group.Interface, group.VHID)
		if !ok {
			result = append(result, VHIDState{
				Key: key, Interface: group.Interface, VHID: group.VHID, Checks: group.Checks,
				Ready: group.Ready, Healthy: group.Healthy, DesiredDemoted: group.DesiredDemoted,
				CarpState: "MISSING", ControlOK: false, Error: "Configured CARP VHID was not found",
			})
			continue
		}
		desiredAdvskew := carp.Advskew
		if group.DesiredDemoted && group.FailureAdvskew > desiredAdvskew {
			desiredAdvskew = group.FailureAdvskew
		}
		runtime, err := c.platform.GetCARP(carp.Device, carp.VHID)
		controlOK := err == nil
		if controlOK && runtime.Advskew != desiredAdvskew {
			runtime, err = c.platform.SetCARPAdvskew(carp.Device, carp.VHID, desiredAdvskew)
			controlOK = err == nil
		}
		if controlOK {
			controlOK = runtime.Advskew == desiredAdvskew
		}
		stateName := "UNKNOWN"
		var current *int
		if err == nil {
			stateName = runtime.State
			current = intPtr(runtime.Advskew)
		}
		errText := ""
		if !controlOK {
			errText = "Unable to enforce CARP VHID state"
		}
		result = append(result, VHIDState{
			Key: key, Interface: carp.Interface, Device: carp.Device, VHID: carp.VHID,
			Checks: group.Checks, Ready: group.Ready, Healthy: group.Healthy,
			DesiredDemoted: group.DesiredDemoted, DesiredAdvskew: intPtr(desiredAdvskew),
			ConfiguredAdvskew: intPtr(carp.Advskew), CurrentAdvskew: current,
			CarpState: stateName, ControlOK: controlOK, Error: errText,
		})
	}
	now := time.Now()
	active := map[string]bool{}
	for i := range result {
		row := &result[i]
		if row.Retired || !row.ControlOK || row.CarpState != "BACKUP" {
			delete(c.backupSince, row.Key)
			continue
		}
		active[row.Key] = true
		if _, ok := c.backupSince[row.Key]; !ok {
			c.backupSince[row.Key] = now
		}
	}
	for key := range c.backupSince {
		if !active[key] {
			delete(c.backupSince, key)
		}
	}
	return result
}

func fallbackSpecs(check Check) []RouteState {
	var out []RouteState
	add := func(family, routeType, destination, gateway, trigger string) {
		if destination == "" || gateway == "" {
			return
		}
		key := check.UUID + ":" + family + ":" + routeType + ":" + trigger + ":" + destination
		out = append(out, RouteState{
			Key: key, CheckUUID: check.UUID, Check: check.Name, Family: family,
			RouteType: routeType, Trigger: trigger, Destination: destination, Gateway: gateway,
		})
	}
	add("inet", "host", check.FallbackIPv4Target, check.FallbackIPv4Gateway, "unhealthy")
	add("inet6", "host", check.FallbackIPv6Target, check.FallbackIPv6Gateway, "unhealthy")
	if check.FallbackIPv4DefaultGateway != "" {
		add("inet", "network", "0.0.0.0/1", check.FallbackIPv4DefaultGateway, "unhealthy_backup")
		add("inet", "network", "128.0.0.0/1", check.FallbackIPv4DefaultGateway, "unhealthy_backup")
	}
	if check.FallbackIPv6DefaultGateway != "" {
		add("inet6", "network", "::/1", check.FallbackIPv6DefaultGateway, "unhealthy_backup")
		add("inet6", "network", "8000::/1", check.FallbackIPv6DefaultGateway, "unhealthy_backup")
	}
	if check.BackupIPv4DefaultGateway != "" {
		add("inet", "network", "0.0.0.0/1", check.BackupIPv4DefaultGateway, "backup")
		add("inet", "network", "128.0.0.0/1", check.BackupIPv4DefaultGateway, "backup")
	}
	if check.BackupIPv6DefaultGateway != "" {
		add("inet6", "network", "::/1", check.BackupIPv6DefaultGateway, "backup")
		add("inet6", "network", "8000::/1", check.BackupIPv6DefaultGateway, "backup")
	}
	return out
}

func (c *Controller) backupDefaultAllowed(check Check, vhids []VHIDState, now time.Time) bool {
	if check.Scope == "global" {
		return false
	}
	currentByKey := map[string]VHIDState{}
	for _, item := range vhids {
		if !item.Retired {
			currentByKey[item.Key] = item
		}
	}
	targets := resolveVhidTargets(check, c.cfg)
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		key := target.Key()
		current, ok := currentByKey[key]
		since, stable := c.backupSince[key]
		if !ok || !current.ControlOK || current.CarpState != "BACKUP" ||
			!stable || now.Sub(since) < c.cfg.Interval {
			return false
		}
	}
	return true
}

func (c *Controller) reconcileRoutes(previous RuntimeState, vhids []VHIDState, audit bool) []RouteState {
	oldByKey := map[string]RouteState{}
	for _, old := range previous.Routes {
		if old.Key != "" {
			oldByKey[old.Key] = old
		}
	}
	desired := map[string]RouteState{}
	now := time.Now()
	for _, check := range c.cfg.Checks {
		rec := c.tracker.Records[check.UUID]
		unhealthy := c.cfg.Enabled && (rec == nil || rec.Healthy == nil || !*rec.Healthy)
		backupAllowed := c.backupDefaultAllowed(check, vhids, now)
		for _, spec := range fallbackSpecs(check) {
			switch spec.Trigger {
			case "unhealthy":
				spec.DesiredInstalled = unhealthy
			case "unhealthy_backup":
				spec.DesiredInstalled = unhealthy && backupAllowed
			case "backup":
				spec.DesiredInstalled = backupAllowed
			}
			desired[spec.Key] = spec
		}
	}

	var result []RouteState
	for key, old := range oldByKey {
		newSpec, stillDesired := desired[key]
		changed := stillDesired && (old.Destination != newSpec.Destination || old.Gateway != newSpec.Gateway || old.RouteType != newSpec.RouteType)
		if stillDesired && !changed {
			continue
		}
		if !old.Managed {
			continue
		}
		current, present, err := c.platform.GetRoute(routeSpecFromState(old))
		controlOK := err == nil
		if controlOK && present && current == old.Gateway {
			err = c.platform.DeleteRoute(routeSpecFromState(old))
			if err == nil {
				current, present, err = c.platform.GetRoute(routeSpecFromState(old))
			}
			controlOK = err == nil && (!present || current != old.Gateway)
		}
		if !controlOK {
			old.DesiredInstalled = false
			old.Installed = true
			old.ControlOK = false
			old.Retired = true
			old.Error = "Failed to remove fallback route"
			result = append(result, old)
		}
	}

	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		spec := desired[key]
		old := oldByKey[key]
		if old.Key != "" && (old.Destination != spec.Destination || old.Gateway != spec.Gateway || old.RouteType != spec.RouteType) {
			old = RouteState{}
		}
		if old.Key != "" && !audit && old.DesiredInstalled == spec.DesiredInstalled && old.ControlOK {
			spec.Installed = old.Installed
			spec.Managed = old.Managed
			spec.ControlOK = true
			spec.Error = old.Error
			result = append(result, spec)
			continue
		}
		managed := old.Managed
		current, present, err := c.platform.GetRoute(routeSpecFromState(spec))
		controlOK := err == nil
		if spec.DesiredInstalled {
			if controlOK && (!present || current != spec.Gateway) {
				if err = c.platform.AddRoute(routeSpecFromState(spec)); err == nil {
					managed = true
					current, present, err = c.platform.GetRoute(routeSpecFromState(spec))
				}
			}
			installed := err == nil && present && current == spec.Gateway
			spec.Installed = installed
			spec.ControlOK = installed
			spec.Managed = managed
			if !spec.ControlOK {
				spec.Error = "Unable to install fallback route"
			}
		} else {
			if controlOK && managed && present && current == spec.Gateway {
				if err = c.platform.DeleteRoute(routeSpecFromState(spec)); err == nil {
					current, present, err = c.platform.GetRoute(routeSpecFromState(spec))
				}
			}
			installed := err == nil && present && current == spec.Gateway
			spec.Installed = installed
			spec.ControlOK = err == nil && !(managed && installed)
			if spec.ControlOK {
				managed = false
			} else {
				spec.Error = "Unable to remove fallback route"
			}
			spec.Managed = managed
		}
		result = append(result, spec)
	}
	return result
}

func routeSpecFromState(s RouteState) RouteSpec {
	return RouteSpec{Family: s.Family, RouteType: s.RouteType, Destination: s.Destination, Gateway: s.Gateway}
}

func (c *Controller) buildState(ready, probeHealthy bool, vhids []VHIDState, routes []RouteState, now time.Time) RuntimeState {
	global, _ := scopeHealth(c.cfg, c.tracker)
	vhidByKey := map[string]VHIDState{}
	for _, v := range vhids {
		if !v.Retired {
			vhidByKey[v.Key] = v
		}
	}
	routesByCheck := map[string][]RouteState{}
	for _, r := range routes {
		if !r.Retired {
			routesByCheck[r.CheckUUID] = append(routesByCheck[r.CheckUUID], r)
		}
	}

	var checks []CheckState
	for _, check := range c.cfg.Checks {
		rec := c.tracker.Records[check.UUID]
		if rec == nil {
			if !c.cfg.Enabled {
				continue
			}
			rec = &HealthRecord{}
		}
		targets := resolveVhidTargets(check, c.cfg)
		var targetRows []VHIDState
		var targetKeys []string
		for _, target := range targets {
			targetKeys = append(targetKeys, target.Key())
			if row, ok := vhidByKey[target.Key()]; ok {
				targetRows = append(targetRows, row)
			} else {
				targetRows = append(targetRows, VHIDState{})
			}
		}
		var configured []string
		for _, target := range check.VHIDTargets {
			configured = append(configured, target.Key())
		}
		row := CheckState{
			UUID: check.UUID, Name: check.Name, Interface: check.Interface, Device: check.Device,
			Target: check.Target, Scope: check.Scope, VHID: check.VHID, VHIDTargets: targetKeys,
			ConfiguredVHIDTargets: configured, FailureAdvskew: check.FailureAdvskew,
			VHIDStates: targetRows, FallbackRoutes: routesByCheck[check.UUID],
			Healthy: rec.Healthy, Failures: rec.Failures, Successes: rec.Successes,
		}
		switch check.Scope {
		case "vhid":
			if len(targetRows) > 0 && targetRows[0].Key != "" {
				row.CarpState = targetRows[0].CarpState
				row.ConfiguredAdvskew = targetRows[0].ConfiguredAdvskew
				row.CurrentAdvskew = targetRows[0].CurrentAdvskew
				row.ControlOK = targetRows[0].ControlOK
			}
		case "interface", "all_carp", "vhid_group":
			row.CarpState = "GROUP"
			row.ControlOK = len(targetRows) > 0
			for _, target := range targetRows {
				if !target.ControlOK {
					row.ControlOK = false
				}
			}
		default:
			row.ControlOK = true
		}
		checks = append(checks, row)
	}

	controlOK := true
	for _, v := range vhids {
		if !v.ControlOK {
			controlOK = false
		}
	}
	for _, r := range routes {
		if !r.ControlOK {
			controlOK = false
		}
	}
	if c.cfg.Enabled {
		for _, check := range c.cfg.Checks {
			if check.Scope != "global" && len(resolveVhidTargets(check, c.cfg)) == 0 {
				controlOK = false
			}
		}
	}

	return RuntimeState{
		Status: "ok", Enabled: c.cfg.Enabled, Ready: ready,
		Healthy: probeHealthy && controlOK, ProbeHealthy: probeHealthy, ControlOK: controlOK,
		Timestamp:       float64(now.UnixNano()) / float64(time.Second),
		ConfigSignature: c.cfg.Signature, Global: global,
		VHIDs: vhids, Routes: routes, Checks: checks,
	}
}

func (c *Controller) persistIfControlChanged(state RuntimeState) error {
	hash, err := controlFingerprint(state)
	if err != nil {
		return err
	}
	if hash == c.persistHash {
		return nil
	}
	persisted := state
	persisted.Running = false
	if err := writeStateAtomic(c.statePath, persisted); err != nil {
		return err
	}
	c.persistHash = hash
	return nil
}

func (c *Controller) reconcileServiceStatus(global GlobalState) {
	report := fmt.Sprintf("%t:%t:%t", global.Active, global.Ready, global.Healthy)
	if report == c.lastGlobal {
		return
	}
	if c.triggerService != nil && c.triggerService() {
		c.lastGlobal = report
	}
}

func triggerCarpServiceStatus() bool {
	cmd := exec.Command("/usr/local/sbin/configctl", "interface", "update", "carp", "service_status")
	return cmd.Run() == nil
}

func (c *Controller) recordControllerError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.state
	state.Status = "failed"
	state.ControlOK = false
	state.Healthy = false
	state.Running = true
	if len(state.Checks) == 0 {
		state.Checks = []CheckState{{Name: "controller", ControlOK: false}}
	}
	c.state = state
	_ = errors.Is(err, context.Canceled)
}
