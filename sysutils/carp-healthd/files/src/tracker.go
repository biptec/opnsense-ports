package main

type HealthTracker struct {
	FailureThreshold  int
	RecoveryThreshold int
	Records           map[string]*HealthRecord
}

func NewHealthTracker(failure, recovery int) *HealthTracker {
	return &HealthTracker{
		FailureThreshold:  failure,
		RecoveryThreshold: recovery,
		Records:           map[string]*HealthRecord{},
	}
}

func (t *HealthTracker) Update(checks []Check, results map[string]bool) (bool, bool) {
	active := map[string]bool{}
	for _, check := range checks {
		active[check.UUID] = true
	}
	for key := range t.Records {
		if !active[key] {
			delete(t.Records, key)
		}
	}
	for _, check := range checks {
		rec := t.Records[check.UUID]
		if rec == nil {
			rec = &HealthRecord{}
			t.Records[check.UUID] = rec
		}
		if results[check.UUID] {
			rec.Failures = 0
			if rec.Healthy == nil || !*rec.Healthy {
				rec.Successes++
				if rec.Successes >= t.RecoveryThreshold {
					rec.Healthy = boolPtr(true)
					rec.Successes = 0
				}
			} else {
				rec.Successes = 0
			}
		} else {
			rec.Successes = 0
			rec.Failures++
			if rec.Failures >= t.FailureThreshold {
				rec.Healthy = boolPtr(false)
			}
		}
	}
	if len(checks) == 0 {
		return true, true
	}
	ready := true
	healthy := true
	for _, check := range checks {
		rec := t.Records[check.UUID]
		if rec == nil || rec.Healthy == nil {
			ready = false
			healthy = false
			continue
		}
		if !*rec.Healthy {
			healthy = false
		}
	}
	return ready, ready && healthy
}

func healthForChecks(checks []Check, tracker *HealthTracker) (bool, bool) {
	if len(checks) == 0 {
		return true, true
	}
	ready := true
	healthy := true
	for _, check := range checks {
		rec := tracker.Records[check.UUID]
		if rec == nil || rec.Healthy == nil {
			ready = false
			healthy = false
			continue
		}
		if !*rec.Healthy {
			healthy = false
		}
	}
	return ready, ready && healthy
}

type desiredVHID struct {
	Interface      string
	VHID           int
	Checks         []string
	Ready          bool
	Healthy        bool
	DesiredDemoted bool
	FailureAdvskew int
}

func scopeHealth(cfg Config, tracker *HealthTracker) (GlobalState, map[string]desiredVHID) {
	var globalChecks []Check
	for _, check := range cfg.Checks {
		if check.Scope == "global" {
			globalChecks = append(globalChecks, check)
		}
	}
	globalReady, globalHealthy := healthForChecks(globalChecks, tracker)
	globalActive := cfg.Enabled && len(globalChecks) > 0
	globalState := GlobalState{
		Active:     globalActive,
		CheckCount: len(globalChecks),
		Ready:      true,
		Healthy:    true,
	}
	if globalActive {
		globalState.Ready = globalReady
		globalState.Healthy = globalHealthy
	}

	groups := map[string][]Check{}
	for _, check := range cfg.Checks {
		switch check.Scope {
		case "interface", "all_carp", "vhid", "vhid_group":
		default:
			continue
		}
		for _, target := range resolveVhidTargets(check, cfg) {
			groups[target.Key()] = append(groups[target.Key()], check)
		}
	}

	out := map[string]desiredVHID{}
	for key, checks := range groups {
		ready, healthy := healthForChecks(checks, tracker)
		if !cfg.Enabled {
			ready, healthy = true, true
		}
		d := desiredVHID{Ready: ready, Healthy: healthy}
		if len(checks) > 0 {
			targets := resolveVhidTargets(checks[0], cfg)
			for _, target := range targets {
				if target.Key() == key {
					d.Interface = target.Interface
					d.VHID = target.VHID
					break
				}
			}
			if d.Interface == "" {
				for _, carp := range cfg.CarpVhids {
					if (VhidTarget{Interface: carp.Interface, VHID: carp.VHID}).Key() == key {
						d.Interface, d.VHID = carp.Interface, carp.VHID
						break
					}
				}
			}
		}
		for _, check := range checks {
			d.Checks = append(d.Checks, check.Name)
			rec := tracker.Records[check.UUID]
			blocked := cfg.Enabled && (rec == nil || rec.Healthy == nil || !*rec.Healthy)
			if blocked {
				d.DesiredDemoted = true
				if check.FailureAdvskew > d.FailureAdvskew {
					d.FailureAdvskew = check.FailureAdvskew
				}
			}
		}
		out[key] = d
	}
	return globalState, out
}
