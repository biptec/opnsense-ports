package main

import "testing"

const sampleConfigXML = `<opnsense>
<interfaces><wan><if>vtnet1</if></wan><opt2><if>vlan02</if></opt2><opt3><if>vlan03</if></opt3></interfaces>
<virtualip>
<vip><interface>opt2</interface><mode>carp</mode><vhid>51</vhid><advskew>10</advskew></vip>
<vip><interface>opt3</interface><mode>carp</mode><vhid>52</vhid><advskew>100</advskew></vip>
</virtualip>
<OPNsense><ApiExtensions><CarpHealth>
<enabled>1</enabled><interval>1</interval><failure_threshold>2</failure_threshold><recovery_threshold>2</recovery_threshold>
<checks>
<check uuid="a"><enabled>1</enabled><name>wan-a</name><interface>opt2</interface><target>192.0.2.2</target><scope>interface</scope><failure_advskew>200</failure_advskew><fallback_ipv4_target>192.0.2.99</fallback_ipv4_target><fallback_ipv4_gateway>10.0.0.1</fallback_ipv4_gateway></check>
<check uuid="b"><enabled>1</enabled><name>wan-b</name><interface>opt2</interface><target>192.0.2.2</target><scope>vhid_group</scope><vhid_targets>opt2:51,opt3:52</vhid_targets><failure_advskew>254</failure_advskew><backup_ipv6_default_gateway>fe80::1%vlan03</backup_ipv6_default_gateway></check>
</checks>
</CarpHealth></ApiExtensions></OPNsense></opnsense>`

func TestParseConfigParityWithPython(t *testing.T) {
	cfg, err := parseConfig([]byte(sampleConfigXML))
	if err != nil {
		t.Fatal(err)
	}
	const pythonSignature = "5e76170edced4eb12f981ecce5e543800e8e8200d53faa10b999848987d6cbeb"
	if cfg.Signature != pythonSignature {
		t.Fatalf("signature=%s want Python %s", cfg.Signature, pythonSignature)
	}
	if !cfg.Enabled || cfg.IntervalSeconds != 1 || cfg.FailureThreshold != 2 || cfg.RecoveryThreshold != 2 {
		t.Fatalf("unexpected service config: %+v", cfg)
	}
	if len(cfg.CarpVhids) != 2 || cfg.CarpVhids[0].Device != "vlan02" || cfg.CarpVhids[1].Advskew != 100 {
		t.Fatalf("unexpected CARP inventory: %+v", cfg.CarpVhids)
	}
	if len(cfg.Checks) != 2 {
		t.Fatalf("checks=%d", len(cfg.Checks))
	}
	if got := resolveVhidTargets(cfg.Checks[0], cfg); len(got) != 1 || got[0].Key() != "opt2:51" {
		t.Fatalf("interface targets=%+v", got)
	}
	got := resolveVhidTargets(cfg.Checks[1], cfg)
	if len(got) != 2 || got[0].Key() != "opt2:51" || got[1].Key() != "opt3:52" {
		t.Fatalf("group targets=%+v", got)
	}
	if cfg.Checks[1].BackupIPv6DefaultGateway != "fe80::1%vlan03" {
		t.Fatalf("scoped IPv6 gateway=%q", cfg.Checks[1].BackupIPv6DefaultGateway)
	}
}

func TestLegacyMissingScopeDefaultsGlobal(t *testing.T) {
	xml := `<opnsense><interfaces><opt2><if>vlan02</if></opt2></interfaces><virtualip><vip><interface>opt2</interface><mode>carp</mode><vhid>51</vhid><advskew>10</advskew></vip></virtualip><OPNsense><ApiExtensions><CarpHealth><enabled>1</enabled><checks><check uuid="legacy"><enabled>1</enabled><name>legacy</name><interface>opt2</interface><target>192.0.2.2</target></check></checks></CarpHealth></ApiExtensions></OPNsense></opnsense>`
	cfg, err := parseConfig([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Checks) != 1 || cfg.Checks[0].Scope != "global" {
		t.Fatalf("legacy scope=%+v", cfg.Checks)
	}
}
