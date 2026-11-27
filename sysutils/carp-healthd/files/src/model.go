package main

import "time"

const (
	defaultConfigPath = "/conf/config.xml"
	defaultStatePath  = "/var/run/api_extensions_carp_health.json"
	defaultSocketPath = "/var/run/api_extensions_carp_health.sock"

	failoverAdvskew = 254
)

type VhidTarget struct {
	Interface string
	VHID      int
}

func (t VhidTarget) Key() string {
	return t.Interface + ":" + itoa(t.VHID)
}

type Check struct {
	UUID                       string
	Name                       string
	Interface                  string
	Device                     string
	Target                     string
	Scope                      string
	VHID                       int
	VHIDTargets                []VhidTarget
	FailureAdvskew             int
	FallbackIPv4Target         string
	FallbackIPv4Gateway        string
	FallbackIPv6Target         string
	FallbackIPv6Gateway        string
	FallbackIPv4DefaultGateway string
	FallbackIPv6DefaultGateway string
	BackupIPv4DefaultGateway   string
	BackupIPv6DefaultGateway   string
}

type CarpVhid struct {
	Interface string
	Device    string
	VHID      int
	Advskew   int
}

type Config struct {
	Enabled           bool
	Interval          time.Duration
	IntervalSeconds   int
	FailureThreshold  int
	RecoveryThreshold int
	Checks            []Check
	CarpVhids         []CarpVhid
	Signature         string
}

type HealthRecord struct {
	Healthy   *bool
	Failures  int
	Successes int
}

type GlobalState struct {
	Active     bool
	CheckCount int
	Ready      bool
	Healthy    bool
}

type VHIDState struct {
	Key               string
	Interface         string
	Device            string
	VHID              int
	Checks            []string
	Ready             bool
	Healthy           bool
	DesiredDemoted    bool
	DesiredAdvskew    *int
	ConfiguredAdvskew *int
	CurrentAdvskew    *int
	CarpState         string
	ControlOK         bool
	Retired           bool
	Error             string
}

type RouteState struct {
	Key              string
	CheckUUID        string
	Check            string
	Family           string
	RouteType        string
	Trigger          string
	Destination      string
	Gateway          string
	DesiredInstalled bool
	Installed        bool
	Managed          bool
	ControlOK        bool
	Retired          bool
	Error            string
}

type CheckState struct {
	UUID                  string
	Name                  string
	Interface             string
	Device                string
	Target                string
	Scope                 string
	VHID                  int
	VHIDTargets           []string
	ConfiguredVHIDTargets []string
	FailureAdvskew        int
	VHIDStates            []VHIDState
	FallbackRoutes        []RouteState
	CarpState             string
	ConfiguredAdvskew     *int
	CurrentAdvskew        *int
	ControlOK             bool
	Healthy               *bool
	Failures              int
	Successes             int
}

type RuntimeState struct {
	Status          string
	Enabled         bool
	Ready           bool
	Healthy         bool
	ProbeHealthy    bool
	ControlOK       bool
	Running         bool
	Timestamp       float64
	ConfigSignature string
	Global          GlobalState
	VHIDs           []VHIDState
	Routes          []RouteState
	Checks          []CheckState
}

type CarpRuntime struct {
	State   string
	Advskew int
}

type RouteSpec struct {
	Family      string
	RouteType   string
	Destination string
	Gateway     string
}

type NativeEvent struct {
	Kind   string
	Device string
	VHID   int
	State  string
}
