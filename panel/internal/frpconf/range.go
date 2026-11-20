package frpconf

import (
	"fmt"
	"strconv"
	"strings"
)

// PortSpec is a single port or an inclusive port range from user input.
type PortSpec struct {
	Start int
	End   int
}

// IsRange reports whether the spec spans more than one port.
func (p PortSpec) IsRange() bool { return p.End != p.Start }

// Len returns the number of ports the spec expands to.
func (p PortSpec) Len() int { return p.End - p.Start + 1 }

// ParsePortSpecs parses "22,6000-6006,6007" into ordered specs.
//
// Grammar:  ports := spec ("," spec)* ; spec := port | port "-" port
// Rules:    ports are 1..65535, ranges are inclusive, and a port may appear
// only once across the whole input (duplicate proxy names would break frp).
func ParsePortSpecs(input string) ([]PortSpec, error) {
	var specs []PortSpec
	seen := make(map[int]bool)

	fields := strings.Split(input, ",")
	for i, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			if i == 0 && len(fields) == 1 {
				return nil, fmt.Errorf("empty port list")
			}
			continue // tolerate trailing/double commas elsewhere
		}
		start, end, err := parseOneSpec(f)
		if err != nil {
			return nil, err
		}
		for p := start; p <= end; p++ {
			if seen[p] {
				return nil, fmt.Errorf("port %d appears more than once in input", p)
			}
			seen[p] = true
		}
		specs = append(specs, PortSpec{Start: start, End: end})
	}
	return specs, nil
}

// FormatPortSpecs renders specs back into the compact "22,6000-6006" form.
// Consecutive single ports are not merged: the input shape is preserved.
func FormatPortSpecs(specs []PortSpec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.IsRange() {
			parts = append(parts, fmt.Sprintf("%d-%d", s.Start, s.End))
		} else {
			parts = append(parts, strconv.Itoa(s.Start))
		}
	}
	return strings.Join(parts, ",")
}

func parseOneSpec(f string) (int, int, error) {
	startStr, endStr, isRange := strings.Cut(f, "-")
	start, err := strconv.Atoi(strings.TrimSpace(startStr))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port spec %q", f)
	}
	end := start
	if isRange {
		end, err = strconv.Atoi(strings.TrimSpace(endStr))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q", f)
		}
	}
	if start < 1 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("invalid port range %q (want 1..65535 with start <= end)", f)
	}
	return start, end, nil
}

// ExpandAll flattens specs to individual ports. max limits the expansion;
// when exceeded, callers should offer FRP's Go-template rendering instead
// (see docs/ARCHITECTURE.md §4.3).
func ExpandAll(specs []PortSpec, max int) ([]int, error) {
	total := 0
	for _, s := range specs {
		total += s.Len()
		if max > 0 && total > max {
			return nil, fmt.Errorf("input expands to %d ports (limit %d); use template mode or reduce the range", total, max)
		}
	}
	ports := make([]int, 0, total)
	for _, s := range specs {
		for p := s.Start; p <= s.End; p++ {
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// ProtoToggle controls which proxy types are emitted per port.
type ProtoToggle uint8

const (
	// ProtoUnset means "caller did not choose" — builders apply the suite
	// default (ProtoTCPAndUDP). It is the zero value on purpose, so
	// ProtoTCPOnly/ProtoUDPOnly can never be clobbered by defaults.
	ProtoUnset ProtoToggle = iota
	// ProtoTCPOnly emits only tcp-<port> proxies.
	ProtoTCPOnly
	// ProtoUDPOnly emits only udp-<port> proxies.
	ProtoUDPOnly
	// ProtoTCPAndUDP emits paired tcp-<port> and udp-<port> proxies — the
	// single-toggle dual forwarding requested for the suite.
	ProtoTCPAndUDP
)

// BuildProxies expands specs into ordered proxy blocks. For every port the
// tcp block comes first; with ProtoTCPAndUDP the udp block follows it.
func BuildProxies(specs []PortSpec, proto ProtoToggle, localIP string, encryption, compression bool) []Proxy {
	proxies := []Proxy{}
	for _, s := range specs {
		for p := s.Start; p <= s.End; p++ {
			if proto == ProtoTCPOnly || proto == ProtoTCPAndUDP {
				proxies = append(proxies, newProxy("tcp", p, localIP, encryption, compression))
			}
			if proto == ProtoUDPOnly || proto == ProtoTCPAndUDP {
				proxies = append(proxies, newProxy("udp", p, localIP, encryption, compression))
			}
		}
	}
	return proxies
}

func newProxy(typ string, port int, localIP string, encryption, compression bool) Proxy {
	var p Proxy
	p.Name = fmt.Sprintf("%s-%d", typ, port)
	p.Type = typ
	p.LocalIP = localIP
	p.LocalPort = port
	p.RemotePort = port
	p.Transport.UseEncryption = encryption
	p.Transport.UseCompression = compression
	return p
}
