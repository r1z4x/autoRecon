package models

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// TargetType represents the type of target
type TargetType string

const (
	TargetTypeDomain  TargetType = "domain"
	TargetTypeURL     TargetType = "url"
	TargetTypeIP      TargetType = "ip"
	TargetTypeIPRange TargetType = "ip_range"
	TargetTypeUnknown TargetType = "unknown"
)

// Target represents a single target for scanning
type Target struct {
	Value           string          `json:"value" yaml:"value"`
	Type            TargetType      `json:"type" yaml:"type"`
	Validated       bool            `json:"validated" yaml:"validated"`
	Expanded        []string        `json:"expanded,omitempty" yaml:"expanded,omitempty"`
	Results         []string        `json:"results,omitempty" yaml:"results,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`

	// Enhanced data collection
	Ports      []PortInfo    `json:"ports,omitempty" yaml:"ports,omitempty"`
	Services   []ServiceInfo `json:"services,omitempty" yaml:"services,omitempty"`
	OSInfo     OSInfo        `json:"os_info,omitempty" yaml:"os_info,omitempty"`
	SSLInfo    SSLInfo       `json:"ssl_info,omitempty" yaml:"ssl_info,omitempty"`
	ShodanData ShodanInfo    `json:"shodan_data,omitempty" yaml:"shodan_data,omitempty"`

	// New fields for unified target management
	PortsFound     []int    `json:"ports_found,omitempty" yaml:"ports_found,omitempty"`         // Open ports found
	Source         string   `json:"source" yaml:"source"`                                       // Where this target was discovered (subfinder, ssl_discovery, port_scan, etc.)
	DiscoveredAt   string   `json:"discovered_at" yaml:"discovered_at"`                         // When this target was discovered
	RelatedTargets []string `json:"related_targets,omitempty" yaml:"related_targets,omitempty"` // Related targets (same SSL cert, etc.)
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	Template    string `json:"template" yaml:"template"`
	Severity    string `json:"severity" yaml:"severity"`
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description" yaml:"description"`
	MatchedAt   string `json:"matched_at" yaml:"matched_at"`
}

// TargetList represents a collection of targets
type TargetList struct {
	Domains  []Target `json:"domains" yaml:"domains"`
	URLs     []Target `json:"urls" yaml:"urls"`
	IPs      []Target `json:"ips" yaml:"ips"`
	IPRanges []Target `json:"ip_ranges" yaml:"ip_ranges"`
	Unknown  []Target `json:"unknown" yaml:"unknown"`
}

// PortInfo represents port information
type PortInfo struct {
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
	State    string `json:"state" yaml:"state"`
	Service  string `json:"service" yaml:"service"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
}

// ServiceInfo represents service information
type ServiceInfo struct {
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Service  string `json:"service" yaml:"service"`
	Product  string `json:"product,omitempty" yaml:"product,omitempty"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Extra    string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// OSInfo represents operating system information
type OSInfo struct {
	Name         string `json:"name" yaml:"name"`
	Version      string `json:"version" yaml:"version"`
	Architecture string `json:"architecture" yaml:"architecture"`
	Type         string `json:"type" yaml:"type"`
	Accuracy     int    `json:"accuracy" yaml:"accuracy"`
}

// SSLInfo represents SSL/TLS certificate information
type SSLInfo struct {
	Valid         bool     `json:"valid" yaml:"valid"`
	Issuer        string   `json:"issuer" yaml:"issuer"`
	Subject       string   `json:"subject" yaml:"subject"`
	ValidFrom     string   `json:"valid_from" yaml:"valid_from"`
	ValidUntil    string   `json:"valid_until" yaml:"valid_until"`
	SerialNumber  string   `json:"serial_number" yaml:"serial_number"`
	SignatureAlgo string   `json:"signature_algo" yaml:"signature_algo"`
	KeySize       int      `json:"key_size" yaml:"key_size"`
	DNSNames      []string `json:"dns_names" yaml:"dns_names"`
	IPAddresses   []string `json:"ip_addresses" yaml:"ip_addresses"`
}

// ShodanInfo represents Shodan data
type ShodanInfo struct {
	LastUpdate string                 `json:"last_update" yaml:"last_update"`
	Data       map[string]interface{} `json:"data" yaml:"data"`
	Hostnames  []string               `json:"hostnames" yaml:"hostnames"`
	Ports      []int                  `json:"ports" yaml:"ports"`
	Tags       []string               `json:"tags" yaml:"tags"`
}

// UnifiedTargetList represents all targets in a single structure
type UnifiedTargetList struct {
	Targets   []UnifiedTarget `json:"targets" yaml:"targets"`
	Summary   TargetSummary   `json:"summary" yaml:"summary"`
	UpdatedAt string          `json:"updated_at" yaml:"updated_at"`
}

// UnifiedTarget represents a target with all its information
type UnifiedTarget struct {
	Value          string     `json:"value" yaml:"value"`
	Type           TargetType `json:"type" yaml:"type"`
	Ports          []int      `json:"ports,omitempty" yaml:"ports,omitempty"`
	Source         string     `json:"source" yaml:"source"`
	DiscoveredAt   string     `json:"discovered_at" yaml:"discovered_at"`
	RelatedTargets []string   `json:"related_targets,omitempty" yaml:"related_targets,omitempty"`
	Status         string     `json:"status" yaml:"status"` // active, scanned, completed
}

// TargetSummary provides summary statistics
type TargetSummary struct {
	TotalTargets    int            `json:"total_targets" yaml:"total_targets"`
	ByType          map[string]int `json:"by_type" yaml:"by_type"`
	BySource        map[string]int `json:"by_source" yaml:"by_source"`
	TotalPortsFound int            `json:"total_ports_found" yaml:"total_ports_found"`
}

// ParseTarget parses a string and returns a Target with appropriate type
func ParseTarget(input string) Target {
	input = strings.TrimSpace(input)

	// Skip empty lines and comments
	if input == "" || strings.HasPrefix(input, "#") {
		return Target{Value: input, Type: TargetTypeUnknown}
	}

	// URL pattern
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return Target{Value: input, Type: TargetTypeURL, Validated: false}
	}

	// IP range pattern (CIDR)
	if strings.Contains(input, "/") {
		if _, _, err := net.ParseCIDR(input); err == nil {
			return Target{Value: input, Type: TargetTypeIPRange, Validated: false}
		}
	}

	// IP range pattern (dash notation)
	if strings.Contains(input, "-") {
		parts := strings.Split(input, "-")
		if len(parts) == 2 {
			if net.ParseIP(strings.TrimSpace(parts[0])) != nil &&
				net.ParseIP(strings.TrimSpace(parts[1])) != nil {
				return Target{Value: input, Type: TargetTypeIPRange, Validated: false}
			}
		}
	}

	// Single IP pattern
	if net.ParseIP(input) != nil {
		return Target{Value: input, Type: TargetTypeIP, Validated: false}
	}

	// Domain pattern
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if domainRegex.MatchString(input) {
		return Target{Value: input, Type: TargetTypeDomain, Validated: false}
	}

	return Target{Value: input, Type: TargetTypeUnknown, Validated: false}
}

// ExpandIPRange expands an IP range into individual IPs
func (t *Target) ExpandIPRange() error {
	if t.Type != TargetTypeIPRange {
		return fmt.Errorf("target is not an IP range")
	}

	var ips []string

	if strings.Contains(t.Value, "/") {
		// CIDR notation
		ip, ipnet, err := net.ParseCIDR(t.Value)
		if err != nil {
			return err
		}

		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
	} else if strings.Contains(t.Value, "-") {
		// Dash notation
		parts := strings.Split(t.Value, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid IP range format")
		}

		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))

		if start == nil || end == nil {
			return fmt.Errorf("invalid IP addresses in range")
		}

		for ip := start; !ip.Equal(end); inc(ip) {
			ips = append(ips, ip.String())
		}
		ips = append(ips, end.String())
	}

	t.Expanded = ips
	return nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetSummary returns a summary of the target list
func (tl *TargetList) GetSummary() map[string]int {
	return map[string]int{
		"domains":   len(tl.Domains),
		"urls":      len(tl.URLs),
		"ips":       len(tl.IPs),
		"ip_ranges": len(tl.IPRanges),
		"unknown":   len(tl.Unknown),
	}
}

// AddTarget adds a target to the appropriate category
func (tl *TargetList) AddTarget(target Target) {
	switch target.Type {
	case TargetTypeDomain:
		tl.Domains = append(tl.Domains, target)
	case TargetTypeURL:
		tl.URLs = append(tl.URLs, target)
	case TargetTypeIP:
		tl.IPs = append(tl.IPs, target)
	case TargetTypeIPRange:
		tl.IPRanges = append(tl.IPRanges, target)
	case TargetTypeUnknown:
		tl.Unknown = append(tl.Unknown, target)
	}
}
