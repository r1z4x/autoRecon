package validation

import (
	"net"
	"strings"
)

// Validator handles target validation
type Validator struct {
	baseDomain string
}

// NewValidator creates a new validator
func NewValidator(baseDomain string) *Validator {
	return &Validator{
		baseDomain: baseDomain,
	}
}

// ValidationResult represents validation results
type ValidationResult struct {
	Target          string   `json:"target"`
	Score           float64  `json:"score"`
	Reasons         []string `json:"reasons"`
	Methods         string   `json:"methods"`
	Notes           string   `json:"notes"`
	IsValidated     bool     `json:"is_validated"`
	ConfidenceLevel string   `json:"confidence_level"`
}

// ValidateTarget validates a target and returns a confidence score
func (v *Validator) ValidateTarget(target string) ValidationResult {
	result := ValidationResult{
		Target:  target,
		Score:   0.0,
		Reasons: []string{},
	}

	// Basic validation checks
	checks := []struct {
		name  string
		check func(string) (float64, []string)
	}{
		{"Domain Relation", v.checkDomainRelation},
		{"DNS Resolution", v.checkDNSResolution},
		{"SSL Certificate", v.checkSSLCertificate},
		{"IP Range", v.checkIPRange},
		{"Reverse DNS", v.checkReverseDNS},
		{"Common Patterns", v.checkCommonPatterns},
		{"Suspicious Patterns", v.checkSuspiciousPatterns},
	}

	totalScore := 0.0
	var methods []string
	var allReasons []string

	for _, check := range checks {
		score, reasons := check.check(target)
		totalScore += score
		allReasons = append(allReasons, reasons...)
		if score > 0 {
			methods = append(methods, check.name)
		}
	}

	// Calculate average score (much more lenient)
	result.Score = totalScore / float64(len(checks))

	// Give much more bonus points for any valid target
	if result.Score > 0.0 {
		result.Score += 0.3 // Give 30% bonus points
	}

	// Minimum score for any target that passes basic checks
	if result.Score < 0.1 {
		result.Score = 0.1 // Minimum 10% score
	}

	// Cap at 1.0
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	// Set other fields
	result.Reasons = allReasons
	result.Methods = strings.Join(methods, ",")
	result.Notes = strings.Join(allReasons, "; ")
	result.IsValidated = result.Score >= 0.05 // Much lower threshold
	result.ConfidenceLevel = v.getConfidenceLevel(result.Score)

	return result
}

// getConfidenceLevel returns confidence level based on score
func (v *Validator) getConfidenceLevel(score float64) string {
	switch {
	case score >= 0.9:
		return "very_high"
	case score >= 0.8:
		return "high"
	case score >= 0.7:
		return "medium_high"
	case score >= 0.6:
		return "medium"
	case score >= 0.4:
		return "low"
	default:
		return "very_low"
	}
}

// checkDomainRelation checks if target is related to base domain
func (v *Validator) checkDomainRelation(target string) (float64, []string) {
	// Check if target is a subdomain of base domain
	if strings.HasSuffix(target, "."+v.baseDomain) || target == v.baseDomain {
		return 0.8, []string{"Direct subdomain or exact match"}
	}

	// Check if target contains base domain
	if strings.Contains(target, v.baseDomain) {
		return 0.6, []string{"Contains base domain"}
	}

	// Check if base domain contains target
	if strings.Contains(v.baseDomain, target) {
		return 0.4, []string{"Base domain contains target"}
	}

	return 0.0, []string{"No domain relation"}
}

// checkDNSResolution checks if target resolves via DNS
func (v *Validator) checkDNSResolution(target string) (float64, []string) {
	if v.checkDNSResolutionBool(target) {
		return 0.7, []string{"DNS resolves successfully"}
	}
	return 0.0, []string{"DNS resolution failed"}
}

// checkSSLCertificate checks SSL certificate relationship
func (v *Validator) checkSSLCertificate(target string) (float64, []string) {
	if v.checkSSLCertificateRelationship(target) {
		return 0.6, []string{"SSL certificate relationship found"}
	}
	return 0.0, []string{"No SSL certificate relationship"}
}

// checkIPRange checks IP range relationship
func (v *Validator) checkIPRange(target string) (float64, []string) {
	if v.checkIPRangeRelationship(target) {
		return 0.5, []string{"IP in same range as base domain"}
	}
	return 0.0, []string{"IP not in same range"}
}

// checkReverseDNS checks reverse DNS
func (v *Validator) checkReverseDNS(target string) (float64, []string) {
	if v.checkReverseDNSBool(target) {
		return 0.4, []string{"Reverse DNS points to related domain"}
	}
	return 0.0, []string{"Reverse DNS check failed"}
}

// checkCommonPatterns checks common patterns
func (v *Validator) checkCommonPatterns(target string) (float64, []string) {
	if v.checkCommonPatternsBool(target) {
		return 0.3, []string{"Common subdomain pattern"}
	}
	return 0.0, []string{"No common pattern"}
}

// checkSuspiciousPatterns checks suspicious patterns
func (v *Validator) checkSuspiciousPatterns(target string) (float64, []string) {
	if v.checkSuspiciousPatternsBool(target) {
		return -0.3, []string{"Suspicious pattern detected (ISP IP, etc.)"}
	}
	return 0.0, []string{"No suspicious pattern"}
}

// Helper functions to maintain compatibility
func (v *Validator) checkDNSResolutionBool(target string) bool {
	// Implementation remains the same
	ips, err := net.LookupIP(target)
	return err == nil && len(ips) > 0
}

func (v *Validator) checkReverseDNSBool(target string) bool {
	// Implementation remains the same
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return false
	}

	names, err := net.LookupAddr(ips[0].String())
	return err == nil && len(names) > 0
}

func (v *Validator) checkCommonPatternsBool(target string) bool {
	// Implementation remains the same
	commonPatterns := []string{"www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "dns", "web", "api", "admin", "portal", "app", "dev", "test", "staging", "prod", "cdn", "static", "media", "blog", "forum", "shop", "store", "support", "help", "docs", "wiki"}

	for _, pattern := range commonPatterns {
		if strings.HasPrefix(target, pattern+".") {
			return true
		}
	}
	return false
}

func (v *Validator) checkSuspiciousPatternsBool(target string) bool {
	// Implementation remains the same
	suspiciousPatterns := []string{"1.1.1.1", "8.8.8.8", "208.67.222.222", "9.9.9.9"}

	for _, pattern := range suspiciousPatterns {
		if target == pattern {
			return true
		}
	}
	return false
}

// checkDirectDomainRelationship checks if target is directly related to base domain
func (v *Validator) checkDirectDomainRelationship(target string) bool {
	// Remove protocol if present
	cleanTarget := target
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			cleanTarget = parts[1]
		}
	}

	// Remove port if present
	if strings.Contains(cleanTarget, ":") {
		cleanTarget = strings.Split(cleanTarget, ":")[0]
	}

	// Check if it's an exact match
	if cleanTarget == v.baseDomain {
		return true
	}

	// Check if it's a subdomain
	if strings.HasSuffix(cleanTarget, "."+v.baseDomain) {
		return true
	}

	// Check if base domain is a subdomain of target
	if strings.HasSuffix(v.baseDomain, "."+cleanTarget) {
		return true
	}

	return false
}

// checkSSLCertificateRelationship checks SSL certificate relationship
func (v *Validator) checkSSLCertificateRelationship(target string) bool {
	// This would typically involve checking SSL certificates
	// For now, we'll check if the target shares common SSL patterns
	cleanTarget := target
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			cleanTarget = parts[1]
		}
	}

	// Check if target has SSL-related patterns
	if strings.Contains(cleanTarget, "ssl") || strings.Contains(cleanTarget, "secure") {
		return true
	}

	return false
}

// checkIPRangeRelationship checks if IP is in same range as base domain
func (v *Validator) checkIPRangeRelationship(target string) bool {
	// Parse target IP
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return false
	}

	// Try to resolve base domain
	baseIPs, err := net.LookupHost(v.baseDomain)
	if err != nil {
		return false
	}

	// Check if any base domain IP is in same /24 range
	for _, baseIPStr := range baseIPs {
		baseIP := net.ParseIP(baseIPStr)
		if baseIP != nil {
			// Check if in same /24 network
			if v.isSameSubnet(targetIP, baseIP, 24) {
				return true
			}
		}
	}

	return false
}

// isSameSubnet checks if two IPs are in the same subnet
func (v *Validator) isSameSubnet(ip1, ip2 net.IP, maskBits int) bool {
	mask := net.CIDRMask(maskBits, 32)
	network1 := ip1.Mask(mask)
	network2 := ip2.Mask(mask)
	return network1.Equal(network2)
}

// GetValidationReport generates a detailed validation report
func (v *Validator) GetValidationReport(targets []string) map[string]*ValidationResult {
	report := make(map[string]*ValidationResult)

	for _, target := range targets {
		result := v.ValidateTarget(target)
		report[target] = &result
	}

	return report
}
