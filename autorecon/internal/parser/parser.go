package parser

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"autorecon/internal/database"
	"autorecon/pkg/models"
)

// Parser handles target parsing and categorization
type Parser struct {
	// Dynamic discovery settings
	EnableDynamicDiscovery bool
	MaxNewTargets          int
	DiscoveredTargets      map[string]bool // Track discovered targets to avoid duplicates
}

// NewParser creates a new parser instance
func NewParser() *Parser {
	return &Parser{
		EnableDynamicDiscovery: true,
		MaxNewTargets:          1000, // Maximum new targets to add dynamically
		DiscoveredTargets:      make(map[string]bool),
	}
}

// ParseTargets parses and categorizes input targets
func (p *Parser) ParseTargets(targets []string) *models.TargetList {
	targetList := &models.TargetList{
		Domains:  []models.Target{},
		URLs:     []models.Target{},
		IPs:      []models.Target{},
		IPRanges: []models.Target{},
		Unknown:  []models.Target{},
	}

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}

		categorized := p.categorizeTarget(target)
		targetList.AddTarget(categorized)

		// Track discovered target
		p.DiscoveredTargets[target] = true
	}

	return targetList
}

// ParseFile parses targets from a file
func (p *Parser) ParseFile(filename string) (*models.TargetList, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return p.ParseTargets(targets), nil
}

// categorizeTarget categorizes a single target
func (p *Parser) categorizeTarget(target string) models.Target {
	// Remove protocol if present
	cleanTarget := target
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			cleanTarget = parts[1]
		}
	}

	// Remove path and query parameters
	if strings.Contains(cleanTarget, "/") {
		cleanTarget = strings.Split(cleanTarget, "/")[0]
	}

	// Check if it's a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return models.Target{
			Type:  models.TargetTypeURL,
			Value: target,
		}
	}

	// Check if it's a domain
	if p.isDomain(cleanTarget) {
		return models.Target{
			Type:  models.TargetTypeDomain,
			Value: cleanTarget,
		}
	}

	// Check if it's an IP range (CIDR notation)
	if strings.Contains(cleanTarget, "/") {
		if p.isCIDR(cleanTarget) {
			return models.Target{
				Type:  models.TargetTypeIPRange,
				Value: cleanTarget,
			}
		}
	}

	// Check if it's an IP range (dash notation)
	if strings.Contains(cleanTarget, "-") {
		if p.isIPRange(cleanTarget) {
			return models.Target{
				Type:  models.TargetTypeIPRange,
				Value: cleanTarget,
			}
		}
	}

	// Check if it's a single IP
	if p.isIP(cleanTarget) {
		return models.Target{
			Type:  models.TargetTypeIP,
			Value: cleanTarget,
		}
	}

	// Unknown type
	return models.Target{
		Type:  models.TargetTypeUnknown,
		Value: target,
	}
}

// isDomain checks if a string is a valid domain
func (p *Parser) isDomain(s string) bool {
	// Basic domain regex
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainRegex.MatchString(s) && strings.Contains(s, ".")
}

// isIP checks if a string is a valid IP address
func (p *Parser) isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// isCIDR checks if a string is a valid CIDR notation
func (p *Parser) isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// isIPRange checks if a string is a valid IP range (dash notation)
func (p *Parser) isIPRange(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false
	}
	return p.isIP(parts[0]) && p.isIP(parts[1])
}

// ExpandIPRanges expands IP ranges into individual IPs
func (p *Parser) ExpandIPRanges(targetList *models.TargetList) error {
	var newIPs []models.Target

	for _, ipRange := range targetList.IPRanges {
		ips, err := p.expandIPRange(ipRange.Value)
		if err != nil {
			continue // Skip invalid ranges
		}

		for _, ip := range ips {
			newIPs = append(newIPs, models.Target{
				Type:  "ip",
				Value: ip,
			})
		}
	}

	// Add expanded IPs to the list
	targetList.IPs = append(targetList.IPs, newIPs...)

	// Clear IP ranges since they're now expanded
	targetList.IPRanges = []models.Target{}

	return nil
}

// expandIPRange expands a single IP range
func (p *Parser) expandIPRange(ipRange string) ([]string, error) {
	var ips []string

	// Handle CIDR notation
	if strings.Contains(ipRange, "/") {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, err
		}

		// Convert to IP
		ip := ipNet.IP.To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 CIDR")
		}

		// Get network mask
		mask := ipNet.Mask
		ones, bits := mask.Size()

		// Calculate number of hosts
		numHosts := 1 << uint(bits-ones)

		// Generate all IPs in the range
		for i := 0; i < numHosts; i++ {
			// Skip network and broadcast addresses
			if i == 0 || i == numHosts-1 {
				continue
			}

			// Calculate IP
			newIP := make(net.IP, len(ip))
			copy(newIP, ip)
			for j := len(newIP) - 1; j >= 0; j-- {
				newIP[j] += byte(i & 0xFF)
				i >>= 8
			}

			ips = append(ips, newIP.String())
		}

		return ips, nil
	}

	// Handle dash notation
	if strings.Contains(ipRange, "-") {
		parts := strings.Split(ipRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range format")
		}

		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP addresses")
		}

		// Convert to uint32 for comparison
		start := p.ipToUint32(startIP)
		end := p.ipToUint32(endIP)

		if start > end {
			return nil, fmt.Errorf("start IP greater than end IP")
		}

		// Generate IPs in range
		for i := start; i <= end; i++ {
			ip := p.uint32ToIP(i)
			ips = append(ips, ip.String())
		}

		return ips, nil
	}

	return nil, fmt.Errorf("unsupported IP range format")
}

// ipToUint32 converts IP to uint32
func (p *Parser) ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

// uint32ToIP converts uint32 to IP
func (p *Parser) uint32ToIP(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}

// AddDiscoveredTargets adds newly discovered targets to the list
func (p *Parser) AddDiscoveredTargets(targetList *models.TargetList, newTargets []string) {
	if !p.EnableDynamicDiscovery {
		return
	}

	count := 0
	for _, target := range newTargets {
		if count >= p.MaxNewTargets {
			break
		}

		target = strings.TrimSpace(target)
		if target == "" || p.DiscoveredTargets[target] {
			continue
		}

		// Categorize and add new target
		categorized := p.categorizeTarget(target)
		targetList.AddTarget(categorized)

		// Track as discovered
		p.DiscoveredTargets[target] = true
		count++
	}
}

// ExtractSubdomainsFromResults extracts potential new subdomains from scan results
func (p *Parser) ExtractSubdomainsFromResults(results []string, baseDomain string) []string {
	var newSubdomains []string
	subdomainRegex := regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.` + regexp.QuoteMeta(baseDomain))

	for _, result := range results {
		matches := subdomainRegex.FindAllString(result, -1)
		for _, match := range matches {
			if !p.DiscoveredTargets[match] {
				newSubdomains = append(newSubdomains, match)
			}
		}
	}

	return newSubdomains
}

// ExtractURLsFromResults extracts potential new URLs from scan results
func (p *Parser) ExtractURLsFromResults(results []string) []string {
	var newURLs []string
	urlRegex := regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`)

	for _, result := range results {
		matches := urlRegex.FindAllString(result, -1)
		for _, match := range matches {
			if !p.DiscoveredTargets[match] {
				newURLs = append(newURLs, match)
			}
		}
	}

	return newURLs
}

// ExtractIPsFromResults extracts potential new IPs from scan results
func (p *Parser) ExtractIPsFromResults(results []string) []string {
	var newIPs []string
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

	for _, result := range results {
		matches := ipRegex.FindAllString(result, -1)
		for _, match := range matches {
			if p.isIP(match) && !p.DiscoveredTargets[match] {
				newIPs = append(newIPs, match)
			}
		}
	}

	return newIPs
}

// GetDiscoveryStats returns discovery statistics
func (p *Parser) GetDiscoveryStats() map[string]int {
	stats := make(map[string]int)

	for target := range p.DiscoveredTargets {
		categorized := p.categorizeTarget(target)
		stats[string(categorized.Type)]++
	}

	return stats
}

// ResetDiscovery resets the discovery tracking
func (p *Parser) ResetDiscovery() {
	p.DiscoveredTargets = make(map[string]bool)
}

// ParseSingleTarget parses a single target string
func (p *Parser) ParseSingleTarget(target string) *models.TargetList {
	return p.ParseTargets([]string{target})
}

// GetTargetSummary returns a summary of parsed targets
func (p *Parser) GetTargetSummary(targetList *models.TargetList) map[string]int {
	return targetList.GetSummary()
}

// ValidateTargets validates targets and marks them as validated
func (p *Parser) ValidateTargets(targetList *models.TargetList) {
	// This would typically involve checking if targets are reachable
	// For now, we'll just mark them as validated
	for i := range targetList.Domains {
		targetList.Domains[i].Validated = true
	}
	for i := range targetList.URLs {
		targetList.URLs[i].Validated = true
	}
	for i := range targetList.IPs {
		targetList.IPs[i].Validated = true
	}
}

// ExtractTargetsFromSSLData extracts new targets from SSL certificate data
func (p *Parser) ExtractTargetsFromSSLData(sslData []string) []string {
	var newTargets []string

	for _, data := range sslData {
		// Extract DNS names from SSL certificates
		if strings.Contains(data, "DNS:") {
			// Extract domain names from DNS entries
			domains := p.extractDomainsFromSSL(data)
			newTargets = append(newTargets, domains...)
		}

		// Extract IP addresses from SSL certificates
		if strings.Contains(data, "IP:") {
			ips := p.extractIPsFromSSL(data)
			newTargets = append(newTargets, ips...)
		}
	}

	return p.removeDuplicates(newTargets)
}

// ExtractTargetsFromShodanData extracts new targets from Shodan data
func (p *Parser) ExtractTargetsFromShodanData(shodanData []string) []string {
	var newTargets []string

	for _, data := range shodanData {
		// Extract hostnames from Shodan data
		if strings.Contains(data, "SHODAN_HOSTNAME:") {
			hostnames := p.extractHostnamesFromShodan(data)
			newTargets = append(newTargets, hostnames...)
		}

		// Extract IP addresses from Shodan data
		if strings.Contains(data, "SHODAN_DATA:") {
			ips := p.extractIPsFromShodan(data)
			newTargets = append(newTargets, ips...)
		}

		// Extract URLs from Shodan data
		if strings.Contains(data, "SHODAN_DATA:") {
			urls := p.extractURLsFromShodan(data)
			newTargets = append(newTargets, urls...)
		}
	}

	return p.removeDuplicates(newTargets)
}

// extractDomainsFromSSL extracts domain names from SSL certificate data
func (p *Parser) extractDomainsFromSSL(sslData string) []string {
	var domains []string

	// Look for DNS: patterns
	dnsPattern := regexp.MustCompile(`DNS:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	matches := dnsPattern.FindAllStringSubmatch(sslData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			domain := strings.TrimSpace(match[1])
			if p.isValidDomain(domain) {
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// extractIPsFromSSL extracts IP addresses from SSL certificate data
func (p *Parser) extractIPsFromSSL(sslData string) []string {
	var ips []string

	// Look for IP: patterns
	ipPattern := regexp.MustCompile(`IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := ipPattern.FindAllStringSubmatch(sslData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			ip := strings.TrimSpace(match[1])
			if p.isValidIP(ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// extractHostnamesFromShodan extracts hostnames from Shodan data
func (p *Parser) extractHostnamesFromShodan(shodanData string) []string {
	var hostnames []string

	// Look for hostname patterns in JSON-like data
	hostnamePattern := regexp.MustCompile(`"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"`)
	matches := hostnamePattern.FindAllStringSubmatch(shodanData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			hostname := strings.TrimSpace(match[1])
			if p.isValidDomain(hostname) {
				hostnames = append(hostnames, hostname)
			}
		}
	}

	return hostnames
}

// extractIPsFromShodan extracts IP addresses from Shodan data
func (p *Parser) extractIPsFromShodan(shodanData string) []string {
	var ips []string

	// Look for IP patterns in JSON-like data
	ipPattern := regexp.MustCompile(`"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`)
	matches := ipPattern.FindAllStringSubmatch(shodanData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			ip := strings.TrimSpace(match[1])
			if p.isValidIP(ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// extractURLsFromShodan extracts URLs from Shodan data
func (p *Parser) extractURLsFromShodan(shodanData string) []string {
	var urls []string

	// Look for URL patterns in JSON-like data
	urlPattern := regexp.MustCompile(`"(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"]*)?)"`)
	matches := urlPattern.FindAllStringSubmatch(shodanData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			url := strings.TrimSpace(match[1])
			if p.isValidURL(url) {
				urls = append(urls, url)
			}
		}
	}

	return urls
}

// isValidDomain checks if a string is a valid domain
func (p *Parser) isValidDomain(domain string) bool {
	domainPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainPattern.MatchString(domain) && len(domain) > 0
}

// isValidIP checks if a string is a valid IP address
func (p *Parser) isValidIP(ip string) bool {
	ipPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !ipPattern.MatchString(ip) {
		return false
	}

	parts := strings.Split(ip, ".")
	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

// isValidURL checks if a string is a valid URL
func (p *Parser) isValidURL(url string) bool {
	urlPattern := regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?$`)
	return urlPattern.MatchString(url)
}

// removeDuplicates removes duplicate strings from a slice
func (p *Parser) removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ExtractTargetsFromSSLDiscovery extracts new targets from SSL certificate discovery results
func (p *Parser) ExtractTargetsFromSSLDiscovery(sslDiscoveryData []string) []string {
	var newTargets []string

	for _, data := range sslDiscoveryData {
		// Extract domains from Certificate Transparency results
		if strings.Contains(data, "CT_DOMAIN:") {
			domains := p.extractDomainsFromCT(data)
			newTargets = append(newTargets, domains...)
		}

		// Extract IPs from Shodan SSL results
		if strings.Contains(data, "SHODAN_SSL_IP:") {
			ips := p.extractIPsFromShodanSSL(data)
			newTargets = append(newTargets, ips...)
		}

		// Extract hostnames from Shodan SSL results
		if strings.Contains(data, "SHODAN_SSL_HOSTNAME:") {
			hostnames := p.extractHostnamesFromShodanSSL(data)
			newTargets = append(newTargets, hostnames...)
		}
	}

	return p.removeDuplicates(newTargets)
}

// extractDomainsFromCT extracts domain names from Certificate Transparency results
func (p *Parser) extractDomainsFromCT(ctData string) []string {
	var domains []string

	// Look for domain patterns in JSON-like data
	domainPattern := regexp.MustCompile(`"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"`)
	matches := domainPattern.FindAllStringSubmatch(ctData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			domain := strings.TrimSpace(match[1])
			if p.isValidDomain(domain) {
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// extractIPsFromShodanSSL extracts IP addresses from Shodan SSL results
func (p *Parser) extractIPsFromShodanSSL(shodanSSLData string) []string {
	var ips []string

	// Look for IP patterns in JSON-like data
	ipPattern := regexp.MustCompile(`"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`)
	matches := ipPattern.FindAllStringSubmatch(shodanSSLData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			ip := strings.TrimSpace(match[1])
			if p.isValidIP(ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// extractHostnamesFromShodanSSL extracts hostnames from Shodan SSL results
func (p *Parser) extractHostnamesFromShodanSSL(shodanSSLData string) []string {
	var hostnames []string

	// Look for hostname patterns in JSON-like data
	hostnamePattern := regexp.MustCompile(`"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"`)
	matches := hostnamePattern.FindAllStringSubmatch(shodanSSLData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			hostname := strings.TrimSpace(match[1])
			if p.isValidDomain(hostname) {
				hostnames = append(hostnames, hostname)
			}
		}
	}

	return hostnames
}

// ValidateURLs validates and filters URLs based on open ports
func (p *Parser) ValidateURLs(urls []models.Target, openPorts map[string][]int) []models.Target {
	var validURLs []models.Target

	for _, url := range urls {
		// Extract hostname from URL
		hostname := url.Value
		if strings.HasPrefix(hostname, "http://") || strings.HasPrefix(hostname, "https://") {
			hostname = strings.TrimPrefix(strings.TrimPrefix(hostname, "http://"), "https://")
		}
		if strings.Contains(hostname, "/") {
			hostname = strings.Split(hostname, "/")[0]
		}
		if strings.Contains(hostname, ":") {
			hostname = strings.Split(hostname, ":")[0]
		}

		// Check if this hostname has open ports
		if ports, exists := openPorts[hostname]; exists && len(ports) > 0 {
			// Check if it has web ports (80, 443, 8080, 8443, etc.)
			hasWebPort := false
			webPorts := []int{80, 443, 8080, 8443, 3000, 8000, 8888, 9000}

			for _, port := range ports {
				for _, webPort := range webPorts {
					if port == webPort {
						hasWebPort = true
						break
					}
				}
				if hasWebPort {
					break
				}
			}

			if hasWebPort {
				validURLs = append(validURLs, url)
			}
		}
	}

	return validURLs
}

// ValidateURLsFromDatabase validates URLs using database port information
func (p *Parser) ValidateURLsFromDatabase(urls []models.Target, db *database.Database) []models.Target {
	var validURLs []models.Target

	for _, url := range urls {
		// Extract hostname from URL
		hostname := url.Value
		if strings.HasPrefix(hostname, "http://") || strings.HasPrefix(hostname, "https://") {
			hostname = strings.TrimPrefix(strings.TrimPrefix(hostname, "http://"), "https://")
		}
		if strings.Contains(hostname, "/") {
			hostname = strings.Split(hostname, "/")[0]
		}
		if strings.Contains(hostname, ":") {
			hostname = strings.Split(hostname, ":")[0]
		}

		// Get target from database
		target, err := db.GetTargetByValue(hostname)
		if err == nil {
			// Get ports for this target
			ports, err := db.GetTargetPorts(target.ID)
			if err == nil && len(ports) > 0 {
				// Check if it has web ports
				hasWebPort := false
				webPorts := []int{80, 443, 8080, 8443, 3000, 8000, 8888, 9000}

				for _, port := range ports {
					for _, webPort := range webPorts {
						if port.Port == webPort {
							hasWebPort = true
							break
						}
					}
					if hasWebPort {
						break
					}
				}

				if hasWebPort {
					validURLs = append(validURLs, url)
				}
			}
		}
	}

	return validURLs
}

// ParseSSLDiscoveryResults parses SSL discovery results for new targets
func (p *Parser) ParseSSLDiscoveryResults(results []string) []string {
	var newTargets []string

	for _, result := range results {
		// Extract domains from Certificate Transparency results
		if strings.Contains(result, "CT_DOMAIN:") {
			domains := p.extractDomainsFromCT(result)
			newTargets = append(newTargets, domains...)
		}

		// Extract IPs from Shodan SSL results
		if strings.Contains(result, "SHODAN_SSL_IP:") {
			ips := p.extractIPsFromShodanSSL(result)
			newTargets = append(newTargets, ips...)
		}

		// Extract hostnames from Shodan SSL results
		if strings.Contains(result, "SHODAN_SSL_HOSTNAME:") {
			hostnames := p.extractHostnamesFromShodanSSL(result)
			newTargets = append(newTargets, hostnames...)
		}

		// Extract general domains and IPs from any result
		if strings.Contains(result, ".") {
			// Extract potential domain/IP
			parts := strings.Fields(result)
			for _, part := range parts {
				if strings.Contains(part, ".") && !strings.Contains(part, "://") {
					// Remove any trailing punctuation
					cleanPart := strings.TrimRight(part, ".,;:!")
					if len(cleanPart) > 3 {
						// Check if it's a valid domain or IP
						if p.isValidDomain(cleanPart) || p.isValidIP(cleanPart) {
							newTargets = append(newTargets, cleanPart)
						}
					}
				}
			}
		}
	}

	return p.removeDuplicates(newTargets)
}

// ValidateURLsWithHTTPTest validates URLs using HTTP access test results
func (p *Parser) ValidateURLsWithHTTPTest(urls []models.Target, httpResults map[string]bool) []models.Target {
	var validURLs []models.Target

	for _, url := range urls {
		// Check if URL has HTTP access
		if hasAccess, exists := httpResults[url.Value]; exists && hasAccess {
			validURLs = append(validURLs, url)
		}
	}

	return validURLs
}

// GetSubdomainsFromTargets extracts subdomains from target list
func (p *Parser) GetSubdomainsFromTargets(targets models.TargetList) []string {
	var subdomains []string

	// Extract subdomains from domains
	for _, domain := range targets.Domains {
		// This is a simplified subdomain extraction
		// In a real implementation, you would use subfinder or similar tools
		subdomains = append(subdomains, domain.Value)
	}

	return subdomains
}

// ParseWhoisDiscoveryResults parses whois discovery results for new targets
func (p *Parser) ParseWhoisDiscoveryResults(results []string) []string {
	var newTargets []string

	for _, result := range results {
		// Extract IP ranges from whois results
		if strings.Contains(result, "/") {
			// This is likely a CIDR range
			if p.isValidCIDR(result) {
				newTargets = append(newTargets, result)
			}
		} else if strings.Contains(result, ".") {
			// This might be a single IP or domain
			if p.isValidIP(result) {
				// Convert single IP to /24 range
				if ipRange := p.ipToRange(result); ipRange != "" {
					newTargets = append(newTargets, ipRange)
				}
			} else if p.isValidDomain(result) {
				newTargets = append(newTargets, result)
			}
		}
	}

	return p.removeDuplicates(newTargets)
}

// isValidCIDR checks if a string is a valid CIDR notation
func (p *Parser) isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// ipToRange converts IP to /24 range
func (p *Parser) ipToRange(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return ""
}
