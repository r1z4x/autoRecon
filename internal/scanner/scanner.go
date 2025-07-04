package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Task represents a scanning task
type Task struct {
	ID       string
	Type     string // "port_scan", "ssl_discovery", "subdomain_discovery", "whois_discovery"
	Target   string
	Priority int // Higher number = higher priority
	Data     map[string]interface{}
}

// TaskResult represents the result of a task
type TaskResult struct {
	TaskID   string
	Type     string
	Target   string
	Results  []string
	Error    error
	Duration time.Duration
}

// CentralQueue manages all scanning tasks
type CentralQueue struct {
	tasks   chan Task
	results chan TaskResult
	workers int
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
	stats   *QueueStats
}

// QueueStats tracks queue statistics
type QueueStats struct {
	TotalTasks     int
	CompletedTasks int
	FailedTasks    int
	ActiveWorkers  int
	QueueSize      int
	mu             sync.RWMutex
}

// Scanner struct with enhanced multithreading
type Scanner struct {
	config     *ScannerConfig
	mu         sync.RWMutex
	stats      *ScanStats
	queue      *CentralQueue
	workerPool *WorkerPool
}

// WorkerPool manages worker goroutines
type WorkerPool struct {
	workers    int
	taskQueue  chan Task
	resultChan chan TaskResult
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// ScannerConfig represents scanner configuration
type ScannerConfig struct {
	RateLimit      int
	StatusCodes    []string
	SeverityLevels []string
	DNSXWordlist   string
	ResolverList   string
	CustomHeaders  map[string]string
	UseProxychains bool
	UseNucleiCloud bool
	MaxWorkers     int // Number of concurrent workers
	BatchSize      int // Number of targets per batch
	QueueSize      int // Size of task queue
}

// ScanStats represents scanning statistics
type ScanStats struct {
	TotalTargets     int
	ProcessedTargets int
	FoundResults     int
	Errors           int
	StartTime        time.Time
	mu               sync.RWMutex
}

// ScanResult represents a scan result
type ScanResult struct {
	Results []string
	Error   error
}

// WhoisInfo represents whois information
type WhoisInfo struct {
	Domain      string   `json:"domain"`
	Registrar   string   `json:"registrar"`
	OrgName     string   `json:"org_name"`
	AdminEmail  string   `json:"admin_email"`
	NameServers []string `json:"name_servers"`
	IPRanges    []string `json:"ip_ranges"`
	ASN         string   `json:"asn"`
	Country     string   `json:"country"`
	Created     string   `json:"created"`
	Updated     string   `json:"updated"`
	Expires     string   `json:"expires"`
}

// SSLCertificateInfo represents SSL certificate information
type SSLCertificateInfo struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	Serial      string   `json:"serial"`
	Fingerprint string   `json:"fingerprint"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	ValidFrom   string   `json:"valid_from"`
	ValidUntil  string   `json:"valid_until"`
}

// ASNInfo represents ASN information
type ASNInfo struct {
	ASN         string   `json:"asn"`
	OrgName     string   `json:"org_name"`
	Description string   `json:"description"`
	IPRanges    []string `json:"ip_ranges"`
	Country     string   `json:"country"`
}

// NewScanner creates a new scanner instance
func NewScanner(config *ScannerConfig) *Scanner {
	if config == nil {
		config = &ScannerConfig{
			RateLimit:      100,
			StatusCodes:    []string{"200", "301", "302", "404"},
			SeverityLevels: []string{"high", "medium", "low"},
			MaxWorkers:     10,
			BatchSize:      50,
			QueueSize:      1000,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	scanner := &Scanner{
		config: config,
		stats: &ScanStats{
			StartTime: time.Now(),
		},
		queue: &CentralQueue{
			tasks:   make(chan Task, config.QueueSize),
			results: make(chan TaskResult, config.QueueSize),
			workers: config.MaxWorkers,
			ctx:     ctx,
			cancel:  cancel,
			stats:   &QueueStats{},
		},
		workerPool: &WorkerPool{
			workers:    config.MaxWorkers,
			taskQueue:  make(chan Task, config.QueueSize),
			resultChan: make(chan TaskResult, config.QueueSize),
			ctx:        ctx,
			cancel:     cancel,
		},
	}

	// Start worker pool
	scanner.workerPool.Start()

	// Start result processor
	go scanner.processResults()

	return scanner
}

// GetStats returns current scan statistics
func (s *Scanner) GetStats() *ScanStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	return &ScanStats{
		TotalTargets:     s.stats.TotalTargets,
		ProcessedTargets: s.stats.ProcessedTargets,
		FoundResults:     s.stats.FoundResults,
		Errors:           s.stats.Errors,
		StartTime:        s.stats.StartTime,
	}
}

// GetTotalTargets returns total targets
func (s *ScanStats) GetTotalTargets() int {
	return s.TotalTargets
}

// GetProcessedTargets returns processed targets
func (s *ScanStats) GetProcessedTargets() int {
	return s.ProcessedTargets
}

// GetFoundResults returns found results
func (s *ScanStats) GetFoundResults() int {
	return s.FoundResults
}

// GetErrors returns error count
func (s *ScanStats) GetErrors() int {
	return s.Errors
}

// GetStartTime returns start time
func (s *ScanStats) GetStartTime() time.Time {
	return s.StartTime
}

// UpdateStats updates scan statistics
func (s *Scanner) UpdateStats(processed, found, errors int) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	s.stats.ProcessedTargets += processed
	s.stats.FoundResults += found
	s.stats.Errors += errors
}

// checkTool checks if a tool is available
func (s *Scanner) checkTool(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("tool '%s' not found in PATH. Please install it with: go install -v github.com/projectdiscovery/%s/cmd/%s@latest",
			toolName, toolName, toolName)
	}
	return nil
}

// checkFile checks if a file exists
func (s *Scanner) checkFile(filePath, description string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("%s not found: %s", description, filePath)
	}
	return nil
}

// processBatch processes a batch of targets with multi-threading
func (s *Scanner) processBatch(ctx context.Context, targets []string, workerFunc func(context.Context, string) ScanResult) []ScanResult {
	// Use much more workers for better performance
	maxWorkers := 100 // Increased from 50 to 100
	if s.config.MaxWorkers > 0 {
		maxWorkers = s.config.MaxWorkers
	}

	// Limit workers to batch size but allow more parallelism
	if maxWorkers > len(targets) {
		maxWorkers = len(targets)
	}

	// Ensure minimum workers for small batches
	if maxWorkers < 10 {
		maxWorkers = 10
	}

	// Create channels for work distribution and result collection
	targetChan := make(chan string, len(targets))
	resultChan := make(chan ScanResult, len(targets))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				select {
				case <-ctx.Done():
					return
				default:
					result := workerFunc(ctx, target)
					resultChan <- result
				}
			}
		}()
	}

	// Send targets to workers in parallel
	go func() {
		defer close(targetChan)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case targetChan <- target:
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Gather all results
	var results []ScanResult
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// ScanDomains performs subdomain discovery with multi-threading
func (s *Scanner) ScanDomains(ctx context.Context, domains []string, projectDir string) ([]ScanResult, error) {
	// Check prerequisites
	if err := s.checkTool("subfinder"); err != nil {
		return nil, err
	}
	if err := s.checkTool("dnsx"); err != nil {
		return nil, err
	}
	if err := s.checkFile(s.config.DNSXWordlist, "DNSX wordlist"); err != nil {
		return nil, err
	}
	if err := s.checkFile(s.config.ResolverList, "Resolver list"); err != nil {
		return nil, err
	}

	// Process domains in batches
	var allResults []ScanResult
	for i := 0; i < len(domains); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(domains) {
			end = len(domains)
		}

		batch := domains[i:end]
		results := s.processBatch(ctx, batch, func(ctx context.Context, domain string) ScanResult {
			return s.scanSingleDomain(ctx, domain, projectDir)
		})

		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// scanSingleDomain scans a single domain
func (s *Scanner) scanSingleDomain(ctx context.Context, domain, projectDir string) ScanResult {
	// Run subfinder
	subfinderOutput := filepath.Join(projectDir, "logs", "subfinder", fmt.Sprintf("%s.txt", strings.ReplaceAll(domain, ".", "_")))
	subfinderCmd := exec.CommandContext(ctx, "subfinder",
		"-d", domain,
		"-silent",
		"-o", subfinderOutput,
	)

	if err := subfinderCmd.Run(); err != nil {
		return ScanResult{Error: fmt.Errorf("subfinder failed for %s: %w", domain, err)}
	}

	// Run dnsx for validation
	dnsxOutput := filepath.Join(projectDir, "logs", "subfinder", fmt.Sprintf("%s_dnsx.txt", strings.ReplaceAll(domain, ".", "_")))
	dnsxCmd := exec.CommandContext(ctx, "dnsx",
		"-l", subfinderOutput,
		"-silent",
		"-o", dnsxOutput,
	)

	if err := dnsxCmd.Run(); err != nil {
		return ScanResult{Error: fmt.Errorf("dnsx failed for %s: %w", domain, err)}
	}

	// Read results
	content, err := os.ReadFile(dnsxOutput)
	if err != nil {
		return ScanResult{Error: fmt.Errorf("failed to read dnsx output for %s: %w", domain, err)}
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var results []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			results = append(results, strings.TrimSpace(line))
		}
	}

	return ScanResult{Results: results}
}

// ScanURLs validates URLs with multi-threading
func (s *Scanner) ScanURLs(ctx context.Context, urls []string, projectDir string) ([]ScanResult, error) {
	// Check if httpx is available
	if err := s.checkTool("httpx"); err != nil {
		return nil, err
	}

	// Process URLs in batches
	var allResults []ScanResult
	for i := 0; i < len(urls); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(urls) {
			end = len(urls)
		}

		batch := urls[i:end]
		results := s.processBatch(ctx, batch, func(ctx context.Context, url string) ScanResult {
			return s.scanSingleURL(ctx, url, projectDir)
		})

		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// scanSingleURL scans a single URL
func (s *Scanner) scanSingleURL(ctx context.Context, url, projectDir string) ScanResult {
	// Create URL directory
	urlDir := filepath.Join(projectDir, "urls", strings.ReplaceAll(url, "://", "_"))
	if err := os.MkdirAll(urlDir, 0755); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create URL directory: %w", err)}
	}

	// Create URL list file
	urlListFile := filepath.Join(urlDir, "urls.txt")
	if err := os.WriteFile(urlListFile, []byte(url), 0644); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create URL list file: %w", err)}
	}

	// Run httpx
	httpxOutput := filepath.Join(urlDir, "httpx.txt")
	httpxArgs := []string{
		"-l", urlListFile,
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-o", httpxOutput,
	}

	// Add custom headers
	for key, value := range s.config.CustomHeaders {
		httpxArgs = append(httpxArgs, "-H", fmt.Sprintf("%s: %s", key, value))
	}

	httpxCmd := exec.CommandContext(ctx, "httpx", httpxArgs...)

	if err := httpxCmd.Run(); err != nil {
		return ScanResult{Error: fmt.Errorf("httpx failed for %s: %w", url, err)}
	}

	// Read results
	content, err := os.ReadFile(httpxOutput)
	if err != nil {
		return ScanResult{Error: fmt.Errorf("failed to read httpx output for %s: %w", url, err)}
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var results []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			results = append(results, strings.TrimSpace(line))
		}
	}

	return ScanResult{Results: results}
}

// ScanIPs performs port scanning with multi-threading
func (s *Scanner) ScanIPs(ctx context.Context, ips []string, projectDir string) ([]ScanResult, error) {
	// Check if naabu is available
	if err := s.checkTool("naabu"); err != nil {
		return nil, err
	}

	// Process IPs in batches
	var allResults []ScanResult
	for i := 0; i < len(ips); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]
		results := s.processBatch(ctx, batch, func(ctx context.Context, ip string) ScanResult {
			return s.scanSingleIP(ctx, ip, projectDir)
		})

		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// scanSingleIP scans a single IP
func (s *Scanner) scanSingleIP(ctx context.Context, ip, projectDir string) ScanResult {
	// Create IP directory
	ipDir := filepath.Join(projectDir, "ips", strings.ReplaceAll(ip, ".", "_"))
	if err := os.MkdirAll(ipDir, 0755); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create IP directory: %w", err)}
	}

	// Create IP list file
	ipListFile := filepath.Join(ipDir, "ips.txt")
	if err := os.WriteFile(ipListFile, []byte(ip), 0644); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create IP list file: %w", err)}
	}

	// Run naabu
	naabuOutput := filepath.Join(ipDir, "naabu.txt")
	naabuArgs := []string{
		"-l", ipListFile,
		"-silent",
		"-o", naabuOutput,
	}

	naabuCmd := exec.CommandContext(ctx, "naabu", naabuArgs...)

	if err := naabuCmd.Run(); err != nil {
		return ScanResult{Error: fmt.Errorf("naabu failed for %s: %w", ip, err)}
	}

	// Read results
	content, err := os.ReadFile(naabuOutput)
	if err != nil {
		return ScanResult{Error: fmt.Errorf("failed to read naabu output for %s: %w", ip, err)}
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var results []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			// Convert IP:port to http://IP:port format for vulnerability scanning
			if strings.Contains(line, ":") {
				results = append(results, fmt.Sprintf("http://%s", line))
			} else {
				results = append(results, line)
			}
		}
	}

	return ScanResult{Results: results}
}

// RunVulnerabilityScan runs nuclei vulnerability scan with queue system
func (s *Scanner) RunVulnerabilityScan(ctx context.Context, urls []string, projectDir string) (ScanResult, error) {
	// Check if nuclei is available
	if err := s.checkTool("nuclei"); err != nil {
		return ScanResult{}, err
	}

	// Create vulnerability scan directory
	vulnDir := filepath.Join(projectDir, "vulnerabilities")
	if err := os.MkdirAll(vulnDir, 0755); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create vulnerability directory: %w", err)}, nil
	}

	// Update total targets for vulnerability scan
	s.stats.mu.Lock()
	s.stats.TotalTargets += len(urls)
	s.stats.mu.Unlock()

	// Process URLs in batches for vulnerability scanning
	var allResults []string
	for i := 0; i < len(urls); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(urls) {
			end = len(urls)
		}

		batch := urls[i:end]
		batchResults := s.scanVulnerabilityBatch(ctx, batch, vulnDir, i/s.config.BatchSize)
		allResults = append(allResults, batchResults...)

		// Update stats after each batch
		s.UpdateStats(len(batch), len(batchResults), 0)
	}

	return ScanResult{Results: allResults}, nil
}

// scanVulnerabilityBatch scans a batch of URLs for vulnerabilities
func (s *Scanner) scanVulnerabilityBatch(ctx context.Context, urls []string, vulnDir string, batchNum int) []string {
	// Create batch-specific output file
	batchOutput := filepath.Join(vulnDir, fmt.Sprintf("nuclei_batch_%d.txt", batchNum))

	// Create URL list file for this batch
	urlListFile := filepath.Join(vulnDir, fmt.Sprintf("urls_batch_%d.txt", batchNum))
	urlContent := strings.Join(urls, "\n")
	if err := os.WriteFile(urlListFile, []byte(urlContent), 0644); err != nil {
		return nil
	}

	// Run nuclei
	nucleiArgs := []string{
		"-l", urlListFile,
		"-silent",
		"-o", batchOutput,
	}

	// Add severity levels if specified
	if len(s.config.SeverityLevels) > 0 {
		nucleiArgs = append(nucleiArgs, "-severity", strings.Join(s.config.SeverityLevels, ","))
	}

	// Add rate limit
	if s.config.RateLimit > 0 {
		nucleiArgs = append(nucleiArgs, "-rate-limit", fmt.Sprintf("%d", s.config.RateLimit))
	}

	nucleiCmd := exec.CommandContext(ctx, "nuclei", nucleiArgs...)

	if err := nucleiCmd.Run(); err != nil {
		return nil
	}

	// Read results
	content, err := os.ReadFile(batchOutput)
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var results []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			results = append(results, strings.TrimSpace(line))
		}
	}

	// Clean up temporary files
	os.Remove(urlListFile)

	return results
}

// GetScanProgress returns current scan progress
func (s *Scanner) GetScanProgress() float64 {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	if s.stats.TotalTargets == 0 {
		return 0.0
	}

	return float64(s.stats.ProcessedTargets) / float64(s.stats.TotalTargets)
}

// StopScan stops the current scan
func (s *Scanner) StopScan() error {
	// This is a simplified implementation
	// In a real implementation, you would cancel running processes
	return nil
}

// EnhancedScanTarget performs comprehensive scanning on a target
func (s *Scanner) EnhancedScanTarget(ctx context.Context, target string, projectDir string) (ScanResult, error) {
	// Create target directory
	targetDir := filepath.Join(projectDir, "targets", strings.ReplaceAll(target, ".", "_"))
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create target directory: %w", err)}, nil
	}

	var allResults []string

	// Step 1: Port scanning with Naabu
	naabuResults, err := s.runNaabuScan(ctx, target, targetDir)
	if err != nil {
		return ScanResult{Error: fmt.Errorf("naabu scan failed: %w", err)}, nil
	}
	allResults = append(allResults, naabuResults...)

	// Step 2: ASN-based target discovery
	asnTargets, err := s.DiscoverTargetsFromASN(ctx, target, targetDir)
	if err == nil && len(asnTargets) > 0 {
		// Add discovered targets to results
		for _, asnTarget := range asnTargets {
			allResults = append(allResults, fmt.Sprintf("ASN_DISCOVERED: %s", asnTarget))
		}
	}

	// Step 3: SSL certificate scanning
	sslResults, err := s.runSSLScan(ctx, target, targetDir)
	if err == nil {
		allResults = append(allResults, sslResults...)
	}

	// Step 4: Shodan data collection
	shodanResults, err := s.runShodanScan(ctx, target, targetDir)
	if err == nil {
		allResults = append(allResults, shodanResults...)
	}

	return ScanResult{Results: allResults}, nil
}

// runNaabuScan performs comprehensive port scanning using naabu
func (s *Scanner) runNaabuScan(ctx context.Context, target, targetDir string) ([]string, error) {
	// Check if naabu is available
	if err := s.checkTool("naabu"); err != nil {
		return nil, fmt.Errorf("naabu not found: %w", err)
	}

	// Create naabu output file
	naabuOutput := filepath.Join(targetDir, "naabu.txt")
	naabuArgs := []string{
		"-host", target,
		"-silent",
		"-o", naabuOutput,
	}

	naabuCmd := exec.CommandContext(ctx, "naabu", naabuArgs...)
	if err := naabuCmd.Run(); err != nil {
		return nil, fmt.Errorf("naabu failed: %w", err)
	}

	// Parse naabu output and extract results
	results, err := s.parseNaabuOutput(naabuOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse naabu output: %w", err)
	}

	return results, nil
}

// runSSLScan performs SSL certificate scanning
func (s *Scanner) runSSLScan(ctx context.Context, target, targetDir string) ([]string, error) {
	// Check if openssl is available
	if err := s.checkTool("openssl"); err != nil {
		return nil, fmt.Errorf("openssl not found: %w", err)
	}

	var results []string

	// Common SSL ports to check
	sslPorts := []string{"443", "8443", "9443", "2083", "2087", "2096", "8080", "8888"}

	for _, port := range sslPorts {
		// Test SSL connection
		sslCmd := exec.CommandContext(ctx, "openssl", "s_client", "-connect", fmt.Sprintf("%s:%s", target, port), "-servername", target, "-verify_return_error")
		sslCmd.Stdin = strings.NewReader("Q\n") // Send quit command

		output, err := sslCmd.CombinedOutput()
		if err == nil {
			// Extract certificate information
			certInfo := s.extractCertificateInfo(string(output))
			if certInfo != "" {
				results = append(results, fmt.Sprintf("SSL[%s]: %s", port, certInfo))
			}
		}
	}

	return results, nil
}

// runShodanScan collects data from Shodan (if API key is available)
func (s *Scanner) runShodanScan(ctx context.Context, target, targetDir string) ([]string, error) {
	// Check if shodan CLI is available
	if err := s.checkTool("shodan"); err != nil {
		return nil, fmt.Errorf("shodan CLI not found: %w", err)
	}

	// Create shodan output file
	shodanOutput := filepath.Join(targetDir, "shodan.json")
	shodanArgs := []string{
		"host", target,
		"--format", "json",
		"-o", shodanOutput,
	}

	shodanCmd := exec.CommandContext(ctx, "shodan", shodanArgs...)
	if err := shodanCmd.Run(); err != nil {
		return nil, fmt.Errorf("shodan scan failed: %w", err)
	}

	// Read and parse results
	content, err := os.ReadFile(shodanOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to read shodan output: %w", err)
	}

	// Parse JSON and extract relevant information
	results, err := s.parseShodanJSON(string(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse shodan output: %w", err)
	}

	return results, nil
}

// extractCertificateInfo extracts SSL certificate information
func (s *Scanner) extractCertificateInfo(output string) string {
	lines := strings.Split(output, "\n")
	var certInfo []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "subject=") {
			certInfo = append(certInfo, fmt.Sprintf("Subject: %s", line))
		}
		if strings.Contains(line, "issuer=") {
			certInfo = append(certInfo, fmt.Sprintf("Issuer: %s", line))
		}
		if strings.Contains(line, "DNS:") {
			certInfo = append(certInfo, fmt.Sprintf("DNS: %s", line))
		}
	}

	if len(certInfo) > 0 {
		return strings.Join(certInfo, " | ")
	}
	return ""
}

// parseShodanJSON parses Shodan JSON output
func (s *Scanner) parseShodanJSON(jsonData string) ([]string, error) {
	// Simple parsing - in production, use proper JSON parsing
	lines := strings.Split(jsonData, "\n")
	var results []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"port\"") {
			results = append(results, fmt.Sprintf("SHODAN_PORT: %s", line))
		}
		if strings.Contains(line, "\"hostnames\"") {
			results = append(results, fmt.Sprintf("SHODAN_HOSTNAME: %s", line))
		}
		if strings.Contains(line, "\"data\"") {
			results = append(results, fmt.Sprintf("SHODAN_DATA: %s", line))
		}
	}

	return results, nil
}

// GetBatchSize returns the batch size configuration
func (s *Scanner) GetBatchSize() int {
	return s.config.BatchSize
}

// GetMaxWorkers returns the max workers configuration
func (s *Scanner) GetMaxWorkers() int {
	return s.config.MaxWorkers
}

// SSLCertificateDiscovery performs SSL certificate discovery
func (s *Scanner) ScanSSLDiscovery(ctx context.Context, targets []string, projectDir string) ([]string, error) {
	var allResults []string

	// Create SSL discovery directory
	sslDir := filepath.Join(projectDir, "logs", "ssl_discovery")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create SSL discovery directory: %w", err)
	}

	for _, target := range targets {
		// Extract SSL certificate information
		certInfo, err := s.extractSSLCertificateInfo(ctx, target)
		if err != nil {
			// Log the error but continue with other targets
			errorLog := filepath.Join(sslDir, fmt.Sprintf("%s_error.log", strings.ReplaceAll(target, ".", "_")))
			os.WriteFile(errorLog, []byte(fmt.Sprintf("SSL extraction failed: %v", err)), 0644)
			continue
		}

		// Save certificate info to file
		certFile := filepath.Join(sslDir, fmt.Sprintf("%s_cert.json", strings.ReplaceAll(target, ".", "_")))
		if certData, err := json.MarshalIndent(certInfo, "", "  "); err == nil {
			os.WriteFile(certFile, certData, 0644)
		}

		// Add DNS names from certificate to results
		for _, dnsName := range certInfo.DNSNames {
			if dnsName != "" && dnsName != target {
				allResults = append(allResults, dnsName)
			}
		}

		// Add IP addresses from certificate to results
		for _, ip := range certInfo.IPAddresses {
			if ip != "" {
				allResults = append(allResults, ip)
			}
		}

		// Try to find related targets using certificate fingerprint
		if certInfo.Fingerprint != "" {
			// Search for targets with similar certificate patterns
			relatedTargets := s.searchRelatedTargetsByCertificate(ctx, certInfo, sslDir)
			allResults = append(allResults, relatedTargets...)
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return allResults, ctx.Err()
		default:
		}
	}

	return s.removeDuplicateTargets(allResults), nil
}

// searchRelatedTargetsByCertificate searches for targets with similar certificates
func (s *Scanner) searchRelatedTargetsByCertificate(ctx context.Context, certInfo *SSLCertificateInfo, sslDir string) []string {
	var results []string

	// Method 1: Search by issuer
	if certInfo.Issuer != "" {
		// Look for common patterns in issuer
		issuerPatterns := []string{"Let's Encrypt", "DigiCert", "Comodo", "GlobalSign", "GoDaddy", "Sectigo"}
		for _, pattern := range issuerPatterns {
			if strings.Contains(certInfo.Issuer, pattern) {
				// This could indicate similar certificate patterns
				// For now, we'll just log this information
				logFile := filepath.Join(sslDir, "issuer_patterns.log")
				logEntry := fmt.Sprintf("Target with %s issuer: %s\n", pattern, certInfo.Subject)
				os.WriteFile(logFile, []byte(logEntry), 0644)
			}
		}
	}

	// Method 2: Search by subject patterns
	if certInfo.Subject != "" {
		// Extract domain from subject
		domain := certInfo.Subject
		if strings.Contains(domain, ".") {
			// Try to find related subdomains
			parts := strings.Split(domain, ".")
			if len(parts) >= 2 {
				baseDomain := strings.Join(parts[len(parts)-2:], ".")
				// Add common subdomain patterns
				commonSubdomains := []string{"www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "dns", "web", "api", "admin", "portal", "app", "dev", "test", "staging", "prod", "cdn", "static", "media", "blog", "forum", "shop", "store", "support", "help", "docs", "wiki"}
				for _, subdomain := range commonSubdomains {
					results = append(results, subdomain+"."+baseDomain)
				}
			}
		}
	}

	return results
}

// removeDuplicateTargets removes duplicate targets
func (s *Scanner) removeDuplicateTargets(targets []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, target := range targets {
		if !seen[target] {
			seen[target] = true
			result = append(result, target)
		}
	}

	return result
}

// extractSSLCertificateInfo extracts SSL certificate information from a target
func (s *Scanner) extractSSLCertificateInfo(ctx context.Context, target string) (*SSLCertificateInfo, error) {
	certInfo := &SSLCertificateInfo{}

	// Common SSL ports to try
	sslPorts := []string{"443", "8443", "9443", "9444", "9445", "9446", "9447", "9448", "9449", "9450"}

	for _, port := range sslPorts {
		// Try to connect and get SSL certificate
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", target+":"+port, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			continue // Try next port
		}
		defer conn.Close()

		// Get certificate
		if len(conn.ConnectionState().PeerCertificates) == 0 {
			continue // No certificate found
		}

		cert := conn.ConnectionState().PeerCertificates[0]

		// Extract certificate information
		certInfo.Subject = cert.Subject.CommonName
		certInfo.Issuer = cert.Issuer.CommonName
		certInfo.Serial = cert.SerialNumber.String()
		certInfo.Fingerprint = fmt.Sprintf("%x", cert.Signature)
		certInfo.DNSNames = cert.DNSNames
		certInfo.ValidFrom = cert.NotBefore.Format("2006-01-02")
		certInfo.ValidUntil = cert.NotAfter.Format("2006-01-02")

		// Extract IP addresses from certificate
		for _, ip := range cert.IPAddresses {
			certInfo.IPAddresses = append(certInfo.IPAddresses, ip.String())
		}

		// Found a valid certificate, return it
		return certInfo, nil
	}

	return nil, fmt.Errorf("no valid SSL certificate found for %s on any port", target)
}

// ScanAllTargets performs comprehensive scanning on all targets
func (s *Scanner) ScanAllTargets(ctx context.Context, targets []string, projectDir string) ([]ScanResult, error) {
	// Check if naabu is available
	if err := s.checkTool("naabu"); err != nil {
		return nil, err
	}

	// Use much larger batch size for better performance
	batchSize := 500 // Increased from 100 to 500
	if s.config.BatchSize > 0 {
		batchSize = s.config.BatchSize
	}

	// Process targets in larger batches with parallel processing
	var allResults []ScanResult

	// Create a semaphore to limit concurrent batch processing
	semaphore := make(chan struct{}, 5) // Allow 5 concurrent batches
	var wg sync.WaitGroup
	resultChan := make(chan []ScanResult, len(targets)/batchSize+1)

	for i := 0; i < len(targets); i += batchSize {
		end := i + batchSize
		if end > len(targets) {
			end = len(targets)
		}

		batch := targets[i:end]
		wg.Add(1)

		go func(batchTargets []string, batchNum int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			results := s.processBatch(ctx, batchTargets, func(ctx context.Context, target string) ScanResult {
				return s.scanSingleTargetForPorts(ctx, target, projectDir)
			})

			resultChan <- results
		}(batch, i/batchSize)
	}

	// Wait for all batches to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect all results
	for results := range resultChan {
		allResults = append(allResults, results...)
		// Update stats
		s.UpdateStats(len(results), len(results), 0)
	}

	return allResults, nil
}

// scanSingleTargetForPorts scans a single target (domain, URL, or IP) for open ports
func (s *Scanner) scanSingleTargetForPorts(ctx context.Context, target, projectDir string) ScanResult {
	// Create target directory
	targetDir := filepath.Join(projectDir, "logs", "naabu", strings.ReplaceAll(target, ".", "_"))
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create target directory: %w", err)}
	}

	// Create target list file
	targetListFile := filepath.Join(targetDir, "targets.txt")
	if err := os.WriteFile(targetListFile, []byte(target), 0644); err != nil {
		return ScanResult{Error: fmt.Errorf("failed to create target list file: %w", err)}
	}

	// Run naabu with optimized settings for speed
	naabuOutput := filepath.Join(targetDir, "naabu.txt")
	naabuArgs := []string{
		"-l", targetListFile,
		"-silent",
		"-o", naabuOutput,
		"-rate-limit", "1000", // High rate limit
		"-c", "100", // High concurrency
		"-timeout", "5", // Short timeout
		"-retries", "2", // Few retries for speed
		"-warm-up-time", "1", // Short warm-up
	}

	naabuCmd := exec.CommandContext(ctx, "naabu", naabuArgs...)
	if err := naabuCmd.Run(); err != nil {
		return ScanResult{Error: fmt.Errorf("naabu failed for %s: %w", target, err)}
	}

	// Read results
	content, err := os.ReadFile(naabuOutput)
	if err != nil {
		return ScanResult{Error: fmt.Errorf("failed to read naabu output for %s: %w", target, err)}
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var results []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			// Convert IP:port to http://IP:port format for vulnerability scanning
			if strings.Contains(line, ":") {
				results = append(results, fmt.Sprintf("NAABU: http://%s", line))
			} else {
				results = append(results, fmt.Sprintf("NAABU: %s", line))
			}
		}
	}

	return ScanResult{Results: results}
}

// TestHTTPAccess tests HTTP/HTTPS access to URLs
func (s *Scanner) TestHTTPAccess(ctx context.Context, urls []string, projectDir string) map[string]bool {
	accessResults := make(map[string]bool)

	for _, url := range urls {
		// Test HTTP access
		httpURL := url
		if !strings.HasPrefix(httpURL, "http://") && !strings.HasPrefix(httpURL, "https://") {
			httpURL = "http://" + httpURL
		}

		// Simple HTTP test - you might want to enhance this with proper HTTP client
		// For now, we'll just check if the URL has a valid format
		hasWebPort := false

		// Extract hostname and check if it has web ports in database
		hostname := httpURL
		if strings.HasPrefix(hostname, "http://") || strings.HasPrefix(hostname, "https://") {
			hostname = strings.TrimPrefix(strings.TrimPrefix(hostname, "http://"), "https://")
		}
		if strings.Contains(hostname, "/") {
			hostname = strings.Split(hostname, "/")[0]
		}
		if strings.Contains(hostname, ":") {
			hostname = strings.Split(hostname, ":")[0]
		}

		// Check if hostname has web ports (this would be enhanced with actual HTTP testing)
		webPorts := []int{80, 443, 8080, 8443, 3000, 8000, 8888, 9000}
		for _, port := range webPorts {
			if strings.Contains(hostname, fmt.Sprintf(":%d", port)) {
				hasWebPort = true
				break
			}
		}

		accessResults[url] = hasWebPort

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return accessResults
		default:
		}
	}

	return accessResults
}

// ScanSubdomains performs subdomain discovery using subfinder + amass + dnsx
func (s *Scanner) ScanSubdomains(ctx context.Context, domains []string, projectDir string) ([]string, error) {
	var allSubdomains []string

	// Create subfinder directory
	subfinderDir := filepath.Join(projectDir, "logs", "subdomain_discovery")
	if err := os.MkdirAll(subfinderDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create subfinder directory: %w", err)
	}

	for _, domain := range domains {
		// Method 1: Run subfinder
		subfinderOutput := filepath.Join(subfinderDir, fmt.Sprintf("%s_subfinder.txt", strings.ReplaceAll(domain, ".", "_")))
		subfinderCmd := exec.CommandContext(ctx, "subfinder",
			"-d", domain,
			"-silent",
			"-o", subfinderOutput,
		)

		if err := subfinderCmd.Run(); err == nil {
			// Read subfinder results
			if content, err := os.ReadFile(subfinderOutput); err == nil {
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						allSubdomains = append(allSubdomains, strings.TrimSpace(line))
					}
				}
			}
		}

		// Method 2: Run amass (if available)
		if err := s.checkTool("amass"); err == nil {
			amassOutput := filepath.Join(subfinderDir, fmt.Sprintf("%s_amass.txt", strings.ReplaceAll(domain, ".", "_")))
			amassCmd := exec.CommandContext(ctx, "amass", "enum",
				"-d", domain,
				"-passive",
				"-brute",                                                            // Add brute force
				"-w", "/opt/Seclists/Discovery/DNS/subdomains-top1million-5000.txt", // Use wordlist
				"-o", amassOutput)

			if err := amassCmd.Run(); err == nil {
				// Read amass results
				if content, err := os.ReadFile(amassOutput); err == nil {
					lines := strings.Split(strings.TrimSpace(string(content)), "\n")
					for _, line := range lines {
						if strings.TrimSpace(line) != "" {
							allSubdomains = append(allSubdomains, strings.TrimSpace(line))
						}
					}
				}
			}
		}

		// Method 3: Run dnsx for validation
		if err := s.checkTool("dnsx"); err == nil {
			// Create temporary file with discovered subdomains
			tempFile := filepath.Join(subfinderDir, fmt.Sprintf("%s_temp.txt", strings.ReplaceAll(domain, ".", "_")))
			if len(allSubdomains) > 0 {
				content := strings.Join(allSubdomains, "\n")
				os.WriteFile(tempFile, []byte(content), 0644)

				dnsxOutput := filepath.Join(subfinderDir, fmt.Sprintf("%s_dnsx.txt", strings.ReplaceAll(domain, ".", "_")))
				dnsxCmd := exec.CommandContext(ctx, "dnsx",
					"-l", tempFile,
					"-silent",
					"-o", dnsxOutput)

				if err := dnsxCmd.Run(); err == nil {
					// Read validated results from dnsx
					if content, err := os.ReadFile(dnsxOutput); err == nil {
						lines := strings.Split(strings.TrimSpace(string(content)), "\n")
						allSubdomains = nil // Reset and use only validated results
						for _, line := range lines {
							if strings.TrimSpace(line) != "" {
								allSubdomains = append(allSubdomains, strings.TrimSpace(line))
							}
						}
					}
				}

				// Clean up temp file
				os.Remove(tempFile)
			}
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return allSubdomains, ctx.Err()
		default:
		}
	}

	return s.removeDuplicateSubdomains(allSubdomains), nil
}

// removeDuplicateSubdomains removes duplicate subdomains
func (s *Scanner) removeDuplicateSubdomains(subdomains []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, subdomain := range subdomains {
		if !seen[subdomain] {
			seen[subdomain] = true
			result = append(result, subdomain)
		}
	}

	return result
}

// ScanWhoisDiscovery performs whois-based IP range discovery
func (s *Scanner) ScanWhoisDiscovery(ctx context.Context, domains []string, projectDir string) ([]string, error) {
	var allIPRanges []string

	// Create whois directory
	whoisDir := filepath.Join(projectDir, "logs", "whois_discovery")
	if err := os.MkdirAll(whoisDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create whois directory: %w", err)
	}

	for _, domain := range domains {
		// Get whois information
		whoisInfo, err := s.getWhoisInfo(ctx, domain)
		if err != nil {
			// Log error but continue
			errorLog := filepath.Join(whoisDir, fmt.Sprintf("%s_error.log", strings.ReplaceAll(domain, ".", "_")))
			os.WriteFile(errorLog, []byte(fmt.Sprintf("Whois failed: %v", err)), 0644)
			continue
		}

		// Save whois info to file
		whoisFile := filepath.Join(whoisDir, fmt.Sprintf("%s_whois.json", strings.ReplaceAll(domain, ".", "_")))
		if whoisData, err := json.MarshalIndent(whoisInfo, "", "  "); err == nil {
			os.WriteFile(whoisFile, whoisData, 0644)
		}

		// Extract IP ranges from whois info
		if len(whoisInfo.IPRanges) > 0 {
			allIPRanges = append(allIPRanges, whoisInfo.IPRanges...)
		}

		// Search for related IP ranges based on organization name
		if whoisInfo.OrgName != "" {
			relatedRanges, err := s.searchRelatedIPRanges(ctx, whoisInfo.OrgName, whoisDir)
			if err == nil {
				allIPRanges = append(allIPRanges, relatedRanges...)
			}
		}

		// Search for related IP ranges based on ASN
		if whoisInfo.ASN != "" {
			asnRanges, err := s.searchASNIPRanges(ctx, whoisInfo.ASN, whoisDir)
			if err == nil {
				allIPRanges = append(allIPRanges, asnRanges...)
			}
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return allIPRanges, ctx.Err()
		default:
		}
	}

	return s.removeDuplicateRanges(allIPRanges), nil
}

// getWhoisInfo retrieves whois information for a domain
func (s *Scanner) getWhoisInfo(ctx context.Context, domain string) (*WhoisInfo, error) {
	// Use whois command
	cmd := exec.CommandContext(ctx, "whois", domain)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("whois command failed: %w", err)
	}

	whoisInfo := &WhoisInfo{
		Domain: domain,
	}

	// Parse whois output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse different whois fields
		if strings.HasPrefix(strings.ToLower(line), "registrar:") {
			whoisInfo.Registrar = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "organization:") {
			whoisInfo.OrgName = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "org-name:") {
			whoisInfo.OrgName = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "admin-email:") {
			whoisInfo.AdminEmail = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "nserver:") {
			ns := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			whoisInfo.NameServers = append(whoisInfo.NameServers, ns)
		} else if strings.HasPrefix(strings.ToLower(line), "origin:") {
			whoisInfo.ASN = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "country:") {
			whoisInfo.Country = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "created:") {
			whoisInfo.Created = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "updated:") {
			whoisInfo.Updated = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "expires:") {
			whoisInfo.Expires = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	return whoisInfo, nil
}

// searchRelatedIPRanges searches for IP ranges related to organization name
func (s *Scanner) searchRelatedIPRanges(ctx context.Context, orgName, whoisDir string) ([]string, error) {
	var ranges []string

	// Search using various methods
	// 1. Search in RIPE database
	if ripeRanges, err := s.searchRIPEForOrg(ctx, orgName); err == nil {
		ranges = append(ranges, ripeRanges...)
	}

	// 2. Search in ARIN database
	if arinRanges, err := s.searchARINForOrg(ctx, orgName); err == nil {
		ranges = append(ranges, arinRanges...)
	}

	// 3. Search using Shodan
	if shodanRanges, err := s.searchShodanForOrg(ctx, orgName); err == nil {
		ranges = append(ranges, shodanRanges...)
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ranges, ctx.Err()
	default:
	}

	return ranges, nil
}

// searchASNIPRanges searches for IP ranges belonging to an ASN
func (s *Scanner) searchASNIPRanges(ctx context.Context, asn, whoisDir string) ([]string, error) {
	var ranges []string

	// Remove "AS" prefix if present
	asn = strings.TrimPrefix(asn, "AS")
	asn = strings.TrimPrefix(asn, "as")

	// Search using various methods
	// 1. Search in RIPE database
	if ripeRanges, err := s.searchRIPEForASN(ctx, asn); err == nil {
		ranges = append(ranges, ripeRanges...)
	}

	// 2. Search in ARIN database
	if arinRanges, err := s.searchARINForASN(ctx, asn); err == nil {
		ranges = append(ranges, arinRanges...)
	}

	// 3. Search using Shodan
	if shodanRanges, err := s.searchShodanForASN(ctx, asn); err == nil {
		ranges = append(ranges, shodanRanges...)
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ranges, ctx.Err()
	default:
	}

	return ranges, nil
}

// searchRIPEForOrg searches RIPE database for organization
func (s *Scanner) searchRIPEForOrg(ctx context.Context, orgName string) ([]string, error) {
	var ranges []string

	// Use whois to search RIPE database
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.ripe.net", orgName)
	output, err := cmd.Output()
	if err == nil {
		// Parse RIPE output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// searchARINForOrg searches ARIN database for organization
func (s *Scanner) searchARINForOrg(ctx context.Context, orgName string) ([]string, error) {
	var ranges []string

	// Use whois to search ARIN database
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.arin.net", orgName)
	output, err := cmd.Output()
	if err == nil {
		// Parse ARIN output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// searchShodanForOrg searches Shodan for organization
func (s *Scanner) searchShodanForOrg(ctx context.Context, orgName string) ([]string, error) {
	var ranges []string

	// Check if shodan CLI is available
	if err := s.checkTool("shodan"); err != nil {
		return ranges, fmt.Errorf("shodan CLI not found: %w", err)
	}

	// Search Shodan for organization
	cmd := exec.CommandContext(ctx, "shodan", "search",
		fmt.Sprintf("org:\"%s\"", orgName),
		"--format", "json")

	output, err := cmd.Output()
	if err == nil {
		// Parse Shodan results for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "\"ip_str\"") {
				// Extract IP from JSON
				if ip := s.extractIPFromJSON(line); ip != "" {
					// Convert IP to /24 range
					if ipRange := s.ipToRange(ip); ipRange != "" {
						ranges = append(ranges, ipRange)
					}
				}
			}
		}
	}

	return ranges, nil
}

// searchRIPEForASN searches RIPE database for ASN
func (s *Scanner) searchRIPEForASN(ctx context.Context, asn string) ([]string, error) {
	var ranges []string

	// Use whois to search RIPE database for ASN
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.ripe.net", fmt.Sprintf("AS%s", asn))
	output, err := cmd.Output()
	if err == nil {
		// Parse RIPE output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// searchARINForASN searches ARIN database for ASN
func (s *Scanner) searchARINForASN(ctx context.Context, asn string) ([]string, error) {
	var ranges []string

	// Use whois to search ARIN database for ASN
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.arin.net", fmt.Sprintf("AS%s", asn))
	output, err := cmd.Output()
	if err == nil {
		// Parse ARIN output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// searchShodanForASN searches Shodan for ASN
func (s *Scanner) searchShodanForASN(ctx context.Context, asn string) ([]string, error) {
	var ranges []string

	// Check if shodan CLI is available
	if err := s.checkTool("shodan"); err != nil {
		return ranges, fmt.Errorf("shodan CLI not found: %w", err)
	}

	// Search Shodan for ASN
	cmd := exec.CommandContext(ctx, "shodan", "search",
		fmt.Sprintf("asn:AS%s", asn),
		"--format", "json")

	output, err := cmd.Output()
	if err == nil {
		// Parse Shodan results for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "\"ip_str\"") {
				// Extract IP from JSON
				if ip := s.extractIPFromJSON(line); ip != "" {
					// Convert IP to /24 range
					if ipRange := s.ipToRange(ip); ipRange != "" {
						ranges = append(ranges, ipRange)
					}
				}
			}
		}
	}

	return ranges, nil
}

// extractIPFromJSON extracts IP address from JSON line
func (s *Scanner) extractIPFromJSON(jsonLine string) string {
	// Simple IP extraction from JSON
	ipPattern := regexp.MustCompile(`"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`)
	matches := ipPattern.FindStringSubmatch(jsonLine)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ipToRange converts IP to /24 range
func (s *Scanner) ipToRange(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
	}
	return ""
}

// removeDuplicateRanges removes duplicate IP ranges
func (s *Scanner) removeDuplicateRanges(ranges []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, r := range ranges {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}

	return result
}

// Start starts the worker pool
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
	wp.cancel()
	wp.wg.Wait()
}

// worker is a worker goroutine that processes tasks
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case task := <-wp.taskQueue:
			start := time.Now()
			result := wp.processTask(task)
			result.Duration = time.Since(start)
			wp.resultChan <- result
		case <-wp.ctx.Done():
			return
		}
	}
}

// processTask processes a single task
func (wp *WorkerPool) processTask(task Task) TaskResult {
	result := TaskResult{
		TaskID: task.ID,
		Type:   task.Type,
		Target: task.Target,
	}

	switch task.Type {
	case "port_scan":
		results, err := wp.scanPorts(task.Target, task.Data)
		result.Results = results
		result.Error = err
	case "ssl_discovery":
		results, err := wp.scanSSL(task.Target, task.Data)
		result.Results = results
		result.Error = err
	case "subdomain_discovery":
		results, err := wp.scanSubdomains(task.Target, task.Data)
		result.Results = results
		result.Error = err
	case "whois_discovery":
		results, err := wp.scanWhois(task.Target, task.Data)
		result.Results = results
		result.Error = err
	default:
		result.Error = fmt.Errorf("unknown task type: %s", task.Type)
	}

	return result
}

// scanPorts performs port scanning
func (wp *WorkerPool) scanPorts(target string, data map[string]interface{}) ([]string, error) {
	projectDir, ok := data["project_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("project_dir not provided")
	}

	// Create target directory
	targetDir := filepath.Join(projectDir, "logs", "port_scan", strings.ReplaceAll(target, ".", "_"))
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create target directory: %w", err)
	}

	// Create target list file
	targetListFile := filepath.Join(targetDir, "targets.txt")
	if err := os.WriteFile(targetListFile, []byte(target), 0644); err != nil {
		return nil, fmt.Errorf("failed to create target list file: %w", err)
	}

	// Run naabu
	naabuOutput := filepath.Join(targetDir, "naabu.txt")
	naabuArgs := []string{
		"-l", targetListFile,
		"-silent",
		"-o", naabuOutput,
	}

	cmd := exec.CommandContext(wp.ctx, "naabu", naabuArgs...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("naabu failed for %s: %w", target, err)
	}

	// Read results
	content, err := os.ReadFile(naabuOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to read naabu output for %s: %w", target, err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var results []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			results = append(results, strings.TrimSpace(line))
		}
	}

	return results, nil
}

// scanSSL performs SSL discovery
func (wp *WorkerPool) scanSSL(target string, data map[string]interface{}) ([]string, error) {
	var results []string

	// Extract SSL certificate information
	certInfo, err := wp.extractSSLCertificateInfo(target)
	if err != nil {
		// Even if SSL fails, return empty results
		return results, nil // Continue with other targets
	}

	// Add DNS names from certificate to results
	for _, dnsName := range certInfo.DNSNames {
		if dnsName != "" && dnsName != target {
			results = append(results, dnsName)
		}
	}

	// Add IP addresses from certificate to results
	for _, ip := range certInfo.IPAddresses {
		if ip != "" {
			results = append(results, ip)
		}
	}

	// Try to find related targets using certificate fingerprint
	if certInfo.Fingerprint != "" {
		relatedTargets := wp.searchRelatedTargetsByCertificate(certInfo)
		results = append(results, relatedTargets...)
	}

	return results, nil
}

// scanSubdomains performs subdomain discovery
func (wp *WorkerPool) scanSubdomains(target string, data map[string]interface{}) ([]string, error) {
	projectDir, ok := data["project_dir"].(string)
	if !ok {
		return nil, fmt.Errorf("project_dir not provided")
	}

	var allSubdomains []string

	// Create subfinder directory
	subfinderDir := filepath.Join(projectDir, "logs", "subdomain_discovery")
	if err := os.MkdirAll(subfinderDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create subfinder directory: %w", err)
	}

	// Method 1: Run subfinder with more comprehensive settings
	subfinderOutput := filepath.Join(subfinderDir, fmt.Sprintf("%s_subfinder.txt", strings.ReplaceAll(target, ".", "_")))
	subfinderCmd := exec.CommandContext(wp.ctx, "subfinder",
		"-d", target,
		"-silent",
		"-all", // Use all sources
		"-o", subfinderOutput,
	)

	if err := subfinderCmd.Run(); err == nil {
		// Read subfinder results
		if content, err := os.ReadFile(subfinderOutput); err == nil {
			lines := strings.Split(strings.TrimSpace(string(content)), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					allSubdomains = append(allSubdomains, strings.TrimSpace(line))
				}
			}
		}
	}

	// Method 2: Run amass with more comprehensive settings
	if err := wp.checkTool("amass"); err == nil {
		amassOutput := filepath.Join(subfinderDir, fmt.Sprintf("%s_amass.txt", strings.ReplaceAll(target, ".", "_")))
		amassCmd := exec.CommandContext(wp.ctx, "amass", "enum",
			"-d", target,
			"-passive",
			"-brute",                                                            // Add brute force
			"-w", "/opt/Seclists/Discovery/DNS/subdomains-top1million-5000.txt", // Use wordlist
			"-o", amassOutput)

		if err := amassCmd.Run(); err == nil {
			// Read amass results
			if content, err := os.ReadFile(amassOutput); err == nil {
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						allSubdomains = append(allSubdomains, strings.TrimSpace(line))
					}
				}
			}
		}
	}

	// Method 3: Run dnsx for validation
	if err := wp.checkTool("dnsx"); err == nil {
		// Create temporary file with discovered subdomains
		tempFile := filepath.Join(subfinderDir, fmt.Sprintf("%s_temp.txt", strings.ReplaceAll(target, ".", "_")))
		if len(allSubdomains) > 0 {
			content := strings.Join(allSubdomains, "\n")
			os.WriteFile(tempFile, []byte(content), 0644)

			dnsxOutput := filepath.Join(subfinderDir, fmt.Sprintf("%s_dnsx.txt", strings.ReplaceAll(target, ".", "_")))
			dnsxCmd := exec.CommandContext(wp.ctx, "dnsx",
				"-l", tempFile,
				"-silent",
				"-o", dnsxOutput)

			if err := dnsxCmd.Run(); err == nil {
				// Read validated results from dnsx and add to existing results
				if content, err := os.ReadFile(dnsxOutput); err == nil {
					lines := strings.Split(strings.TrimSpace(string(content)), "\n")
					for _, line := range lines {
						if strings.TrimSpace(line) != "" {
							allSubdomains = append(allSubdomains, strings.TrimSpace(line))
						}
					}
				}
			}

			// Clean up temp file
			os.Remove(tempFile)
		}
	}

	return wp.removeDuplicateSubdomains(allSubdomains), nil
}

// scanWhois performs whois discovery
func (wp *WorkerPool) scanWhois(target string, data map[string]interface{}) ([]string, error) {
	var ranges []string

	// Get whois information
	whoisInfo, err := wp.getWhoisInfo(target)
	if err != nil {
		return ranges, nil // Continue with other targets
	}

	// Search related IP ranges by organization name
	if whoisInfo.OrgName != "" {
		if orgRanges, err := wp.searchRelatedIPRanges(whoisInfo.OrgName); err == nil {
			ranges = append(ranges, orgRanges...)
		}
	}

	// Search related IP ranges by ASN
	if whoisInfo.ASN != "" {
		if asnRanges, err := wp.searchASNIPRanges(whoisInfo.ASN); err == nil {
			ranges = append(ranges, asnRanges...)
		}
	}

	return wp.removeDuplicateRanges(ranges), nil
}

// Helper functions for worker pool
func (wp *WorkerPool) extractSSLCertificateInfo(target string) (*SSLCertificateInfo, error) {
	certInfo := &SSLCertificateInfo{}

	// Common SSL ports to try
	sslPorts := []string{"443", "8443", "9443", "9444", "9445", "9446", "9447", "9448", "9449", "9450"}

	for _, port := range sslPorts {
		// Try to connect and get SSL certificate
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", target+":"+port, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			continue // Try next port
		}
		defer conn.Close()

		// Get certificate
		if len(conn.ConnectionState().PeerCertificates) == 0 {
			continue // No certificate found
		}

		cert := conn.ConnectionState().PeerCertificates[0]

		// Extract certificate information
		certInfo.Subject = cert.Subject.CommonName
		certInfo.Issuer = cert.Issuer.CommonName
		certInfo.Serial = cert.SerialNumber.String()
		certInfo.Fingerprint = fmt.Sprintf("%x", cert.Signature)
		certInfo.DNSNames = cert.DNSNames
		certInfo.ValidFrom = cert.NotBefore.Format("2006-01-02")
		certInfo.ValidUntil = cert.NotAfter.Format("2006-01-02")

		// Extract IP addresses from certificate
		for _, ip := range cert.IPAddresses {
			certInfo.IPAddresses = append(certInfo.IPAddresses, ip.String())
		}

		// Found a valid certificate, return it
		return certInfo, nil
	}

	return nil, fmt.Errorf("no valid SSL certificate found for %s on any port", target)
}

func (wp *WorkerPool) searchRelatedTargetsByCertificate(certInfo *SSLCertificateInfo) []string {
	var results []string

	// Method 1: Search by issuer
	if certInfo.Issuer != "" {
		// Look for common patterns in issuer
		issuerPatterns := []string{"Let's Encrypt", "DigiCert", "Comodo", "GlobalSign", "GoDaddy", "Sectigo"}
		for _, pattern := range issuerPatterns {
			if strings.Contains(certInfo.Issuer, pattern) {
				// This could indicate similar certificate patterns
				// For now, we'll just log this information
				break
			}
		}
	}

	return results
}

func (wp *WorkerPool) removeDuplicateSubdomains(subdomains []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, subdomain := range subdomains {
		if !seen[subdomain] {
			seen[subdomain] = true
			result = append(result, subdomain)
		}
	}

	return result
}

func (wp *WorkerPool) getWhoisInfo(domain string) (*WhoisInfo, error) {
	// This is a simplified whois implementation
	// In a real implementation, you would use a proper whois library
	whoisInfo := &WhoisInfo{
		Domain: domain,
		// Other fields would be populated from actual whois query
	}
	return whoisInfo, nil
}

func (wp *WorkerPool) searchRelatedIPRanges(orgName string) ([]string, error) {
	// Simplified implementation
	return []string{}, nil
}

func (wp *WorkerPool) searchASNIPRanges(asn string) ([]string, error) {
	// Simplified implementation
	return []string{}, nil
}

func (wp *WorkerPool) removeDuplicateRanges(ranges []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, r := range ranges {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}

	return result
}

func (wp *WorkerPool) checkTool(toolName string) error {
	_, err := exec.LookPath(toolName)
	return err
}

// AddTask adds a task to the queue
func (s *Scanner) AddTask(task Task) error {
	select {
	case s.workerPool.taskQueue <- task:
		s.queue.stats.mu.Lock()
		s.queue.stats.TotalTasks++
		s.queue.stats.QueueSize++
		s.queue.stats.mu.Unlock()
		return nil
	case <-s.queue.ctx.Done():
		return fmt.Errorf("queue is closed")
	default:
		return fmt.Errorf("queue is full")
	}
}

// AddTasks adds multiple tasks to the queue
func (s *Scanner) AddTasks(tasks []Task) error {
	for _, task := range tasks {
		if err := s.AddTask(task); err != nil {
			return err
		}
	}
	return nil
}

// processResults processes results from the worker pool
func (s *Scanner) processResults() {
	for {
		select {
		case result := <-s.workerPool.resultChan:
			s.queue.stats.mu.Lock()
			s.queue.stats.CompletedTasks++
			s.queue.stats.QueueSize--
			if result.Error != nil {
				s.queue.stats.FailedTasks++
			}
			s.queue.stats.mu.Unlock()

			// Update scanner stats
			s.stats.mu.Lock()
			s.stats.ProcessedTargets++
			if result.Error == nil {
				s.stats.FoundResults += len(result.Results)
			} else {
				s.stats.Errors++
			}
			s.stats.mu.Unlock()

		case <-s.queue.ctx.Done():
			return
		}
	}
}

// GetQueueStats returns queue statistics
func (s *Scanner) GetQueueStats() *QueueStats {
	s.queue.stats.mu.RLock()
	defer s.queue.stats.mu.RUnlock()

	stats := *s.queue.stats
	return &stats
}

// Stop stops the scanner and all workers
func (s *Scanner) Stop() {
	s.queue.cancel()
	s.workerPool.Stop()
}

// WaitForCompletion waits for all tasks to complete
func (s *Scanner) WaitForCompletion() {
	s.queue.wg.Wait()
}

// parseNaabuOutput parses naabu text output and extracts relevant information
func (s *Scanner) parseNaabuOutput(outputFile string) ([]string, error) {
	content, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, err
	}

	// Parse naabu output (simple text format)
	lines := strings.Split(string(content), "\n")
	var results []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			// Convert IP:port to http://IP:port format for vulnerability scanning
			if strings.Contains(line, ":") {
				results = append(results, fmt.Sprintf("NAABU: http://%s", line))
			} else {
				results = append(results, fmt.Sprintf("NAABU: %s", line))
			}
		}
	}

	return results, nil
}

// searchAPNICForASN searches APNIC database for ASN
func (s *Scanner) searchAPNICForASN(ctx context.Context, asn string) ([]string, error) {
	var ranges []string

	// Use whois to search APNIC database for ASN
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.apnic.net", fmt.Sprintf("AS%s", asn))
	output, err := cmd.Output()
	if err == nil {
		// Parse APNIC output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// searchLACNICForASN searches LACNIC database for ASN
func (s *Scanner) searchLACNICForASN(ctx context.Context, asn string) ([]string, error) {
	var ranges []string

	// Use whois to search LACNIC database for ASN
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.lacnic.net", fmt.Sprintf("AS%s", asn))
	output, err := cmd.Output()
	if err == nil {
		// Parse LACNIC output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// searchAFRINICForASN searches AFRINIC database for ASN
func (s *Scanner) searchAFRINICForASN(ctx context.Context, asn string) ([]string, error) {
	var ranges []string

	// Use whois to search AFRINIC database for ASN
	cmd := exec.CommandContext(ctx, "whois", "-h", "whois.afrinic.net", fmt.Sprintf("AS%s", asn))
	output, err := cmd.Output()
	if err == nil {
		// Parse AFRINIC output for IP ranges
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "route:") || strings.Contains(line, "route6:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					ranges = append(ranges, parts[1])
				}
			}
		}
	}

	return ranges, nil
}

// ScanASNDiscovery performs ASN-based IP range discovery
func (s *Scanner) ScanASNDiscovery(ctx context.Context, asns []string, projectDir string) ([]string, error) {
	var allIPRanges []string

	// Create ASN discovery directory
	asnDir := filepath.Join(projectDir, "logs", "asn_discovery")
	if err := os.MkdirAll(asnDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ASN discovery directory: %w", err)
	}

	for _, asn := range asns {
		// Clean ASN format
		asn = strings.TrimPrefix(strings.TrimPrefix(asn, "AS"), "as")

		// Get ASN information and IP ranges
		asnInfo, err := s.getASNInfo(ctx, asn)
		if err != nil {
			// Log error but continue
			errorLog := filepath.Join(asnDir, fmt.Sprintf("AS%s_error.log", asn))
			os.WriteFile(errorLog, []byte(fmt.Sprintf("ASN lookup failed: %v", err)), 0644)
			continue
		}

		// Save ASN info to file
		asnFile := filepath.Join(asnDir, fmt.Sprintf("AS%s_info.json", asn))
		if asnData, err := json.MarshalIndent(asnInfo, "", "  "); err == nil {
			os.WriteFile(asnFile, asnData, 0644)
		}

		// Add IP ranges to results
		allIPRanges = append(allIPRanges, asnInfo.IPRanges...)

		// Search for related ASNs based on organization
		if asnInfo.OrgName != "" {
			relatedASNs, err := s.searchRelatedASNs(ctx, asnInfo.OrgName, asnDir)
			if err == nil {
				for _, relatedASN := range relatedASNs {
					if relatedInfo, err := s.getASNInfo(ctx, relatedASN); err == nil {
						allIPRanges = append(allIPRanges, relatedInfo.IPRanges...)
					}
				}
			}
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return allIPRanges, ctx.Err()
		default:
		}
	}

	return s.removeDuplicateRanges(allIPRanges), nil
}

// DiscoverTargetsFromASN discovers targets from ASN information
func (s *Scanner) DiscoverTargetsFromASN(ctx context.Context, target string, projectDir string) ([]string, error) {
	var discoveredTargets []string

	// First, try to find ASN for the given target
	asnInfo, err := s.findASNForTarget(ctx, target)
	if err != nil {
		return discoveredTargets, nil // Continue with other targets
	}

	// Add all IP ranges from the ASN
	discoveredTargets = append(discoveredTargets, asnInfo.IPRanges...)

	// Search for related ASNs
	if asnInfo.OrgName != "" {
		relatedASNs, err := s.searchRelatedASNs(ctx, asnInfo.OrgName, projectDir)
		if err == nil {
			for _, relatedASN := range relatedASNs {
				if relatedInfo, err := s.getASNInfo(ctx, relatedASN); err == nil {
					discoveredTargets = append(discoveredTargets, relatedInfo.IPRanges...)
				}
			}
		}
	}

	// Convert IP ranges to individual IPs for scanning
	individualIPs := s.expandIPRanges(discoveredTargets)
	discoveredTargets = append(discoveredTargets, individualIPs...)

	return s.removeDuplicateTargets(discoveredTargets), nil
}

// getASNInfo retrieves ASN information and IP ranges
func (s *Scanner) getASNInfo(ctx context.Context, asn string) (*ASNInfo, error) {
	asnInfo := &ASNInfo{
		ASN: asn,
	}

	// Method 1: Search RIPE database
	if ripeRanges, err := s.searchRIPEForASN(ctx, asn); err == nil {
		asnInfo.IPRanges = append(asnInfo.IPRanges, ripeRanges...)
	}

	// Method 2: Search ARIN database
	if arinRanges, err := s.searchARINForASN(ctx, asn); err == nil {
		asnInfo.IPRanges = append(asnInfo.IPRanges, arinRanges...)
	}

	// Method 3: Search APNIC database
	if apnicRanges, err := s.searchAPNICForASN(ctx, asn); err == nil {
		asnInfo.IPRanges = append(asnInfo.IPRanges, apnicRanges...)
	}

	// Method 4: Search LACNIC database
	if lacnicRanges, err := s.searchLACNICForASN(ctx, asn); err == nil {
		asnInfo.IPRanges = append(asnInfo.IPRanges, lacnicRanges...)
	}

	// Method 5: Search AFRINIC database
	if afrinicRanges, err := s.searchAFRINICForASN(ctx, asn); err == nil {
		asnInfo.IPRanges = append(asnInfo.IPRanges, afrinicRanges...)
	}

	// Get organization information
	if orgInfo, err := s.getASNOrgInfo(ctx, asn); err == nil {
		asnInfo.OrgName = orgInfo.OrgName
		asnInfo.Description = orgInfo.Description
		asnInfo.Country = orgInfo.Country
	}

	return asnInfo, nil
}

// findASNForTarget finds ASN information for a given target (IP or domain)
func (s *Scanner) findASNForTarget(ctx context.Context, target string) (*ASNInfo, error) {
	// Resolve domain to IP if needed
	ip := target
	if !s.isIPAddress(target) {
		resolvedIPs, err := s.resolveDomain(target)
		if err != nil || len(resolvedIPs) == 0 {
			return nil, fmt.Errorf("failed to resolve domain: %s", target)
		}
		ip = resolvedIPs[0] // Use first resolved IP
	}

	// Find ASN for IP
	asn, err := s.findASNForIP(ctx, ip)
	if err != nil {
		return nil, err
	}

	// Get full ASN information
	return s.getASNInfo(ctx, asn)
}

// findASNForIP finds ASN for a given IP address
func (s *Scanner) findASNForIP(ctx context.Context, ip string) (string, error) {
	// Method 1: Use whois
	cmd := exec.CommandContext(ctx, "whois", ip)
	output, err := cmd.Output()
	if err == nil {
		// Parse whois output for ASN
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "origin:") {
				asn := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				return strings.TrimPrefix(asn, "AS"), nil
			}
		}
	}

	// Method 2: Use bgp.tools API (if available)
	if bgpASN, err := s.queryBGPTools(ctx, ip); err == nil {
		return bgpASN, nil
	}

	// Method 3: Use ipinfo.io API (if available)
	if ipinfoASN, err := s.queryIPInfo(ctx, ip); err == nil {
		return ipinfoASN, nil
	}

	return "", fmt.Errorf("could not find ASN for IP: %s", ip)
}

// searchRelatedASNs searches for ASNs related to an organization
func (s *Scanner) searchRelatedASNs(ctx context.Context, orgName, projectDir string) ([]string, error) {
	var relatedASNs []string

	// Search in various RIR databases
	rirSearches := []struct {
		name string
		host string
	}{
		{"RIPE", "whois.ripe.net"},
		{"ARIN", "whois.arin.net"},
		{"APNIC", "whois.apnic.net"},
		{"LACNIC", "whois.lacnic.net"},
		{"AFRINIC", "whois.afrinic.net"},
	}

	for _, rir := range rirSearches {
		cmd := exec.CommandContext(ctx, "whois", "-h", rir.host, orgName)
		output, err := cmd.Output()
		if err == nil {
			// Parse for ASN entries
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "origin:") {
					parts := strings.Fields(line)
					for _, part := range parts {
						if strings.HasPrefix(part, "AS") {
							asn := strings.TrimPrefix(part, "AS")
							relatedASNs = append(relatedASNs, asn)
						}
					}
				}
			}
		}
	}

	return s.removeDuplicateASNs(relatedASNs), nil
}

// expandIPRanges converts IP ranges to individual IPs
func (s *Scanner) expandIPRanges(ranges []string) []string {
	var individualIPs []string

	for _, ipRange := range ranges {
		// Handle CIDR notation (e.g., 192.168.1.0/24)
		if strings.Contains(ipRange, "/") {
			ips := s.expandCIDR(ipRange)
			individualIPs = append(individualIPs, ips...)
		} else {
			// Single IP
			individualIPs = append(individualIPs, ipRange)
		}
	}

	return individualIPs
}

// expandCIDR expands a CIDR range to individual IPs
func (s *Scanner) expandCIDR(cidr string) []string {
	var ips []string

	// Parse CIDR
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return ips
	}

	ip := parts[0]
	mask, err := strconv.Atoi(parts[1])
	if err != nil {
		return ips
	}

	// For /24 and smaller ranges, expand to individual IPs
	if mask >= 24 {
		// Simple expansion for /24
		ipParts := strings.Split(ip, ".")
		if len(ipParts) == 4 {
			baseIP := strings.Join(ipParts[:3], ".")
			for i := 1; i <= 254; i++ {
				ips = append(ips, fmt.Sprintf("%s.%d", baseIP, i))
			}
		}
	} else {
		// For larger ranges, just return the range
		ips = append(ips, cidr)
	}

	return ips
}

// Helper functions
func (s *Scanner) isIPAddress(input string) bool {
	return net.ParseIP(input) != nil
}

func (s *Scanner) resolveDomain(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			result = append(result, ipv4.String())
		}
	}

	return result, nil
}

func (s *Scanner) queryBGPTools(ctx context.Context, ip string) (string, error) {
	// Implementation for bgp.tools API
	// This would require API key and proper HTTP client
	return "", fmt.Errorf("bgp.tools API not implemented")
}

func (s *Scanner) queryIPInfo(ctx context.Context, ip string) (string, error) {
	// Implementation for ipinfo.io API
	// This would require API key and proper HTTP client
	return "", fmt.Errorf("ipinfo.io API not implemented")
}

func (s *Scanner) getASNOrgInfo(ctx context.Context, asn string) (*ASNInfo, error) {
	// Get organization information for ASN
	cmd := exec.CommandContext(ctx, "whois", fmt.Sprintf("AS%s", asn))
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	asnInfo := &ASNInfo{ASN: asn}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "org-name:") {
			asnInfo.OrgName = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "descr:") {
			asnInfo.Description = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(strings.ToLower(line), "country:") {
			asnInfo.Country = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	return asnInfo, nil
}

func (s *Scanner) removeDuplicateASNs(asns []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, asn := range asns {
		if !seen[asn] {
			seen[asn] = true
			result = append(result, asn)
		}
	}

	return result
}
