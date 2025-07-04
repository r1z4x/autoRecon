package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"autorecon/internal/config"
	"autorecon/internal/database"
	"autorecon/internal/parser"
	"autorecon/internal/scanner"
	"autorecon/internal/storage"
	"autorecon/internal/ui"
	"autorecon/internal/validation"
	"autorecon/pkg/models"

	"github.com/spf13/cobra"
)

var (
	cfg         *config.Config
	uiInstance  *ui.UI
	parserInst  *parser.Parser
	scannerInst *scanner.Scanner
	storageInst *storage.Storage
	ctx         context.Context
)

func main() {
	// Initialize components
	cfg = config.NewConfig()
	uiInstance = ui.NewUI()
	parserInst = parser.NewParser()
	storageInst = storage.NewStorage(cfg.GlobalDataDir)
	ctx = context.Background()

	// Create root command
	var rootCmd = &cobra.Command{
		Use:   "autorecon",
		Short: "Automated security reconnaissance tool",
		Long: `AutoRecon is a comprehensive security reconnaissance tool that automates 
the process of discovering subdomains, validating URLs, scanning ports, and 
identifying vulnerabilities using various security tools.`,
		Run: func(cmd *cobra.Command, args []string) {
			uiInstance.ShowUsage()
		},
	}

	// Add commands
	rootCmd.AddCommand(domainCmd())
	rootCmd.AddCommand(urlCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(resumeCmd())
	rootCmd.AddCommand(stopCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(installCmd())

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// installCmd handles tool installation
func installCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install required tools and dependencies",
		Run: func(cmd *cobra.Command, args []string) {
			installRequiredTools()
		},
	}

	return cmd
}

// installRequiredTools installs all required Go tools
func installRequiredTools() {
	uiInstance.ShowBanner()
	uiInstance.ShowInfo("Installing required tools...")

	tools := []struct {
		name string
		path string
	}{
		{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
		{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{"nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"},
		{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
		{"mapcidr", "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"},
		{"anew", "github.com/tomnomnom/anew@latest"},
	}

	for _, tool := range tools {
		uiInstance.ShowInfo(fmt.Sprintf("Installing %s...", tool.name))

		cmd := exec.Command("go", "install", "-v", tool.path)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			uiInstance.ShowError(fmt.Sprintf("Failed to install %s: %v", tool.name, err))
		} else {
			uiInstance.ShowSuccess(fmt.Sprintf("✓ %s installed successfully", tool.name))
		}
	}

	uiInstance.ShowInfo("Installation completed!")
	uiInstance.ShowInfo("Note: Make sure to add $HOME/go/bin to your PATH")
}

// domainCmd handles single domain scans
func domainCmd() *cobra.Command {
	var projectName string

	cmd := &cobra.Command{
		Use:   "domain [domain]",
		Short: "Scan a single domain",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return checkPrerequisites()
		},
		Run: func(cmd *cobra.Command, args []string) {
			domain := args[0]

			if projectName == "" {
				projectName = fmt.Sprintf("domain_scan_%s", strings.ReplaceAll(domain, ".", "_"))
			}

			runScan(projectName, []string{domain}, "domain")
		},
	}

	cmd.Flags().StringVarP(&projectName, "project", "p", "", "Project name")
	return cmd
}

// urlCmd handles single URL scans
func urlCmd() *cobra.Command {
	var projectName string

	cmd := &cobra.Command{
		Use:   "url [url]",
		Short: "Scan a single URL",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return checkPrerequisites()
		},
		Run: func(cmd *cobra.Command, args []string) {
			url := args[0]

			if projectName == "" {
				projectName = fmt.Sprintf("url_scan_%s", strings.ReplaceAll(url, "://", "_"))
			}

			runScan(projectName, []string{url}, "url")
		},
	}

	cmd.Flags().StringVarP(&projectName, "project", "p", "", "Project name")
	return cmd
}

// listCmd handles target list scans
func listCmd() *cobra.Command {
	var projectName string

	cmd := &cobra.Command{
		Use:   "list [file]",
		Short: "Scan targets from a file",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return checkPrerequisites()
		},
		Run: func(cmd *cobra.Command, args []string) {
			file := args[0]

			if projectName == "" {
				projectName = fmt.Sprintf("list_scan_%s", strings.TrimSuffix(filepath.Base(file), filepath.Ext(file)))
			}

			runScan(projectName, nil, "list", file)
		},
	}

	cmd.Flags().StringVarP(&projectName, "project", "p", "", "Project name")
	return cmd
}

// checkPrerequisites checks if all required tools and files are available
func checkPrerequisites() error {
	// Check required tools
	if err := cfg.CheckRequiredTools(); err != nil {
		uiInstance.ShowError(err.Error())
		uiInstance.ShowInfo("Run 'autorecon install' to install required tools")
		return err
	}

	// Check configuration
	if err := cfg.Validate(); err != nil {
		uiInstance.ShowError(err.Error())
		return err
	}

	return nil
}

// resumeCmd handles project resumption
func resumeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resume [project]",
		Short: "Resume a paused project",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return checkPrerequisites()
		},
		Run: func(cmd *cobra.Command, args []string) {
			projectName := args[0]
			resumeProject(projectName)
		},
	}

	return cmd
}

// stopCmd handles project stopping
func stopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop [project]",
		Short: "Stop a running project",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			projectName := args[0]
			stopProject(projectName)
		},
	}

	return cmd
}

// statusCmd shows global status
func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show global files status",
		Run: func(cmd *cobra.Command, args []string) {
			showGlobalStatus()
		},
	}

	return cmd
}

// runScan executes a scan with the given parameters
func runScan(projectName string, targets []string, scanType string, file ...string) {
	// Initialize UI and show banner
	uiInstance.ShowBanner()
	uiInstance.ShowInfo(fmt.Sprintf("Starting scan for project: %s", projectName))
	uiInstance.ShowInfo(fmt.Sprintf("Initial targets: %d domains, %d IPs, %d URLs",
		len(targets), len(targets), len(targets)))

	// Create or load project
	var project *models.Project

	if file != nil {
		// Load targets from file
		targetList, err := parserInst.ParseFile(file[0])
		if err != nil {
			uiInstance.ShowError(fmt.Sprintf("Failed to parse file: %v", err))
			os.Exit(1)
		}

		project = models.NewProject(projectName, cfg.ProjectsDir)
		project.Targets = *targetList
	} else {
		// Parse single targets
		targetList := parserInst.ParseTargets(targets)
		project = models.NewProject(projectName, cfg.ProjectsDir)
		project.Targets = *targetList
	}

	// Save project
	if err := project.Save(); err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to save project: %v", err))
		os.Exit(1)
	}

	// Initialize database
	db, err := database.NewDatabase(project.GetProjectDir())
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to initialize database: %v", err))
		os.Exit(1)
	}
	defer db.Close()

	// Add initial targets to database
	for _, domain := range project.Targets.Domains {
		_, err := db.AddTarget(domain.Value, string(domain.Type), "initial")
		if err != nil {
			uiInstance.ShowError(fmt.Sprintf("Failed to add target to database: %v", err))
		}
	}

	// Create project structure
	if err := storageInst.CreateProjectStructure(project.GetProjectDir()); err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to create project structure: %v", err))
		os.Exit(1)
	}

	// Show project status
	uiInstance.ShowProjectStatus(project)

	// Show target summary
	summary := project.Targets.GetSummary()
	uiInstance.ShowTargetSummary(summary)

	// Initialize scanner with high-performance configuration
	scannerConfig := &scanner.ScannerConfig{
		MaxWorkers: 100,   // Çok daha fazla worker (50'den 100'e)
		BatchSize:  1000,  // Çok daha büyük batch (500'den 1000'e)
		QueueSize:  10000, // Büyük queue (5000'den 10000'e)
		RateLimit:  1000,  // Yüksek rate limit
	}
	scannerInst = scanner.NewScanner(scannerConfig)
	defer scannerInst.Stop()

	// Initialize scan tracking variables
	currentStep := "Initializing"
	completedSteps := 0
	totalSteps := 6 // Port Scanning, Subdomain Discovery, SSL Discovery, Whois Discovery, URL Validation, Final Summary
	discoveredTargets := 0
	stepStatus := map[string]string{
		"Port Scanning":       "pending",
		"Subdomain Discovery": "pending",
		"SSL Discovery":       "pending",
		"Whois Discovery":     "pending",
		"URL Validation":      "pending",
		"Final Summary":       "pending",
	}
	recentDiscoveries := []models.Target{}

	// Start dashboard update goroutine
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				// Update dashboard with current progress
				dbSummary, _ := db.GetTargetSummary()
				validationSummary, _ := db.GetTargetValidationSummary()

				stats := &models.ScanStats{
					CurrentStep:       currentStep,
					CompletedSteps:    completedSteps,
					TotalSteps:        totalSteps,
					InitialTargets:    len(project.Targets.Domains) + len(project.Targets.IPs),
					DiscoveredTargets: discoveredTargets,
					TotalTargets:      len(project.Targets.Domains) + len(project.Targets.IPs) + discoveredTargets,
					StepStatus:        stepStatus,
					RecentDiscoveries: recentDiscoveries,
				}

				uiInstance.UpdateDashboard(stats, dbSummary, validationSummary)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Step 1: Port Scanning (Parallel)
	currentStep = "Port Scanning"
	stepStatus["Port Scanning"] = "running"
	uiInstance.ShowInfo("Step 1/6: Port scanning all targets in parallel...")

	// Get all targets for port scanning
	allTargets := []string{}
	for _, domain := range project.Targets.Domains {
		allTargets = append(allTargets, domain.Value)
	}
	for _, ip := range project.Targets.IPs {
		allTargets = append(allTargets, ip.Value)
	}
	for _, url := range project.Targets.URLs {
		allTargets = append(allTargets, url.Value)
	}

	// Port scan all targets in parallel (much faster)
	portScanResults, err := scannerInst.ScanAllTargets(ctx, allTargets, project.GetProjectDir())
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Port scanning failed: %v", err))
		os.Exit(1)
	}

	// Process results in parallel
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20) // Limit concurrent database operations

	for i, result := range portScanResults {
		if result.Error == nil && i < len(allTargets) {
			wg.Add(1)
			go func(target string, scanResult scanner.ScanResult) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire semaphore
				defer func() { <-semaphore }() // Release semaphore

				// Get or create target in database
				targetObj, err := db.GetTargetByValue(target)
				if err != nil {
					// Target doesn't exist, add it
					targetType := "unknown"
					if net.ParseIP(target) != nil {
						targetType = "ip"
					} else if strings.Contains(target, ".") && !strings.Contains(target, "://") {
						targetType = "domain"
					} else if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
						targetType = "url"
					}

					targetID, err := db.AddTarget(target, targetType, "initial")
					if err != nil {
						return
					}
					targetObj = &database.Target{ID: targetID, Value: target}
				}

				// Extract ports from results
				for _, res := range scanResult.Results {
					if strings.Contains(res, ":") {
						parts := strings.Split(res, ":")
						if len(parts) > 1 {
							if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
								db.AddPort(targetObj.ID, port, "", "")
							}
						}
					}
				}

				// Update target status
				db.UpdateTargetStatus(targetObj.ID, "scanned")
			}(allTargets[i], result)
		}
	}

	// Wait for all database operations to complete
	wg.Wait()

	completedSteps++
	stepStatus["Port Scanning"] = "completed"
	uiInstance.ShowInfo(fmt.Sprintf("Port scanning completed: %d targets processed", len(allTargets)))

	// Step 2: Subdomain Discovery
	currentStep = "Subdomain Discovery"
	stepStatus["Subdomain Discovery"] = "running"
	uiInstance.ShowInfo("Step 2/6: Discovering subdomains...")

	// Extract domain strings for subfinder
	var domainStrings []string
	for _, domain := range project.Targets.Domains {
		domainStrings = append(domainStrings, domain.Value)
	}

	// Run subfinder for subdomain discovery
	subdomains, err := scannerInst.ScanSubdomains(ctx, domainStrings, project.GetProjectDir())
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Subdomain discovery failed: %v", err))
	} else {
		// Update discovered targets count
		discoveredTargets += len(subdomains)

		// Add new targets to recent discoveries
		for _, target := range subdomains {
			recentDiscoveries = append(recentDiscoveries, models.Target{
				Value:  target,
				Source: "subdomain_discovery",
			})
		}

		// Add new targets to database
		for _, target := range subdomains {
			// Determine target type
			targetType := "unknown"
			if net.ParseIP(target) != nil {
				targetType = "ip"
			} else if strings.Contains(target, ".") && !strings.Contains(target, "://") {
				targetType = "domain"
			} else if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				targetType = "url"
			}

			// Validate target against base domain
			baseDomain := project.Targets.Domains[0].Value // Use first domain as base
			validator := validation.NewValidator(baseDomain)
			validationResult := validator.ValidateTarget(target)

			// Only add targets with reasonable validation score (>= 0.05)
			if validationResult.Score >= 0.05 {
				// Add to database
				targetID, err := db.AddTarget(target, targetType, "subdomain_discovery")
				if err != nil {
					uiInstance.ShowError(fmt.Sprintf("Failed to add subdomain discovery target to database: %v", err))
					continue
				}

				// Add validation information to database
				db.AddTargetValidation(targetID, target, validationResult.Score, validationResult.Methods, validationResult.Notes)

				// Port scan for this newly discovered target
				portScanResults, err := scannerInst.ScanAllTargets(ctx, []string{target}, project.GetProjectDir())
				if err == nil && len(portScanResults) > 0 && portScanResults[0].Error == nil {
					// Extract ports from results
					for _, res := range portScanResults[0].Results {
						if strings.Contains(res, ":") {
							parts := strings.Split(res, ":")
							if len(parts) > 1 {
								if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
									db.AddPort(targetID, port, "", "")
								}
							}
						}
					}

					// Update target status to scanned
					db.UpdateTargetStatus(targetID, "scanned")
				}

				uiInstance.ShowInfo(fmt.Sprintf("Validated target: %s (Score: %.2f, Confidence: %s)",
					target, validationResult.Score, validationResult.ConfidenceLevel))
			} else {
				uiInstance.ShowInfo(fmt.Sprintf("Rejected target: %s (Score: %.2f, Reason: %s)",
					target, validationResult.Score, validationResult.Notes))
			}
		}
	}

	completedSteps++
	stepStatus["Subdomain Discovery"] = "completed"
	uiInstance.ShowInfo(fmt.Sprintf("Subdomain Discovery completed: %d subdomains found", len(subdomains)))

	// Step 3: SSL Discovery
	currentStep = "SSL Discovery"
	stepStatus["SSL Discovery"] = "running"
	uiInstance.ShowInfo("Step 3/6: SSL certificate discovery...")

	// Get targets with open ports for SSL discovery
	targetsWithPorts, err := db.GetTargetsWithPorts()
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to get targets with ports: %v", err))
	} else {
		// Perform SSL discovery
		sslDiscoveryResults, err := scannerInst.ScanSSLDiscovery(ctx, targetsWithPorts, project.GetProjectDir())
		if err != nil {
			uiInstance.ShowError(fmt.Sprintf("SSL discovery failed: %v", err))
		} else {
			// Parse SSL discovery results for new targets
			newSSLDiscoveryTargets := parserInst.ParseSSLDiscoveryResults(sslDiscoveryResults)

			// Update discovered targets count
			discoveredTargets += len(newSSLDiscoveryTargets)

			// Add new targets to recent discoveries
			for _, target := range newSSLDiscoveryTargets {
				recentDiscoveries = append(recentDiscoveries, models.Target{
					Value:  target,
					Source: "ssl_discovery",
				})
			}

			// Add new targets to database and port scan them
			for _, target := range newSSLDiscoveryTargets {
				// Determine target type
				targetType := "unknown"
				if net.ParseIP(target) != nil {
					targetType = "ip"
				} else if strings.Contains(target, ".") && !strings.Contains(target, "://") {
					targetType = "domain"
				} else if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
					targetType = "url"
				}

				// Validate target against base domain
				baseDomain := project.Targets.Domains[0].Value // Use first domain as base
				validator := validation.NewValidator(baseDomain)
				validationResult := validator.ValidateTarget(target)

				// Only add targets with reasonable validation score (>= 0.05)
				if validationResult.Score >= 0.05 {
					// Add to database
					targetID, err := db.AddTarget(target, targetType, "ssl_discovery")
					if err != nil {
						uiInstance.ShowError(fmt.Sprintf("Failed to add SSL discovery target to database: %v", err))
						continue
					}

					// Add validation information to database
					db.AddTargetValidation(targetID, target, validationResult.Score, validationResult.Methods, validationResult.Notes)

					// Port scan for this newly discovered target
					portScanResults, err := scannerInst.ScanAllTargets(ctx, []string{target}, project.GetProjectDir())
					if err == nil && len(portScanResults) > 0 && portScanResults[0].Error == nil {
						// Extract ports from results
						for _, res := range portScanResults[0].Results {
							if strings.Contains(res, ":") {
								parts := strings.Split(res, ":")
								if len(parts) > 1 {
									if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
										db.AddPort(targetID, port, "", "")
									}
								}
							}
						}

						// Update target status to scanned
						db.UpdateTargetStatus(targetID, "scanned")
					}

					uiInstance.ShowInfo(fmt.Sprintf("Validated target: %s (Score: %.2f, Confidence: %s)",
						target, validationResult.Score, validationResult.ConfidenceLevel))
				} else {
					uiInstance.ShowInfo(fmt.Sprintf("Rejected target: %s (Score: %.2f, Reason: %s)",
						target, validationResult.Score, validationResult.Notes))
				}
			}
		}
	}

	completedSteps++
	stepStatus["SSL Discovery"] = "completed"
	uiInstance.ShowInfo("SSL Discovery completed")

	// Step 4: Whois Discovery
	currentStep = "Whois Discovery"
	stepStatus["Whois Discovery"] = "running"
	uiInstance.ShowInfo("Step 4/6: Discovering whois information...")

	// Run whois discovery
	// Extract domain strings for whois discovery
	var whoisDomainStrings []string
	for _, domain := range project.Targets.Domains {
		whoisDomainStrings = append(whoisDomainStrings, domain.Value)
	}

	whoisResults, err := scannerInst.ScanWhoisDiscovery(ctx, whoisDomainStrings, project.GetProjectDir())
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Whois discovery failed: %v", err))
	} else {
		// Parse whois results for new targets
		newWhoisTargets := parserInst.ParseWhoisDiscoveryResults(whoisResults)

		// Update discovered targets count
		discoveredTargets += len(newWhoisTargets)

		// Add new targets to recent discoveries
		for _, target := range newWhoisTargets {
			recentDiscoveries = append(recentDiscoveries, models.Target{
				Value:  target,
				Source: "whois_discovery",
			})
		}

		// Add new targets to database
		for _, target := range newWhoisTargets {
			// Determine target type
			targetType := "unknown"
			if net.ParseIP(target) != nil {
				targetType = "ip"
			} else if strings.Contains(target, ".") && !strings.Contains(target, "://") {
				targetType = "domain"
			} else if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				targetType = "url"
			}

			// Validate target against base domain
			baseDomain := project.Targets.Domains[0].Value // Use first domain as base
			validator := validation.NewValidator(baseDomain)
			validationResult := validator.ValidateTarget(target)

			// Only add targets with reasonable validation score (>= 0.05)
			if validationResult.Score >= 0.05 {
				// Add to database
				targetID, err := db.AddTarget(target, targetType, "whois_discovery")
				if err != nil {
					uiInstance.ShowError(fmt.Sprintf("Failed to add whois discovery target to database: %v", err))
					continue
				}

				// Add validation information to database
				db.AddTargetValidation(targetID, target, validationResult.Score, validationResult.Methods, validationResult.Notes)

				// Port scan for this newly discovered target
				portScanResults, err := scannerInst.ScanAllTargets(ctx, []string{target}, project.GetProjectDir())
				if err == nil && len(portScanResults) > 0 && portScanResults[0].Error == nil {
					// Extract ports from results
					for _, res := range portScanResults[0].Results {
						if strings.Contains(res, ":") {
							parts := strings.Split(res, ":")
							if len(parts) > 1 {
								if port, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
									db.AddPort(targetID, port, "", "")
								}
							}
						}
					}

					// Update target status to scanned
					db.UpdateTargetStatus(targetID, "scanned")
				}

				uiInstance.ShowInfo(fmt.Sprintf("Validated target: %s (Score: %.2f, Confidence: %s)",
					target, validationResult.Score, validationResult.ConfidenceLevel))
			} else {
				uiInstance.ShowInfo(fmt.Sprintf("Rejected target: %s (Score: %.2f, Reason: %s)",
					target, validationResult.Score, validationResult.Notes))
			}
		}

		completedSteps++
		stepStatus["Whois Discovery"] = "completed"
		uiInstance.ShowInfo(fmt.Sprintf("Whois Discovery completed: %d whois records found", len(newWhoisTargets)))
	}

	// Step 5: URL Validation
	currentStep = "URL Validation"
	stepStatus["URL Validation"] = "running"
	uiInstance.ShowInfo("Step 5/6: Validating URLs based on open ports and HTTP access...")

	// Extract URL strings for testing
	var urlStrings []string
	for _, url := range project.Targets.URLs {
		urlStrings = append(urlStrings, url.Value)
	}

	// Test HTTP access for URLs
	httpResults := scannerInst.TestHTTPAccess(ctx, urlStrings, project.GetProjectDir())

	// Validate URLs using database port information and HTTP test results
	validatedTargets := parserInst.ValidateURLsFromDatabase(project.Targets.URLs, db)
	validatedTargets = parserInst.ValidateURLsWithHTTPTest(validatedTargets, httpResults)
	project.Targets.URLs = validatedTargets

	completedSteps++
	stepStatus["URL Validation"] = "completed"
	uiInstance.ShowInfo(fmt.Sprintf("URL Validation completed: %d valid URLs (with web ports and HTTP access)", len(validatedTargets)))

	// Step 6: Final Summary
	currentStep = "Final Summary"
	stepStatus["Final Summary"] = "running"
	uiInstance.ShowInfo("Step 6/6: Generating final summary...")

	// Wait a moment to ensure all previous steps are fully completed
	time.Sleep(2 * time.Second)

	// Complete project
	project.UpdateState(models.ProjectStateCompleted)
	project.Save()

	completedSteps++
	stepStatus["Final Summary"] = "completed"

	// Stop the dashboard update goroutine
	ticker.Stop()

	// Clear screen and show final results
	fmt.Print("\033[2J\033[H")
	uiInstance.ShowBanner()
	uiInstance.ShowSuccess("Scan completed successfully!")

	// Show database summary
	dbSummary, err := db.GetTargetSummary()
	if err == nil {
		uiInstance.ShowInfo(fmt.Sprintf("Database Summary: %d total targets, %d ports found",
			dbSummary.TotalTargets, dbSummary.TotalPortsFound))
	}

	// Show validation summary
	validationSummary, err := db.GetTargetValidationSummary()
	if err == nil {
		uiInstance.ShowInfo(fmt.Sprintf("Validation Summary: %d/%d targets validated (%.1f%%), Avg Score: %.2f",
			validationSummary.ValidatedTargets, validationSummary.TotalTargets,
			float64(validationSummary.ValidatedTargets)/float64(validationSummary.TotalTargets)*100,
			validationSummary.AverageScore))

		// Show score distribution
		uiInstance.ShowInfo(fmt.Sprintf("Score Distribution: High(%.1f+): %d, Medium(0.6+): %d, Low(0.4+): %d, Very Low: %d",
			validationSummary.ScoreRanges["high"], validationSummary.ScoreRanges["medium"],
			validationSummary.ScoreRanges["low"], validationSummary.ScoreRanges["very_low"]))
	}

	// Show discovery statistics
	discoveryStats := parserInst.GetDiscoveryStats()
	uiInstance.ShowInfo(fmt.Sprintf("Dynamic Discovery: %d new targets found",
		discoveryStats["domain"]+discoveryStats["url"]+discoveryStats["ip"]))

	// Create project structure
	if err := storageInst.CreateProjectStructure(project.GetProjectDir()); err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to create project structure: %v", err))
		os.Exit(1)
	}

	// Save updated targets
	if err := storageInst.SaveTargets(project.GetProjectDir(), project.Targets); err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to save targets: %v", err))
		os.Exit(1)
	}
}

// resumeProject resumes a paused project
func resumeProject(projectName string) {
	uiInstance.ShowBanner()

	project, err := models.LoadProject(projectName, cfg.ProjectsDir)
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to load project: %v", err))
		os.Exit(1)
	}

	if !project.CanResume() {
		uiInstance.ShowError("Project cannot be resumed")
		os.Exit(1)
	}

	uiInstance.ShowInfo(fmt.Sprintf("Resuming project: %s", projectName))
	runScan(projectName, nil, "", "")
}

// stopProject stops a running project
func stopProject(projectName string) {
	uiInstance.ShowBanner()

	project, err := models.LoadProject(projectName, cfg.ProjectsDir)
	if err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to load project: %v", err))
		os.Exit(1)
	}

	if !project.CanStop() {
		uiInstance.ShowError("Project cannot be stopped")
		os.Exit(1)
	}

	project.UpdateState(models.ProjectStateStopped)
	if err := project.Save(); err != nil {
		uiInstance.ShowError(fmt.Sprintf("Failed to save project: %v", err))
		os.Exit(1)
	}

	uiInstance.ShowSuccess(fmt.Sprintf("Project '%s' stopped successfully", projectName))
}

// showGlobalStatus shows the status of global files
func showGlobalStatus() {
	uiInstance.ShowBanner()

	seclistsPath := storageInst.GetSecListsPath()
	resolversPath := storageInst.GetResolversPath()

	var seclistsSize int64
	var resolverCount int
	var err error

	if storageInst.CheckSecListsExists() {
		seclistsSize, err = storageInst.GetSecListsSize()
		if err != nil {
			seclistsSize = 0
		}
	}

	if storageInst.CheckResolversExists() {
		resolverCount, err = storageInst.GetResolverCount()
		if err != nil {
			resolverCount = 0
		}
	}

	uiInstance.ShowGlobalStatus(seclistsPath, resolversPath, int(seclistsSize), resolverCount)
}
