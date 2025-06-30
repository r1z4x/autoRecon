package ui

import (
	"fmt"
	"time"

	"autorecon/internal/database"
	"autorecon/pkg/models"

	"github.com/fatih/color"
)

// ScanStats interface for scanner statistics
type ScanStats interface {
	GetTotalTargets() int
	GetProcessedTargets() int
	GetFoundResults() int
	GetErrors() int
	GetStartTime() time.Time
}

// UI handles all user interface elements
type UI struct {
	colors *UIColors
}

// UIColors holds color definitions
type UIColors struct {
	Blue    *color.Color
	Green   *color.Color
	Red     *color.Color
	Yellow  *color.Color
	Cyan    *color.Color
	Orange  *color.Color
	Magenta *color.Color
	White   *color.Color
}

// NewUI creates a new UI instance
func NewUI() *UI {
	return &UI{
		colors: &UIColors{
			Blue:    color.New(color.FgBlue),
			Green:   color.New(color.FgGreen),
			Red:     color.New(color.FgRed),
			Yellow:  color.New(color.FgYellow),
			Cyan:    color.New(color.FgCyan),
			Orange:  color.New(color.FgHiYellow),
			Magenta: color.New(color.FgMagenta),
			White:   color.New(color.FgWhite),
		},
	}
}

// ShowBanner displays the application banner
func (u *UI) ShowBanner() {
	u.colors.Blue.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Blue.Println("║                    AutoRecon Scanner                         ║")
	u.colors.Blue.Println("║                    coded by: r1z4x                           ║")
	u.colors.Blue.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// ShowStep displays a step with progress
func (u *UI) ShowStep(stepNum int, totalSteps int, stepName string, status string) {
	progress := float64(stepNum) / float64(totalSteps) * 100

	// Clear previous lines if possible
	fmt.Print("\033[2K") // Clear line

	// Simple progress bar
	barWidth := 50
	filled := int(float64(barWidth) * progress / 100)

	u.colors.Cyan.Printf("  [%d/%d] %s\n", stepNum, totalSteps, stepName)
	u.colors.White.Printf("  [")
	for i := 0; i < barWidth; i++ {
		if i < filled {
			u.colors.Green.Printf("=")
		} else {
			u.colors.White.Printf(" ")
		}
	}
	u.colors.White.Printf("] %.1f%%\n", progress)

	// Show status
	switch status {
	case "running":
		u.colors.Yellow.Printf("  Status: %s\n", status)
	case "completed":
		u.colors.Green.Printf("  Status: %s\n", status)
	case "failed":
		u.colors.Red.Printf("  Status: %s\n", status)
	default:
		u.colors.Cyan.Printf("  Status: %s\n", status)
	}
	fmt.Println()
}

// ShowLiveProgress displays live progress with real-time updates
func (u *UI) ShowLiveProgress(stepNum int, totalSteps int, stepName string, processed, total, found, errors int) {
	progress := float64(stepNum) / float64(totalSteps) * 100
	targetProgress := 0.0
	if total > 0 {
		targetProgress = float64(processed) / float64(total) * 100
	}

	// Clear previous lines
	fmt.Print("\033[2K") // Clear line

	// Step progress
	u.colors.Cyan.Printf("  [%d/%d] %s\n", stepNum, totalSteps, stepName)

	// Overall progress bar
	barWidth := 50
	filled := int(float64(barWidth) * progress / 100)
	u.colors.White.Printf("  Overall: [")
	for i := 0; i < barWidth; i++ {
		if i < filled {
			u.colors.Green.Printf("=")
		} else {
			u.colors.White.Printf(" ")
		}
	}
	u.colors.White.Printf("] %.1f%%\n", progress)

	// Target progress bar
	targetFilled := int(float64(barWidth) * targetProgress / 100)
	u.colors.White.Printf("  Targets: [")
	for i := 0; i < barWidth; i++ {
		if i < targetFilled {
			u.colors.Blue.Printf("=")
		} else {
			u.colors.White.Printf(" ")
		}
	}
	u.colors.White.Printf("] %.1f%% (%d/%d)\n", targetProgress, processed, total)

	// Statistics
	u.colors.Green.Printf("  Found: %d", found)
	u.colors.Red.Printf("  Errors: %d", errors)
	u.colors.Yellow.Printf("  Status: running\n")

	// Move cursor up for next update
	fmt.Print("\033[4A")
}

// ShowLoading displays a loading animation
func (u *UI) ShowLoading(message string) {
	u.colors.Cyan.Printf("  %s", message)

	// Simple loading animation
	for i := 0; i < 3; i++ {
		time.Sleep(500 * time.Millisecond)
		fmt.Print(".")
	}
	fmt.Println()
}

// ShowProgress displays overall progress
func (u *UI) ShowProgress(project *models.Project) {
	fmt.Println()
	u.colors.Orange.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Orange.Printf("║  Project: %-50s ║\n", project.Name)
	u.colors.Orange.Printf("║  State: %-52s ║\n", project.State)
	u.colors.Orange.Printf("║  Progress: %.1f%% (%d/%d steps) %-30s ║\n",
		project.Progress.Progress*100,
		project.Progress.CurrentStepNum,
		project.Progress.TotalSteps,
		"")
	u.colors.Orange.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// ShowStepDetails displays detailed step information
func (u *UI) ShowStepDetails(step models.StepProgress) {
	u.colors.Cyan.Printf("  Step: %s\n", step.Name)
	u.colors.White.Printf("  Status: %s\n", step.Status)

	if step.StartedAt != nil {
		u.colors.White.Printf("  Started: %s\n", step.StartedAt.Format("15:04:05"))
	}

	if step.EndedAt != nil {
		u.colors.White.Printf("  Ended: %s\n", step.EndedAt.Format("15:04:05"))
	}

	if step.Progress > 0 {
		u.colors.White.Printf("  Progress: %.1f%%\n", step.Progress*100)
	}

	if step.Message != "" {
		u.colors.White.Printf("  Message: %s\n", step.Message)
	}
	fmt.Println()
}

// ShowTargetSummary displays target parsing summary
func (u *UI) ShowTargetSummary(summary map[string]int) {
	u.colors.Green.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Green.Println("║                    Target Summary                           ║")
	u.colors.Green.Println("╠══════════════════════════════════════════════════════════════╣")
	u.colors.White.Printf("║  Domains:   %-50d ║\n", summary["domains"])
	u.colors.White.Printf("║  URLs:      %-50d ║\n", summary["urls"])
	u.colors.White.Printf("║  IPs:       %-50d ║\n", summary["ips"])
	u.colors.White.Printf("║  IP Ranges: %-50d ║\n", summary["ip_ranges"])
	u.colors.White.Printf("║  Unknown:   %-50d ║\n", summary["unknown"])
	u.colors.Green.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// ShowLiveTargetSummary displays live target summary with real-time updates
func (u *UI) ShowLiveTargetSummary(summary map[string]int, processed, total int) {
	progress := 0.0
	if total > 0 {
		progress = float64(processed) / float64(total) * 100
	}

	// Clear previous lines
	fmt.Print("\033[8K") // Clear 8 lines

	u.colors.Green.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Green.Println("║                    Target Summary (Live)                    ║")
	u.colors.Green.Println("╠══════════════════════════════════════════════════════════════╣")
	u.colors.White.Printf("║  Domains:   %-50d ║\n", summary["domains"])
	u.colors.White.Printf("║  URLs:      %-50d ║\n", summary["urls"])
	u.colors.White.Printf("║  IPs:       %-50d ║\n", summary["ips"])
	u.colors.White.Printf("║  IP Ranges: %-50d ║\n", summary["ip_ranges"])
	u.colors.White.Printf("║  Unknown:   %-50d ║\n", summary["unknown"])
	u.colors.Yellow.Printf("║  Progress:  %-50.1f%% ║\n", progress)
	u.colors.Green.Println("╚══════════════════════════════════════════════════════════════╝")

	// Move cursor up for next update
	fmt.Print("\033[8A")
}

// ShowScanResults displays scan results
func (u *UI) ShowScanResults(results []models.Vulnerability) {
	if len(results) == 0 {
		u.colors.Green.Println("  ✓ No vulnerabilities found")
		return
	}

	u.colors.Red.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Red.Println("║                  Vulnerabilities Found                      ║")
	u.colors.Red.Println("╚══════════════════════════════════════════════════════════════╝")

	for i, vuln := range results {
		u.colors.White.Printf("  %d. %s\n", i+1, vuln.Template)
		u.colors.Cyan.Printf("     Severity: %s\n", vuln.Severity)
		u.colors.Yellow.Printf("     URL: %s\n", vuln.URL)
		if vuln.Description != "" {
			u.colors.White.Printf("     Description: %s\n", vuln.Description)
		}
		fmt.Println()
	}
}

// ShowError displays an error message
func (u *UI) ShowError(message string) {
	u.colors.Red.Printf("  ✗ Error: %s\n", message)
}

// ShowSuccess displays a success message
func (u *UI) ShowSuccess(message string) {
	u.colors.Green.Printf("  ✓ %s\n", message)
}

// ShowInfo displays an info message
func (u *UI) ShowInfo(message string) {
	u.colors.Cyan.Printf("  ℹ %s\n", message)
}

// ShowWarning displays a warning message
func (u *UI) ShowWarning(message string) {
	u.colors.Yellow.Printf("  ⚠ %s\n", message)
}

// ShowProjectStatus displays project status
func (u *UI) ShowProjectStatus(project *models.Project) {
	u.colors.Orange.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Orange.Printf("║  Project Status: %-40s ║\n", project.Name)
	u.colors.Orange.Println("╠══════════════════════════════════════════════════════════════╣")
	u.colors.White.Printf("║  State: %-52s ║\n", project.State)
	u.colors.White.Printf("║  Created: %-50s ║\n", project.CreatedAt.Format("2006-01-02 15:04:05"))
	u.colors.White.Printf("║  Updated: %-50s ║\n", project.UpdatedAt.Format("2006-01-02 15:04:05"))
	u.colors.Orange.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// ShowGlobalStatus shows the status of global files
func (u *UI) ShowGlobalStatus(seclistsPath, resolversPath string, seclistsSize, resolverCount int) {
	u.colors.Blue.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Blue.Println("║                    Global Files Status                      ║")
	u.colors.Blue.Println("╠══════════════════════════════════════════════════════════════╣")

	// SecLists status
	if seclistsSize > 0 {
		u.colors.Green.Printf("║  SecLists:  ✓ %-45s ║\n", formatSize(seclistsSize))
	} else {
		u.colors.Red.Printf("║  SecLists:  ✗ Not found %-40s ║\n", "")
	}

	// Resolvers status
	if resolverCount > 0 {
		u.colors.Green.Printf("║  Resolvers: ✓ %d resolvers %-35s ║\n", resolverCount, "")
	} else {
		u.colors.Red.Printf("║  Resolvers: ✗ Not found %-40s ║\n", "")
	}

	u.colors.Blue.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// ShowUsage displays usage information
func (u *UI) ShowUsage() {
	u.colors.Cyan.Println("Usage:")
	u.colors.White.Println("  autorecon domain <domain>     Scan a single domain")
	u.colors.White.Println("  autorecon url <url>           Scan a single URL")
	u.colors.White.Println("  autorecon list <file>         Scan targets from a file")
	u.colors.White.Println("  autorecon resume <project>    Resume a paused project")
	u.colors.White.Println("  autorecon stop <project>      Stop a running project")
	u.colors.White.Println("  autorecon status              Show global files status")
	u.colors.White.Println("  autorecon install             Install required tools")
	fmt.Println()
	u.colors.Cyan.Println("Examples:")
	u.colors.White.Println("  autorecon domain example.com")
	u.colors.White.Println("  autorecon url https://example.com")
	u.colors.White.Println("  autorecon list targets.txt")
	u.colors.White.Println("  autorecon -p myproject domain example.com")
	fmt.Println()
	u.colors.Cyan.Println("Target Formats:")
	u.colors.White.Println("  Domains:   example.com, *.example.com")
	u.colors.White.Println("  URLs:      https://example.com, http://sub.example.com")
	u.colors.White.Println("  IPs:       192.168.1.1, 10.0.0.0/24")
	u.colors.White.Println("  IP Ranges: 192.168.1.1-192.168.1.254")
	fmt.Println()
}

// formatSize formats bytes into human readable format
func formatSize(bytes int) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// ClearScreen clears the terminal screen
func (u *UI) ClearScreen() {
	fmt.Print("\033[2J\033[H")
}

// ShowSpinner displays a spinning animation
func (u *UI) ShowSpinner(message string, done chan bool) {
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0

	for {
		select {
		case <-done:
			fmt.Print("\r\033[K") // Clear line
			return
		default:
			fmt.Printf("\r%s %s", spinner[i], message)
			time.Sleep(100 * time.Millisecond)
			i = (i + 1) % len(spinner)
		}
	}
}

// ShowRealTimeStats displays real-time scanning statistics
func (u *UI) ShowRealTimeStats(total, processed, found, errors int, elapsed time.Duration) {
	progress := 0.0
	if total > 0 {
		progress = float64(processed) / float64(total) * 100
	}

	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(processed) / elapsed.Seconds()
	}

	eta := time.Duration(0)
	if rate > 0 && processed < total {
		eta = time.Duration(float64(total-processed)/rate) * time.Second
	}

	// Clear previous lines
	fmt.Print("\033[6K") // Clear 6 lines

	u.colors.Cyan.Println("╔══════════════════════════════════════════════════════════════╗")
	u.colors.Cyan.Println("║                    Real-Time Statistics                     ║")
	u.colors.Cyan.Println("╠══════════════════════════════════════════════════════════════╣")
	u.colors.White.Printf("║  Progress:  %-50.1f%% ║\n", progress)
	u.colors.White.Printf("║  Processed: %d/%d %-40s ║\n", processed, total, "")
	u.colors.Green.Printf("║  Found:     %-50d ║\n", found)
	u.colors.Red.Printf("║  Errors:    %-50d ║\n", errors)
	u.colors.Yellow.Printf("║  Rate:      %.1f targets/sec %-30s ║\n", rate, "")
	u.colors.Yellow.Printf("║  Elapsed:   %s %-30s ║\n", elapsed.Round(time.Second), "")
	if eta > 0 {
		u.colors.Yellow.Printf("║  ETA:       %s %-30s ║\n", eta.Round(time.Second), "")
	}
	u.colors.Cyan.Println("╚══════════════════════════════════════════════════════════════╝")

	// Move cursor up for next update
	fmt.Print("\033[9A")
}

// UpdateDashboard updates the dashboard with current scan progress
func (u *UI) UpdateDashboard(stats *models.ScanStats, dbSummary *database.TargetSummary, validationSummary *database.ValidationSummary) {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	// Print banner
	u.ShowBanner()

	// Print scan progress
	fmt.Printf("\n\x1b[1;36m[SCAN PROGRESS]\x1b[0m\n")
	fmt.Printf("Current Step: %s\n", stats.CurrentStep)
	fmt.Printf("Progress: %d/%d steps completed\n", stats.CompletedSteps, stats.TotalSteps)

	// Print target statistics
	fmt.Printf("\n\x1b[1;32m[TARGET STATISTICS]\x1b[0m\n")
	fmt.Printf("Initial Targets: %d\n", stats.InitialTargets)
	fmt.Printf("Discovered Targets: %d\n", stats.DiscoveredTargets)
	fmt.Printf("Total Targets: %d\n", stats.TotalTargets)

	// Print database summary if available
	if dbSummary != nil {
		fmt.Printf("Database Targets: %d\n", dbSummary.TotalTargets)
		fmt.Printf("Total Ports Found: %d\n", dbSummary.TotalPortsFound)
	}

	// Print validation summary if available
	if validationSummary != nil {
		fmt.Printf("\n\x1b[1;33m[VALIDATION STATISTICS]\x1b[0m\n")
		fmt.Printf("Validated Targets: %d/%d (%.1f%%)\n",
			validationSummary.ValidatedTargets, validationSummary.TotalTargets,
			float64(validationSummary.ValidatedTargets)/float64(validationSummary.TotalTargets)*100)
		fmt.Printf("Average Validation Score: %.2f\n", validationSummary.AverageScore)
		fmt.Printf("Score Distribution:\n")
		fmt.Printf("  High (0.8+): %d targets\n", validationSummary.ScoreRanges["high"])
		fmt.Printf("  Medium (0.6+): %d targets\n", validationSummary.ScoreRanges["medium"])
		fmt.Printf("  Low (0.4+): %d targets\n", validationSummary.ScoreRanges["low"])
		fmt.Printf("  Very Low (<0.4): %d targets\n", validationSummary.ScoreRanges["very_low"])
	}

	// Print step details
	fmt.Printf("\n\x1b[1;35m[STEP DETAILS]\x1b[0m\n")
	for step, status := range stats.StepStatus {
		statusColor := "\x1b[32m" // Green for completed
		if status == "running" {
			statusColor = "\x1b[33m" // Yellow for running
		} else if status == "pending" {
			statusColor = "\x1b[37m" // White for pending
		}
		fmt.Printf("%s: %s%s\x1b[0m\n", step, statusColor, status)
	}

	// Print recent discoveries
	if len(stats.RecentDiscoveries) > 0 {
		fmt.Printf("\n\x1b[1;34m[RECENT DISCOVERIES]\x1b[0m\n")
		for i, discovery := range stats.RecentDiscoveries {
			if i >= 5 { // Show only last 5 discoveries
				break
			}
			fmt.Printf("• %s (%s)\n", discovery.Value, discovery.Source)
		}
	}

	fmt.Printf("\n\x1b[1;31mPress Ctrl+C to stop scan\x1b[0m\n")
}

// ShowLiveStepProgress updates a specific step in the dashboard
func (u *UI) ShowLiveStepProgress(stepNum int, status string, progress float64, message string) {
	// For now, just update the entire dashboard to avoid cursor positioning issues
	// This will be called from the scanner with project data
}

// ShowLiveResults updates the results summary in the dashboard
func (u *UI) ShowLiveResults(subdomains, urls, ports, vulns int) {
	// For now, just update the entire dashboard to avoid cursor positioning issues
	// This will be called from the scanner with project data
}

// ShowLiveStats updates the statistics in the dashboard
func (u *UI) ShowLiveStats(stats ScanStats) {
	// For now, just update the entire dashboard to avoid cursor positioning issues
	// This will be called from the scanner with project data
}
