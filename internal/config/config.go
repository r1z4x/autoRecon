package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config holds application configuration
type Config struct {
	// Global data directory
	GlobalDataDir string

	// Project directory
	ProjectsDir string

	// Tool paths
	DNSXWordlist string
	ResolverList string

	// Scan settings
	RateLimit      int
	StatusCodes    []string
	SeverityLevels []string

	// Multi-threading settings
	MaxWorkers int // Number of concurrent workers per tool
	BatchSize  int // Number of targets per batch

	// Tool settings
	UseProxychains bool
	UseNucleiCloud bool

	// Custom headers
	CustomHeaders map[string]string
}

// NewConfig creates a new configuration instance
func NewConfig() *Config {
	config := &Config{
		GlobalDataDir:  "/opt",
		ProjectsDir:    "./projects",
		RateLimit:      5,
		StatusCodes:    []string{"200", "201", "202", "203", "204", "206", "301", "302", "303", "307", "308"},
		SeverityLevels: []string{},
		MaxWorkers:     5,  // Default to 5 concurrent workers
		BatchSize:      10, // Default to 10 targets per batch
		UseProxychains: false,
		UseNucleiCloud: false,
		CustomHeaders:  make(map[string]string),
	}

	// Set default paths
	config.DNSXWordlist = filepath.Join(config.GlobalDataDir, "Seclists", "Discovery", "DNS", "subdomains-top1million-5000.txt")
	config.ResolverList = filepath.Join(config.GlobalDataDir, "Resolvers", "resolvers-trusted.txt")

	// Set default custom headers
	config.CustomHeaders["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	// config.CustomHeaders["x-bugcrowd-research"] = "researcher@autorecon"

	// Ensure directories exist
	config.ensureDirectories()

	// Setup PATH for Go tools
	config.setupPath()

	return config
}

// setupPath adds Go bin directories to PATH
func (c *Config) setupPath() {
	// Add common Go bin paths to PATH
	goPaths := []string{
		filepath.Join(os.Getenv("HOME"), "go", "bin"),
		"/usr/local/go/bin",
		"/opt/homebrew/bin",
	}

	currentPath := os.Getenv("PATH")
	for _, goPath := range goPaths {
		if _, err := os.Stat(goPath); err == nil {
			if !strings.Contains(currentPath, goPath) {
				os.Setenv("PATH", goPath+":"+currentPath)
			}
		}
	}
}

// ensureDirectories creates necessary directories
func (c *Config) ensureDirectories() error {
	dirs := []string{
		c.GlobalDataDir,
		c.ProjectsDir,
		filepath.Join(c.GlobalDataDir, "Resolvers"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// CheckRequiredTools checks if all required tools are available
func (c *Config) CheckRequiredTools() error {
	requiredTools := []string{"subfinder", "dnsx", "httpx", "nuclei", "naabu"}
	var missingTools []string

	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingTools = append(missingTools, tool)
		}
	}

	if len(missingTools) > 0 {
		return fmt.Errorf("missing required tools: %s. Please install them with: go install -v github.com/projectdiscovery/%s/cmd/%s@latest",
			strings.Join(missingTools, ", "),
			missingTools[0],
			missingTools[0])
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Check if SecLists exists
	if _, err := os.Stat(filepath.Join(c.GlobalDataDir, "Seclists")); os.IsNotExist(err) {
		return fmt.Errorf("SecLists not found in %s. Please run: sudo git clone https://github.com/danielmiessler/SecLists.git %s",
			c.GlobalDataDir, filepath.Join(c.GlobalDataDir, "Seclists"))
	}

	// Check if resolvers exist
	if _, err := os.Stat(c.ResolverList); os.IsNotExist(err) {
		return fmt.Errorf("resolver list not found: %s. Please run: sudo curl -L -o %s https://raw.githubusercontent.com/projectdiscovery/dnsx/main/scripts/resolvers-trusted.txt",
			c.ResolverList, c.ResolverList)
	}

	// Check if DNSX wordlist exists
	if _, err := os.Stat(c.DNSXWordlist); os.IsNotExist(err) {
		return fmt.Errorf("DNSX wordlist not found: %s", c.DNSXWordlist)
	}

	return nil
}

// GetStatusCodesString returns status codes as comma-separated string
func (c *Config) GetStatusCodesString() string {
	return strings.Join(c.StatusCodes, ",")
}

// GetSeverityLevelsString returns severity levels as comma-separated string
func (c *Config) GetSeverityLevelsString() string {
	return strings.Join(c.SeverityLevels, ",")
}
