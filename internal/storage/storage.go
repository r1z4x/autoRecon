package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Storage handles global file management
type Storage struct {
	globalDataDir string
}

// NewStorage creates a new storage instance
func NewStorage(globalDataDir string) *Storage {
	return &Storage{
		globalDataDir: globalDataDir,
	}
}

// CreateProjectStructure creates the new project directory structure
func (s *Storage) CreateProjectStructure(projectDir string) error {
	// Create main project directory
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	// Create logs directory for all tool outputs
	logsDir := filepath.Join(projectDir, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Create subdirectories for different tool types
	toolDirs := []string{"subfinder", "naabu", "nuclei", "ssl_discovery", "asn_discovery"}
	for _, tool := range toolDirs {
		toolDir := filepath.Join(logsDir, tool)
		if err := os.MkdirAll(toolDir, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", tool, err)
		}
	}

	return nil
}

// SaveTargets saves all targets to a single targets.json file
func (s *Storage) SaveTargets(projectDir string, targets interface{}) error {
	targetsFile := filepath.Join(projectDir, "targets.json")

	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal targets: %w", err)
	}

	if err := os.WriteFile(targetsFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write targets file: %w", err)
	}

	return nil
}

// LoadTargets loads targets from targets.json file
func (s *Storage) LoadTargets(projectDir string, targets interface{}) error {
	targetsFile := filepath.Join(projectDir, "targets.json")

	data, err := os.ReadFile(targetsFile)
	if err != nil {
		return fmt.Errorf("failed to read targets file: %w", err)
	}

	if err := json.Unmarshal(data, targets); err != nil {
		return fmt.Errorf("failed to unmarshal targets: %w", err)
	}

	return nil
}

// SaveToolLog saves tool output to the logs directory
func (s *Storage) SaveToolLog(projectDir, toolName, filename, content string) error {
	logsDir := filepath.Join(projectDir, "logs", toolName)

	// Ensure tool directory exists
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create tool directory: %w", err)
	}

	logFile := filepath.Join(logsDir, filename)
	if err := os.WriteFile(logFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write log file: %w", err)
	}

	return nil
}

// GetLogsDir returns the logs directory path for a project
func (s *Storage) GetLogsDir(projectDir string) string {
	return filepath.Join(projectDir, "logs")
}

// GetToolLogsDir returns the specific tool logs directory
func (s *Storage) GetToolLogsDir(projectDir, toolName string) string {
	return filepath.Join(projectDir, "logs", toolName)
}

// DownloadSecLists downloads SecLists repository
func (s *Storage) DownloadSecLists() error {
	seclistsPath := filepath.Join(s.globalDataDir, "Seclists")

	// Check if already exists
	if _, err := os.Stat(seclistsPath); err == nil {
		return nil // Already exists
	}

	// Clone repository
	cmd := exec.Command("git", "clone", "https://github.com/danielmiessler/SecLists.git", seclistsPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clone SecLists: %w", err)
	}

	return nil
}

// DownloadResolvers downloads trusted resolvers
func (s *Storage) DownloadResolvers() error {
	resolversPath := filepath.Join(s.globalDataDir, "Resolvers", "resolvers-trusted.txt")

	// Check if already exists
	if _, err := os.Stat(resolversPath); err == nil {
		return nil // Already exists
	}

	// Create resolvers directory
	resolversDir := filepath.Dir(resolversPath)
	if err := os.MkdirAll(resolversDir, 0755); err != nil {
		return fmt.Errorf("failed to create resolvers directory: %w", err)
	}

	// Download resolvers
	cmd := exec.Command("curl", "-L", "-o", resolversPath, "https://raw.githubusercontent.com/projectdiscovery/dnsx/main/scripts/resolvers-trusted.txt")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Fallback to default resolvers
		return s.createDefaultResolvers(resolversPath)
	}

	return nil
}

// createDefaultResolvers creates default resolver list
func (s *Storage) createDefaultResolvers(path string) error {
	defaultResolvers := `8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
208.67.222.222
208.67.220.220`

	if err := os.WriteFile(path, []byte(defaultResolvers), 0644); err != nil {
		return fmt.Errorf("failed to create default resolvers: %w", err)
	}

	return nil
}

// GetSecListsPath returns the path to SecLists
func (s *Storage) GetSecListsPath() string {
	return filepath.Join(s.globalDataDir, "Seclists")
}

// GetResolversPath returns the path to resolvers
func (s *Storage) GetResolversPath() string {
	return filepath.Join(s.globalDataDir, "Resolvers", "resolvers-trusted.txt")
}

// GetGlobalDataDir returns the global data directory
func (s *Storage) GetGlobalDataDir() string {
	return s.globalDataDir
}

// CheckSecListsExists checks if SecLists exists
func (s *Storage) CheckSecListsExists() bool {
	_, err := os.Stat(s.GetSecListsPath())
	return err == nil
}

// CheckResolversExists checks if resolvers exist
func (s *Storage) CheckResolversExists() bool {
	_, err := os.Stat(s.GetResolversPath())
	return err == nil
}

// GetSecListsSize returns the size of SecLists directory
func (s *Storage) GetSecListsSize() (int64, error) {
	var size int64
	err := filepath.Walk(s.GetSecListsPath(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// GetResolverCount returns the number of resolvers
func (s *Storage) GetResolverCount() (int, error) {
	data, err := os.ReadFile(s.GetResolversPath())
	if err != nil {
		return 0, err
	}

	lines := 0
	for _, char := range data {
		if char == '\n' {
			lines++
		}
	}

	return lines, nil
}
