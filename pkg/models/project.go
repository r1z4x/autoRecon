package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ProjectState represents the current state of a project
type ProjectState string

const (
	ProjectStateNew       ProjectState = "new"
	ProjectStateParsed    ProjectState = "parsed"
	ProjectStateExpanded  ProjectState = "expanded"
	ProjectStateScanning  ProjectState = "scanning"
	ProjectStateCompleted ProjectState = "completed"
	ProjectStatePaused    ProjectState = "paused"
	ProjectStateStopped   ProjectState = "stopped"
	ProjectStateError     ProjectState = "error"
)

// Project represents a scanning project
type Project struct {
	Name        string       `json:"name" yaml:"name"`
	State       ProjectState `json:"state" yaml:"state"`
	CreatedAt   time.Time    `json:"created_at" yaml:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at" yaml:"updated_at"`
	StartedAt   *time.Time   `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	CompletedAt *time.Time   `json:"completed_at,omitempty" yaml:"completed_at,omitempty"`

	// Configuration
	Config ProjectConfig `json:"config" yaml:"config"`

	// Targets
	Targets TargetList `json:"targets" yaml:"targets"`

	// Results
	Results ProjectResults `json:"results" yaml:"results"`

	// Progress tracking
	Progress ProgressTracker `json:"progress" yaml:"progress"`

	// File paths
	BaseDir string `json:"base_dir" yaml:"base_dir"`
}

// ProjectConfig holds project configuration
type ProjectConfig struct {
	// Scan settings
	RateLimit      int      `json:"rate_limit" yaml:"rate_limit"`
	StatusCodes    []string `json:"status_codes" yaml:"status_codes"`
	SeverityLevels []string `json:"severity_levels" yaml:"severity_levels"`

	// Tool settings
	UseProxychains bool `json:"use_proxychains" yaml:"use_proxychains"`
	UseNucleiCloud bool `json:"use_nuclei_cloud" yaml:"use_nuclei_cloud"`

	// Wordlists and resolvers
	DNSXWordlist string `json:"dnsx_wordlist" yaml:"dnsx_wordlist"`
	ResolverList string `json:"resolver_list" yaml:"resolver_list"`

	// Custom headers
	CustomHeaders map[string]string `json:"custom_headers" yaml:"custom_headers"`
}

// ProjectResults holds all scan results
type ProjectResults struct {
	Subdomains []string `json:"subdomains" yaml:"subdomains"`
	OpenPorts  []string `json:"open_ports" yaml:"open_ports"`
	Logs       []string `json:"logs" yaml:"logs"`
}

// ProgressTracker tracks scanning progress
type ProgressTracker struct {
	CurrentStep    string  `json:"current_step" yaml:"current_step"`
	TotalSteps     int     `json:"total_steps" yaml:"total_steps"`
	CurrentStepNum int     `json:"current_step_num" yaml:"current_step_num"`
	Progress       float64 `json:"progress" yaml:"progress"`

	// Step details
	Steps []StepProgress `json:"steps" yaml:"steps"`
}

// StepProgress tracks progress of individual steps
type StepProgress struct {
	Name      string     `json:"name" yaml:"name"`
	Status    string     `json:"status" yaml:"status"` // pending, running, completed, failed
	StartedAt *time.Time `json:"started_at,omitempty" yaml:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty" yaml:"ended_at,omitempty"`
	Progress  float64    `json:"progress" yaml:"progress"`
	Message   string     `json:"message" yaml:"message"`
}

// ScanStats represents scan statistics
type ScanStats struct {
	CurrentStep       string
	CompletedSteps    int
	TotalSteps        int
	InitialTargets    int
	DiscoveredTargets int
	TotalTargets      int
	StepStatus        map[string]string
	RecentDiscoveries []Target
}

// NewProject creates a new project
func NewProject(name string, baseDir string) *Project {
	now := time.Now()
	return &Project{
		Name:      name,
		State:     ProjectStateNew,
		CreatedAt: now,
		UpdatedAt: now,
		BaseDir:   baseDir,
		Config: ProjectConfig{
			RateLimit:      5,
			StatusCodes:    []string{"200", "201", "202", "203", "204", "206", "301", "302", "303", "307", "308"},
			SeverityLevels: []string{},
			UseProxychains: false,
			UseNucleiCloud: false,
			CustomHeaders:  make(map[string]string),
		},
		Progress: ProgressTracker{
			TotalSteps: 5, // parse, expand, subfinder, port scan, ssl discovery
			Steps: []StepProgress{
				{Name: "Parse Targets", Status: "pending"},
				{Name: "Expand IP Ranges", Status: "pending"},
				{Name: "Subdomain Discovery", Status: "pending"},
				{Name: "Port Scanning", Status: "pending"},
				{Name: "SSL Discovery", Status: "pending"},
			},
		},
	}
}

// Save saves the project to disk
func (p *Project) Save() error {
	p.UpdatedAt = time.Now()

	// Create project directory
	projectDir := filepath.Join(p.BaseDir, p.Name)
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	// Save project state
	stateFile := filepath.Join(projectDir, "project.json")
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal project: %w", err)
	}

	if err := os.WriteFile(stateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write project file: %w", err)
	}

	return nil
}

// Load loads a project from disk
func LoadProject(name string, baseDir string) (*Project, error) {
	projectDir := filepath.Join(baseDir, name)
	stateFile := filepath.Join(projectDir, "project.json")

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read project file: %w", err)
	}

	var project Project
	if err := json.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("failed to unmarshal project: %w", err)
	}

	return &project, nil
}

// UpdateState updates the project state
func (p *Project) UpdateState(state ProjectState) {
	p.State = state
	p.UpdatedAt = time.Now()

	switch state {
	case ProjectStateScanning:
		if p.StartedAt == nil {
			now := time.Now()
			p.StartedAt = &now
		}
	case ProjectStateCompleted:
		now := time.Now()
		p.CompletedAt = &now
	}
}

// UpdateStepProgress updates the progress of a specific step
func (p *Project) UpdateStepProgress(stepIndex int, status string, progress float64, message string) {
	if stepIndex >= 0 && stepIndex < len(p.Progress.Steps) {
		now := time.Now()
		step := &p.Progress.Steps[stepIndex]
		step.Status = status
		step.Progress = progress
		step.Message = message

		if status == "running" && step.StartedAt == nil {
			step.StartedAt = &now
		} else if status == "completed" || status == "failed" {
			step.EndedAt = &now
		}

		p.Progress.CurrentStep = step.Name
		p.Progress.CurrentStepNum = stepIndex + 1
		p.Progress.Progress = float64(stepIndex+1) / float64(p.Progress.TotalSteps)
	}
}

// GetProjectDir returns the project directory path
func (p *Project) GetProjectDir() string {
	return filepath.Join(p.BaseDir, p.Name)
}

// GetResultsDir returns the results directory path
func (p *Project) GetResultsDir() string {
	return filepath.Join(p.GetProjectDir(), "results")
}

// GetLogsDir returns the logs directory path
func (p *Project) GetLogsDir() string {
	return filepath.Join(p.GetProjectDir(), "logs")
}

// CanResume checks if the project can be resumed
func (p *Project) CanResume() bool {
	return p.State == ProjectStatePaused || p.State == ProjectStateScanning
}

// CanStop checks if the project can be stopped
func (p *Project) CanStop() bool {
	return p.State == ProjectStateScanning
}
