package database

// Target represents a target in the database
type Target struct {
	ID           int64    `json:"id"`
	Value        string   `json:"value"`
	Type         string   `json:"type"`
	Source       string   `json:"source"`
	DiscoveredAt string   `json:"discovered_at"`
	Status       string   `json:"status"`
	Ports        []Port   `json:"ports,omitempty"`
	IPs          []string `json:"ips,omitempty"` // Resolved IP addresses
}

// Port represents a port in the database
type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
}

// ScanLog represents a scan log entry
type ScanLog struct {
	ID        int64  `json:"id"`
	ToolName  string `json:"tool_name"`
	TargetID  *int64 `json:"target_id,omitempty"`
	LogFile   string `json:"log_file"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
}

// TargetSummary provides summary statistics
type TargetSummary struct {
	TotalTargets    int            `json:"total_targets"`
	ByType          map[string]int `json:"by_type"`
	BySource        map[string]int `json:"by_source"`
	TotalPortsFound int            `json:"total_ports_found"`
}

// TargetValidation represents target validation information
type TargetValidation struct {
	ID                int64   `json:"id"`
	TargetID          int64   `json:"target_id"`
	BaseDomain        string  `json:"base_domain"`
	ValidationScore   float64 `json:"validation_score"`
	ValidationMethods string  `json:"validation_methods"`
	IsValidated       bool    `json:"is_validated"`
	ValidationNotes   string  `json:"validation_notes"`
	CreatedAt         string  `json:"created_at"`
}

// ValidationSummary provides validation statistics
type ValidationSummary struct {
	TotalTargets     int            `json:"total_targets"`
	ValidatedTargets int            `json:"validated_targets"`
	AverageScore     float64        `json:"average_score"`
	ScoreRanges      map[string]int `json:"score_ranges"`
}
