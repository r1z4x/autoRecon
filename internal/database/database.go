package database

import (
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database handles SQLite database operations
type Database struct {
	db *sql.DB
}

// NewDatabase creates a new database connection
func NewDatabase(projectDir string) (*Database, error) {
	dbPath := filepath.Join(projectDir, "autorecon.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	database := &Database{db: db}

	// Initialize tables
	if err := database.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return database, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// initTables creates all necessary tables
func (d *Database) initTables() error {
	// Create targets table
	targetsTable := `
	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		value TEXT UNIQUE NOT NULL,
		type TEXT NOT NULL,
		source TEXT NOT NULL,
		discovered_at TEXT NOT NULL,
		status TEXT DEFAULT 'discovered',
		updated_at TEXT
	);`

	// Create target_ips table for storing IP information
	targetIPsTable := `
	CREATE TABLE IF NOT EXISTS target_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		ip_address TEXT NOT NULL,
		source TEXT NOT NULL,
		discovered_at TEXT NOT NULL,
		FOREIGN KEY (target_id) REFERENCES targets (id),
		UNIQUE(target_id, ip_address)
	);`

	// Create ports table
	portsTable := `
	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		port INTEGER NOT NULL,
		service TEXT,
		version TEXT,
		discovered_at TEXT NOT NULL,
		FOREIGN KEY (target_id) REFERENCES targets (id),
		UNIQUE(target_id, port)
	);`

	// Create target_validation table
	validationTable := `
	CREATE TABLE IF NOT EXISTS target_validation (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		base_domain TEXT NOT NULL,
		validation_score REAL NOT NULL,
		validation_methods TEXT NOT NULL,
		is_validated BOOLEAN DEFAULT FALSE,
		validation_notes TEXT,
		created_at TEXT NOT NULL,
		FOREIGN KEY (target_id) REFERENCES targets (id)
	);`

	// Create scan_logs table
	logsTable := `
	CREATE TABLE IF NOT EXISTS scan_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tool_name TEXT NOT NULL,
		target_id INTEGER,
		log_file TEXT NOT NULL,
		content TEXT,
		created_at TEXT NOT NULL,
		FOREIGN KEY (target_id) REFERENCES targets (id)
	);`

	// Execute table creation
	tables := []string{targetsTable, targetIPsTable, portsTable, validationTable, logsTable}
	for _, table := range tables {
		if _, err := d.db.Exec(table); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

// AddTarget adds a new target to the database
func (d *Database) AddTarget(value, targetType, source string) (int64, error) {
	query := `INSERT INTO targets (value, type, source, discovered_at, status) VALUES (?, ?, ?, ?, ?)`

	result, err := d.db.Exec(query, value, targetType, source, time.Now().Format(time.RFC3339), "discovered")
	if err != nil {
		return 0, fmt.Errorf("failed to add target: %w", err)
	}

	targetID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get target ID: %w", err)
	}

	// If it's a domain, automatically resolve and store IP information
	if targetType == "domain" {
		go d.resolveAndStoreDomainIPs(targetID, value)
	}

	return targetID, nil
}

// resolveAndStoreDomainIPs resolves domain to IPs and stores them
func (d *Database) resolveAndStoreDomainIPs(targetID int64, domain string) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			// Store IP information
			d.AddTargetIP(targetID, ipv4.String(), "resolved")
		}
	}
}

// AddTargetIP adds IP information for a target
func (d *Database) AddTargetIP(targetID int64, ip, source string) error {
	query := `INSERT OR IGNORE INTO target_ips (target_id, ip_address, source, discovered_at) VALUES (?, ?, ?, ?)`

	_, err := d.db.Exec(query, targetID, ip, source, time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to add target IP: %w", err)
	}

	return nil
}

// GetTargetIPs retrieves IP addresses for a target
func (d *Database) GetTargetIPs(targetID int64) ([]string, error) {
	query := `SELECT ip_address FROM target_ips WHERE target_id = ?`

	rows, err := d.db.Query(query, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to query target IPs: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// GetTargetByValue retrieves a target by its value
func (d *Database) GetTargetByValue(value string) (*Target, error) {
	query := `SELECT id, value, type, source, discovered_at, status FROM targets WHERE value = ?`

	var target Target
	err := d.db.QueryRow(query, value).Scan(&target.ID, &target.Value, &target.Type, &target.Source, &target.DiscoveredAt, &target.Status)
	if err != nil {
		return nil, fmt.Errorf("target not found: %w", err)
	}

	// Get ports for this target
	ports, err := d.GetTargetPorts(target.ID)
	if err != nil {
		return nil, err
	}
	target.Ports = ports

	// Get IPs for this target
	ips, err := d.GetTargetIPs(target.ID)
	if err != nil {
		return nil, err
	}
	target.IPs = ips

	return &target, nil
}

// GetAllTargets retrieves all targets
func (d *Database) GetAllTargets() ([]Target, error) {
	query := `SELECT id, value, type, source, discovered_at, status FROM targets ORDER BY discovered_at DESC`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query targets: %w", err)
	}
	defer rows.Close()

	var targets []Target
	for rows.Next() {
		var target Target
		err := rows.Scan(&target.ID, &target.Value, &target.Type, &target.Source, &target.DiscoveredAt, &target.Status)
		if err != nil {
			return nil, err
		}

		// Get ports for this target
		ports, err := d.GetTargetPorts(target.ID)
		if err != nil {
			return nil, err
		}
		target.Ports = ports

		targets = append(targets, target)
	}

	return targets, nil
}

// AddPort adds a port to a target
func (d *Database) AddPort(targetID int64, port int, service, version string) error {
	query := `
	INSERT OR REPLACE INTO ports (target_id, port, service, version)
	VALUES (?, ?, ?, ?)`

	_, err := d.db.Exec(query, targetID, port, service, version)
	if err != nil {
		return fmt.Errorf("failed to add port: %w", err)
	}

	return nil
}

// GetTargetPorts retrieves all ports for a target
func (d *Database) GetTargetPorts(targetID int64) ([]Port, error) {
	query := `SELECT port, service, version FROM ports WHERE target_id = ? ORDER BY port`

	rows, err := d.db.Query(query, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to query ports: %w", err)
	}
	defer rows.Close()

	var ports []Port
	for rows.Next() {
		var port Port
		err := rows.Scan(&port.Port, &port.Service, &port.Version)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}

	return ports, nil
}

// AddScanLog adds a scan log entry
func (d *Database) AddScanLog(toolName string, targetID *int64, logFile, content string) error {
	query := `
	INSERT INTO scan_logs (tool_name, target_id, log_file, content)
	VALUES (?, ?, ?, ?)`

	_, err := d.db.Exec(query, toolName, targetID, logFile, content)
	if err != nil {
		return fmt.Errorf("failed to add scan log: %w", err)
	}

	return nil
}

// GetScanLogs retrieves scan logs
func (d *Database) GetScanLogs(toolName string) ([]ScanLog, error) {
	query := `SELECT id, tool_name, target_id, log_file, content, created_at FROM scan_logs WHERE tool_name = ? ORDER BY created_at DESC`

	rows, err := d.db.Query(query, toolName)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan logs: %w", err)
	}
	defer rows.Close()

	var logs []ScanLog
	for rows.Next() {
		var log ScanLog
		err := rows.Scan(&log.ID, &log.ToolName, &log.TargetID, &log.LogFile, &log.Content, &log.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// GetTargetSummary returns target statistics
func (d *Database) GetTargetSummary() (*TargetSummary, error) {
	// Total targets
	var totalTargets int
	err := d.db.QueryRow("SELECT COUNT(*) FROM targets").Scan(&totalTargets)
	if err != nil {
		return nil, err
	}

	// By type
	typeQuery := `SELECT type, COUNT(*) FROM targets GROUP BY type`
	rows, err := d.db.Query(typeQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byType := make(map[string]int)
	for rows.Next() {
		var targetType string
		var count int
		err := rows.Scan(&targetType, &count)
		if err != nil {
			return nil, err
		}
		byType[targetType] = count
	}

	// By source
	sourceQuery := `SELECT source, COUNT(*) FROM targets GROUP BY source`
	rows, err = d.db.Query(sourceQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bySource := make(map[string]int)
	for rows.Next() {
		var source string
		var count int
		err := rows.Scan(&source, &count)
		if err != nil {
			return nil, err
		}
		bySource[source] = count
	}

	// Total ports
	var totalPorts int
	err = d.db.QueryRow("SELECT COUNT(*) FROM ports").Scan(&totalPorts)
	if err != nil {
		return nil, err
	}

	return &TargetSummary{
		TotalTargets:    totalTargets,
		ByType:          byType,
		BySource:        bySource,
		TotalPortsFound: totalPorts,
	}, nil
}

// UpdateTargetStatus updates target status
func (d *Database) UpdateTargetStatus(targetID int64, status string) error {
	query := `UPDATE targets SET status = ?, updated_at = ? WHERE id = ?`

	_, err := d.db.Exec(query, status, time.Now().Format(time.RFC3339), targetID)
	if err != nil {
		return fmt.Errorf("failed to update target status: %w", err)
	}

	return nil
}

// AddTargetValidation adds validation information for a target
func (d *Database) AddTargetValidation(targetID int64, baseDomain string, score float64, methods, notes string) error {
	query := `
	INSERT OR REPLACE INTO target_validation (target_id, base_domain, validation_score, validation_methods, validation_notes, is_validated)
	VALUES (?, ?, ?, ?, ?, ?)`

	isValidated := score >= 0.3 // 30% threshold for validation (much lower)

	_, err := d.db.Exec(query, targetID, baseDomain, score, methods, notes, isValidated)
	if err != nil {
		return fmt.Errorf("failed to add target validation: %w", err)
	}

	return nil
}

// GetTargetValidation retrieves validation information for a target
func (d *Database) GetTargetValidation(targetID int64) (*TargetValidation, error) {
	query := `SELECT id, target_id, base_domain, validation_score, validation_methods, is_validated, validation_notes, created_at FROM target_validation WHERE target_id = ?`

	var validation TargetValidation
	err := d.db.QueryRow(query, targetID).Scan(&validation.ID, &validation.TargetID, &validation.BaseDomain, &validation.ValidationScore, &validation.ValidationMethods, &validation.IsValidated, &validation.ValidationNotes, &validation.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &validation, nil
}

// GetValidatedTargets retrieves only validated targets
func (d *Database) GetValidatedTargets() ([]Target, error) {
	query := `
	SELECT t.id, t.value, t.type, t.source, t.discovered_at, t.status 
	FROM targets t 
	JOIN target_validation tv ON t.id = tv.target_id 
	WHERE tv.is_validated = TRUE 
	ORDER BY tv.validation_score DESC`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query validated targets: %w", err)
	}
	defer rows.Close()

	var targets []Target
	for rows.Next() {
		var target Target
		err := rows.Scan(&target.ID, &target.Value, &target.Type, &target.Source, &target.DiscoveredAt, &target.Status)
		if err != nil {
			return nil, err
		}

		// Get ports for this target
		ports, err := d.GetTargetPorts(target.ID)
		if err != nil {
			return nil, err
		}
		target.Ports = ports

		targets = append(targets, target)
	}

	return targets, nil
}

// GetTargetValidationSummary returns validation statistics
func (d *Database) GetTargetValidationSummary() (*ValidationSummary, error) {
	// Total targets
	var totalTargets int
	err := d.db.QueryRow("SELECT COUNT(*) FROM targets").Scan(&totalTargets)
	if err != nil {
		return nil, err
	}

	// Validated targets
	var validatedTargets int
	err = d.db.QueryRow("SELECT COUNT(*) FROM target_validation WHERE is_validated = TRUE").Scan(&validatedTargets)
	if err != nil {
		return nil, err
	}

	// Average validation score
	var avgScore float64
	err = d.db.QueryRow("SELECT AVG(validation_score) FROM target_validation").Scan(&avgScore)
	if err != nil {
		avgScore = 0.0
	}

	// By validation score ranges
	scoreRanges := map[string]int{
		"high":     0, // 0.8-1.0
		"medium":   0, // 0.6-0.79
		"low":      0, // 0.4-0.59
		"very_low": 0, // 0.0-0.39
	}

	// Count by score ranges
	scoreQuery := `
	SELECT 
		SUM(CASE WHEN validation_score >= 0.8 THEN 1 ELSE 0 END) as high,
		SUM(CASE WHEN validation_score >= 0.6 AND validation_score < 0.8 THEN 1 ELSE 0 END) as medium,
		SUM(CASE WHEN validation_score >= 0.4 AND validation_score < 0.6 THEN 1 ELSE 0 END) as low,
		SUM(CASE WHEN validation_score < 0.4 THEN 1 ELSE 0 END) as very_low
	FROM target_validation`

	var high, medium, low, veryLow int
	err = d.db.QueryRow(scoreQuery).Scan(&high, &medium, &low, &veryLow)
	if err == nil {
		scoreRanges["high"] = high
		scoreRanges["medium"] = medium
		scoreRanges["low"] = low
		scoreRanges["very_low"] = veryLow
	}

	return &ValidationSummary{
		TotalTargets:     totalTargets,
		ValidatedTargets: validatedTargets,
		AverageScore:     avgScore,
		ScoreRanges:      scoreRanges,
	}, nil
}

// GetTargetsWithPorts retrieves targets that have open ports
func (d *Database) GetTargetsWithPorts() ([]string, error) {
	query := `
	SELECT DISTINCT t.value 
	FROM targets t 
	JOIN ports p ON t.id = p.target_id 
	WHERE p.port > 0`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query targets with ports: %w", err)
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var target string
		err := rows.Scan(&target)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}

	return targets, nil
}
