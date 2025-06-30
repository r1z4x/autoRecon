# AutoRecon - Go Edition

AutoRecon is a comprehensive security reconnaissance tool written in Go that automates the process of discovering subdomains, validating URLs, scanning ports, and identifying vulnerabilities using various security tools.

## Features

### 🎯 **Advanced Input Support**
- **Single domain**: `autorecon domain example.com`
- **Single URL**: `autorecon url https://example.com`
- **Target list**: `autorecon list targets.txt`
- **Project-based**: `autorecon -p myproject domain example.com`

### 📊 **Project Management**
- **Resume scans**: `autorecon resume myproject`
- **Stop scans**: `autorecon stop myproject`
- **Status check**: `autorecon status`

### 🔍 **Target Categorization**
Automatically parses and categorizes:
- **Domains** (example.com)
- **URLs** (https://example.com)
- **IPs** (192.168.1.1)
- **IP ranges** (192.168.1.0/24, 192.168.1.1-192.168.1.10)

### 🏗️ **Modular Architecture**
- **Parser Module**: Handles target parsing and categorization
- **Scanner Module**: Manages different scanning tools (subfinder, httpx, naabu, nuclei)
- **Storage Module**: Handles global file management
- **UI Module**: Provides progress bars, loading indicators, and step-by-step progress
- **Config Module**: Manages application configuration

### 📈 **Real-time Progress Tracking**
- Step-by-step progress display
- Loading animations
- Progress bars
- Project state management
- Pause/Resume functionality

### 🌐 **Global Storage**
- SecLists stored in `/opt/autorecon/SecLists`
- Resolvers stored in `/opt/autorecon/resolvers`
- Symbolic links created for easy access

## Installation

### Prerequisites
- Go 1.21 or later
- Git
- sudo access (for global file installation)

### Quick Setup

1. **Clone and build:**
```bash
git clone <repository-url>
cd autorecon
go mod tidy
go build -o autorecon cmd/autorecon/main.go
```

2. **Install required tools:**
```bash
./autorecon install
```

3. **Add Go bin to PATH (add to your shell profile):**
```bash
export PATH="$HOME/go/bin:$PATH"
```

4. **Install global dependencies:**
```bash
# Install SecLists
sudo mkdir -p /opt/autorecon
sudo git clone https://github.com/danielmiessler/SecLists.git /opt/autorecon/SecLists

# Install resolvers
sudo mkdir -p /opt/autorecon/resolvers
sudo curl -L -o /opt/autorecon/resolvers/resolvers-trusted.txt "https://raw.githubusercontent.com/projectdiscovery/dnsx/main/scripts/resolvers-trusted.txt"
```

### Manual Tool Installation (if needed)
```bash
# Install Go tools manually
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/tomnomnom/anew@latest
```

## Usage

### Basic Commands

```bash
# Single domain scan
./autorecon domain example.com

# Single URL scan
./autorecon url https://example.com

# Target list scan
./autorecon list targets.txt

# Project-based scan
./autorecon -p myproject domain example.com

# Resume project
./autorecon resume myproject

# Stop project
./autorecon stop myproject

# Show global status
./autorecon status

# Install required tools
./autorecon install

# Show help
./autorecon -h
```

### Input Formats

The tool supports various input formats:

```bash
# Domains
example.com
*.example.com

# URLs
https://example.com
http://sub.example.com

# IPs
192.168.1.1
10.0.0.0/24

# IP Ranges
192.168.1.1-192.168.1.254

# Mixed content in files
# Sample targets.txt:
example.com
https://example.com
192.168.1.1
192.168.1.0/24
```

## Project Structure

```
autorecon/
├── cmd/
│   └── autorecon/
│       └── main.go          # Main application entry point
├── internal/
│   ├── config/
│   │   └── config.go        # Configuration management
│   ├── parser/
│   │   └── parser.go        # Target parsing and categorization
│   ├── scanner/
│   │   └── scanner.go       # Scanning tools management
│   ├── storage/
│   │   └── storage.go       # Global file management
│   └── ui/
│       └── ui.go           # User interface and progress display
├── pkg/
│   └── models/
│       ├── target.go        # Target data models
│       └── project.go       # Project management models
├── go.mod
├── go.sum
└── README.md
```

## Scanning Process

The tool follows a 6-step scanning process:

1. **Parse Targets** - Parse and categorize input targets
2. **Expand IP Ranges** - Expand CIDR and dash notation IP ranges
3. **Subdomain Discovery** - Use subfinder and dnsx for domain enumeration
4. **URL Validation** - Use httpx to validate URLs and discover services
5. **Port Scanning** - Use naabu for port discovery on IPs
6. **Vulnerability Scan** - Use nuclei for vulnerability assessment

## Project Management

### Project States
- `new` - Project created but not started
- `scanning` - Project is currently running
- `paused` - Project is paused and can be resumed
- `completed` - Project has finished successfully
- `stopped` - Project was manually stopped
- `error` - Project encountered an error

### Project Files
Each project creates a directory structure:
```
projects/myproject/
├── project.json           # Project state and configuration
├── domains/               # Domain scan results
├── urls/                  # URL scan results
├── ips/                   # IP scan results
└── results/               # Combined results
```

## Configuration

The application uses a configuration system that supports:

- **Global data directory**: `/opt/autorecon`
- **Project directory**: `./projects`
- **Rate limiting**: Configurable scan rates
- **Status codes**: Customizable HTTP status codes
- **Custom headers**: User-defined HTTP headers
- **Tool settings**: Proxychains, Nuclei cloud features

## Troubleshooting

### Common Issues

1. **"subfinder not found" error:**
   ```bash
   ./autorecon install
   export PATH="$HOME/go/bin:$PATH"
   ```

2. **"SecLists not found" error:**
   ```bash
   sudo mkdir -p /opt/autorecon
   sudo git clone https://github.com/danielmiessler/SecLists.git /opt/autorecon/SecLists
   ```

3. **"resolver list not found" error:**
   ```bash
   sudo mkdir -p /opt/autorecon/resolvers
   sudo curl -L -o /opt/autorecon/resolvers/resolvers-trusted.txt "https://raw.githubusercontent.com/projectdiscovery/dnsx/main/scripts/resolvers-trusted.txt"
   ```

4. **Permission denied errors:**
   ```bash
   sudo chmod -R 755 /opt/autorecon
   ```

### Verification Commands

```bash
# Check if tools are available
which subfinder dnsx httpx nuclei naabu

# Check global files
ls -la /opt/autorecon/SecLists
ls -la /opt/autorecon/resolvers/

# Check project status
./autorecon status
```

## Dependencies

- **github.com/fatih/color** - Terminal color output
- **github.com/spf13/cobra** - CLI command framework
- **github.com/spf13/viper** - Configuration management
- **gopkg.in/yaml.v3** - YAML parsing

## Security Tools Used

- **subfinder** - Subdomain discovery
- **dnsx** - DNS enumeration
- **httpx** - HTTP probe
- **naabu** - Port scanner
- **nuclei** - Vulnerability scanner
- **mapcidr** - IP range expansion

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Author

**coded by: r1z4x**

---

## Examples

### Quick Start
```