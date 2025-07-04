#!/bin/bash

# AutoRecon Installation Script
# This script installs all required dependencies and builds the application

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    AutoRecon Installer                       ║"
echo "║                    coded by: r1z4x                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Check if running as root for global installations
if [[ $EUID -eq 0 ]]; then
   echo "✓ Running as root - will install global dependencies"
else
   echo "⚠ Not running as root - some installations may require sudo"
fi

# Detect OS
OS=$(uname -s)
case $OS in
    Darwin)
        echo "✓ Detected macOS"
        PACKAGE_MANAGER="brew"
        ;;
    Linux)
        echo "✓ Detected Linux"
        if command -v apt-get &> /dev/null; then
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            PACKAGE_MANAGER="yum"
        else
            echo "✗ Unsupported package manager"
            exit 1
        fi
        ;;
    *)
        echo "✗ Unsupported operating system: $OS"
        exit 1
        ;;
esac

# Install system dependencies
echo
echo "📦 Installing system dependencies..."

case $PACKAGE_MANAGER in
    brew)
        brew update
        brew install go git curl wget nmap openssl
        ;;
    apt)
        sudo apt-get update
        sudo apt-get install -y golang-go git curl wget nmap openssl
        ;;
    yum)
        sudo yum update -y
        sudo yum install -y golang git curl wget nmap openssl
        ;;
esac

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go..."
    case $OS in
        Darwin)
            brew install go
            ;;
        Linux)
            # Download and install Go
            GO_VERSION="1.21.0"
            wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            source ~/.bashrc
            rm go${GO_VERSION}.linux-amd64.tar.gz
            ;;
    esac
fi

# Setup Go environment
echo "🔧 Setting up Go environment..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Add to shell profile
if [[ "$SHELL" == *"zsh"* ]]; then
    echo 'export GOPATH=$HOME/go' >> ~/.zshrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
elif [[ "$SHELL" == *"bash"* ]]; then
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
fi

# Install Go tools
echo "🔧 Installing Go security tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# Install Shodan CLI
echo "Installing Shodan CLI..."
pip3 install shodan

# Note: Set your API keys after installation:
# shodan init YOUR_API_KEY
# censys config

# Create global directories
echo "📁 Creating global directories..."
sudo mkdir -p /opt/SecLists
sudo mkdir -p /opt/Resolvers

# Download SecLists if not present
if [ ! -d "/opt/SecLists" ] || [ -z "$(ls -A /opt/SecLists)" ]; then
    echo "📥 Downloading SecLists..."
    sudo git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
else
    echo "✓ SecLists already exists, updating..."
    sudo git -C /opt/SecLists pull
fi

# Download resolvers if not present
if [ ! -f "/opt/Resolvers/resolvers-trusted.txt" ]; then
    echo "📥 Downloading trusted resolvers..."
    sudo curl -L -o /opt/Resolvers/resolvers-trusted.txt \
        https://raw.githubusercontent.com/projectdiscovery/dnsx/main/scripts/resolvers-trusted.txt
else
    echo "✓ Trusted resolvers already exist"
fi

# Set permissions
echo "🔐 Setting permissions..."
sudo chown -R $USER:$USER /opt/SecLists
sudo chown -R $USER:$USER /opt/Resolvers
chmod -R 755 /opt/SecLists
chmod -R 755 /opt/Resolvers

# Build the application
echo "🔨 Building AutoRecon..."
go mod tidy
go build -o autorecon cmd/autorecon/main.go

# Create symbolic links
echo "🔗 Creating symbolic links..."
if [[ $EUID -eq 0 ]]; then
    sudo ln -sf $(pwd)/autorecon /usr/local/bin/autorecon
else
    sudo ln -sf $(pwd)/autorecon /usr/local/bin/autorecon
fi

echo
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Installation Complete!                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo
echo "✓ AutoRecon has been installed successfully!"
echo "✓ Global dependencies are available in /opt/SecLists and /opt/Resolvers"
echo "✓ You can now run: autorecon --help"
echo
echo "📋 Next steps:"
echo "  1. Set up your Shodan API key: shodan init"
echo "  2. Run a test scan: autorecon domain example.com"
echo "  3. Check status: autorecon status"
echo
echo "🔧 Enhanced features available:"
echo "  - Nmap port and service scanning"
echo "  - SSL certificate analysis"
echo "  - Shodan data integration"
echo "  - Dynamic target discovery from SSL/Shodan data"
echo 