<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange.svg" alt="Version">
</p>

<h1 align="center">🛡️ Cyber Toolkit</h1>

<p align="center">
  <strong>Professional Multi-Platform Security Analysis Suite</strong>
</p>

<p align="center">
  A comprehensive security toolkit for web vulnerability scanning and Android APK static analysis.<br>
  Designed for security researchers, penetration testers, and developers.
</p>

---

## 🚀 Features

### Web Scanner
- **Security Header Analysis** - Checks for CSP, X-Frame-Options, HSTS, and more
- **Technology Detection** - Identifies web frameworks, servers, and libraries
- **SSL/TLS Verification** - Validates certificate configuration
- **Robots.txt Analysis** - Discovers hidden paths and directives
- **OWASP ZAP Integration** - Optional spider scanning for deeper analysis

### APK Analyzer
- **Manifest Parsing** - Extracts permissions, components, and security flags
- **Secret Detection** - Finds API keys, credentials, and sensitive data
- **Dangerous Permission Identification** - Highlights privacy-invasive permissions
- **Security Scoring** - Calculates risk score based on findings
- **MobSF Integration** - Optional automated mobile security analysis

### Report Generator
- **Modern HTML Dashboard** - Beautiful, responsive security reports
- **Security Score Visualization** - At-a-glance risk assessment
- **Detailed Findings** - Comprehensive breakdown of vulnerabilities
- **Export Ready** - Professional reports for stakeholders

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Java JRE 11+ (for APK analysis)
- Git

### Quick Install

```bash
# Clone the repository
git clone https://github.com/BlackOussema/cyber-toolkit.git
cd cyber-toolkit/cyber-toolkit

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install APK analysis tools
# Ubuntu/Debian
sudo apt install apktool jadx

# Arch/BlackArch
sudo pacman -S apktool jadx

# macOS
brew install apktool jadx
```

### Docker Installation (Recommended)

```bash
# Start all services
docker compose up -d

# Run with Docker
docker compose run --rm scanner python3 web-scanner/scanner.py example.com
```

---

## 🔧 Usage

### Web Scanner

```bash
# Basic scan
python3 web-scanner/scanner.py example.com

# Save results to file
python3 web-scanner/scanner.py example.com -o results/scan.json

# With OWASP ZAP integration
python3 web-scanner/scanner.py example.com --use-zap

# Disable SSL verification (for testing)
python3 web-scanner/scanner.py example.com --no-verify-ssl

# Verbose output
python3 web-scanner/scanner.py example.com -v --stdout
```

### APK Analyzer

```bash
# Basic analysis
python3 apk-analyzer/analyze.py app.apk

# Save report to file
python3 apk-analyzer/analyze.py app.apk -o report.json

# Skip MobSF (offline analysis)
python3 apk-analyzer/analyze.py app.apk --no-mobsf

# Keep decompiled files for inspection
python3 apk-analyzer/analyze.py app.apk --keep-temp

# Use custom secret detection rules
python3 apk-analyzer/analyze.py app.apk --rules custom_rules.txt
```

### Batch Processing

```bash
# Scan multiple websites
./run_all.sh --targets targets.txt

# Analyze multiple APKs
./run_all.sh --apks /path/to/apks/

# Combined analysis
./run_all.sh --targets targets.txt --apks /path/to/apks/
```

### Report Generation

```bash
# Generate HTML report from results
python3 report_generator.py -d results/ -o report.html

# Open in browser
xdg-open results/report.html  # Linux
open results/report.html       # macOS
```

---

## 📁 Project Structure

```
cyber-toolkit/
├── web-scanner/
│   └── scanner.py          # Web vulnerability scanner
├── apk-analyzer/
│   └── analyze.py          # Android APK analyzer
├── results/                # Scan results (JSON)
├── report_generator.py     # HTML report generator
├── run_all.sh             # Batch processing script
├── docker-compose.yml     # Docker configuration
├── requirements.txt       # Python dependencies
└── README.md
```

---

## 🔒 Security Headers Checked

| Header | Description |
|--------|-------------|
| `Content-Security-Policy` | Prevents XSS and injection attacks |
| `X-Frame-Options` | Prevents clickjacking |
| `X-Content-Type-Options` | Prevents MIME-type sniffing |
| `Strict-Transport-Security` | Enforces HTTPS |
| `Referrer-Policy` | Controls referrer information |
| `Permissions-Policy` | Restricts browser features |
| `X-XSS-Protection` | Legacy XSS filter (deprecated) |

---

## 📱 APK Security Checks

### Dangerous Permissions Detected
- Camera, Microphone access
- Location tracking (fine/coarse)
- SMS read/send capabilities
- Contact and call log access
- Storage permissions
- Phone state access
- System alert window

### Secret Patterns
- API keys and tokens
- AWS credentials
- Firebase configurations
- Database connection strings
- Private keys and certificates
- OAuth secrets

---

## 🐳 Docker Services

```yaml
# Available services in docker-compose.yml
services:
  scanner:    # Web scanner container
  analyzer:   # APK analyzer container
  zap:        # OWASP ZAP proxy
  mobsf:      # Mobile Security Framework
```

### Starting Services

```bash
# Start ZAP and MobSF
docker compose up -d zap mobsf

# Check status
docker compose ps

# View logs
docker compose logs -f
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# ZAP Configuration
export ZAP_BASE="http://localhost:8090"

# MobSF Configuration
export MOBSF_URL="http://localhost:8000"
export MOBSF_API_KEY="your-api-key"
```

### Custom Rules File

Create a `rules.txt` file with one regex pattern per line:

```
(?i)api[_-]?key\s*[:=]
(?i)password\s*[:=]
AKIA[0-9A-Z]{16}
(?i)-----BEGIN PRIVATE KEY-----
```

---

## 📊 Sample Output

### Web Scan Result
```json
{
  "target": "https://example.com",
  "timestamp": 1704931200,
  "status_code": 200,
  "server": "nginx/1.24.0",
  "security_headers": {
    "Content-Security-Policy": {
      "present": true,
      "value": "default-src 'self'"
    },
    "X-Frame-Options": {
      "present": true,
      "value": "DENY"
    }
  },
  "technologies": ["Nginx", "React"]
}
```

### APK Analysis Result
```json
{
  "apk_name": "app.apk",
  "security_score": 65,
  "manifest": {
    "package": "com.example.app",
    "debuggable": false,
    "dangerous_permissions": [
      {"permission": "android.permission.CAMERA", "description": "Access camera"}
    ]
  },
  "secrets": [
    {"rule": "api_key", "file": "Config.java", "line": 42, "severity": "high"}
  ]
}
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black .
flake8 .
```

---

## ⚠️ Legal Disclaimer

**This toolkit is provided for educational and authorized security testing purposes only.**

- Only scan targets you own or have explicit permission to test
- Unauthorized scanning may violate laws and regulations
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ghariani Oussema**
- GitHub: [@BlackOussema](https://github.com/BlackOussema)
- Role: Cyber Security Researcher & Full-Stack Developer

---

## 🙏 Acknowledgments

- [OWASP ZAP](https://www.zaproxy.org/) - Web security scanner
- [MobSF](https://mobsf.github.io/Mobile-Security-Framework-MobSF/) - Mobile security framework
- [apktool](https://ibotpeaches.github.io/Apktool/) - APK reverse engineering
- [jadx](https://github.com/skylot/jadx) - DEX to Java decompiler

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
