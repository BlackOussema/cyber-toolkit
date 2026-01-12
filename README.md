# 🛡️ Cyber Toolkit: Multi-Platform Security Analysis Suite

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)

## Overview

Cyber Toolkit is a comprehensive, multi-platform security analysis suite designed for security researchers, penetration testers, and developers. It provides robust functionalities for both web vulnerability scanning and Android APK static analysis, making it an invaluable tool for identifying security weaknesses across different application types.

## Features

### Web Scanner
*   **Security Header Analysis**: Automatically checks for critical security headers such as Content-Security-Policy (CSP), X-Frame-Options, HTTP Strict Transport Security (HSTS), and more.
*   **Technology Detection**: Identifies underlying web frameworks, server technologies, and client-side libraries.
*   **SSL/TLS Verification**: Validates SSL/TLS certificate configurations and identifies potential misconfigurations.
*   **Robots.txt Analysis**: Parses `robots.txt` files to discover disallowed paths and potentially sensitive directories.
*   **OWASP ZAP Integration**: Offers optional integration with OWASP ZAP for deeper, dynamic application security testing (DAST) including spidering and active scanning.

### APK Analyzer
*   **Manifest Parsing**: Extracts detailed information from AndroidManifest.xml, including permissions, components, and security flags.
*   **Secret Detection**: Scans for hardcoded sensitive information such as API keys, credentials, and other confidential data within the APK.
*   **Dangerous Permission Identification**: Highlights permissions that could pose privacy or security risks to users.
*   **Security Scoring**: Calculates a risk score for the APK based on identified vulnerabilities and misconfigurations.
*   **MobSF Integration**: Provides optional integration with Mobile Security Framework (MobSF) for advanced automated mobile security analysis.

### Report Generator
*   **Modern HTML Dashboard**: Generates beautiful, responsive HTML security reports that are easy to navigate and understand.
*   **Security Score Visualization**: Presents an at-a-glance risk assessment with visual indicators.
*   **Detailed Findings**: Provides a comprehensive breakdown of all identified vulnerabilities, misconfigurations, and potential risks.
*   **Export Ready**: Produces professional-grade reports suitable for stakeholders and compliance documentation.

## Installation

### Prerequisites
*   Python 3.8 or higher
*   Java JRE 11+ (required for APK analysis tools like `apktool` and `jadx`)
*   Git

### Quick Install (Local)

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/BlackOussema/cyber-toolkit.git
    cd cyber-toolkit/cyber-toolkit
    ```

2.  **Install Python dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **(Optional) Install APK analysis tools**:
    *   **Ubuntu/Debian**:
        ```bash
        sudo apt install apktool jadx
        ```
    *   **Arch/BlackArch**:
        ```bash
        sudo pacman -S apktool jadx
        ```
    *   **macOS**:
        ```bash
        brew install apktool jadx
        ```

### Docker Installation (Recommended for full environment)

1.  **Start all services** (including OWASP ZAP and MobSF):
    ```bash
    docker compose up -d
    ```

2.  **Run with Docker** (example for web scanner):
    ```bash
    docker compose run --rm scanner python3 web-scanner/scanner.py example.com
    ```

## Usage

### Web Scanner

*   **Basic scan**:
    ```bash
    python3 web-scanner/scanner.py https://example.com
    ```

*   **Save results to file**:
    ```bash
    python3 web-scanner/scanner.py https://example.com -o results/scan.json
    ```

*   **With OWASP ZAP integration**:
    ```bash
    python3 web-scanner/scanner.py https://example.com --use-zap
    ```

*   **Disable SSL verification (for testing)**:
    ```bash
    python3 web-scanner/scanner.py https://example.com --no-verify-ssl
    ```

*   **Verbose output**:
    ```bash
    python3 web-scanner/scanner.py https://example.com -v --stdout
    ```

### APK Analyzer

*   **Basic analysis**:
    ```bash
    python3 apk-analyzer/analyze.py app.apk
    ```

*   **Save report to file**:
    ```bash
    python3 apk-analyzer/analyze.py app.apk -o report.json
    ```

*   **Skip MobSF (offline analysis)**:
    ```bash
    python3 apk-analyzer/analyze.py app.apk --no-mobsf
    ```

*   **Keep decompiled files for inspection**:
    ```bash
    python3 apk-analyzer/analyze.py app.apk --keep-temp
    ```

*   **Use custom secret detection rules**:
    ```bash
    python3 apk-analyzer/analyze.py app.apk --rules custom_rules.txt
    ```

### Batch Processing

*   **Scan multiple websites**:
    ```bash
    ./run_all.sh --targets targets.txt
    ```

*   **Analyze multiple APKs**:
    ```bash
    ./run_all.sh --apks /path/to/apks/
    ```

*   **Combined analysis**:
    ```bash
    ./run_all.sh --targets targets.txt --apks /path/to/apks/
    ```

### Report Generation

*   **Generate HTML report from results**:
    ```bash
    python3 report_generator.py -d results/ -o report.html
    ```

*   **Open in browser**:
    ```bash
    xdg-open results/report.html  # For Linux
    open results/report.html       # For macOS
    start results/report.html      # For Windows
    ```

## Project Structure

```
cyber-toolkit/
├── web-scanner/            # Contains the web vulnerability scanner module
│   └── scanner.py          # Main script for web scanning
├── apk-analyzer/           # Contains the Android APK analyzer module
│   └── analyze.py          # Main script for APK analysis
├── results/                # Directory to store scan results (JSON format)
├── report_generator.py     # Script to generate HTML reports from JSON results
├── run_all.sh              # Shell script for batch processing of scans/analyses
├── docker-compose.yml      # Docker Compose configuration for setting up the environment
├── requirements.txt        # Python dependencies for the toolkit
└── README.md               # Project documentation (this file)
```

## Security Headers Checked (Web Scanner)

| Header | Description |
|-----------------------------|-----------------------------------------------------|
| `Content-Security-Policy`   | Prevents Cross-Site Scripting (XSS) and injection attacks by specifying allowed content sources. |
| `X-Frame-Options`           | Protects against clickjacking attacks by controlling whether a page can be rendered in a `<frame>`, `<iframe>`, `<embed>`, or `<object>`. |
| `X-Content-Type-Options`    | Prevents MIME-type sniffing by browsers, reducing exposure to drive-by download attacks. |
| `Strict-Transport-Security` | Enforces secure connections (HTTPS) by instructing browsers to only access the site using HTTPS. |
| `Referrer-Policy`           | Controls how much referrer information is included with requests, enhancing user privacy. |
| `Permissions-Policy`        | Allows or disallows the use of browser features (e.g., camera, microphone) in its own frame and in embedded iframes. |
| `X-XSS-Protection`          | A legacy header that enables the browser's built-in XSS filter (though CSP is preferred). |

## APK Security Checks (APK Analyzer)

### Dangerous Permissions Detected
*   **Camera, Microphone access**: Permissions that allow an app to record audio or video.
*   **Location tracking (fine/coarse)**: Permissions to access precise or approximate user location.
*   **SMS read/send capabilities**: Permissions to read or send SMS messages, potentially leading to fraud or privacy breaches.
*   **Contact and call log access**: Permissions to read user contacts or call history.
*   **Storage permissions**: Permissions to read from or write to external storage.
*   **Phone state access**: Permissions to read phone status and identity.
*   **System alert window**: Permission to draw over other apps, often abused by malware.

### Secret Patterns Identified
*   **API keys and tokens**: Hardcoded API keys for various services.
*   **AWS credentials**: Amazon Web Services access keys and secret keys.
*   **Firebase configurations**: Firebase API keys and project IDs.
*   **Database connection strings**: Credentials for connecting to databases.
*   **Private keys and certificates**: Cryptographic keys that should be kept confidential.
*   **OAuth secrets**: Client secrets for OAuth authentication.

## Docker Services

The `docker-compose.yml` file defines several services for a complete security analysis environment:

```yaml
# Example services available in docker-compose.yml
services:
  scanner:    # Web scanner container for web vulnerability analysis
  analyzer:   # APK analyzer container for Android application security analysis
  zap:        # OWASP ZAP proxy for dynamic web application security testing
  mobsf:      # Mobile Security Framework (MobSF) for comprehensive mobile app analysis
```

### Starting Services

```bash
# Start specific services (e.g., ZAP and MobSF)
docker compose up -d zap mobsf

# Check the status of running services
docker compose ps

# View logs of all services
docker compose logs -f
```

## Configuration

### Environment Variables

Configure external tool integrations using environment variables:

```bash
# OWASP ZAP Configuration
export ZAP_BASE="http://localhost:8090"

# MobSF Configuration
export MOBSF_URL="http://localhost:8000"
export MOBSF_API_KEY="your-api-key" # Replace with your actual MobSF API key
```

### Custom Rules File (for Secret Detection)

Create a `rules.txt` file in the `apk-analyzer/` directory with one regex pattern per line to define custom secret detection rules:

```
(?i)api[_-]?key\s*[:=]
(?i)password\s*[:=]
AKIA[0-9A-Z]{16}
(?i)-----BEGIN PRIVATE KEY-----
# Add your custom regex patterns here
```

## Sample Output

### Web Scan Result Example
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

### APK Analysis Result Example
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

## Contributing

Contributions are highly encouraged! If you have ideas for new features, improvements, or bug fixes, please follow these steps:

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b feature/your-awesome-feature`).
3.  Implement your changes and ensure they are well-tested.
4.  Commit your changes with a descriptive message (`git commit -m 'Add your awesome feature'`).
5.  Push to the branch (`git push origin feature/your-awesome-feature`).
6.  Open a Pull Request, detailing the changes you've made.

### Development Setup

```bash
# Install development dependencies (e.g., pytest, black, flake8)
pip install -r requirements-dev.txt

# Run tests to ensure functionality
pytest tests/

# Format code for consistency
black .

# Run linting checks
flake8 .
```

## Legal Disclaimer

**This toolkit is provided for educational and authorized security testing purposes only.**

*   Only use this tool on targets you own or for which you have explicit, written permission to test.
*   Unauthorized scanning or analysis of systems may violate laws and regulations and could lead to severe legal consequences.
*   The authors and contributors are not responsible for any misuse or damage caused by this tool.
*   Always adhere to responsible disclosure practices when identifying vulnerabilities.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

## Author

**Ghariani Oussema**
*   GitHub: [@BlackOussema](https://github.com/BlackOussema)
*   Role: Cybersecurity Researcher & Full-Stack Developer

## Acknowledgments

*   [OWASP ZAP](https://www.zaproxy.org/) - A leading open-source web application security scanner.
*   [MobSF](https://mobsf.github.io/Mobile-Security-Framework-MobSF/) - An automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework.
*   [apktool](https://ibotpeaches.github.io/Apktool/) - A reverse engineering tool for Android applications.
*   [jadx](https://github.com/skylot/jadx) - DEX to Java decompiler.

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
