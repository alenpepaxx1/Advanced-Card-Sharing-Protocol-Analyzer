# 🔍 Advanced Card Sharing Protocol Analyzer

[![Python](#maybeCitation:<https://img.shields.io/badge/Python-3.8+-blue.svg>)](<https://www.python.org/>)
[![License](#maybeCitation:<https://img.shields.io/badge/License-MIT-green.svg>)](LICENSE)
[![Version](#maybeCitation:<https://img.shields.io/badge/Version-3.0-orange.svg>)](<https://github.com/alenpepa/card-sharing-analyzer>)
[![Platform](#maybeCitation:<https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg>)](<https://github.com/alenpepa/card-sharing-analyzer>)

> **Professional card sharing server monitoring and analysis tool with advanced protocol detection and expiry tracking.**

🔒 Legal Notice: This tool is intended for personal and educational use only. Any misuse, including unauthorized access to pay TV services, is strictly prohibited. The developer assumes no responsibility for illegal use.

## 🚀 Features

### 🔧 Protocol Support
- **CCcam** - Full handshake analysis and version detection
- **NewCamd** - DES encryption support and CAID detection
- **MGcamd** - Compatible with NewCamd protocol analysis
- **OSCam** - Web interface integration and JSON parsing

### 📊 Advanced Analysis
- ✅ **Real-time server status monitoring**
- ✅ **Automatic version detection**
- ✅ **Smart expiry date calculation**
- ✅ **Provider/package identification** (Sky, Canal+, Nova, etc.)
- ✅ **Response time measurement**
- ✅ **Card count and share type detection**
- ✅ **Multi-threaded parallel processing**

### 🎨 Modern Dark Mode GUI
- ✅ **Professional dark theme interface**
- ✅ **Real-time progress tracking**
- ✅ **Color-coded status indicators**
- ✅ **Advanced data table with sorting**
- ✅ **Expiry warning system**

### 📈 Export & Reporting
- ✅ **HTML reports** with professional styling
- ✅ **JSON data export** for integration
- ✅ **Detailed text reports**
- ✅ **Statistical summaries**
- ✅ **Copyright and branding included**

## 🖼️ Screenshots

### Main Interface
! [Main Interface](#maybeCitation:screenshots/main-interface.png)

### Analysis Results
! [Analysis Results](#maybeCitation:screenshots/analysis-results.png)

### HTML Report
! [HTML Report](#maybeCitation:screenshots/html-report.png)

## 🔧 Installation

### Prerequisites
```bash
Python 3.8 or higher
tkinter (usually included with Python)

Install Dependencies
pip install -r requirements.txt

​
Quick Start
git clone <https://github.com/alenpepa/card-sharing-analyzer.git>
cd card-sharing-analyzer
python card_sharing_analyzer.py

​
📝 Configuration
Server Configuration Format
# CCcam servers
C: hostname port username password

# NewCamd servers
N: hostname port username password DES_KEY

# MGcamd servers
M: hostname port username password

​
Sample Configuration
C: cccam-server.com 12000 testuser testpass
C: premium.server.tv 12001 monthuser monthpass
N: newcamd.server.org 15000 newuser newpass 0102030405060708091011121314
M: mgcamd.example.com 15001 mguser mgpass

​
🚀 Usage
Load Configuration
Use built-in sample or load your config file
Supports .cfg, .txt, and custom formats
Analyze Servers
Click "Analyze Servers" for comprehensive analysis
Real-time progress tracking with status updates
View Results
Color-coded status indicators
Detailed server information
Expiry warnings and notifications
Export Reports
HTML reports for presentation
JSON data for integration
Text reports for documentation
📊 Analysis Details
Expiry Detection
The analyzer uses intelligent username pattern matching:
test, trial, demo → 3-7 days
month, 30d, monthly → 30 days
year, 365, annual → 365 days
vip, premium, platinum → 90 days
Provider Detection
Automatic detection of major providers:
Sky UK/Deutschland
Canal+ France
Polsat Poland
Nova Czech Republic
Cyfra+ Poland
And many more...
Protocol Versions
CCcam: 2.0.11 - 2.3.2
NewCamd: 5.25 - 6.1
MGcamd: 1.35 - 1.40
OSCam: 1.20 - 11710
🔒 Security & Legal
⚠️ Important Notice
This tool is for educational and testing purposes only
Respect all terms of service and local laws
Use only on servers you own or have permission to test
No warranty provided - use at your own risk
🛠️ Development
Project Structure
card-sharing-analyzer/
├── card_sharing_analyzer.py    # Main application
├── requirements.txt            # Dependencies
├── config/
│   ├── sample_servers.cfg     # Sample configuration
│   └── settings.json          # Application settings
├── exports/
│   ├── reports/               # HTML reports
│   └── data/                  # JSON exports
├── screenshots/               # GUI screenshots
└── README.md                  # This file

​
Contributing
Fork the repository
Create a feature branch
Commit your changes
Push to the branch
Create a Pull Request
📞 Support
Issues: GitHub Issues
LinkedIn: Alen Pepa
📜 License
MIT License

Copyright (c) 2025 Alen Pepa

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

🔒 Legal Notice: This tool is intended for personal and educational use only. Any misuse, including unauthorized access to pay TV services, is strictly prohibited. The developer assumes no responsibility for illegal use.
​
🙏 Acknowledgments
Thanks to the card sharing community for protocol documentation
Special thanks to all beta testers and contributors
Inspired by the need for professional monitoring tools
⭐ If you find this tool useful, please give it a star on GitHub!
Made with ❤️ by Alen Pepa
