# Memory Dump Forensics Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Volatility3](https://img.shields.io/badge/Framework-Volatility3-green)
![License](https://img.shields.io/badge/License-MIT-orange)

A powerful Python-based memory dump analysis tool built on top of the Volatility3 framework. This tool automates the triage of memory dumps, providing rich terminal output and comprehensive forensic capabilities for incident response and malware analysis.

## Features

### Core Analysis
- **Process Enumeration:** Deep analysis of running processes and hierarchy.
- **Network Detection:** Identification of active connections and listening ports.
- **OS Extraction:** Automated retrieval of system architecture and version details.
- **Command Line Reconstruction:** Recover arguments used to launch processes.

### Advanced Forensics
- **Windows Services:** Analysis of service configurations and associated binaries.
- **DLL Inspection:** Mapping of loaded modules and base addresses.
- **Malware Detection:** Automated scanning for injected code and malicious memory sections (Malfind).
- **Registry Analysis:** Extraction of active hives and modification times.
- **Suspicious Patterns:** Heuristic detection of potential threats.

### Tool Highlights
- 🖥️ **Rich Terminal UI:** Formatted tables and color-coded output.
- ⏳ **Progress Tracking:** Live progress bars for long-running operations.
- 📝 **Comprehensive Logging:** Auto-generates detailed logs for evidence.
- ⚡ **Asynchronous:** Optimized for performance.

## Requirements

- Python 3.8+
- Volatility3 framework
- Rich library (for terminal output)

## Installation

1. Clone the repository:
```bash
git clone [https://github.com/Guransh-ship-it/Memory-forensic-tool.git]
cd Memory-forensic-tool
Create a virtual environment (recommended):

Bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
Install dependencies:

Bash
pip install volatility3 rich
Usage
Run the tool against a memory dump file (e.g., .raw, .dmp, .mem):

Bash
python memory_forensics.py path/to/memory_dump.raw
The tool will automatically:

Analyze the memory dump.

Display progress bars for each analysis phase.

Output formatted results to the terminal.

Save a full log to memory_analysis.log.

Output Example
Plaintext
=== Memory Dump Analysis Results ===

[Operating System Information]
- OS Version: Windows 10
- System Architecture: x64
- Installation Time: 2023-01-01 12:00:00

[Process Information]
- Running processes: 142
- Suspicious processes detected: 2

[Network Information]
- Active connections: 15
- Listening ports: 445, 135, 80

[Malfind Analysis]
- Injected Code Detected: PID 452 (svchost.exe) - RWX region found
Legal & Disclaimer
This tool is intended for legitimate forensic investigation, incident response, security research, and educational purposes only.

Important: Ensure you have proper authorization before analyzing any memory dumps. The author is not responsible for any damage caused by the use of this tool or for any unauthorized forensic analysis.

Contributing
Contributions are welcome! If you have ideas for new modules or detection capabilities, please submit a Pull Request.

Future Plans
[ ] Timeline analysis

[ ] String search capabilities

[ ] User session information

[ ] Export to JSON/CSV



Contact
Project Maintainer: Guransh

If you discover any security-related issues or have feature requests, please open an issue on the GitHub repository.